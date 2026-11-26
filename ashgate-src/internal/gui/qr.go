package gui

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"

	qrcode "github.com/skip2/go-qrcode"

	"ashgate/internal/config"
	"ashgate/internal/subs"
	"ashgate/internal/vless"
)

const (
	vlessAndroidWarning = "Ashgate для Android поддерживает только VLESS XHTTP с Reality или TLS. Этот QR подойдёт для других клиентов."
	httpSubWarning      = "Ashgate для Android принимает только https://-подписки и отклонит http://. Переключитесь на «Активный сервер» или используйте https://."
	qrECThreshold       = 400
)

type qrResponse struct {
	Name     string   `json:"name"`
	Subtitle string   `json:"subtitle"`
	Image    string   `json:"image"`
	Warning  string   `json:"warning,omitempty"`
	Mode     string   `json:"mode,omitempty"`
	Modes    []string `json:"modes,omitempty"`
}

// qrPlan is the resolved QR payload and display metadata before encoding to SVG.
// Payload is never logged and never returned outside the encoded SVG image.
type qrPlan struct {
	name     string
	subtitle string
	payload  string
	warning  string
	mode     string
	modes    []string
}

func (c *controller) proxyQR(name, mode string) (qrResponse, error) {
	c.mu.Lock()
	var (
		p         config.Proxy
		ok        bool
		subURL    string
		entries   []subs.Entry
		activeIdx int
		hasGroup  bool
	)
	if c.cfg != nil {
		p, ok = c.cfg.ProxyByName(name)
	}
	if ok {
		if p.VLESS != nil {
			v := *p.VLESS
			if v.Extra != nil {
				v.Extra = append(json.RawMessage(nil), v.Extra...)
			}
			p.VLESS = &v
		}
		if p.Sub != nil {
			s := *p.Sub
			p.Sub = &s
			if g := c.subs[p.Name]; g != nil {
				hasGroup = true
				subURL = g.url
				entries = append([]subs.Entry(nil), g.entries...)
				if g.fo != nil {
					activeIdx = g.fo.Active
				}
			}
		}
	}
	c.mu.Unlock()

	if !ok {
		return qrResponse{}, errors.New("прокси не найден")
	}

	if p.Sub != nil && !hasGroup && p.Sub.Sealed != "" {
		if sec, err := subs.Open(p.Sub.Sealed); err == nil {
			subURL = sec.URL
			entries = subs.Entries(sec.Links)
		}
	}

	plan, err := buildProxyQRPlan(p, mode, subURL, entries, activeIdx)
	if err != nil {
		return qrResponse{}, err
	}
	img, err := encodeQRDataURL(plan.payload)
	if err != nil {
		return qrResponse{}, err
	}
	return qrResponse{
		Name:     plan.name,
		Subtitle: plan.subtitle,
		Image:    img,
		Warning:  plan.warning,
		Mode:     plan.mode,
		Modes:    plan.modes,
	}, nil
}

func buildProxyQRPlan(p config.Proxy, mode, subURL string, entries []subs.Entry, activeIdx int) (qrPlan, error) {
	if p.Sub != nil {
		return buildSubQRPlan(p, mode, subURL, entries, activeIdx)
	}
	switch strings.ToLower(strings.TrimSpace(p.Type)) {
	case "vless":
		return buildVLESSQRPlan(p)
	case "socks5", "http":
		return buildPlainProxyQRPlan(p)
	default:
		return qrPlan{}, errors.New("неподдерживаемый тип прокси")
	}
}

func buildSubQRPlan(p config.Proxy, mode, subURL string, entries []subs.Entry, activeIdx int) (qrPlan, error) {
	mode = strings.TrimSpace(mode)
	if mode == "" {
		mode = "subscription"
	}
	if mode != "subscription" && mode != "active" {
		return qrPlan{}, errors.New("неизвестный режим QR-кода")
	}

	hasActive := len(entries) > 0
	modes := []string{"subscription"}
	if hasActive {
		modes = []string{"subscription", "active"}
	}

	if mode == "subscription" {
		payload := strings.TrimSpace(subURL)
		if payload == "" {
			return qrPlan{}, errors.New("не удалось расшифровать ссылку подписки")
		}
		host := subscriptionHost(payload, p.Sub.Host)
		subtitle := "Подписка"
		if host != "" {
			subtitle = "Подписка · " + host
		}
		var warning string
		if !strings.HasPrefix(strings.ToLower(payload), "https://") {
			warning = httpSubWarning
		}
		return qrPlan{
			name:     p.Name,
			subtitle: subtitle,
			payload:  payload,
			warning:  warning,
			mode:     mode,
			modes:    modes,
		}, nil
	}

	if !hasActive {
		return qrPlan{}, errors.New("в подписке нет рабочих серверов")
	}
	if activeIdx < 0 || activeIdx >= len(entries) {
		activeIdx = 0
	}
	entry := entries[activeIdx]
	payload := strings.TrimSpace(entry.Link)
	if payload == "" {
		return qrPlan{}, errors.New("у профиля нет ссылки vless://")
	}
	host := hostFromAddress(entry.Address)
	if host == "" {
		if u, err := url.Parse(payload); err == nil {
			host = u.Hostname()
		}
	}
	subtitle := "VLESS"
	if host != "" {
		subtitle = "VLESS · " + host
	}
	var warning string
	if !vlessAndroidCompatible(entry.Params) {
		warning = vlessAndroidWarning
	}
	return qrPlan{
		name:     p.Name,
		subtitle: subtitle,
		payload:  payload,
		warning:  warning,
		mode:     mode,
		modes:    modes,
	}, nil
}

func buildVLESSQRPlan(p config.Proxy) (qrPlan, error) {
	rawLink := strings.TrimSpace(p.Link)
	var (
		payload   string
		params    vless.Params
		hasParams bool
		host      string
	)

	if p.VLESS != nil {
		eff := *p.VLESS
		_ = eff.Normalize()
		params = eff
		hasParams = true
		host = hostFromAddress(p.Address)

		// Keep original p.Link verbatim only if it matches the effective address
		// and structured VLESS params; otherwise synthesize canonical vless:// from
		// the edited fields (config.Proxy.Prepare prioritizes p.VLESS).
		if rawLink != "" {
			if parsed, err := vless.ParseLink(rawLink); err == nil && vlessMatches(parsed, p.Address, eff) {
				payload = rawLink
				if host == "" {
					host = hostFromAddress(parsed.Address)
				}
			}
		}
		if payload == "" {
			built, h, err := encodeVLESSURI(p.Name, p.Address, eff)
			if err != nil {
				if rawLink == "" {
					return qrPlan{}, err
				}
				payload = rawLink
			} else {
				payload = built
				if host == "" {
					host = h
				}
			}
		}
	} else {
		if rawLink == "" {
			return qrPlan{}, errors.New("у профиля нет ссылки vless://")
		}
		payload = rawLink
		if parsed, err := vless.ParseLink(payload); err == nil {
			params = parsed.Params
			hasParams = true
			host = hostFromAddress(parsed.Address)
		} else if loose, ok := parseVLESSParamsLoose(payload); ok {
			params = loose
			hasParams = true
		}
	}

	if host == "" {
		host = hostFromAddress(p.Address)
	}
	if host == "" {
		if u, err := url.Parse(payload); err == nil {
			host = u.Hostname()
		}
	}

	subtitle := "VLESS"
	if host != "" {
		subtitle = "VLESS · " + host
	}

	var warning string
	if !hasParams || !vlessAndroidCompatible(params) {
		warning = vlessAndroidWarning
	}
	return qrPlan{
		name:     p.Name,
		subtitle: subtitle,
		payload:  payload,
		warning:  warning,
	}, nil
}

func vlessMatches(parsed vless.Parsed, addr string, eff vless.Params) bool {
	if strings.TrimSpace(addr) != "" && !strings.EqualFold(strings.TrimSpace(parsed.Address), strings.TrimSpace(addr)) {
		return false
	}
	a := parsed.Params
	return a.UUID == eff.UUID &&
		a.Encryption == eff.Encryption &&
		a.Flow == eff.Flow &&
		a.Network == eff.Network &&
		a.Security == eff.Security &&
		a.SNI == eff.SNI &&
		a.Fingerprint == eff.Fingerprint &&
		a.PublicKey == eff.PublicKey &&
		a.ShortID == eff.ShortID &&
		a.SpiderX == eff.SpiderX &&
		a.Path == eff.Path &&
		a.Host == eff.Host &&
		a.ServiceName == eff.ServiceName &&
		a.Mode == eff.Mode &&
		a.Authority == eff.Authority &&
		a.ALPN == eff.ALPN &&
		a.HeaderType == eff.HeaderType &&
		a.AllowInsecure == eff.AllowInsecure &&
		a.PinnedSHA256 == eff.PinnedSHA256 &&
		bytes.Equal(bytes.TrimSpace(a.Extra), bytes.TrimSpace(eff.Extra))
}

func encodeVLESSURI(name, address string, v vless.Params) (uri, host string, err error) {
	if strings.TrimSpace(v.UUID) == "" {
		return "", "", errors.New("у профиля нет UUID VLESS")
	}
	rawHost, rawPort, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return "", "", errors.New("неверный адрес прокси")
	}
	host = strings.TrimSpace(rawHost)
	portNum, err := strconv.Atoi(strings.TrimSpace(rawPort))
	if host == "" || strings.ContainsAny(host, "/?#@ \t\r\n") || err != nil || portNum < 1 || portNum > 65535 {
		return "", "", errors.New("неверный адрес прокси")
	}
	hostPart := host
	if strings.Contains(host, ":") && (!strings.HasPrefix(host, "[") || !strings.HasSuffix(host, "]")) {
		hostPart = "[" + host + "]"
	}
	q := url.Values{}
	enc := v.Encryption
	if enc == "" {
		enc = "none"
	}
	q.Set("encryption", enc)
	if v.Network != "" {
		q.Set("type", v.Network)
	}
	if v.Security != "" {
		q.Set("security", v.Security)
	}
	setIf := func(k, val string) {
		if val != "" {
			q.Set(k, val)
		}
	}
	setIf("flow", v.Flow)
	setIf("sni", v.SNI)
	setIf("fp", v.Fingerprint)
	setIf("pbk", v.PublicKey)
	setIf("sid", v.ShortID)
	setIf("spx", v.SpiderX)
	setIf("path", v.Path)
	setIf("host", v.Host)
	setIf("serviceName", v.ServiceName)
	setIf("mode", v.Mode)
	setIf("authority", v.Authority)
	setIf("alpn", v.ALPN)
	setIf("headerType", v.HeaderType)
	setIf("pcs", v.PinnedSHA256)
	if v.AllowInsecure {
		q.Set("allowInsecure", "1")
	}
	if extra := strings.TrimSpace(string(v.Extra)); extra != "" {
		q.Set("extra", extra)
	}
	var frag string
	if trimmed := strings.TrimSpace(name); trimmed != "" {
		frag = "#" + percentEncodeRFC3986(trimmed)
	}
	return "vless://" + percentEncodeRFC3986(v.UUID) + "@" + hostPart + ":" + strconv.Itoa(portNum) + "?" + q.Encode() + frag, host, nil
}

func buildPlainProxyQRPlan(p config.Proxy) (qrPlan, error) {
	scheme := strings.ToLower(strings.TrimSpace(p.Type))
	payload, hostPart, port, err := encodePlainProxyURI(scheme, p.Name, p.Address, p.Username, p.Password)
	if err != nil {
		return qrPlan{}, err
	}
	label := "SOCKS5"
	if scheme == "http" {
		label = "HTTP"
	}
	return qrPlan{
		name:     p.Name,
		subtitle: label + " · " + hostPart + ":" + port,
		payload:  payload,
	}, nil
}

// encodePlainProxyURI builds a SOCKS5 or HTTP proxy URI compatible with
// Android's ProfileQr.kt. It never emits a path or query string so HTTP
// proxies are never confused with insecure http:// subscriptions.
func encodePlainProxyURI(scheme, name, address, user, pass string) (uri, hostPart, port string, err error) {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	if scheme != "socks5" && scheme != "http" {
		return "", "", "", errors.New("неподдерживаемый тип прокси")
	}
	rawHost, rawPort, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return "", "", "", errors.New("неверный адрес прокси")
	}
	host := strings.TrimSpace(rawHost)
	portNum, err := strconv.Atoi(strings.TrimSpace(rawPort))
	if host == "" || strings.ContainsAny(host, "/?#@ \t\r\n") || err != nil || portNum < 1 || portNum > 65535 {
		return "", "", "", errors.New("неверный адрес прокси")
	}
	port = strconv.Itoa(portNum)

	hostPart = host
	if strings.Contains(host, ":") && (!strings.HasPrefix(host, "[") || !strings.HasSuffix(host, "]")) {
		hostPart = "[" + host + "]"
	}

	var auth string
	if user != "" {
		auth = percentEncodeRFC3986(user)
		if pass != "" {
			auth += ":" + percentEncodeRFC3986(pass)
		}
		auth += "@"
	}

	trimmedName := strings.TrimSpace(name)
	unbracketedHost := strings.TrimRight(strings.TrimLeft(host, "["), "]")
	unbracketedName := strings.TrimRight(strings.TrimLeft(trimmedName, "["), "]")
	var fragment string
	if trimmedName != "" && trimmedName != host && unbracketedName != unbracketedHost {
		fragment = "#" + percentEncodeRFC3986(trimmedName)
	}

	uri = scheme + "://" + auth + hostPart + ":" + port + fragment
	return uri, hostPart, port, nil
}

// vlessAndroidCompatible mirrors mobilecfg.checkLink on android-mvp.
func vlessAndroidCompatible(params vless.Params) bool {
	if strings.ToLower(strings.TrimSpace(params.Network)) != "xhttp" {
		return false
	}
	sec := strings.ToLower(strings.TrimSpace(params.Security))
	if sec != "reality" && sec != "tls" {
		return false
	}
	if len(params.Extra) == 0 {
		return true
	}
	var extra struct {
		DownloadSettings *struct {
			Security string `json:"security"`
		} `json:"downloadSettings"`
	}
	if err := json.Unmarshal(params.Extra, &extra); err != nil {
		return false
	}
	if d := extra.DownloadSettings; d != nil {
		ds := strings.ToLower(strings.TrimSpace(d.Security))
		if ds != "tls" && ds != "reality" {
			return false
		}
	}
	return true
}

// parseVLESSParamsLoose extracts transport/security/extra from a vless:// link
// when vless.ParseLink rejects it (for example when extra contains downloadSettings).
func parseVLESSParamsLoose(raw string) (vless.Params, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !strings.EqualFold(u.Scheme, "vless") {
		return vless.Params{}, false
	}
	q := u.Query()
	netType := strings.ToLower(strings.TrimSpace(q.Get("type")))
	switch netType {
	case "", "raw":
		netType = "tcp"
	case "splithttp":
		netType = "xhttp"
	case "websocket":
		netType = "ws"
	case "gun":
		netType = "grpc"
	}
	sec := strings.ToLower(strings.TrimSpace(q.Get("security")))
	if sec == "" {
		if strings.TrimSpace(q.Get("pbk")) != "" || strings.TrimSpace(q.Get("publicKey")) != "" {
			sec = "reality"
		} else {
			sec = "none"
		}
	}
	var extra json.RawMessage
	if rawExtra := strings.TrimSpace(q.Get("extra")); rawExtra != "" {
		extra = json.RawMessage(rawExtra)
	}
	return vless.Params{
		Network:  netType,
		Security: sec,
		Extra:    extra,
	}, true
}

func hostFromAddress(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return strings.Trim(addr, "[]")
}

func subscriptionHost(subURL, fallback string) string {
	if u, err := url.Parse(strings.TrimSpace(subURL)); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	if fallback = strings.TrimSpace(fallback); fallback != "" {
		if u, err := url.Parse(fallback); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
		s := fallback
		if i := strings.Index(s, "://"); i >= 0 {
			s = s[i+3:]
		}
		if i := strings.IndexAny(s, "/?#"); i >= 0 {
			s = s[:i]
		}
		if h, _, err := net.SplitHostPort(s); err == nil && h != "" {
			return h
		}
		return s
	}
	return ""
}

// percentEncodeRFC3986 leaves RFC 3986 unreserved bytes untouched and encodes
// all other UTF-8 bytes as uppercase %XX (space is %20, never +).
func percentEncodeRFC3986(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s) * 2)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0x0F])
	}
	return b.String()
}

func qrRecoveryLevel(payload string) qrcode.RecoveryLevel {
	if len(payload) <= qrECThreshold {
		return qrcode.Medium
	}
	return qrcode.Low
}

func encodeQRDataURL(payload string) (string, error) {
	qr, err := qrcode.New(payload, qrRecoveryLevel(payload))
	if err != nil {
		return "", errors.New("не удалось сформировать QR-код")
	}
	qr.DisableBorder = false
	svg := renderQRSVG(qr.Bitmap())
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString(svg), nil
}

// renderQRSVG renders a QR bitmap (including its 4-module white quiet zone)
// as a compact, crisp SVG using horizontal run-merged path segments.
func renderQRSVG(bitmap [][]bool) []byte {
	n := len(bitmap)
	dim := strconv.Itoa(n)
	var buf bytes.Buffer
	buf.Grow(n * n * 2)
	buf.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 `)
	buf.WriteString(dim)
	buf.WriteByte(' ')
	buf.WriteString(dim)
	buf.WriteString(`" shape-rendering="crispEdges"><rect width="`)
	buf.WriteString(dim)
	buf.WriteString(`" height="`)
	buf.WriteString(dim)
	buf.WriteString(`" fill="#ffffff"/><path fill="#000000" d="`)
	for y, row := range bitmap {
		yStr := strconv.Itoa(y)
		for x := 0; x < len(row); {
			if !row[x] {
				x++
				continue
			}
			x0 := x
			for x < len(row) && row[x] {
				x++
			}
			w := x - x0
			wStr := strconv.Itoa(w)
			buf.WriteByte('M')
			buf.WriteString(strconv.Itoa(x0))
			buf.WriteByte(' ')
			buf.WriteString(yStr)
			buf.WriteByte('h')
			buf.WriteString(wStr)
			buf.WriteString("v1h-")
			buf.WriteString(wStr)
			buf.WriteByte('z')
		}
	}
	buf.WriteString(`"/></svg>`)
	return buf.Bytes()
}
