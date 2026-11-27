// Package mobilecfg is the Android app's profile model and the Xray
// document built from a profile. It imports no Xray code: the document is
// plain JSON, so it is tested without the core.
//
// The document has one inbound, Xray's TUN, which reads the VpnService
// descriptor. Nothing listens on a local port.
package mobilecfg

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"ashgate/internal/config"
	"ashgate/internal/subs"
	"ashgate/internal/vless"
)

// Profile kinds.
const (
	KindVLESS  = "vless"
	KindSOCKS5 = "socks5"
	KindHTTP   = "http"
)

// Profile is one saved server. A VLESS profile keeps its share link, a
// plain proxy keeps host, port and an optional login.
type Profile struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	Link string `json:"link,omitempty"`
	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitempty"`
	User string `json:"user,omitempty"`
	Pass string `json:"pass,omitempty"`
}

var (
	errNotXHTTP     = errors.New("Поддерживается только VLESS через XHTTP")
	errNoEncryption = errors.New("Ссылка без защиты (security=none): UUID и трафик шли бы открытым текстом. Нужна ссылка с reality или tls")
	errPlainExtra   = errors.New("Поле extra отправляет загрузку без защиты (downloadSettings). Нужен reality или tls")
)

// checkLink отклоняет неподдерживаемые транспорты и незашифрованные соединения.
// downloadSettings проверяется рекурсивно на любой глубине extra.
func checkLink(v vless.Params) error {
	if v.Network != "xhttp" {
		return errNotXHTTP
	}
	if v.Security == "none" {
		return errNoEncryption
	}
	if len(v.Extra) == 0 {
		return nil
	}
	var raw any
	if err := json.Unmarshal(v.Extra, &raw); err != nil {
		return errPlainExtra
	}
	if !checkExtraDownloadSettings(raw) {
		return errPlainExtra
	}
	return nil
}

func checkExtraDownloadSettings(node any) bool {
	switch m := node.(type) {
	case map[string]any:
		for k, val := range m {
			if strings.EqualFold(k, "downloadSettings") && val != nil {
				obj, ok := val.(map[string]any)
				if !ok {
					return false
				}
				var sec string
				for dk, dv := range obj {
					if strings.EqualFold(dk, "security") {
						s, ok := dv.(string)
						if !ok {
							return false
						}
						sec = strings.ToLower(s)
					}
				}
				if sec != "tls" && sec != "reality" {
					return false
				}
			}
			if !checkExtraDownloadSettings(val) {
				return false
			}
		}
	case []any:
		for _, item := range m {
			if !checkExtraDownloadSettings(item) {
				return false
			}
		}
	}
	return true
}

// FromLink reads a vless:// link. Only XHTTP is accepted.
func FromLink(link string) (Profile, error) {
	link = strings.TrimSpace(link)
	p, err := vless.ParseLink(link)
	if err != nil {
		return Profile{}, err
	}
	if err := checkLink(p.Params); err != nil {
		return Profile{}, err
	}
	host, port, err := splitAddress(p.Address)
	if err != nil {
		return Profile{}, err
	}
	name := p.Name
	if name == "" {
		name = host
	}
	return Profile{Name: name, Kind: KindVLESS, Link: link, Host: host, Port: port}, nil
}

// FromSubscription reads a 3x-ui subscription body (base64 or plain text)
// and keeps its XHTTP servers, in the subscription's order.
func FromSubscription(body []byte) ([]Profile, error) {
	entries, _ := subs.Parse(body)
	var out []Profile
	for _, e := range entries {
		if p, err := FromLink(e.Link); err == nil {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("В подписке нет серверов VLESS через XHTTP")
	}
	return out, nil
}

// Proxy checks a plain SOCKS5 or HTTP proxy typed into the form.
func Proxy(kind, name, host string, port int, user, pass string) (Profile, error) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "socks5", "socks":
		kind = KindSOCKS5
	case "http":
		kind = KindHTTP
	default:
		return Profile{}, errors.New("Тип прокси должен быть SOCKS5 или HTTP")
	}
	host = strings.TrimSpace(host)
	hasOpen := strings.HasPrefix(host, "[")
	hasClose := strings.HasSuffix(host, "]")
	if hasOpen != hasClose {
		return Profile{}, errors.New("Неверный адрес прокси")
	}
	if h := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"); net.ParseIP(h) != nil {
		host = h
	} else if hasOpen || !validHostname(host) {
		return Profile{}, errors.New("Неверный адрес прокси")
	}
	if port < 1 || port > 65535 {
		return Profile{}, errors.New("Неверный порт прокси")
	}
	if user == "" && pass != "" {
		return Profile{}, errors.New("Пароль указан без логина")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = host
	}
	return Profile{Name: name, Kind: kind, Host: host, Port: port, User: user, Pass: pass}, nil
}

func validHostname(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
			default:
				return false
			}
		}
	}
	return true
}

func splitAddress(addr string) (string, int, error) {
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, errors.New("Неверный адрес сервера")
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return "", 0, errors.New("Неверный порт сервера")
	}
	return host, port, nil
}

// Tags of the document. The first outbound, TagProxy, takes everything no
// rule sends elsewhere.
const (
	TagTun    = "tun"
	TagProxy  = "proxy"
	TagDirect = "direct"
	TagDNS    = "dns-out"
	TagDNSIn  = "dns-in"
	TagBlock  = "block"
)

// DNSServers resolve the names that go through the proxy, over HTTPS
// through the proxy. RawDNS gets the query types Xray's DNS does not answer.
var (
	DNSServers = []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"}
	RawDNS     = "1.1.1.1"
)

// Encrypted DNS of the apps (DoT, or DoH to a Russian resolver, which the
// direct rules would otherwise match) goes through the proxy, so "Private
// DNS" set to a Russian provider does not take every name around the tunnel.
var (
	DoTPort                = "853"
	RussianResolverDomains = []string{"domain:dns.yandex.net", "domain:dns.yandex.ru"}
	RussianResolverIPs     = []string{
		"77.88.8.0/24",
		"2a02:6b8::feed:0ff", "2a02:6b8:0:1::feed:0ff",
		"2a02:6b8::feed:bad", "2a02:6b8:0:1::feed:bad",
		"2a02:6b8::feed:a11", "2a02:6b8:0:1::feed:a11",
	}
)

// LANRanges — частные, link-local, loopback, multicast и broadcast адреса.
// Они имеют смысл только в локальной сети телефона и не должны идти в прокси.
var LANRanges = []string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
	"127.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32",
	"fc00::/7", "fe80::/10", "::1/128", "ff00::/8",
}

// MTU of the TUN. VpnService must be given the same value; 1400 fits
// cellular, PPPoE and IPv6 mobile links without fragmenting UDP/QUIC.
const MTU = 1400

// DNSLevel is the policy level of the DNS outbound. Xray keeps a DNS flow
// open after answering it until the flow idles out, and the phone's resolver
// uses a new port for each query, so these flows get a short idle time.
const DNSLevel = 1

var defaultDirectDomains = func() []string {
	c := config.Config{DirectDomains: config.DefaultDirectDomains}
	out := make([]string, 0, len(c.DirectDomains)+1)
	for _, d := range c.BypassDomains() {
		out = append(out, "domain:"+d)
	}
	return append(out, "geosite:category-ru")
}()

// DirectDomains are the desktop's direct list (.ru, .рф, .su, Russian
// services) as Xray rules, plus geosite:category-ru. Only names go direct:
// a Russian address without such a name goes through the proxy.
func DirectDomains() []string {
	return append([]string(nil), defaultDirectDomains...)
}

// XrayJSON is the Xray document for a profile.
//
// Routing, first match wins:
//  1. port 53 from the TUN goes to Xray's DNS: direct names are asked of
//     the system resolver, all others of DNSServers;
//  2. Xray's own DNS queries go to the proxy;
//  3. encrypted DNS of the apps (DoT on 853, Russian DoH resolvers) goes
//     to the proxy;
//  4. Russian domains (by the name the app asked for) go direct;
//  5. addresses of the local network go direct;
//  6. an HTTP proxy cannot carry UDP, so the rest of UDP is dropped;
//  7. everything else goes to the proxy.
// ServerHost возвращает хост прокси-сервера, который нужно зарезолвить до старта Xray.
func ServerHost(p Profile) (string, error) {
	switch p.Kind {
	case KindVLESS:
		parsed, err := vless.ParseLink(p.Link)
		if err != nil {
			return "", err
		}
		host, _, err := splitAddress(parsed.Address)
		return host, err
	case KindSOCKS5, KindHTTP:
		checked, err := Proxy(p.Kind, p.Name, p.Host, p.Port, p.User, p.Pass)
		if err != nil {
			return "", err
		}
		return checked.Host, nil
	default:
		return "", errors.New("Неизвестный тип профиля")
	}
}

// XrayJSON строит JSON-документ Xray для профиля (с исходным адресом из профиля).
func XrayJSON(p Profile) ([]byte, error) {
	return XrayJSONWithAddress(p, "")
}

// XrayJSONWithAddress строит JSON-документ Xray для профиля. Если resolvedIP не пуст,
// Xray подключается напрямую по этому IP (без утечки имени сервера в системный DNS),
// сохраняя исходное доменное имя для TLS/REALITY SNI и HTTP Host.
func XrayJSONWithAddress(p Profile, resolvedIP string) ([]byte, error) {
	proxy, err := proxyOutbound(p, resolvedIP)
	if err != nil {
		return nil, err
	}
	direct := DirectDomains()
	tun := map[string]any{
		"tag":      TagTun,
		"protocol": "tun",
		"port":     0,
		"settings": map[string]any{"name": "ashgate", "mtu": MTU},
		// Route by the name the app asked for (TLS SNI, HTTP Host, QUIC);
		// the connection still goes to the address the app chose, so
		// nothing is resolved a second time outside the tunnel.
		"sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true},
	}
	dnsOut := map[string]any{
		"tag":      TagDNS,
		"protocol": "dns",
		// A and AAAA are answered by Xray's DNS. Other types (HTTPS, SRV,
		// TXT) for direct domains get an empty local NOERROR answer so
		// Russian sites never wait on or leak through the proxy; the rest
		// go as they are to RawDNS over TCP through the proxy.
		"settings": map[string]any{
			"rewriteNetwork": "tcp", "rewriteAddress": RawDNS, "rewritePort": 53,
			"userLevel": DNSLevel,
			"rules": []any{
				map[string]any{"action": "hijack", "qType": "1,28"},
				map[string]any{"action": "return", "domain": direct},
				map[string]any{"action": "direct"},
			},
		},
		"streamSettings": map[string]any{"sockopt": map[string]any{"dialerProxy": TagProxy}},
	}
	rules := []any{
		map[string]any{"type": "field", "inboundTag": []string{TagTun}, "port": "53", "outboundTag": TagDNS},
		map[string]any{"type": "field", "inboundTag": []string{TagDNSIn}, "outboundTag": TagProxy},
		map[string]any{"type": "field", "inboundTag": []string{TagTun}, "port": DoTPort, "outboundTag": TagProxy},
		map[string]any{"type": "field", "inboundTag": []string{TagTun}, "domain": RussianResolverDomains, "outboundTag": TagProxy},
		map[string]any{"type": "field", "inboundTag": []string{TagTun}, "ip": RussianResolverIPs, "outboundTag": TagProxy},
		map[string]any{"type": "field", "inboundTag": []string{TagTun}, "domain": direct, "outboundTag": TagDirect},
		map[string]any{"type": "field", "inboundTag": []string{TagTun}, "ip": LANRanges, "outboundTag": TagDirect},
	}
	if p.Kind == KindHTTP {
		rules = append(rules, map[string]any{"type": "field", "inboundTag": []string{TagTun}, "network": "udp", "outboundTag": TagBlock})
	}
	// As on the desktop: names that go direct are resolved by the system
	// resolver (Ashgate is outside the tunnel, so that is the network's
	// DNS, and Russian sites give their local answers); every other name
	// is resolved by DNSServers through the proxy and never falls back.
	servers := []any{map[string]any{"address": "localhost", "domains": direct, "skipFallback": true, "finalQuery": true}}
	for _, s := range DNSServers {
		servers = append(servers, s)
	}
	doc := map[string]any{
		// No logs at all: Xray's access log is on by default and gomobile
		// sends the console to logcat, which would keep every site and the
		// server's address. Start errors still come back as errors.
		"log": map[string]any{"access": "none", "error": "none", "loglevel": "none"},
		// UseIPv4: the TUN keeps its IPv6 route so hard-coded IPv6 literals
		// cannot leak around the tunnel, while DNS answers AAAA with NODATA
		// so apps do not pick IPv6 via the TUN's instant local SYN-ACK and
		// fail on IPv4-only networks or IPv4-only proxy servers.
		"dns": map[string]any{
			"tag": TagDNSIn, "servers": servers, "queryStrategy": "UseIPv4",
			"disableFallbackIfMatch": true, "enableParallelQuery": true,
		},
		"inbounds": []any{tun},
		"outbounds": []any{
			proxy,
			map[string]any{
				"tag":            TagDirect,
				"protocol":       "freedom",
				"streamSettings": map[string]any{"sockopt": map[string]any{"tcpKeepAliveIdle": 300}},
			},
			dnsOut,
			map[string]any{"tag": TagBlock, "protocol": "blackhole"},
		},
		"routing": map[string]any{"domainStrategy": "AsIs", "rules": rules},
		// Idle connections live 5 minutes (instead of the desktop's 30) so idle
		// sockets and UDP flows do not keep the phone's cellular radio awake.
		"policy": map[string]any{"levels": map[string]any{
			"0":                    map[string]any{"connIdle": 300, "uplinkOnly": 2, "downlinkOnly": 5},
			strconv.Itoa(DNSLevel): map[string]any{"connIdle": 30},
		}},
	}
	return json.Marshal(doc)
}

func proxyOutbound(p Profile, resolvedIP string) (map[string]any, error) {
	switch p.Kind {
	case KindVLESS:
		parsed, err := vless.ParseLink(p.Link)
		if err != nil {
			return nil, err
		}
		if err := checkLink(parsed.Params); err != nil {
			return nil, err
		}
		host, port, err := splitAddress(parsed.Address)
		if err != nil {
			return nil, err
		}
		dialHost := host
		params := parsed.Params
		if resolvedIP != "" && net.ParseIP(host) == nil {
			dialHost = resolvedIP
			// Сохраняем SNI/Host, которые Xray иначе вывел бы из адреса подключения.
			if (params.Security == "tls" || params.Security == "reality") && params.SNI == "" {
				params.SNI = host
			}
			if params.Network == "xhttp" && params.Host == "" && params.SNI == "" {
				params.Host = host
			}
		}
		out, err := vless.Outbound(dialHost, port, params)
		if err != nil {
			return nil, err
		}
		if stream, ok := out["streamSettings"].(map[string]any); ok {
			stream["sockopt"] = map[string]any{"tcpKeepAliveIdle": 300}
		}
		return out, nil
	case KindSOCKS5, KindHTTP:
		checked, err := Proxy(p.Kind, p.Name, p.Host, p.Port, p.User, p.Pass)
		if err != nil {
			return nil, err
		}
		dialHost := checked.Host
		if resolvedIP != "" && net.ParseIP(checked.Host) == nil {
			dialHost = resolvedIP
		}
		settings := map[string]any{"address": dialHost, "port": checked.Port}
		if checked.User != "" {
			settings["user"] = checked.User
			settings["pass"] = checked.Pass
		}
		protocol := "socks"
		if checked.Kind == KindHTTP {
			protocol = "http"
		}
		return map[string]any{
			"tag":            TagProxy,
			"protocol":       protocol,
			"settings":       settings,
			"streamSettings": map[string]any{"sockopt": map[string]any{"tcpKeepAliveIdle": 300}},
		}, nil
	default:
		return nil, errors.New("Неизвестный тип профиля")
	}
}

// Mask hides the profile's secrets (UUID, keys, password) and the server's
// address in a message, in case an Xray error quotes them: the message is
// shown on screen and ends up in screenshots. Values under 4 characters
// could match ordinary words and are left alone.
func (p Profile) Mask(msg string) string {
	secrets := []string{p.Pass, p.User, p.Host, p.Link}
	if u, err := url.Parse(strings.TrimSpace(p.Link)); err == nil {
		q := u.Query()
		secrets = append(secrets, u.User.Username(), u.Hostname(), q.Get("pbk"), q.Get("publicKey"), q.Get("sid"), q.Get("shortId"))
	}
	if parsed, err := vless.ParseLink(p.Link); err == nil {
		v := parsed.Params
		noDash := strings.ReplaceAll(v.UUID, "-", "")
		secrets = append(secrets,
			v.UUID, strings.ToUpper(v.UUID), noDash, strings.ToUpper(noDash),
			v.PublicKey, v.ShortID, v.SNI, v.Host,
			v.Path, v.ServiceName, v.Authority,
		)
		if v.PinnedSHA256 != "" {
			secrets = append(secrets, strings.Split(v.PinnedSHA256, ",")...)
		}
		if host, _, err := net.SplitHostPort(parsed.Address); err == nil {
			secrets = append(secrets, host)
		}
		if len(v.Extra) > 0 {
			secrets = append(secrets, string(v.Extra))
			var extraAny any
			if json.Unmarshal(v.Extra, &extraAny) == nil {
				collectExtraStrings(extraAny, &secrets)
			}
		}
	}
	// Longest first, so a shorter value never cuts a longer one in half.
	sort.Slice(secrets, func(i, j int) bool { return len(secrets[i]) > len(secrets[j]) })
	for _, s := range secrets {
		if len(s) >= 4 {
			msg = strings.ReplaceAll(msg, s, "***")
		}
	}
	return msg
}

func collectExtraStrings(node any, out *[]string) {
	switch v := node.(type) {
	case string:
		if len(v) >= 4 {
			*out = append(*out, v)
		}
	case map[string]any:
		for k, val := range v {
			// Ключи-перечисления вроде security/network/mode не маскируем, маскируем значения-секреты.
			switch strings.ToLower(k) {
			case "security", "network", "mode", "fingerprint", "alpn":
				continue
			}
			collectExtraStrings(val, out)
		}
	case []any:
		for _, item := range v {
			collectExtraStrings(item, out)
		}
	}
}
