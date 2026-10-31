// Package vless parses vless:// share links and runs an in-process Xray
// client that exposes each server as a localhost SOCKS5 inbound.
package vless

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strings"
)

// Params is the VLESS client description stored in config.json.
// Empty optional fields are omitted so older configs stay small.
type Params struct {
	UUID          string          `json:"uuid"`
	Encryption    string          `json:"encryption,omitempty"`
	Flow          string          `json:"flow,omitempty"`
	Network       string          `json:"network"`
	Security      string          `json:"security"`
	SNI           string          `json:"sni,omitempty"`
	Fingerprint   string          `json:"fp,omitempty"`
	PublicKey     string          `json:"pbk,omitempty"`
	ShortID       string          `json:"sid,omitempty"`
	SpiderX       string          `json:"spx,omitempty"`
	Path          string          `json:"path,omitempty"`
	Host          string          `json:"host,omitempty"`
	ServiceName   string          `json:"serviceName,omitempty"`
	Mode          string          `json:"mode,omitempty"`
	Authority     string          `json:"authority,omitempty"`
	ALPN          string          `json:"alpn,omitempty"`
	HeaderType    string          `json:"headerType,omitempty"`
	AllowInsecure bool            `json:"allowInsecure,omitempty"`
	Extra         json.RawMessage `json:"extra,omitempty"`
}

// Parsed is a share link broken into the fields the proxy dialog shows.
type Parsed struct {
	Name    string `json:"name,omitempty"`
	Address string `json:"address"`
	Params  Params `json:"vless"`
}

// ParseLink reads a vless:// link exported by 3x-ui or v2rayN.
// The display name is the URL fragment, sanitized to an Ashgate proxy name.
func ParseLink(raw string) (Parsed, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Parsed{}, badLink("")
	}
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Scheme, "vless") {
		return Parsed{}, badLink("")
	}
	id, err := normalizeUUID(u.User.Username())
	if err != nil {
		return Parsed{}, err
	}
	host := u.Hostname()
	if host == "" {
		return Parsed{}, badLink("в ссылке нет адреса сервера")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	if _, err := net.LookupPort("tcp", port); err != nil {
		return Parsed{}, badLink("неверный порт")
	}
	q := u.Query()
	p := Params{
		UUID:        id,
		Encryption:  strings.ToLower(strings.TrimSpace(q.Get("encryption"))),
		Flow:        strings.TrimSpace(q.Get("flow")),
		Network:     canonicalNetwork(q.Get("type")),
		Security:    canonicalSecurity(q.Get("security")),
		SNI:         first(q.Get("sni"), q.Get("serverName")),
		Fingerprint: strings.TrimSpace(q.Get("fp")),
		PublicKey:   strings.TrimSpace(first(q.Get("pbk"), q.Get("publicKey"))),
		ShortID:     strings.TrimSpace(first(q.Get("sid"), q.Get("shortId"))),
		SpiderX:     strings.TrimSpace(first(q.Get("spx"), q.Get("spiderX"))),
		Path:        strings.TrimSpace(q.Get("path")),
		Host:        strings.TrimSpace(q.Get("host")),
		ServiceName: strings.TrimSpace(first(q.Get("serviceName"), q.Get("service"))),
		Mode:        strings.TrimSpace(q.Get("mode")),
		Authority:   strings.TrimSpace(q.Get("authority")),
		ALPN:        strings.TrimSpace(q.Get("alpn")),
		HeaderType:  strings.TrimSpace(q.Get("headerType")),
	}
	if p.Network == "tcp" && p.Flow != "" && !visionFlow(p.Flow) {
		// Dropping it would connect without the flow the server requires,
		// and the server would refuse without saying why.
		return Parsed{}, badLink("flow " + p.Flow + " не поддерживается (нужен xtls-rprx-vision)")
	}
	if v := strings.TrimSpace(q.Get("allowInsecure")); v == "1" || strings.EqualFold(v, "true") {
		p.AllowInsecure = true
	}
	if v := strings.TrimSpace(q.Get("insecure")); v == "1" || strings.EqualFold(v, "true") {
		p.AllowInsecure = true
	}
	if extra := strings.TrimSpace(q.Get("extra")); extra != "" {
		if !json.Valid([]byte(extra)) {
			return Parsed{}, badLink("поле extra не является JSON")
		}
		p.Extra = json.RawMessage(extra)
	}
	// canonicalSecurity already turned a missing value into "none", so look
	// at the raw parameter: a public key without security= means REALITY.
	if strings.TrimSpace(q.Get("security")) == "" && p.PublicKey != "" {
		p.Security = "reality"
	}
	if p.Network == "grpc" && p.ServiceName == "" && p.Path != "" {
		p.ServiceName = strings.Trim(p.Path, "/")
		p.Path = ""
	}
	if err := p.Normalize(); err != nil {
		return Parsed{}, err
	}
	addr := net.JoinHostPort(host, port)
	return Parsed{Name: SuggestName(u.Fragment), Address: addr, Params: p}, nil
}

// SuggestName turns a share-link fragment into a proxy name.
// Characters outside the config name alphabet are dropped. An empty result
// means the user should type a name.
func SuggestName(fragment string) string {
	fragment = strings.TrimSpace(fragment)
	var b strings.Builder
	for _, r := range fragment {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '_' || r == '.' || r == '-':
			b.WriteRune(r)
		case r == ' ' || r == '+' || r == '/':
			b.WriteByte('-')
		}
	}
	s := strings.Trim(b.String(), "_.-")
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	if len(s) > 64 {
		s = strings.Trim(s[:64], "_.-")
	}
	return s
}

// Normalize fills defaults and checks fields the user may have edited by hand.
func (p *Params) Normalize() error {
	if p == nil {
		return badLink("")
	}
	id, err := normalizeUUID(p.UUID)
	if err != nil {
		return err
	}
	p.UUID = id
	if p.Encryption == "" {
		p.Encryption = "none"
	}
	if p.Encryption != "none" {
		return badLink("шифрование должно быть none")
	}
	p.Network = canonicalNetwork(p.Network)
	if p.Network == "" {
		p.Network = "tcp"
	}
	if !supportedNetwork(p.Network) {
		return badLink("транспорт " + p.Network + " не поддерживается (нужен tcp/raw, xhttp, ws, grpc или httpupgrade)")
	}
	p.Security = canonicalSecurity(p.Security)
	if p.Security == "" {
		p.Security = "none"
	}
	switch p.Security {
	case "reality", "tls", "none":
	default:
		return badLink("защита " + p.Security + " не поддерживается")
	}
	p.Flow = strings.TrimSpace(p.Flow)
	if p.Flow != "" && !visionFlow(p.Flow) {
		// 3x-ui sometimes copies an old flow onto transports that reject it.
		// A new link with one on TCP is refused in ParseLink; a saved config
		// must still load, so it is dropped here.
		p.Flow = ""
	}
	if p.Security == "reality" || p.Security == "tls" {
		if p.Fingerprint == "" {
			p.Fingerprint = "chrome"
		}
	}
	if p.Security == "reality" {
		key, err := normalizeKey(p.PublicKey)
		if err != nil {
			return err
		}
		p.PublicKey = key
		if err := normalizeShortID(p.ShortID); err != nil {
			return err
		}
		if strings.TrimSpace(p.SNI) == "" {
			return badLink("для REALITY укажите SNI")
		}
		if p.SpiderX == "" {
			p.SpiderX = "/"
		}
	}
	if p.Network == "grpc" && strings.TrimSpace(p.ServiceName) == "" {
		return badLink("для gRPC укажите serviceName")
	}
	if len(p.Extra) > 0 && !json.Valid(p.Extra) {
		return badLink("поле extra не является JSON")
	}
	return nil
}

// DialFlow is the flow Xray will accept for this transport.
// Vision is only valid on TCP. Share links often copy it onto XHTTP anyway.
func (p Params) DialFlow() string {
	if p.Network != "tcp" {
		return ""
	}
	if visionFlow(p.Flow) {
		return p.Flow
	}
	return ""
}

// visionFlow reports the XTLS Vision flows Xray accepts on RAW (TCP).
func visionFlow(f string) bool {
	return f == "xtls-rprx-vision" || f == "xtls-rprx-vision-udp443"
}

func badLink(detail string) error {
	if detail == "" {
		return errors.New("Не удалось разобрать ссылку VLESS")
	}
	return errors.New("Не удалось разобрать ссылку VLESS: " + detail)
}

func normalizeUUID(s string) (string, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	hexOnly := strings.ReplaceAll(s, "-", "")
	if len(hexOnly) != 32 || !isHex(hexOnly) {
		return "", badLink("неверный UUID")
	}
	return hexOnly[0:8] + "-" + hexOnly[8:12] + "-" + hexOnly[12:16] + "-" + hexOnly[16:20] + "-" + hexOnly[20:], nil
}

func normalizeKey(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", badLink("для REALITY нужен публичный ключ (pbk)")
	}
	var raw []byte
	var err error
	switch {
	case strings.ContainsAny(s, "+/="):
		raw, err = base64.StdEncoding.DecodeString(s)
	default:
		raw, err = base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			raw, err = base64.URLEncoding.DecodeString(s)
		}
		if err != nil {
			raw, err = base64.StdEncoding.DecodeString(s)
		}
	}
	if err != nil || len(raw) != 32 {
		return "", badLink("неверный публичный ключ (pbk)")
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func normalizeShortID(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if len(s) > 16 || len(s)%2 != 0 || !isHex(s) {
		return badLink("неверный short id (sid)")
	}
	return nil
}

func canonicalNetwork(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "tcp", "raw":
		return "tcp"
	case "ws", "websocket":
		return "ws"
	case "grpc", "gun":
		return "grpc"
	case "xhttp", "splithttp":
		return "xhttp"
	case "httpupgrade":
		return "httpupgrade"
	default:
		return strings.ToLower(strings.TrimSpace(s))
	}
}

func supportedNetwork(s string) bool {
	switch s {
	case "tcp", "ws", "grpc", "xhttp", "httpupgrade":
		return true
	default:
		return false
	}
}

func canonicalSecurity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "none":
		return "none"
	case "reality":
		return "reality"
	case "tls":
		return "tls"
	default:
		return strings.ToLower(strings.TrimSpace(s))
	}
}

func first(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
