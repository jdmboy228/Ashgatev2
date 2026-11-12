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

var errNotXHTTP = errors.New("Поддерживается только VLESS через XHTTP")

// FromLink reads a vless:// link. Only XHTTP is accepted.
func FromLink(link string) (Profile, error) {
	link = strings.TrimSpace(link)
	p, err := vless.ParseLink(link)
	if err != nil {
		return Profile{}, err
	}
	if p.Params.Network != "xhttp" {
		return Profile{}, errNotXHTTP
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
	if h := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"); net.ParseIP(h) != nil {
		host = h
	} else if !validHostname(host) {
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

// DNSServers resolve the names of tunneled apps, over HTTPS through the
// proxy. RawDNS gets the query types Xray's DNS does not answer.
var (
	DNSServers = []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"}
	RawDNS     = "1.1.1.1"
)

// MTU of the TUN. VpnService must be given the same value.
const MTU = 1500

// DirectDomains are the desktop's direct list (.ru, .рф, .su, Russian
// services) as Xray rules, plus geosite:category-ru.
func DirectDomains() []string {
	c := config.Config{DirectDomains: config.DefaultDirectDomains}
	var out []string
	for _, d := range c.BypassDomains() {
		out = append(out, "domain:"+d)
	}
	return append(out, "geosite:category-ru")
}

// XrayJSON is the Xray document for a profile.
//
// Routing, first match wins:
//  1. port 53 from the TUN goes to Xray's DNS, which asks DNSServers;
//  2. Xray's own DNS queries go to the proxy;
//  3. Russian domains (by the name the app asked for) go direct;
//  4. Russian addresses go direct;
//  5. an HTTP proxy cannot carry UDP, so the rest of UDP is dropped;
//  6. everything else goes to the proxy.
func XrayJSON(p Profile) ([]byte, error) {
	proxy, err := proxyOutbound(p)
	if err != nil {
		return nil, err
	}
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
		// TXT) go as they are to RawDNS over TCP through the proxy: to
		// the original server they could leave the tunnel.
		"settings": map[string]any{
			"rewriteNetwork": "tcp", "rewriteAddress": RawDNS, "rewritePort": 53,
			"rules": []any{
				map[string]any{"action": "hijack", "qType": "1,28"},
				map[string]any{"action": "direct"},
			},
		},
		"streamSettings": map[string]any{"sockopt": map[string]any{"dialerProxy": TagProxy}},
	}
	rules := []any{
		map[string]any{"type": "field", "inboundTag": []string{TagTun}, "port": "53", "outboundTag": TagDNS},
		map[string]any{"type": "field", "inboundTag": []string{TagDNSIn}, "outboundTag": TagProxy},
		map[string]any{"type": "field", "inboundTag": []string{TagTun}, "domain": DirectDomains(), "outboundTag": TagDirect},
		map[string]any{"type": "field", "inboundTag": []string{TagTun}, "ip": []string{"geoip:ru"}, "outboundTag": TagDirect},
	}
	if p.Kind == KindHTTP {
		rules = append(rules, map[string]any{"type": "field", "inboundTag": []string{TagTun}, "network": "udp", "outboundTag": TagBlock})
	}
	servers := make([]any, 0, len(DNSServers))
	for _, s := range DNSServers {
		servers = append(servers, s)
	}
	doc := map[string]any{
		"log":      map[string]any{"loglevel": "warning"},
		"dns":      map[string]any{"tag": TagDNSIn, "servers": servers, "queryStrategy": "UseIP"},
		"inbounds": []any{tun},
		"outbounds": []any{
			proxy,
			map[string]any{"tag": TagDirect, "protocol": "freedom"},
			dnsOut,
			map[string]any{"tag": TagBlock, "protocol": "blackhole"},
		},
		"routing": map[string]any{"domainStrategy": "AsIs", "rules": rules},
		// As on the desktop: quiet connections live 30 minutes, and a
		// half-closed one gets a few seconds to finish.
		"policy": map[string]any{"levels": map[string]any{"0": map[string]any{
			"connIdle": 1800, "uplinkOnly": 2, "downlinkOnly": 5,
		}}},
	}
	return json.Marshal(doc)
}

func proxyOutbound(p Profile) (map[string]any, error) {
	switch p.Kind {
	case KindVLESS:
		parsed, err := vless.ParseLink(p.Link)
		if err != nil {
			return nil, err
		}
		if parsed.Params.Network != "xhttp" {
			return nil, errNotXHTTP
		}
		host, port, err := splitAddress(parsed.Address)
		if err != nil {
			return nil, err
		}
		return vless.Outbound(host, port, parsed.Params)
	case KindSOCKS5, KindHTTP:
		checked, err := Proxy(p.Kind, p.Name, p.Host, p.Port, p.User, p.Pass)
		if err != nil {
			return nil, err
		}
		settings := map[string]any{"address": checked.Host, "port": checked.Port}
		if checked.User != "" {
			settings["user"] = checked.User
			settings["pass"] = checked.Pass
		}
		protocol := "socks"
		if checked.Kind == KindHTTP {
			protocol = "http"
		}
		return map[string]any{"tag": TagProxy, "protocol": protocol, "settings": settings}, nil
	default:
		return nil, errors.New("Неизвестный тип профиля")
	}
}

// Mask hides the profile's secrets (UUID, keys, password) in a message, in
// case an Xray error quotes them. Values under 4 characters could match
// ordinary words and are left alone.
func (p Profile) Mask(msg string) string {
	secrets := []string{p.Pass}
	if parsed, err := vless.ParseLink(p.Link); err == nil {
		v := parsed.Params
		secrets = append(secrets, v.UUID, strings.ReplaceAll(v.UUID, "-", ""), v.PublicKey, v.ShortID)
	}
	for _, s := range secrets {
		if len(s) >= 4 {
			msg = strings.ReplaceAll(msg, s, "***")
		}
	}
	return msg
}
