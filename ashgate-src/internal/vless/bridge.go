package vless

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Inbound is the published localhost SOCKS5 and HTTP listener of a bridge,
// for other programs. Port 0 publishes nothing. A published port always
// needs a login: an empty User gets random credentials on every start.
type Inbound struct {
	Port int    `json:"port,omitempty"`
	User string `json:"user,omitempty"`
	Pass string `json:"pass,omitempty"`
}

// Routing is what a bridge does with Ashgate's own traffic besides
// proxying it.
type Routing struct {
	// Direct lists domains that leave through Xray's "direct" outbound,
	// from Ashgate's own process, so capture does not take them again.
	Direct []string `json:"direct,omitempty"`
	// DNS, when set, answers port-53 queries with Xray's DNS: these
	// servers (DoH) through the tunnel, Direct domains with the system
	// resolver.
	DNS []string `json:"dns,omitempty"`
	// Raw ("1.1.1.1:53") gets the other query types (HTTPS, SRV, TXT, MX)
	// as they are, over TCP through the tunnel. Empty refuses them.
	Raw string `json:"raw,omitempty"`
}

// ResolveServer, when set, looks up a server host name without the system
// resolver, whose queries the provider sees (see internal/bootstrap). The
// bridge then dials the address. Unset, Xray resolves the name itself.
var ResolveServer func(ctx context.Context, host string) ([]net.IP, error)

// byAddress keeps the handshake of a server dialed by host name when it is
// dialed by IP instead: Xray's TLS and REALITY name, and then the HTTP Host
// and gRPC authority, fall back to the address it dials.
func byAddress(p Params, host string) Params {
	switch p.Security {
	case "tls", "reality":
		if p.SNI == "" {
			p.SNI = host
		}
	default:
		switch p.Network {
		case "ws", "httpupgrade", "xhttp":
			if p.Host == "" {
				p.Host = host
			}
		case "grpc":
			if p.Authority == "" {
				p.Authority = host
			}
		}
	}
	return p
}

// dialTarget is what the bridge dials for a server host: its address from
// ResolveServer when host is a name, with params that keep the handshake.
func dialTarget(ctx context.Context, host string, p Params) (string, Params, error) {
	if ResolveServer == nil || net.ParseIP(host) != nil {
		return host, p, nil
	}
	// The manager waits on this; every resolver blocked must not stall it.
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	ips, err := ResolveServer(ctx, host)
	ip := serverIP(ips)
	if err != nil || ip == nil {
		why := "нет адреса"
		if err != nil {
			why = err.Error()
		}
		return "", p, fmt.Errorf("VLESS: не удалось узнать адрес сервера %s без DNS провайдера (%s). Укажите в ссылке IP-адрес сервера", host, why)
	}
	return ip.String(), byAddress(p, host), nil
}

// serverIP prefers IPv4, the family every network has.
func serverIP(ips []net.IP) net.IP {
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip
		}
	}
	if len(ips) > 0 {
		return ips[0]
	}
	return nil
}

// Bridge is one embedded Xray instance with a VLESS outbound. Ashgate uses
// its private SOCKS5 inbound; a published one is optional.
type Bridge struct {
	// Addr is the private SOCKS5 inbound: 127.0.0.1, a random port and
	// random credentials on every start, no UDP ASSOCIATE.
	Addr       string
	User, Pass string
	// Published is the fixed SOCKS5 port for other programs ("" if none),
	// HTTP the HTTP proxy next to it, PubUser/PubPass their login.
	Published        string
	HTTP             string
	PubUser, PubPass string
	// Generated reports that PubUser/PubPass were made up for this start.
	Generated bool

	routing Routing
	server  string
	inst    *instance
	stop    chan struct{}
	once    sync.Once
}

// Close stops the embedded Xray instance. It is safe to call more than once.
func (b *Bridge) Close() {
	if b == nil {
		return
	}
	b.once.Do(func() {
		close(b.stop)
		unregister(b)
		if b.inst != nil {
			_ = b.inst.Close()
		}
	})
}

// Listen starts a bridge to serverAddr with no routing exceptions.
func Listen(ctx context.Context, serverAddr string, p Params, in Inbound) (*Bridge, error) {
	return ListenWith(ctx, serverAddr, p, in, Routing{})
}

// ListenWith starts a bridge: a private SOCKS5 inbound on 127.0.0.1, an
// optional published SOCKS5/HTTP pair on in.Port and in.Port+1, and a VLESS
// outbound to serverAddr. It stops when ctx is cancelled or Close is called.
func ListenWith(ctx context.Context, serverAddr string, p Params, in Inbound, rt Routing) (*Bridge, error) {
	b, err := listen(ctx, serverAddr, p, in, rt)
	if err != nil {
		// The error reaches the window and ashgate.log.
		return nil, maskSecrets(err, p)
	}
	return b, nil
}

func listen(ctx context.Context, serverAddr string, p Params, in Inbound, rt Routing) (*Bridge, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := p.Normalize(); err != nil {
		return nil, err
	}
	if in.Port < 0 || in.Port > 65535 {
		return nil, errors.New("VLESS: неверный локальный SOCKS5-порт")
	}
	host, portStr, err := net.SplitHostPort(serverAddr)
	if err != nil || host == "" {
		return nil, errors.New("VLESS: неверный адрес сервера")
	}
	serverPort, err := net.LookupPort("tcp", portStr)
	if err != nil || serverPort < 1 || serverPort > 65535 {
		return nil, errors.New("VLESS: неверный адрес сервера")
	}
	dialHost, p, err := dialTarget(ctx, host, p)
	if err != nil {
		return nil, err
	}
	cc := ClientConfig{Server: dialHost, ServerPort: serverPort, Params: p, Published: in, Routing: rt}
	if in.Port != 0 {
		if in.User == "" {
			cc.Published.User, cc.Published.Pass = randomToken(8), randomToken(16)
		}
		if err := portFree(in.Port, false); err != nil {
			return nil, portBusy(in.Port)
		}
		if in.Port < 65535 {
			if err := portFree(in.Port+1, false); err != nil {
				return nil, fmt.Errorf("VLESS: HTTP-порт %d занят. Выберите другой локальный SOCKS5-порт", in.Port+1)
			}
		}
	}
	var last error
	for attempt := 0; attempt < 5; attempt++ {
		port, err := freePort()
		if err != nil {
			return nil, err
		}
		cc.Port, cc.User, cc.Pass = port, randomToken(8), randomToken(16)
		b, err := startBridge(ctx, cc)
		if err == nil {
			b.Generated = in.Port != 0 && in.User == ""
			return b, nil
		}
		last = err
		if !bindConflict(err) {
			return nil, humanizeStart(err)
		}
		if in.Port != 0 && (portFree(in.Port, false) != nil || (in.Port < 65535 && portFree(in.Port+1, false) != nil)) {
			return nil, portBusy(in.Port)
		}
	}
	if last == nil {
		last = errors.New("VLESS: не удалось запустить локальный мост")
	}
	return nil, humanizeStart(last)
}

func startBridge(ctx context.Context, cc ClientConfig) (*Bridge, error) {
	raw, err := ClientJSON(cc)
	if err != nil {
		return nil, err
	}
	inst, err := loadAndStart(raw)
	if err != nil {
		return nil, err
	}
	b := &Bridge{
		Addr: fmt.Sprintf("127.0.0.1:%d", cc.Port), User: cc.User, Pass: cc.Pass,
		routing: cc.Routing, server: net.JoinHostPort(cc.Server, fmt.Sprint(cc.ServerPort)),
		inst: inst, stop: make(chan struct{}),
	}
	if cc.Published.Port != 0 {
		b.Published = fmt.Sprintf("127.0.0.1:%d", cc.Published.Port)
		b.PubUser, b.PubPass = cc.Published.User, cc.Published.Pass
		if cc.Published.Port < 65535 {
			b.HTTP = fmt.Sprintf("127.0.0.1:%d", cc.Published.Port+1)
		}
	}
	register(b)
	go func() {
		select {
		case <-ctx.Done():
			b.Close()
		case <-b.stop:
		}
	}()
	for _, addr := range []string{b.Addr, b.Published, b.HTTP} {
		if addr == "" {
			continue
		}
		if err := waitPort(addr, 2*time.Second); err != nil {
			b.Close()
			return nil, fmt.Errorf("VLESS: локальный порт %s не открылся: %w", addr, err)
		}
	}
	return b, nil
}

// Inbound tags. Routing exceptions apply to Ashgate's own inbound only:
// programs using the published port get the plain tunnel.
const (
	tagAshgate = "ashgate"
	tagProxy   = "proxy"
	tagDirect  = "direct"
	tagDNS     = "dns-out"
)

// ClientConfig describes one bridge's Xray document.
type ClientConfig struct {
	Server     string
	ServerPort int
	Params     Params
	// Port, User and Pass are the private SOCKS5 inbound for Ashgate.
	Port       int
	User, Pass string
	// Published is the optional SOCKS5 (Port) and HTTP (Port+1) pair for
	// other programs. It always has User and Pass here.
	Published Inbound
	Routing   Routing
}

// ClientJSON is the Xray client document for one bridge.
func ClientJSON(c ClientConfig) ([]byte, error) {
	p := c.Params
	if err := p.Normalize(); err != nil {
		return nil, err
	}
	if c.User == "" || (c.Published.Port != 0 && c.Published.User == "") {
		return nil, errors.New("VLESS: локальный прокси без логина")
	}
	vuser := map[string]any{
		"id":         p.UUID,
		"encryption": "none",
	}
	if flow := p.DialFlow(); flow != "" {
		vuser["flow"] = flow
	}
	network := p.Network
	if network == "tcp" {
		// Xray calls TCP "raw" since v24.9.30; config.json keeps "tcp".
		network = "raw"
	}
	stream := map[string]any{
		"network":  network,
		"security": p.Security,
	}
	switch p.Security {
	case "reality":
		stream["realitySettings"] = map[string]any{
			"serverName":  p.SNI,
			"fingerprint": p.Fingerprint,
			"publicKey":   p.PublicKey,
			"shortId":     p.ShortID,
			"spiderX":     p.SpiderX,
		}
	case "tls":
		tls := map[string]any{
			"serverName":  p.SNI,
			"fingerprint": p.Fingerprint,
		}
		switch {
		case p.PinnedSHA256 != "":
			tls["pinnedPeerCertSha256"] = p.PinnedSHA256
		case p.AllowInsecure:
			// Xray 26 refuses to start with allowInsecure.
			return nil, errors.New("VLESS: Xray больше не поддерживает allowInsecure (insecure=1). Добавьте в ссылку отпечаток сертификата сервера (pcs) или поставьте на сервер действительный сертификат")
		}
		if p.ALPN != "" {
			tls["alpn"] = splitComma(p.ALPN)
		}
		stream["tlsSettings"] = tls
	}
	switch p.Network {
	case "xhttp":
		xs := map[string]any{}
		if p.Path != "" {
			xs["path"] = p.Path
		}
		if p.Host != "" {
			xs["host"] = p.Host
		}
		if p.Mode != "" {
			xs["mode"] = p.Mode
		}
		if len(p.Extra) > 0 {
			xs["extra"] = json.RawMessage(p.Extra)
		}
		stream["xhttpSettings"] = xs
	case "ws":
		ws := map[string]any{}
		if p.Path != "" {
			ws["path"] = p.Path
		}
		if p.Host != "" {
			ws["host"] = p.Host
		}
		stream["wsSettings"] = ws
	case "grpc":
		gs := map[string]any{"serviceName": p.ServiceName}
		if p.Authority != "" {
			gs["authority"] = p.Authority
		}
		if p.Mode == "multi" {
			gs["multiMode"] = true
		}
		stream["grpcSettings"] = gs
	case "httpupgrade":
		hs := map[string]any{}
		if p.Path != "" {
			hs["path"] = p.Path
		}
		if p.Host != "" {
			hs["host"] = p.Host
		}
		stream["httpupgradeSettings"] = hs
	default:
		if p.HeaderType != "" && !strings.EqualFold(p.HeaderType, "none") {
			stream["rawSettings"] = map[string]any{
				"header": map[string]any{"type": p.HeaderType},
			}
		}
	}
	private := map[string]any{
		"tag":      tagAshgate,
		"listen":   "127.0.0.1",
		"port":     c.Port,
		"protocol": "socks",
		"settings": socksSettings(c.User, c.Pass),
	}
	if len(c.Routing.Direct) > 0 {
		// Route by the name the program asked for (TLS SNI, HTTP Host,
		// QUIC); the connection still goes to the IP it chose.
		private["sniffing"] = map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true}
	}
	inbounds := []any{private}
	if pub := c.Published; pub.Port != 0 {
		inbounds = append(inbounds, map[string]any{
			"tag": "published", "listen": "127.0.0.1", "port": pub.Port,
			"protocol": "socks", "settings": socksSettings(pub.User, pub.Pass),
		})
		if pub.Port < 65535 {
			inbounds = append(inbounds, map[string]any{
				"tag": "published-http", "listen": "127.0.0.1", "port": pub.Port + 1,
				"protocol": "http", "settings": httpSettings(pub.User, pub.Pass),
			})
		}
	}
	outbounds := []any{map[string]any{
		"tag":      tagProxy,
		"protocol": "vless",
		"settings": map[string]any{
			"vnext": []any{map[string]any{
				"address": c.Server,
				"port":    c.ServerPort,
				"users":   []any{vuser},
			}},
		},
		"streamSettings": stream,
	}}
	var rules []any
	doc := map[string]any{
		"log":      map[string]any{"loglevel": "info"},
		"inbounds": inbounds,
		// Xray closes a connection idle for 300 s by default, which drops
		// quiet SSH and IMAP sessions. 30 minutes; other timeouts stay.
		"policy": map[string]any{"levels": map[string]any{"0": map[string]any{"connIdle": 1800}}},
	}
	if len(c.Routing.DNS) > 0 {
		dnsOut := map[string]any{"tag": tagDNS, "protocol": "dns"}
		if host, port, err := net.SplitHostPort(c.Routing.Raw); err == nil && net.ParseIP(host) != nil {
			// A and AAAA go to Xray's DNS below. Other types (HTTPS, SRV,
			// TXT, MX) go as they are to Raw, over TCP through the tunnel:
			// to the original server they would reach the provider, and
			// refused they break SRV and TXT lookups of every program
			// once Windows' own DNS goes this way.
			portNum, _ := net.LookupPort("tcp", port)
			dnsOut["settings"] = map[string]any{
				"rewriteNetwork": "tcp", "rewriteAddress": host, "rewritePort": portNum,
				"rules": []any{
					map[string]any{"action": "hijack", "qType": "1,28"},
					map[string]any{"action": "direct"},
				},
			}
			dnsOut["streamSettings"] = map[string]any{"sockopt": map[string]any{"dialerProxy": tagProxy}}
		} else {
			// Other query types would otherwise go to the original server
			// outside Xray's DNS.
			dnsOut["settings"] = map[string]any{"nonIPQuery": "reject"}
		}
		outbounds = append(outbounds, dnsOut)
		rules = append(rules, map[string]any{"type": "field", "inboundTag": []string{tagAshgate}, "port": "53", "outboundTag": tagDNS})
		servers := []any{}
		if len(c.Routing.Direct) > 0 {
			servers = append(servers, map[string]any{"address": "localhost", "domains": domainRules(c.Routing.Direct), "skipFallback": true})
		}
		for _, s := range c.Routing.DNS {
			servers = append(servers, s)
		}
		doc["dns"] = map[string]any{"servers": servers, "queryStrategy": "UseIP"}
	}
	if len(c.Routing.Direct) > 0 {
		outbounds = append(outbounds, map[string]any{"tag": tagDirect, "protocol": "freedom"})
		rules = append(rules, map[string]any{"type": "field", "inboundTag": []string{tagAshgate}, "domain": domainRules(c.Routing.Direct), "outboundTag": tagDirect})
	}
	doc["outbounds"] = outbounds
	if len(rules) > 0 {
		doc["routing"] = map[string]any{"domainStrategy": "AsIs", "rules": rules}
	}
	return json.Marshal(doc)
}

// domainRules turns plain domains into Xray rules that also match
// subdomains: "gosuslugi.ru" covers "www.gosuslugi.ru".
func domainRules(domains []string) []string {
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		out = append(out, "domain:"+d)
	}
	return out
}

// socksSettings always asks for a login and never offers UDP ASSOCIATE:
// its UDP relay would take datagrams from any local program. Ashgate sends
// its own UDP through DialUDP instead.
func socksSettings(user, pass string) map[string]any {
	return map[string]any{
		"auth":     "password",
		"udp":      false,
		"accounts": []any{map[string]string{"user": user, "pass": pass}},
	}
}

func httpSettings(user, pass string) map[string]any {
	return map[string]any{
		"accounts": []any{map[string]string{"user": user, "pass": pass}},
	}
}

// randomToken is n random bytes in hex.
func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func portFree(port int, udp bool) error {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	_ = ln.Close()
	if !udp {
		return nil
	}
	pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	_ = pc.Close()
	return nil
}

// PortOwner, when set by the Windows host, names the process bound to a local port.
var PortOwner func(port int) (name string, pid uint32, ok bool)

func portBusy(port int) error {
	if PortOwner != nil {
		name, pid, ok := PortOwner(port)
		if ok && name != "" {
			return fmt.Errorf("VLESS: порт %d занят процессом %s (PID %d). Выберите другой локальный SOCKS5-порт", port, name, pid)
		}
		if ok && pid != 0 {
			return fmt.Errorf("VLESS: порт %d занят процессом PID %d. Выберите другой локальный SOCKS5-порт", port, pid)
		}
	}
	return fmt.Errorf("VLESS: порт %d занят. Выберите другой локальный SOCKS5-порт", port)
}

func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port, nil
}

func waitPort(addr string, d time.Duration) error {
	deadline := time.Now().Add(d)
	var last error
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return nil
		}
		last = err
		time.Sleep(20 * time.Millisecond)
	}
	if last == nil {
		last = errors.New("VLESS: локальный мост не открыл порт")
	}
	return last
}

func bindConflict(err error) bool {
	if err == nil {
		return false
	}
	low := strings.ToLower(err.Error())
	return strings.Contains(low, "bind") || strings.Contains(low, "address already in use") || strings.Contains(low, "only one usage")
}

func humanizeStart(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.Contains(msg, "Не удалось разобрать ссылку VLESS") || strings.HasPrefix(msg, "VLESS:") || strings.HasPrefix(msg, "REALITY:") {
		return err
	}
	low := strings.ToLower(msg)
	const unknownFP = `unknown "fingerprint": `
	switch {
	case strings.Contains(msg, unknownFP):
		fp := strings.TrimSpace(msg[strings.Index(msg, unknownFP)+len(unknownFP):])
		return fmt.Errorf("VLESS: Xray не знает отпечаток браузера fp=%s. Подойдут chrome, firefox, safari, edge, ios, android или random", fp)
	case strings.Contains(low, "reality") && (strings.Contains(low, "public") || strings.Contains(low, "key") || strings.Contains(low, "short")):
		return errors.New("REALITY: рукопожатие не удалось. Проверьте публичный ключ, short id и SNI")
	case strings.Contains(low, "timeout") || strings.Contains(low, "deadline"):
		return errors.New("VLESS: нет ответа от сервера (таймаут)")
	default:
		return fmt.Errorf("VLESS: не удалось запустить локальный мост: %s", msg)
	}
}

// maskSecrets hides the UUID, public key and short id if an Xray error
// quotes them. A short id under 4 characters could match ordinary words
// and is left alone.
func maskSecrets(err error, p Params) error {
	msg := err.Error()
	out := msg
	for _, v := range []string{p.UUID, strings.ReplaceAll(p.UUID, "-", ""), p.PublicKey, p.ShortID} {
		if len(v) >= 4 {
			out = strings.ReplaceAll(out, v, "***")
		}
	}
	if out == msg {
		return err
	}
	return errors.New(out)
}

func splitComma(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
