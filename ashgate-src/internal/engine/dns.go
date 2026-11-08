package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"ashgate/internal/config"
	"ashgate/internal/httpproxy"
	"ashgate/internal/logbuf"
	"ashgate/internal/packet"
	"ashgate/internal/rules"
)

// System DNS. The Windows DNS client (svchost.exe) resolves for every
// program that calls getaddrinfo, and browsers fall back to it when their
// own lookup fails. A DNS packet whose program is still unknown after the
// hold may come from any program too. Either can carry the name a routed
// program asked for, so neither goes to the provider's DNS unless the name
// is a bypass name; everything else goes through one tunnel proxy.

// localNames are the suffixes Xray's DNS always gives to the system
// resolver (its "localhost" server), on top of dotless names. Passing them
// here as well keeps such a lookup from looping svchost → Ashgate → Xray →
// svchost, and keeps LAN names such as router.lan on the LAN.
var localNames = []string{"local", "localdomain", "localhost", "lan", "home.arpa", "example", "invalid", "test"}

// nameSet holds bypass suffixes.
type nameSet map[string]struct{}

func newNameSet(domains []string) nameSet {
	s := nameSet{}
	for _, d := range append(append([]string(nil), localNames...), domains...) {
		d = strings.Trim(strings.ToLower(d), ".")
		if d != "" {
			s[d] = struct{}{}
		}
	}
	return s
}

// bypass reports whether a lookup of name goes to the provider's DNS
// unchanged: a bypass domain or its subdomain, a local name, or a reverse
// lookup of a private address.
func (s nameSet) bypass(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if name == "" {
		return false
	}
	if !strings.Contains(name, ".") || privatePTR(name) {
		return true
	}
	for n := name; ; {
		if _, ok := s[n]; ok {
			return true
		}
		i := strings.IndexByte(n, '.')
		if i < 0 {
			return false
		}
		n = n[i+1:]
	}
}

// privatePTR reports a reverse lookup of a loopback, private or link-local
// address: only the LAN can answer it.
func privatePTR(name string) bool {
	if rest, ok := strings.CutSuffix(name, ".in-addr.arpa"); ok {
		labels := strings.Split(rest, ".")
		n := len(labels)
		a, err := strconv.Atoi(labels[n-1])
		if err != nil {
			return false
		}
		b := -1
		if n >= 2 {
			if v, err := strconv.Atoi(labels[n-2]); err == nil {
				b = v
			}
		}
		switch {
		case a == 10, a == 127:
			return true
		case a == 192 && b == 168, a == 169 && b == 254:
			return true
		case a == 172 && b >= 16 && b <= 31:
			return true
		}
		return false
	}
	if rest, ok := strings.CutSuffix(name, ".ip6.arpa"); ok {
		// Nibbles, lowest first: the last ones are the top of the address.
		nib := strings.Split(rest, ".")
		n := len(nib)
		if n == 32 && nib[0] == "1" && strings.Trim(strings.Join(nib[1:], ""), "0") == "" {
			return true // ::1
		}
		if n < 3 || nib[n-1] != "f" {
			return false
		}
		switch nib[n-2] {
		case "c", "d": // fc00::/7
			return true
		case "e": // fe80::/10
			return strings.Contains("89ab", nib[n-3]) && len(nib[n-3]) == 1
		}
	}
	return false
}

// question returns the first question of a DNS query and where it ends.
func question(msg []byte) (name string, qtype uint16, end int, ok bool) {
	if len(msg) < 12 || msg[2]&0x80 != 0 || binary.BigEndian.Uint16(msg[4:6]) == 0 {
		return "", 0, 0, false
	}
	var b strings.Builder
	off := 12
	for {
		if off >= len(msg) {
			return "", 0, 0, false
		}
		l := int(msg[off])
		off++
		if l == 0 {
			break
		}
		// A query has no compression pointers; anything else is not one.
		if l&0xC0 != 0 || off+l > len(msg) || b.Len()+l > 254 {
			return "", 0, 0, false
		}
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		b.Write(msg[off : off+l])
		off += l
	}
	if off+4 > len(msg) {
		return "", 0, 0, false
	}
	return b.String(), binary.BigEndian.Uint16(msg[off:]), off + 4, true
}

// servfail answers query with SERVFAIL, so the program stops waiting
// instead of retrying or falling back to another resolver.
func servfail(query []byte) []byte {
	_, _, end, ok := question(query)
	if !ok {
		return nil
	}
	out := make([]byte, end)
	copy(out, query[:end])
	out[2] = 0x80 | query[2]&0x79 // a response; opcode and RD as asked
	out[3] = 0x80 | 2             // RA, SERVFAIL
	binary.BigEndian.PutUint16(out[4:], 1)
	clear(out[6:12])
	return out
}

// payloadOf is the UDP or TCP payload of a parsed packet.
func payloadOf(pkt []byte, h *packet.Header) []byte {
	if h.PayloadLen <= 0 || h.PayloadOff <= 0 || h.PayloadOff+h.PayloadLen > len(pkt) {
		return nil
	}
	return pkt[h.PayloadOff : h.PayloadOff+h.PayloadLen]
}

// systemProxy picks the proxy for system DNS: dns.systemResolverProxy, or
// the proxy of the first enabled proxy rule, VLESS first. None means no
// program is routed, so there is nothing to keep from the provider.
func systemProxy(cfg *config.Config, proxies map[string]config.Proxy) (config.Proxy, bool) {
	if !cfg.DNS.SystemTunnel() {
		return config.Proxy{}, false
	}
	if p, ok := proxies[cfg.DNS.SystemResolverProxy]; ok && cfg.DNS.SystemResolverProxy != "" {
		return p, true
	}
	var first *config.Proxy
	for _, r := range cfg.EffectiveRules() {
		if !r.IsEnabled() || r.Action != "proxy" {
			continue
		}
		p, ok := proxies[r.Proxy]
		if !ok {
			continue
		}
		if p.Type == "vless" {
			return p, true
		}
		if first == nil {
			first = &p
		}
	}
	if first != nil {
		return *first, true
	}
	return config.Proxy{}, false
}

// systemDNS decides a DNS packet of the Windows DNS client or of an unknown
// program; proc is empty for the latter.
func (e *Engine) systemDNS(pkt []byte, h *packet.Header, meta Meta, proc rules.Process, snap *snapshot) Result {
	if snap.sysProxy == nil {
		if h.Proto == packet.ProtoTCP && !(h.SYN && !h.ACK) && proc.PID == 0 {
			// As for any mid-connection packet without a program.
			e.rememberBlock(h)
			return Result{Action: ActionDrop}
		}
		e.rememberDirectExceptDNS(h)
		return Result{Action: ActionPass}
	}
	p := *snap.sysProxy
	if h.Proto == packet.ProtoTCP {
		if !(h.SYN && !h.ACK) {
			// Opened before capture; Windows asks again on a new one.
			e.rememberBlock(h)
			return Result{Action: ActionDrop}
		}
		// The name is not visible before the handshake: all of it goes
		// through the tunnel. Windows uses TCP only after a truncated answer.
		return e.startTCP(pkt, h, meta, proc, p, snap, "", nil, true)
	}
	if h.Frag {
		e.dropFragment(h)
		return Result{Action: ActionDrop}
	}
	if name, _, _, ok := question(payloadOf(pkt, h)); ok && snap.bypassNames.bypass(name) {
		return Result{Action: ActionPass}
	}
	return e.startUDP(pkt, h, meta, proc, p, snap, "", nil, false, true)
}

// dohServers are public resolvers Windows can use with DNS over HTTPS
// (its built-in templates, AdGuard and Yandex). Their port 443 carries
// only DNS.
var dohServers = func() map[packet.Addr]struct{} {
	m := map[packet.Addr]struct{}{}
	for _, ip := range []string{
		"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
		"94.140.14.14", "94.140.15.15", "77.88.8.8", "77.88.8.1",
		"2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888",
		"2001:4860:4860::8844", "2620:fe::fe", "2620:fe::9",
	} {
		m[packet.FromIP(net.ParseIP(ip), 443)] = struct{}{}
	}
	return m
}()

// encryptedDNS reports DNS over TLS (TCP 853) or over HTTPS (443, TCP or
// QUIC, to a resolver in dohServers).
func encryptedDNS(h *packet.Header) bool {
	if h.Dst.Port == 853 {
		return h.Proto == packet.ProtoTCP
	}
	_, ok := dohServers[h.Dst]
	return ok
}

// systemEncryptedDNS sends the Windows DNS client's DoT and DoH through
// the system DNS proxy, to the resolver Windows chose. The names inside
// are not visible, so none can be let through for the provider's DNS;
// sent direct, the provider would still see every lookup's time and size
// next to a routed program's traffic.
func (e *Engine) systemEncryptedDNS(pkt []byte, h *packet.Header, meta Meta, proc rules.Process, snap *snapshot) Result {
	if snap.sysProxy == nil {
		e.rememberDirect(h)
		return Result{Action: ActionPass}
	}
	p := *snap.sysProxy
	if h.Proto == packet.ProtoTCP {
		if !(h.SYN && !h.ACK) {
			// Opened before capture: reset, Windows reconnects through the tunnel.
			e.reset(h, meta)
			return Result{Action: ActionDrop}
		}
		return e.startTCP(pkt, h, meta, proc, p, snap, "", nil, false)
	}
	// QUIC that the proxy cannot carry is dropped, never sent direct:
	// Windows then uses DoH over TCP.
	return e.startUDP(pkt, h, meta, proc, p, snap, "", nil, true, false)
}

// forwardDNSTCP sends one query as DNS over TCP through the flow's proxy:
// HTTP proxies have no UDP, and system DNS through SOCKS5 must not depend
// on UDP ASSOCIATE, which many servers lack.
func (e *Engine) forwardDNSTCP(ctx context.Context, flow *udpFlow, payload []byte) error {
	server := flow.relay.String()
	var resp []byte
	var err error
	if flow.proxy.Type == "http" {
		resp, err = httpproxy.DNSQuery(ctx, flow.proxy, server, payload)
	} else {
		resp, err = e.dnsTCP(ctx, flow.proxy, flow.relay, payload)
	}
	if err != nil {
		flow.stat.fail(err.Error(), e.now())
		e.log(logbuf.Event{Process: display(flow.proc), PID: flow.proc.PID, Proto: "UDP", Dest: flow.orig.String(), Via: flow.proxy.Name, Status: "error", Error: err.Error()})
		e.failDNS(flow, payload)
		return err
	}
	n := int64(len(resp))
	flow.down.Add(n)
	e.bytesDown.Add(n)
	if flow.stat != nil {
		flow.stat.down.Add(n)
	}
	return e.injectUDP(flow, resp)
}

// dnsTCP is one DNS-over-TCP exchange with server through p.
func (e *Engine) dnsTCP(ctx context.Context, p config.Proxy, server packet.Addr, query []byte) ([]byte, error) {
	if len(query) == 0 || len(query) > 65535 {
		return nil, errors.New("dns query has an invalid length")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c, err := e.dial.DialTCP(ctx, p, server.NetIP().String(), server.Port)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	msg := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(msg, uint16(len(query)))
	copy(msg[2:], query)
	if _, err := c.Write(msg); err != nil {
		return nil, err
	}
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := io.ReadFull(c, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// failDNS answers a DNS query that could not go through the proxy with
// SERVFAIL. Nothing is sent directly instead.
func (e *Engine) failDNS(flow *udpFlow, query []byte) {
	if flow.orig.Port != 53 {
		return
	}
	if resp := servfail(query); resp != nil {
		_ = e.injectUDP(flow, resp)
	}
}

// dnsRelay picks the server a proxied query is sent to, as host:port.
func dnsRelay(servers []string, n uint64) (packet.Addr, bool) {
	if len(servers) == 0 {
		return packet.Addr{}, false
	}
	s := servers[int(n%uint64(len(servers)))]
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return packet.Addr{}, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return packet.Addr{}, false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return packet.Addr{}, false
	}
	return packet.FromIP(ip, uint16(port)), true
}
