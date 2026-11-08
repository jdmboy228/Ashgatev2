package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"ashgate/internal/config"
	"ashgate/internal/packet"
	"ashgate/internal/process"
	"ashgate/internal/rules"
)

func dnsQuery(id uint16, name string, qtype uint16) []byte {
	b := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0, byte(qtype>>8), byte(qtype), 0, 1)
}

var svchost = fixedRes{p: rules.Process{PID: 900, Name: "svchost.exe"}, ok: true}

func udpDNS(t *testing.T, src, dst packet.Addr, name string) []byte {
	t.Helper()
	pkt, err := packet.BuildUDP(src, dst, dnsQuery(7, name, 1))
	if err != nil {
		t.Fatal(err)
	}
	return pkt
}

func TestBypassNames(t *testing.T) {
	// The starter list: the zones, vk.com and gosuslugi.ru among others.
	s := newNameSet(config.Default().BypassDomains())
	for name, want := range map[string]bool{
		"gosuslugi.ru":             true,
		"WWW.Gosuslugi.RU.":        true,
		"lenta.ru":                 true,
		"xn--c1aapkosapc.xn--p1ai": true, // госуслуги.рф
		"kremlin.su":               true,
		"m.vk.com":                 true,
		"vk.com.evil.org":          false,
		"ru.com":                   false,
		"evil-ru.com":              false,
		"example.com":              false,
		"wpad":                     true, // dotless, as Xray treats it
		"router.lan":               true,
		"printer.local":            true,
		"x.test":                   true,
		"1.1.168.192.in-addr.arpa": true,
		"5.0.20.172.in-addr.arpa":  true,
		"5.0.3.172.in-addr.arpa":   false,
		"8.8.8.8.in-addr.arpa":     false,
		"4.3.2.10.in-addr.arpa":    true,
		"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa": true,
		"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa": false,
		"": false,
	} {
		if got := s.bypass(name); got != want {
			t.Errorf("bypass(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestQuestionAndServfail(t *testing.T) {
	q := dnsQuery(0xbeef, "secret.example.com", 28)
	name, qtype, end, ok := question(q)
	if !ok || name != "secret.example.com" || qtype != 28 || end != len(q) {
		t.Fatalf("question = %q %d %d %v", name, qtype, end, ok)
	}
	resp := servfail(q)
	if binary.BigEndian.Uint16(resp) != 0xbeef || resp[2]&0x80 == 0 || resp[2]&0x01 == 0 || resp[3]&0x0f != 2 {
		t.Fatalf("servfail header %x", resp[:12])
	}
	if binary.BigEndian.Uint16(resp[4:]) != 1 || binary.BigEndian.Uint16(resp[6:]) != 0 {
		t.Fatalf("servfail counts %x", resp[:12])
	}
	if _, _, _, ok := question(resp); ok {
		t.Fatal("a response is not a query")
	}
	if _, _, _, ok := question([]byte{1, 2, 3}); ok {
		t.Fatal("short message parsed")
	}
}

// The Windows DNS client resolves for every program. Its lookups go
// through the tunnel, except bypass names, which keep the provider's DNS.
func TestSystemDNSSplitsByName(t *testing.T) {
	e, _ := newEngine(t, testConfig(), svchost, &fakeDial{}, &memInj{})
	src, router := packet.V4(10, 0, 0, 2, 50001), packet.V4(192, 168, 1, 1, 53)
	if r := e.HandlePacket(udpDNS(t, src, router, "www.gosuslugi.ru"), Meta{}, true); r.Action != ActionPass {
		t.Fatalf("bypass name went %v, want the provider's DNS", r.Action)
	}
	if r := e.HandlePacket(udpDNS(t, src, router, "news.lenta.ru"), Meta{}, true); r.Action != ActionPass {
		t.Fatalf(".ru name went %v", r.Action)
	}
	r := e.HandlePacket(udpDNS(t, src, router, "secret.example.com"), Meta{}, true)
	if r.Action != ActionUDP || r.UDP == nil {
		t.Fatalf("other name went %v, want the tunnel", r.Action)
	}
	if r.UDP.ProxyName != "socks" || r.UDP.RelayDst.String() != "1.1.1.1:53" || r.UDP.OrigDst != router {
		t.Fatalf("via %s to %s (orig %s)", r.UDP.ProxyName, r.UDP.RelayDst, r.UDP.OrigDst)
	}
	// The same socket asking for a bypass name next still goes direct, and
	// a tunnel name after that still goes through the tunnel.
	if r := e.HandlePacket(udpDNS(t, src, router, "vk.com"), Meta{}, true); r.Action != ActionPass {
		t.Fatalf("bypass name on a tunnelled socket went %v", r.Action)
	}
	if r := e.HandlePacket(udpDNS(t, src, router, "other.example.com"), Meta{}, true); r.Action != ActionUDP {
		t.Fatalf("tunnel name on the same socket went %v", r.Action)
	}
	// Not a DNS message: it cannot be checked, so it is not sent direct.
	junk, _ := packet.BuildUDP(packet.V4(10, 0, 0, 2, 50002), router, []byte{1, 2, 3})
	if r := e.HandlePacket(junk, Meta{}, true); r.Action != ActionUDP {
		t.Fatalf("unparsable query went %v", r.Action)
	}
}

// A DNS packet whose program is unknown after the hold may be a routed
// program's: it gets the same treatment as the Windows DNS client.
func TestUnknownOwnerDNSNeverGoesDirect(t *testing.T) {
	e, _ := newEngine(t, testConfig(), fixedRes{}, &fakeDial{}, &memInj{})
	pkt := udpDNS(t, packet.V4(10, 0, 0, 3, 50010), packet.V4(77, 88, 8, 8, 53), "leak.example.com")
	if r := e.HandlePacket(append([]byte(nil), pkt...), Meta{}, false); r.Action != ActionUnknown {
		t.Fatalf("first try went %v, want a hold", r.Action)
	}
	if r := e.HandlePacket(pkt, Meta{}, true); r.Action != ActionUDP {
		t.Fatalf("unknown owner's DNS went %v, want the tunnel", r.Action)
	}
	ok := udpDNS(t, packet.V4(10, 0, 0, 3, 50011), packet.V4(77, 88, 8, 8, 53), "sber.ru")
	if r := e.HandlePacket(ok, Meta{}, true); r.Action != ActionPass {
		t.Fatalf("unknown owner's bypass name went %v", r.Action)
	}
	syn, _ := packet.BuildTCP(packet.V4(10, 0, 0, 3, 50012), packet.V4(77, 88, 8, 8, 53), 0x02)
	if r := e.HandlePacket(syn, Meta{}, true); r.Action != ActionModified {
		t.Fatalf("unknown owner's DNS over TCP went %v, want the relay", r.Action)
	}
}

func TestSystemDNSLeftAloneWhenOffOrNothingRouted(t *testing.T) {
	off := testConfig()
	off.DNS.SystemResolver = "direct"
	none := testConfig()
	none.Rules = []config.Rule{{Process: "direct.exe", Action: "direct"}}
	for name, cfg := range map[string]*config.Config{"off": off, "no proxy rules": none} {
		e, _ := newEngine(t, cfg, svchost, &fakeDial{}, nil)
		pkt := udpDNS(t, packet.V4(10, 0, 0, 2, 50020), packet.V4(192, 168, 1, 1, 53), "secret.example.com")
		if r := e.HandlePacket(pkt, Meta{}, true); r.Action != ActionPass {
			t.Errorf("%s: svchost DNS went %v, want direct", name, r.Action)
		}
	}
}

// A router that hands out its fe80:: address (or 169.254.x.x) as the DNS
// server is still the provider's resolver.
func TestLinkLocalDNSIsProxied(t *testing.T) {
	e, _ := newEngine(t, testConfig(), fixedRes{p: rules.Process{PID: 1, Name: "curl.exe"}, ok: true}, &fakeDial{}, nil)
	v6, err := packet.BuildUDP(packet.V6(net.ParseIP("fe80::2"), 50030), packet.V6(net.ParseIP("fe80::1"), 53), dnsQuery(1, "a.example.com", 1))
	if err != nil {
		t.Fatal(err)
	}
	if r := e.HandlePacket(v6, Meta{}, true); r.Action != ActionUDP {
		t.Fatalf("DNS to fe80::1 went %v", r.Action)
	}
	v4 := udpDNS(t, packet.V4(169, 254, 0, 2, 50031), packet.V4(169, 254, 0, 1, 53), "a.example.com")
	if r := e.HandlePacket(v4, Meta{}, true); r.Action != ActionUDP {
		t.Fatalf("DNS to 169.254.0.1 went %v", r.Action)
	}
	// Other link-local traffic still bypasses.
	other, _ := packet.BuildUDP(packet.V4(169, 254, 0, 2, 50032), packet.V4(169, 254, 0, 1, 5000), []byte{1})
	if r := e.HandlePacket(other, Meta{}, true); r.Action != ActionPass {
		t.Fatalf("link-local non-DNS went %v", r.Action)
	}
}

// mutRes answers with whatever process the test sets.
type mutRes struct {
	mu sync.Mutex
	p  rules.Process
}

func (m *mutRes) Lookup(uint8, packet.Addr) (rules.Process, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.p, m.p.PID != 0
}

// A direct decision for port 53 is not remembered: the next program on the
// same port may be a routed one.
func TestDirectDNSIsNotCached(t *testing.T) {
	res := &mutRes{p: rules.Process{PID: 2, Name: "direct.exe"}}
	e, _ := newEngine(t, testConfig(), res, &fakeDial{}, nil)
	src, dst := packet.V4(10, 0, 0, 4, 50040), packet.V4(192, 168, 1, 1, 53)
	if r := e.HandlePacket(udpDNS(t, src, dst, "a.example.com"), Meta{}, true); r.Action != ActionPass {
		t.Fatalf("direct app's DNS went %v", r.Action)
	}
	res.mu.Lock()
	res.p = rules.Process{PID: 3, Name: "curl.exe"}
	res.mu.Unlock()
	if r := e.HandlePacket(udpDNS(t, src, dst, "b.example.com"), Meta{}, true); r.Action != ActionUDP {
		t.Fatalf("routed app on the same port went %v", r.Action)
	}
}

// staleRes knows only a closed socket of a program without a rule on the
// port; a new DNS socket of someone else has it now.
type staleRes struct{}

func (staleRes) Lookup(uint8, packet.Addr) (rules.Process, bool) {
	return rules.Process{PID: 2, Name: "direct.exe"}, true
}

func (staleRes) LookupLive(uint8, packet.Addr) (rules.Process, bool) {
	return rules.Process{}, false
}

// Owner answers like process.Resolver for a socket that just closed: the
// last packets and a datagram keep it, a new flow does not.
func (staleRes) Owner(_ uint8, _ packet.Addr, start process.Start, _ bool) (rules.Process, bool) {
	if start == process.NewFlow {
		return rules.Process{}, false
	}
	return rules.Process{PID: 2, Name: "direct.exe"}, true
}

func TestDNSIgnoresClosedSocketOwner(t *testing.T) {
	e, _ := newEngine(t, testConfig(), staleRes{}, &fakeDial{}, nil)
	pkt := udpDNS(t, packet.V4(10, 0, 0, 6, 50090), packet.V4(192, 168, 1, 1, 53), "a.example.com")
	if r := e.HandlePacket(append([]byte(nil), pkt...), Meta{}, false); r.Action != ActionUnknown {
		t.Fatalf("first try went %v, want a hold for the new socket's event", r.Action)
	}
	if r := e.HandlePacket(pkt, Meta{}, true); r.Action != ActionUDP {
		t.Fatalf("query on a reused port went %v, want the tunnel", r.Action)
	}
	// A TCP SYN ignores the closed socket. With a proxy rule the unknown
	// owner's packet is dropped, not sent direct.
	syn, _ := packet.BuildTCP(packet.V4(10, 0, 0, 6, 50092), packet.V4(198, 51, 100, 1, 443), 0x02)
	if r := e.HandlePacket(syn, Meta{}, true); r.Action != ActionDrop {
		t.Fatalf("SYN on a reused port went %v", r.Action)
	}
	// The last packets of a connection keep the closed socket's owner.
	ack, _ := packet.BuildTCP(packet.V4(10, 0, 0, 6, 50093), packet.V4(198, 51, 100, 1, 443), 0x11)
	if r := e.HandlePacket(ack, Meta{}, true); r.Action != ActionPass {
		t.Fatalf("FIN of direct.exe went %v", r.Action)
	}
	// So does a UDP datagram that is not DNS: a program that sends once and
	// closes (syslog, NTP) must not lose its packet.
	other, _ := packet.BuildUDP(packet.V4(10, 0, 0, 6, 50091), packet.V4(198, 51, 100, 1, 5000), []byte{1})
	if r := e.HandlePacket(other, Meta{}, true); r.Action != ActionPass {
		t.Fatalf("datagram of a program that closed went %v", r.Action)
	}
}

// With the real resolver: a program without a rule sends one datagram and
// closes at once; DNS and a SYN from the same closed socket are still
// treated as from an unknown owner.
func TestSendThenCloseDatagramIsNotDropped(t *testing.T) {
	r := process.New()
	r.SetImage(func(pid uint32) rules.Process { return rules.Process{PID: pid, Name: "syslogd.exe"} })
	e, _ := newEngine(t, testConfig(), r, &fakeDial{}, nil)
	src := packet.V4(10, 0, 0, 6, 50200)
	r.Observe(packet.ProtoUDP, src, 9, false)
	r.Observe(packet.ProtoUDP, src, 9, true)
	udp, _ := packet.BuildUDP(src, packet.V4(198, 51, 100, 1, 514), []byte("log"))
	if res := e.HandlePacket(udp, Meta{}, true); res.Action != ActionPass {
		t.Fatalf("send-then-close datagram went %v", res.Action)
	}
	dns := udpDNS(t, src, packet.V4(192, 168, 1, 1, 53), "a.example.com")
	if res := e.HandlePacket(dns, Meta{}, true); res.Action == ActionPass {
		t.Fatalf("DNS from a closed socket went %v, want the strict path", res.Action)
	}
	syn, _ := packet.BuildTCP(src, packet.V4(198, 51, 100, 1, 443), 0x02)
	r.Observe(packet.ProtoTCP, src, 9, false)
	r.Observe(packet.ProtoTCP, src, 9, true)
	if res := e.HandlePacket(syn, Meta{}, true); res.Action != ActionDrop {
		t.Fatalf("SYN from a closed socket went %v", res.Action)
	}
}

// A DNS flow is one query and its answer: it goes sooner than other UDP.
func TestIdleDNSFlowsRetireSooner(t *testing.T) {
	e, _ := newEngine(t, testConfig(), fixedRes{p: rules.Process{PID: 5, Name: "curl.exe"}, ok: true}, &fakeDial{}, nil)
	dns := e.HandlePacket(udpDNS(t, packet.V4(10, 0, 0, 5, 50100), packet.V4(1, 1, 1, 1, 53), "a.example.com"), Meta{}, true)
	other, _ := packet.BuildUDP(packet.V4(10, 0, 0, 5, 50101), packet.V4(198, 51, 100, 1, 5000), []byte{1})
	game := e.HandlePacket(other, Meta{}, true)
	if dns.Action != ActionUDP || game.Action != ActionUDP {
		t.Fatalf("flows not opened: %v %v", dns.Action, game.Action)
	}
	e.sweep(time.Now().Add(dnsIdle + time.Second))
	e.mu.Lock()
	_, dnsLeft := e.udp[dns.UDP.Key]
	_, gameLeft := e.udp[game.UDP.Key]
	e.mu.Unlock()
	if dnsLeft || !gameLeft {
		t.Fatalf("after %s idle: dns flow kept %v, other flow kept %v", dnsIdle+time.Second, dnsLeft, gameLeft)
	}
}

func TestSystemProxyChoice(t *testing.T) {
	proxies := map[string]config.Proxy{
		"socks": {Name: "socks", Type: "socks5"},
		"vps":   {Name: "vps", Type: "vless"},
		"web":   {Name: "web", Type: "http"},
	}
	cfg := &config.Config{Rules: []config.Rule{
		{Process: "a.exe", Action: "proxy", Proxy: "socks"},
		{Process: "b.exe", Action: "proxy", Proxy: "vps"},
	}}
	if p, ok := systemProxy(cfg, proxies); !ok || p.Name != "vps" {
		t.Fatalf("auto = %q %v, want the VLESS proxy", p.Name, ok)
	}
	cfg.DNS.SystemResolverProxy = "web"
	if p, _ := systemProxy(cfg, proxies); p.Name != "web" {
		t.Fatalf("explicit = %q", p.Name)
	}
	cfg.DNS.SystemResolver = "direct"
	if _, ok := systemProxy(cfg, proxies); ok {
		t.Fatal("off still picked a proxy")
	}
	off := false
	cfg = &config.Config{Rules: []config.Rule{
		{Process: "a.exe", Action: "proxy", Proxy: "vps", Enabled: &off},
		{Process: "b.exe", Action: "proxy", Proxy: "socks"},
	}}
	if p, _ := systemProxy(cfg, proxies); p.Name != "socks" {
		t.Fatalf("a disabled rule was chosen: %q", p.Name)
	}
}

// tcpDNS answers DNS over TCP by echoing the query as a response.
func tcpDNS(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var hdr [2]byte
				if _, err := io.ReadFull(c, hdr[:]); err != nil {
					return
				}
				msg := make([]byte, binary.BigEndian.Uint16(hdr[:]))
				if _, err := io.ReadFull(c, msg); err != nil {
					return
				}
				msg[2] |= 0x80
				_, _ = c.Write(append(hdr[:], msg...))
			}()
		}
	}()
	return ln.Addr().String()
}

func waitInjected(inj *memInj, n int) {
	for wait := time.Now().Add(3 * time.Second); inj.count() < n && time.Now().Before(wait); {
		time.Sleep(10 * time.Millisecond)
	}
}

// System DNS through SOCKS5 goes as DNS over TCP to the configured server:
// it must not depend on UDP ASSOCIATE.
func TestSystemDNSOverTCPThroughSOCKS(t *testing.T) {
	fd := &fakeDial{target: tcpDNS(t)}
	inj := &memInj{}
	e, _ := newEngine(t, testConfig(), svchost, fd, inj)
	router := packet.V4(192, 168, 1, 1, 53)
	r := e.HandlePacket(udpDNS(t, packet.V4(10, 0, 0, 2, 50050), router, "secret.example.com"), Meta{}, true)
	if r.Action != ActionUDP {
		t.Fatal(r.Action)
	}
	if err := e.ForwardUDP(context.Background(), *r.UDP); err != nil {
		t.Fatal(err)
	}
	waitInjected(inj, 1)
	if inj.count() != 1 {
		t.Fatalf("injected %d", inj.count())
	}
	if len(fd.got) != 1 || fd.got[0] != "1.1.1.1:53" {
		t.Fatalf("dialed %v, want 1.1.1.1:53 through the proxy", fd.got)
	}
	var h packet.Header
	raw := inj.packet(0)
	if err := packet.Parse(raw, &h); err != nil {
		t.Fatal(err)
	}
	if h.Src != router || raw[h.PayloadOff+2]&0x80 == 0 {
		t.Fatalf("reply from %s, payload %x", h.Src, raw[h.PayloadOff:])
	}
}

func rcodeOf(t *testing.T, raw []byte) byte {
	t.Helper()
	var h packet.Header
	if err := packet.Parse(raw, &h); err != nil {
		t.Fatal(err)
	}
	return raw[h.PayloadOff+3] & 0x0f
}

// When the proxy cannot carry a query, the program gets SERVFAIL at once
// and nothing goes direct.
func TestDNSFailureAnswersServfail(t *testing.T) {
	inj := &memInj{}
	e, _ := newEngine(t, testConfig(), svchost, &fakeDial{fail: errors.New("proxy down")}, inj)
	r := e.HandlePacket(udpDNS(t, packet.V4(10, 0, 0, 2, 50060), packet.V4(192, 168, 1, 1, 53), "secret.example.com"), Meta{}, true)
	_ = e.ForwardUDP(context.Background(), *r.UDP)
	waitInjected(inj, 1)
	if inj.count() != 1 || rcodeOf(t, inj.packet(0)) != 2 {
		t.Fatalf("system DNS with the proxy down: %d replies", inj.count())
	}

	inj2 := &memInj{}
	e2, _ := newEngine(t, testConfig(), fixedRes{p: rules.Process{PID: 5, Name: "curl.exe"}, ok: true}, &failUDP{}, inj2)
	r = e2.HandlePacket(udpDNS(t, packet.V4(10, 0, 0, 5, 50061), packet.V4(1, 1, 1, 1, 53), "a.example.com"), Meta{}, true)
	_ = e2.ForwardUDP(context.Background(), *r.UDP)
	if inj2.count() != 1 || rcodeOf(t, inj2.packet(0)) != 2 {
		t.Fatalf("app DNS with UDP ASSOCIATE failing: %d replies", inj2.count())
	}
}

// DNS over TCP of a routed program goes to the configured server, not to
// the provider's resolver it asked.
func TestTCPDNSDialsConfiguredServer(t *testing.T) {
	e, _ := newEngine(t, testConfig(), fixedRes{p: rules.Process{PID: 5, Name: "curl.exe"}, ok: true}, &fakeDial{}, nil)
	src := packet.V4(10, 0, 0, 5, 50070)
	syn, _ := packet.BuildTCP(src, packet.V4(192, 168, 1, 1, 53), 0x02)
	if r := e.HandlePacket(syn, Meta{}, true); r.Action != ActionModified {
		t.Fatal(r.Action)
	}
	e.mu.Lock()
	flow := e.byClient[src]
	e.mu.Unlock()
	if flow == nil || flow.dial.String() != "1.1.1.1:53" {
		t.Fatalf("flow %+v", flow)
	}
}

func TestSystemDNSOldConnectionDropped(t *testing.T) {
	e, _ := newEngine(t, testConfig(), svchost, &fakeDial{}, nil)
	ack, _ := packet.BuildTCP(packet.V4(10, 0, 0, 2, 50080), packet.V4(192, 168, 1, 1, 53), 0x10)
	if r := e.HandlePacket(ack, Meta{}, true); r.Action != ActionDrop {
		t.Fatalf("svchost's open DNS connection went %v", r.Action)
	}
}
