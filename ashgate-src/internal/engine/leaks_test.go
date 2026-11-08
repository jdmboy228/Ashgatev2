package engine

import (
	"context"
	"net"
	"strings"
	"testing"

	"ashgate/internal/packet"
	"ashgate/internal/rules"
)

var curl = rules.Process{PID: 5, Name: "curl.exe"}

// A VLESS server behind a CDN shares its IP with other sites. A routed
// program follows its rule to that IP on any port; only a connection of
// no known program to the server's own IP:port passes direct (Ashgate's
// own socket whose event was missed).
func TestProxyServerIPFollowsRules(t *testing.T) {
	cfg := testConfig()
	cfg.Proxies[0].Address = "203.0.113.10:443"
	server := packet.V4(203, 0, 113, 10, 443)
	other := packet.V4(203, 0, 113, 10, 8443)
	res := &switchRes{p: curl, ok: true}
	e, _ := newEngine(t, cfg, res, &fakeDial{}, nil)
	e.RefreshBypass(context.Background())
	for i, dst := range []packet.Addr{server, other} {
		syn, _ := packet.BuildTCP(packet.V4(10, 0, 0, 2, uint16(4000+i)), dst, 0x02)
		if r := e.HandlePacket(syn, Meta{}, true); r.Action != ActionModified {
			t.Fatalf("routed app to %s went %v, want its proxy", dst, r.Action)
		}
	}
	res.set(false)
	syn, _ := packet.BuildTCP(packet.V4(10, 0, 0, 2, 4100), server, 0x02)
	if r := e.HandlePacket(append([]byte(nil), syn...), Meta{}, false); r.Action != ActionUnknown {
		t.Fatalf("unknown program to the server went %v before the hold", r.Action)
	}
	if r := e.HandlePacket(syn, Meta{}, true); r.Action != ActionPass {
		t.Fatalf("unknown program to the server's IP:port went %v", r.Action)
	}
	syn, _ = packet.BuildTCP(packet.V4(10, 0, 0, 2, 4101), other, 0x02)
	if r := e.HandlePacket(syn, Meta{}, true); r.Action != ActionDrop {
		t.Fatalf("unknown program to the server's IP on another port went %v", r.Action)
	}
}

// fragment marks an IPv4 packet as the first fragment of datagram id, or
// as a later one (no ports) at offset 8*off bytes.
func fragment(pkt []byte, id uint16, off uint16) []byte {
	pkt[4], pkt[5] = byte(id>>8), byte(id)
	if off == 0 {
		pkt[6], pkt[7] = 0x20, 0 // more fragments
	} else {
		pkt[6], pkt[7] = byte(off>>8), byte(off)
	}
	return pkt
}

// Only a first fragment carries ports. One of a proxied TCP flow cannot be
// rewritten whole, so it and its later fragments are dropped.
func TestProxiedTCPFragmentsDropped(t *testing.T) {
	e, _ := newEngine(t, testConfig(), fixedRes{p: curl, ok: true}, &fakeDial{}, nil)
	app, dst := packet.V4(10, 0, 0, 2, 4200), packet.V4(198, 51, 100, 3, 443)
	syn, _ := packet.BuildTCP(app, dst, 0x02)
	if r := e.HandlePacket(syn, Meta{}, true); r.Action != ActionModified {
		t.Fatalf("SYN went %v", r.Action)
	}
	data, _ := packet.BuildTCP(app, dst, 0x18)
	if r := e.HandlePacket(fragment(data, 0x4242, 0), Meta{}, true); r.Action != ActionDrop {
		t.Fatalf("first fragment of a proxied flow went %v", r.Action)
	}
	rest, _ := packet.BuildUDP(packet.V4(10, 0, 0, 2, 1), packet.V4(198, 51, 100, 3, 1), make([]byte, 16))
	rest[9] = packet.ProtoTCP
	if r := e.HandlePacket(fragment(rest, 0x4242, 3), Meta{}, true); r.Action != ActionDrop {
		t.Fatalf("later fragment of a proxied flow went %v", r.Action)
	}
}

// Later fragments of a datagram whose first fragment waits for its owner
// wait too, and follow the first fragment's fate.
func TestLaterFragmentsWaitForTheFirst(t *testing.T) {
	e, _ := newEngine(t, testConfig(), fixedRes{}, &fakeDial{}, nil)
	src, dst := packet.V4(10, 0, 0, 4, 4300), packet.V4(198, 51, 100, 4, 5000)
	first, _ := packet.BuildUDP(src, dst, make([]byte, 64))
	first = fragment(first, 0x777, 0)
	rest, _ := packet.BuildUDP(packet.V4(10, 0, 0, 4, 1), packet.V4(198, 51, 100, 4, 1), make([]byte, 64))
	rest = fragment(rest, 0x777, 9)
	if r := e.HandlePacket(append([]byte(nil), first...), Meta{}, false); r.Action != ActionUnknown {
		t.Fatalf("first fragment went %v before the hold", r.Action)
	}
	if r := e.HandlePacket(append([]byte(nil), rest...), Meta{}, false); r.Action != ActionUnknown {
		t.Fatalf("later fragment went %v while the first is held", r.Action)
	}
	if r := e.HandlePacket(first, Meta{}, true); r.Action != ActionDrop {
		t.Fatalf("first fragment of an unknown program went %v", r.Action)
	}
	if r := e.HandlePacket(rest, Meta{}, true); r.Action != ActionDrop {
		t.Fatalf("later fragment went %v after the first was dropped", r.Action)
	}
}

// Without the IPv6 relay a routed program's IPv6 TCP is dropped (it falls
// back to IPv4), never handed to whatever holds [::1]:34010.
func TestIPv6WithoutRelayDropped(t *testing.T) {
	e, logs := newEngine(t, testConfig(), fixedRes{p: curl, ok: true}, &fakeDial{}, nil)
	e.DisableIPv6Relay()
	app := packet.V6(net.ParseIP("2001:db8:1::10"), 4400)
	dst := packet.V6(net.ParseIP("2001:db8:2::10"), 443)
	for i := 0; i < 2; i++ {
		syn, _ := packet.BuildTCP(app, dst, 0x02)
		if r := e.HandlePacket(syn, Meta{}, true); r.Action != ActionDrop {
			t.Fatalf("IPv6 SYN went %v", r.Action)
		}
	}
	syn, _ := packet.BuildTCP(packet.V4(10, 0, 0, 2, 4400), packet.V4(198, 51, 100, 3, 443), 0x02)
	if r := e.HandlePacket(syn, Meta{}, true); r.Action != ActionModified {
		t.Fatalf("IPv4 SYN went %v", r.Action)
	}
	lines := 0
	for _, ev := range logs.Snapshot() {
		if strings.Contains(ev.Error, "IPv6-приёмник") {
			lines++
		}
	}
	if lines != 1 {
		t.Fatalf("%d lines about the IPv6 relay, want 1", lines)
	}
}

// The Windows DNS client's DNS over TLS and HTTPS goes through the system
// DNS proxy to the resolver it chose. Its other HTTPS stays direct.
func TestSystemEncryptedDNSThroughTunnel(t *testing.T) {
	inj := &memInj{}
	e, _ := newEngine(t, testConfig(), svchost, &fakeDial{}, inj)
	for i, dst := range []packet.Addr{packet.V4(1, 1, 1, 1, 443), packet.V4(9, 9, 9, 9, 853), packet.V4(203, 0, 113, 53, 853),
		packet.V6(net.ParseIP("2606:4700:4700::1111"), 443)} {
		src := packet.V4(10, 0, 0, 2, uint16(4500+i))
		if dst.Len == 16 {
			src = packet.V6(net.ParseIP("2001:db8:1::10"), uint16(4500+i))
		}
		syn, _ := packet.BuildTCP(src, dst, 0x02)
		if r := e.HandlePacket(syn, Meta{}, true); r.Action != ActionModified {
			t.Fatalf("DNS client to %s went %v, want the tunnel", dst, r.Action)
		}
		e.mu.Lock()
		f := e.byClient[src]
		e.mu.Unlock()
		if f == nil || f.proxy.Name != "socks" || f.orig != dst || !f.dial.IsZero() {
			t.Fatalf("flow to %s: %+v", dst, f)
		}
	}
	quic, _ := packet.BuildUDP(packet.V4(10, 0, 0, 2, 4600), packet.V4(8, 8, 8, 8, 443), []byte("quic"))
	r := e.HandlePacket(quic, Meta{}, true)
	if r.Action != ActionUDP || r.UDP.RelayDst != packet.V4(8, 8, 8, 8, 443) {
		t.Fatalf("DoH over QUIC went %v %+v", r.Action, r.UDP)
	}
	update, _ := packet.BuildTCP(packet.V4(10, 0, 0, 2, 4601), packet.V4(13, 107, 4, 50, 443), 0x02)
	if r := e.HandlePacket(update, Meta{}, true); r.Action != ActionPass {
		t.Fatalf("other HTTPS of svchost went %v", r.Action)
	}
	old, _ := packet.BuildTCP(packet.V4(10, 0, 0, 2, 4602), packet.V4(1, 1, 1, 1, 443), 0x18)
	if r := e.HandlePacket(old, Meta{}, true); r.Action != ActionDrop || inj.count() != 1 {
		t.Fatalf("DoH opened before capture went %v (%d resets)", r.Action, inj.count())
	}

	// An HTTP proxy has no UDP: QUIC is dropped, not sent direct, so
	// Windows uses DoH over TCP.
	cfg := testConfig()
	cfg.UDPUnsupported = "direct"
	cfg.DNS.SystemResolverProxy = "web"
	web, _ := newEngine(t, cfg, svchost, &fakeDial{}, nil)
	quic, _ = packet.BuildUDP(packet.V4(10, 0, 0, 2, 4603), packet.V4(8, 8, 8, 8, 443), []byte("quic"))
	if r := web.HandlePacket(quic, Meta{}, true); r.Action != ActionDrop {
		t.Fatalf("DoH over QUIC through an HTTP proxy went %v", r.Action)
	}

	// Switched off, or with nothing routed, it is left alone.
	cfg = testConfig()
	cfg.DNS.SystemResolver = "direct"
	off, _ := newEngine(t, cfg, svchost, &fakeDial{}, nil)
	syn, _ := packet.BuildTCP(packet.V4(10, 0, 0, 2, 4604), packet.V4(1, 1, 1, 1, 443), 0x02)
	if r := off.HandlePacket(syn, Meta{}, true); r.Action != ActionPass {
		t.Fatalf("with system DNS off DoH went %v", r.Action)
	}
}

// A known program whose image cannot be read shows its PID in the log.
func TestDisplayUnnamedProcess(t *testing.T) {
	if got := display(rules.Process{PID: 1234}); got != "PID 1234" {
		t.Fatalf("display = %q", got)
	}
	if got := display(rules.Process{PID: 4, Name: "System"}); got != "System" {
		t.Fatalf("display = %q", got)
	}
	// It matches no rule and goes direct, also with a proxy rule.
	e, _ := newEngine(t, testConfig(), fixedRes{p: rules.Process{PID: 1234}, ok: true}, &fakeDial{}, nil)
	syn, _ := packet.BuildTCP(packet.V4(10, 0, 0, 2, 4700), packet.V4(198, 51, 100, 3, 445), 0x02)
	if r := e.HandlePacket(syn, Meta{}, true); r.Action != ActionPass {
		t.Fatalf("protected process went %v", r.Action)
	}
}

// The Windows DNS client can be a process whose image cannot be read. Its
// DNS has no name for a rule to match and must still go through the
// tunnel like the DNS client's, never direct.
func TestUnnamedProcessDNSThroughTunnel(t *testing.T) {
	e, _ := newEngine(t, testConfig(), fixedRes{p: rules.Process{PID: 1234}, ok: true}, &fakeDial{}, &memInj{})
	q, _ := packet.BuildUDP(packet.V4(10, 0, 0, 2, 60994), packet.V4(168, 63, 129, 16, 53), dnsQuery(7, "n1.e2e-tunnel.example.com", 1))
	if r := e.HandlePacket(q, Meta{}, true); r.Action != ActionUDP {
		t.Fatalf("DNS of a nameless process went %v, want the tunnel", r.Action)
	}
	bypass, _ := packet.BuildUDP(packet.V4(10, 0, 0, 2, 60995), packet.V4(168, 63, 129, 16, 53), dnsQuery(8, "printer.local", 1))
	if r := e.HandlePacket(bypass, Meta{}, true); r.Action != ActionPass {
		t.Fatalf("a local name went %v, want the LAN", r.Action)
	}
}
