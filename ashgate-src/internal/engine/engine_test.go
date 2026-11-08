package engine

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ashgate/internal/config"
	"ashgate/internal/dialer"
	"ashgate/internal/logbuf"
	"ashgate/internal/packet"
	"ashgate/internal/rules"
	"ashgate/internal/testkit"
)

type fixedRes struct {
	p  rules.Process
	ok bool
}

func (f fixedRes) Lookup(uint8, packet.Addr) (rules.Process, bool) { return f.p, f.ok }

type fakeDial struct {
	target string
	got    []string
	fail   error
}

func (f *fakeDial) DialTCP(ctx context.Context, p config.Proxy, host string, port uint16) (net.Conn, error) {
	f.got = append(f.got, net.JoinHostPort(host, strconv.Itoa(int(port))))
	if f.fail != nil {
		return nil, f.fail
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", f.target)
}

func (f *fakeDial) DialUDP(context.Context, config.Proxy) (dialer.Session, error) {
	return nil, dialer.ErrUDPUnsupported
}

type memInj struct {
	mu   sync.Mutex
	pkts [][]byte
}

func (m *memInj) InjectInbound(pkt []byte, _, _ uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pkts = append(m.pkts, append([]byte(nil), pkt...))
	return nil
}

func (m *memInj) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.pkts)
}

func (m *memInj) packet(i int) []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]byte(nil), m.pkts[i]...)
}

func testConfig() *config.Config {
	return &config.Config{
		Proxies: []config.Proxy{
			{Name: "socks", Type: "socks5", Address: "127.0.0.1:1080"},
			{Name: "web", Type: "http", Address: "127.0.0.1:8080"},
		},
		Rules: []config.Rule{
			{Process: "curl.exe", Action: "proxy", Proxy: "socks"},
			{Process: "direct.exe", Action: "direct"},
			{Process: `C:\Apps\browser.exe`, Action: "proxy", Proxy: "web"},
		},
		DNS: config.DNS{Mode: "proxy", Servers: []string{"1.1.1.1:53"}},
	}
}

func newEngine(t *testing.T, cfg *config.Config, res Resolver, d dialer.Dialer, inj Injector) (*Engine, *logbuf.Buffer) {
	t.Helper()
	logs, err := logbuf.New(100, "")
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(cfg, Options{
		Resolver: res,
		Alloc:    &seqAlloc{},
		Dialer:   d,
		Logs:     logs,
		Injector: inj,
		SkipSelf: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return e, logs
}

func TestTCPRedirectAndRelay(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	fd := &fakeDial{target: echo.Addr().String()}
	e, logs := newEngine(t, testConfig(), fixedRes{p: rules.Process{PID: 42, Name: "curl.exe", Path: `C:\Windows\System32\curl.exe`}, ok: true}, fd, nil)

	app := packet.V4(10, 0, 0, 8, 41000)
	dst := packet.V4(9, 9, 9, 9, 443)
	pkt, err := packet.BuildTCP(app, dst, 0x02)
	if err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), pkt...)
	res := e.HandlePacket(pkt, Meta{IfIdx: 7}, true)
	if res.Action != ActionModified || res.Inbound {
		t.Fatalf("syn result %+v", res)
	}
	if err := packet.ValidChecksums(pkt); err != nil {
		t.Fatal(err)
	}
	var h packet.Header
	if err := packet.Parse(pkt, &h); err != nil {
		t.Fatal(err)
	}
	if h.Src.IP[0] != 127 || h.Dst.Port != 34010 || h.Src.Port < 20000 {
		t.Fatalf("rewritten header %+v", h)
	}
	alloc := h.Src.Port

	// Retransmitted SYN keeps the same allocation.
	again := append([]byte(nil), original...)
	res = e.HandlePacket(again, Meta{IfIdx: 7}, true)
	var h2 packet.Header
	if err := packet.Parse(again, &h2); err != nil {
		t.Fatal(err)
	}
	if h2.Src.Port != alloc {
		t.Fatalf("retransmit port %d want %d", h2.Src.Port, alloc)
	}

	// Return path: local stack to the allocated port becomes the real server.
	ret, err := packet.BuildTCP(packet.V4(127, 0, 0, 1, 34010), packet.V4(127, 0, 0, 1, alloc), 0x12)
	if err != nil {
		t.Fatal(err)
	}
	back := e.HandlePacket(ret, Meta{}, true)
	if back.Action != ActionModified || !back.Inbound || back.IfIdx != 7 {
		t.Fatalf("return %+v", back)
	}
	var hr packet.Header
	if err := packet.Parse(ret, &hr); err != nil {
		t.Fatal(err)
	}
	if hr.Src.Port != 443 || hr.Dst.Port != 41000 || hr.Src.IP[0] != 9 {
		t.Fatalf("restored %+v", hr)
	}
	if err := packet.ValidChecksums(ret); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		e.ServeConn(c)
		close(accepted)
	}()
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(alloc)}, Timeout: 2 * time.Second}
	appConn, err := dialer.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer appConn.Close()
	if _, err := appConn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	_ = appConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(appConn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo %q", buf)
	}
	appConn.Close()
	select {
	case <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not finish")
	}
	if len(fd.got) != 1 || fd.got[0] != "9.9.9.9:443" {
		t.Fatalf("dialed %v", fd.got)
	}
	deadline := time.Now().Add(2 * time.Second)
	var closed bool
	for time.Now().Before(deadline) && !closed {
		for _, ev := range logs.Snapshot() {
			if ev.Status == "closed" && ev.BytesUp == 4 && ev.BytesDown == 4 && ev.Via == "socks" {
				closed = true
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !closed {
		t.Fatalf("log %v", logs.Snapshot())
	}
}

func TestDirectOtherAndSelf(t *testing.T) {
	cfg := testConfig()
	e, logs := newEngine(t, cfg, fixedRes{p: rules.Process{PID: 7, Name: "direct.exe"}, ok: true}, &fakeDial{}, nil)
	pkt, err := packet.BuildTCP(packet.V4(10, 0, 0, 2, 3000), packet.V4(1, 2, 3, 4, 80), 0x02)
	if err != nil {
		t.Fatal(err)
	}
	raw := append([]byte(nil), pkt...)
	res := e.HandlePacket(pkt, Meta{}, true)
	if res.Action != ActionPass {
		t.Fatal(res.Action)
	}
	if string(pkt) != string(raw) {
		t.Fatal("direct packet was modified")
	}
	found := false
	for _, ev := range logs.Snapshot() {
		if ev.Status == "direct" && ev.Process == "direct.exe" {
			found = true
		}
	}
	if !found {
		t.Fatalf("log %v", logs.Snapshot())
	}

	// Second packet of the same flow does not log again.
	before := len(logs.Snapshot())
	data, err := packet.BuildTCP(packet.V4(10, 0, 0, 2, 3000), packet.V4(1, 2, 3, 4, 80), 0x18)
	if err != nil {
		t.Fatal(err)
	}
	if e.HandlePacket(data, Meta{}, true).Action != ActionPass {
		t.Fatal("data")
	}
	if len(logs.Snapshot()) != before {
		t.Fatal("duplicate direct log")
	}

	other, _ := newEngine(t, cfg, fixedRes{p: rules.Process{PID: 8, Name: "notepad.exe"}, ok: true}, &fakeDial{}, nil)
	pkt2, _ := packet.BuildTCP(packet.V4(10, 0, 0, 3, 3001), packet.V4(8, 8, 8, 8, 53), 0x02)
	if other.HandlePacket(pkt2, Meta{}, true).Action != ActionPass {
		t.Fatal("unmatched should pass")
	}
	if len(other.logs.Snapshot()) != 0 {
		t.Fatalf("unmatched logged: %v", other.logs.Snapshot())
	}

	self, _ := newEngine(t, cfg, fixedRes{p: rules.Process{PID: 99, Name: "curl.exe"}, ok: true}, &fakeDial{}, nil)
	self.selfPID = 99
	pkt3, _ := packet.BuildTCP(packet.V4(10, 0, 0, 4, 3002), packet.V4(1, 1, 1, 1, 443), 0x02)
	if self.HandlePacket(pkt3, Meta{}, true).Action != ActionPass {
		t.Fatal("self traffic must stay direct")
	}
}

// Without a proxy rule nothing is routed, and a packet whose program is
// still unknown after the hold passes as before.
func TestUnknownThenPass(t *testing.T) {
	cfg := testConfig()
	cfg.Rules = []config.Rule{{Process: "direct.exe", Action: "direct"}}
	e, _ := newEngine(t, cfg, fixedRes{}, &fakeDial{}, nil)
	pkt, err := packet.BuildTCP(packet.V4(10, 0, 0, 9, 2222), packet.V4(1, 1, 1, 1, 443), 0x02)
	if err != nil {
		t.Fatal(err)
	}
	if e.HandlePacket(append([]byte(nil), pkt...), Meta{}, false).Action != ActionUnknown {
		t.Fatal("expected hold")
	}
	if e.HandlePacket(pkt, Meta{}, true).Action != ActionPass {
		t.Fatal("expected pass")
	}
}

// With a proxy rule an unknown program may be the routed one: its new
// connections and UDP are dropped, and the drop is not remembered, so a
// retransmit whose owner is known by then follows its rule.
func TestUnknownOwnerDroppedWithProxyRules(t *testing.T) {
	res := &switchRes{p: rules.Process{PID: 5, Name: "curl.exe"}}
	e, logs := newEngine(t, testConfig(), res, &fakeDial{}, nil)
	src, dst := packet.V4(10, 0, 0, 9, 2223), packet.V4(198, 51, 100, 9, 443)
	syn, _ := packet.BuildTCP(src, dst, 0x02)
	udp, _ := packet.BuildUDP(packet.V4(10, 0, 0, 9, 2224), dst, []byte("q"))
	for i := 0; i < 3; i++ {
		if r := e.HandlePacket(append([]byte(nil), syn...), Meta{}, true); r.Action != ActionDrop {
			t.Fatalf("SYN of an unknown program went %v", r.Action)
		}
		if r := e.HandlePacket(append([]byte(nil), udp...), Meta{}, true); r.Action != ActionDrop {
			t.Fatalf("UDP of an unknown program went %v", r.Action)
		}
	}
	lines := 0
	for _, ev := range logs.Snapshot() {
		if strings.Contains(ev.Error, "программа не определена") {
			lines++
		}
	}
	if lines != 1 {
		t.Fatalf("%d log lines about unknown programs, want 1: %v", lines, logs.Snapshot())
	}
	// A stream of the dropped UDP flow is not held again, packet by packet.
	if r := e.HandlePacket(append([]byte(nil), udp...), Meta{}, false); r.Action != ActionDrop {
		t.Fatalf("next UDP of the dropped flow went %v, want no new hold", r.Action)
	}
	res.set(true)
	if r := e.HandlePacket(append([]byte(nil), syn...), Meta{}, true); r.Action != ActionModified {
		t.Fatalf("retransmit with its owner known went %v", r.Action)
	}
	if r := e.HandlePacket(udp, Meta{}, true); r.Action != ActionUDP {
		t.Fatalf("UDP with its owner known went %v", r.Action)
	}
	// A packet whose headers do not parse may be a routed program's: with
	// proxy rules it is dropped, and the log says what it was.
	if r := e.HandlePacket([]byte{0x45, 0, 0}, Meta{}, true); r.Action != ActionDrop {
		t.Fatalf("unparsable packet went %v", r.Action)
	}
	cfg := testConfig()
	cfg.Rules = nil
	plain, _ := newEngine(t, cfg, fixedRes{}, &fakeDial{}, nil)
	if r := plain.HandlePacket([]byte{0x45, 0, 0}, Meta{}, true); r.Action != ActionPass {
		t.Fatalf("without proxy rules an unparsable packet went %v", r.Action)
	}
}

// After capture restarts (a crash), a socket whose app has exited may still
// send keepalives or its last FIN/ACK. Its owner is gone, the new engine
// does not know the flow was proxied: the packet must not leave directly.
func TestOwnerlessMidConnectionPacketIsDropped(t *testing.T) {
	res := &switchRes{p: rules.Process{PID: 7, Name: "direct.exe"}}
	e, _ := newEngine(t, testConfig(), res, &fakeDial{}, nil)
	src, dst := packet.V4(10, 0, 0, 9, 2300), packet.V4(198, 51, 100, 10, 443)
	ack, _ := packet.BuildTCP(src, dst, 0x10)
	if r := e.HandlePacket(append([]byte(nil), ack...), Meta{}, false); r.Action != ActionUnknown {
		t.Fatalf("first try went %v, want a hold for the owner lookup", r.Action)
	}
	if r := e.HandlePacket(ack, Meta{}, true); r.Action != ActionDrop {
		t.Fatalf("ownerless ACK went %v", r.Action)
	}
	again, _ := packet.BuildTCP(src, dst, 0x11)
	if r := e.HandlePacket(again, Meta{}, true); r.Action != ActionDrop {
		t.Fatalf("next packet of that socket went %v", r.Action)
	}
	// A new connection from the same port is decided afresh.
	res.set(true)
	syn, _ := packet.BuildTCP(src, dst, 0x02)
	if r := e.HandlePacket(syn, Meta{}, true); r.Action != ActionPass {
		t.Fatalf("new SYN went %v", r.Action)
	}
}

func TestLoopbackNotProxied(t *testing.T) {
	e, _ := newEngine(t, testConfig(), fixedRes{p: rules.Process{PID: 1, Name: "curl.exe"}, ok: true}, &fakeDial{}, nil)
	pkt, err := packet.BuildTCP(packet.V4(10, 0, 0, 1, 50), packet.V4(127, 0, 0, 1, 80), 0x02)
	if err != nil {
		t.Fatal(err)
	}
	if e.HandlePacket(pkt, Meta{}, true).Action != ActionPass {
		t.Fatal("loopback should pass")
	}
}

func TestHTTPUDPBlockedAndDNS(t *testing.T) {
	px, err := testkit.ListenHTTP("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer px.Close()
	cfg := testConfig()
	cfg.Proxies[1].Address = px.Addr
	cfg.Rules = []config.Rule{{Process: "browser.exe", Action: "proxy", Proxy: "web"}}
	inj := &memInj{}
	e, logs := newEngine(t, cfg, fixedRes{p: rules.Process{PID: 3, Name: "browser.exe", Path: `C:\Apps\browser.exe`}, ok: true}, dialer.Net{}, inj)

	quic, err := packet.BuildUDP(packet.V4(10, 0, 0, 4, 4444), packet.V4(1, 2, 3, 4, 443), []byte("quic"))
	if err != nil {
		t.Fatal(err)
	}
	res := e.HandlePacket(quic, Meta{}, true)
	if res.Action != ActionDrop {
		t.Fatalf("quic %+v", res.Action)
	}
	again, _ := packet.BuildUDP(packet.V4(10, 0, 0, 4, 4444), packet.V4(1, 2, 3, 4, 443), []byte("quic"))
	if e.HandlePacket(again, Meta{}, true).Action != ActionDrop {
		t.Fatal("repeat block")
	}

	query := []byte{0x12, 0x34, 0x01, 0x00}
	dns, err := packet.BuildUDP(packet.V4(10, 0, 0, 4, 5353), packet.V4(192, 168, 1, 1, 53), query)
	if err != nil {
		t.Fatal(err)
	}
	res = e.HandlePacket(dns, Meta{IfIdx: 4}, true)
	if res.Action != ActionUDP || res.UDP == nil {
		t.Fatalf("dns %+v", res)
	}
	if res.UDP.RelayDst.String() != "1.1.1.1:53" || res.UDP.OrigDst.String() != "192.168.1.1:53" {
		t.Fatalf("dst relay=%s orig=%s", res.UDP.RelayDst, res.UDP.OrigDst)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.ForwardUDP(ctx, *res.UDP); err != nil {
		t.Fatal(err)
	}
	// DNS over CONNECT runs in the background.
	for wait := time.Now().Add(3 * time.Second); inj.count() == 0 && time.Now().Before(wait); {
		time.Sleep(10 * time.Millisecond)
	}
	if inj.count() != 1 {
		t.Fatalf("injected %d", inj.count())
	}
	raw := inj.packet(0)
	var got packet.Header
	if err := packet.Parse(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Src.String() != "192.168.1.1:53" || got.Dst.Port != 5353 || got.PayloadLen < 3 || raw[got.PayloadOff+2]&0x80 == 0 {
		t.Fatalf("injected header %+v payload %x", got, raw[got.PayloadOff:])
	}
	_ = logs
}

func TestSOCKSUDP(t *testing.T) {
	socks, err := testkit.ListenSOCKS("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer socks.Close()
	cfg := testConfig()
	cfg.Proxies[0].Address = socks.Addr
	cfg.DNS.Mode = "original"
	inj := &memInj{}
	e, _ := newEngine(t, cfg, fixedRes{p: rules.Process{Name: "curl.exe", PID: 5}, ok: true}, dialer.Net{}, inj)
	payload := []byte{0xde, 0xad}
	pkt, err := packet.BuildUDP(packet.V4(10, 9, 8, 7, 1900), packet.V4(8, 8, 8, 8, 53), payload)
	if err != nil {
		t.Fatal(err)
	}
	res := e.HandlePacket(pkt, Meta{IfIdx: 3, SubIfIdx: 1}, true)
	if res.Action != ActionUDP {
		t.Fatal(res.Action)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.ForwardUDP(ctx, *res.UDP); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for inj.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if inj.count() == 0 {
		t.Fatal("no udp reply")
	}
	raw := inj.packet(0)
	var h packet.Header
	if err := packet.Parse(raw, &h); err != nil {
		t.Fatal(err)
	}
	if h.Src.String() != "8.8.8.8:53" || h.Dst.String() != "10.9.8.7:1900" {
		t.Fatalf("reply %s -> %s", h.Src, h.Dst)
	}
	if string(raw[h.PayloadOff:h.PayloadOff+h.PayloadLen]) != string(payload) {
		t.Fatal("payload mismatch")
	}
	if err := packet.ValidChecksums(raw); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateBypass(t *testing.T) {
	cfg := testConfig()
	cfg.BypassPrivate = true
	e, _ := newEngine(t, cfg, fixedRes{p: rules.Process{Name: "curl.exe", PID: 1}, ok: true}, &fakeDial{}, nil)
	pkt, err := packet.BuildTCP(packet.V4(10, 0, 0, 5, 1000), packet.V4(192, 168, 0, 1, 445), 0x02)
	if err != nil {
		t.Fatal(err)
	}
	if e.HandlePacket(pkt, Meta{}, true).Action != ActionPass {
		t.Fatal("private dest should bypass")
	}
	// DNS to the router is still the app's DNS: it goes through the proxy.
	dns, err := packet.BuildUDP(packet.V4(10, 0, 0, 5, 1001), packet.V4(192, 168, 0, 1, 53), []byte{0, 1})
	if err != nil {
		t.Fatal(err)
	}
	if got := e.HandlePacket(dns, Meta{}, true).Action; got != ActionUDP {
		t.Fatalf("DNS to a private resolver: action %v, want it proxied", got)
	}
}

func TestBlockDropsTCPAndUDP(t *testing.T) {
	cfg := testConfig()
	cfg.Rules = []config.Rule{{Process: "telemetry.exe", Action: "block"}}
	e, logs := newEngine(t, cfg, fixedRes{p: rules.Process{PID: 4, Name: "telemetry.exe"}, ok: true}, &fakeDial{}, nil)
	syn, err := packet.BuildTCP(packet.V4(10, 0, 0, 8, 4000), packet.V4(1, 2, 3, 4, 443), 0x02)
	if err != nil {
		t.Fatal(err)
	}
	raw := append([]byte(nil), syn...)
	if e.HandlePacket(syn, Meta{}, true).Action != ActionDrop {
		t.Fatal("syn should be dropped")
	}
	if string(syn) != string(raw) {
		t.Fatal("blocked packet was rewritten")
	}
	data, err := packet.BuildTCP(packet.V4(10, 0, 0, 8, 4000), packet.V4(1, 2, 3, 4, 443), 0x18)
	if err != nil {
		t.Fatal(err)
	}
	if e.HandlePacket(data, Meta{}, true).Action != ActionDrop {
		t.Fatal("payload should stay dropped")
	}
	udp, err := packet.BuildUDP(packet.V4(10, 0, 0, 8, 4001), packet.V4(1, 2, 3, 4, 443), []byte("q"))
	if err != nil {
		t.Fatal(err)
	}
	if e.HandlePacket(udp, Meta{}, true).Action != ActionDrop {
		t.Fatal("udp should be dropped")
	}
	again, _ := packet.BuildUDP(packet.V4(10, 0, 0, 8, 4001), packet.V4(1, 2, 3, 4, 443), []byte("q"))
	before := len(logs.Snapshot())
	if e.HandlePacket(again, Meta{}, true).Action != ActionDrop {
		t.Fatal("repeat udp")
	}
	if len(logs.Snapshot()) != before {
		t.Fatal("repeat udp was logged again")
	}
	n := 0
	for _, ev := range logs.Snapshot() {
		if ev.Status == "blocked" && ev.Process == "telemetry.exe" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("blocked events = %d, log %v", n, logs.Snapshot())
	}
}

func TestDirectCacheAges(t *testing.T) {
	e, _ := newEngine(t, testConfig(), fixedRes{p: rules.Process{PID: 7, Name: "other.exe"}, ok: true}, &fakeDial{}, nil)
	start := time.Unix(1000, 0)
	for i := 0; i < 50; i++ {
		pkt, _ := packet.BuildTCP(packet.V4(10, 0, 0, 2, uint16(3000+i)), packet.V4(1, 2, 3, 4, 80), 0x02)
		if res := e.HandlePacket(pkt, Meta{}, true); res.Action != ActionPass {
			t.Fatalf("unmatched app should pass, got %v", res.Action)
		}
	}
	if n := e.directTCP.len(); n != 50 {
		t.Fatalf("direct cache %d", n)
	}
	e.sweep(start)
	e.sweep(start.Add(cacheAge))
	e.sweep(start.Add(2 * cacheAge))
	if n := e.directTCP.len(); n != 0 {
		t.Fatalf("idle direct entries kept: %d", n)
	}
}

type failUDP struct {
	fakeDial
	mu    sync.Mutex
	tries int
}

func (f *failUDP) DialUDP(context.Context, config.Proxy) (dialer.Session, error) {
	f.mu.Lock()
	f.tries++
	f.mu.Unlock()
	return nil, io.ErrUnexpectedEOF
}

func TestUDPDialBacksOff(t *testing.T) {
	fd := &failUDP{}
	cfg := testConfig()
	cfg.DNS.Mode = "original"
	e, logs := newEngine(t, cfg, fixedRes{p: rules.Process{Name: "curl.exe", PID: 5}, ok: true}, fd, nil)
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		pkt, _ := packet.BuildUDP(packet.V4(10, 9, 8, 7, 1900), packet.V4(9, 9, 9, 9, 3478), []byte{1})
		res := e.HandlePacket(pkt, Meta{}, true)
		if res.Action != ActionUDP {
			t.Fatal(res.Action)
		}
		_ = e.ForwardUDP(ctx, *res.UDP)
	}
	if fd.tries != 1 {
		t.Fatalf("dialed %d times while the proxy was down", fd.tries)
	}
	errs := 0
	for _, ev := range logs.Snapshot() {
		if ev.Status == "error" {
			errs++
		}
	}
	if errs != 1 {
		t.Fatalf("%d error lines", errs)
	}
}

func TestChildProcessIsProxied(t *testing.T) {
	child := rules.Process{PID: 77, Name: "helper.exe", Parents: []rules.Process{{PID: 76, Name: "curl.exe"}}}
	e, _ := newEngine(t, testConfig(), fixedRes{p: child, ok: true}, &fakeDial{}, nil)
	pkt, _ := packet.BuildTCP(packet.V4(10, 0, 0, 2, 3100), packet.V4(1, 2, 3, 4, 443), 0x02)
	res := e.HandlePacket(pkt, Meta{}, true)
	if res.Action != ActionModified {
		t.Fatalf("child of a proxied app went %v", res.Action)
	}
	e.mu.Lock()
	flow := e.byClient[packet.V4(10, 0, 0, 2, 3100)]
	e.mu.Unlock()
	if flow == nil || flow.proxy.Name != "socks" || flow.parent != "curl.exe" {
		t.Fatalf("flow %+v", flow)
	}
}

func TestKillSwitchResetsExistingConnection(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch = true
	inj := &memInj{}
	e, _ := newEngine(t, cfg, fixedRes{p: rules.Process{PID: 5, Name: "curl.exe"}, ok: true}, &fakeDial{}, inj)
	data, _ := packet.BuildTCP(packet.V4(10, 0, 0, 2, 3000), packet.V4(1, 2, 3, 4, 443), 0x18)
	if res := e.HandlePacket(data, Meta{}, true); res.Action != ActionDrop {
		t.Fatalf("pre-existing proxied connection went %v", res.Action)
	}
	if inj.count() != 1 {
		t.Fatalf("no reset injected")
	}
	var h packet.Header
	if err := packet.Parse(inj.packet(0), &h); err != nil || !h.RST || h.Dst.String() != "10.0.0.2:3000" {
		t.Fatalf("reset %+v %v", h, err)
	}
	again, _ := packet.BuildTCP(packet.V4(10, 0, 0, 2, 3000), packet.V4(1, 2, 3, 4, 443), 0x18)
	if res := e.HandlePacket(again, Meta{}, true); res.Action != ActionDrop {
		t.Fatal("second packet passed")
	}
}

func TestKillSwitchBlocksUnsupportedUDP(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch = true
	cfg.UDPUnsupported = "direct"
	e, _ := newEngine(t, cfg, fixedRes{p: rules.Process{PID: 3, Name: "browser.exe", Path: `C:\Apps\browser.exe`}, ok: true}, &fakeDial{}, nil)
	quic, _ := packet.BuildUDP(packet.V4(10, 0, 0, 4, 4444), packet.V4(1, 2, 3, 4, 443), []byte("quic"))
	if res := e.HandlePacket(quic, Meta{}, true); res.Action != ActionDrop {
		t.Fatalf("udp leaked past an http proxy: %v", res.Action)
	}
}

func TestLaterFragmentsOfDroppedDatagramAreDropped(t *testing.T) {
	cfg := testConfig()
	e, _ := newEngine(t, cfg, fixedRes{p: rules.Process{PID: 3, Name: "browser.exe", Path: `C:\Apps\browser.exe`}, ok: true}, &fakeDial{}, nil)
	first, _ := packet.BuildUDP(packet.V4(10, 0, 0, 4, 4444), packet.V4(1, 2, 3, 4, 443), make([]byte, 64))
	first[4], first[5] = 0x12, 0x34 // identification
	first[6] = 0x20                 // more fragments
	if res := e.HandlePacket(first, Meta{}, true); res.Action != ActionDrop {
		t.Fatalf("first fragment %v", res.Action)
	}
	rest, _ := packet.BuildUDP(packet.V4(10, 0, 0, 4, 1), packet.V4(1, 2, 3, 4, 1), make([]byte, 64))
	rest[4], rest[5] = 0x12, 0x34
	rest[6], rest[7] = 0x00, 0x09 // offset 72 bytes, last fragment
	if res := e.HandlePacket(rest, Meta{}, true); res.Action != ActionDrop {
		t.Fatalf("later fragment leaked: %v", res.Action)
	}
	other, _ := packet.BuildUDP(packet.V4(10, 0, 0, 4, 1), packet.V4(1, 2, 3, 4, 1), make([]byte, 64))
	other[4], other[5] = 0x99, 0x99
	other[6], other[7] = 0x00, 0x09
	if res := e.HandlePacket(other, Meta{}, true); res.Action != ActionPass {
		t.Fatalf("unrelated fragment %v", res.Action)
	}
}

func TestPerRuleKillSwitchAndTCPOnly(t *testing.T) {
	off := false
	cfg := testConfig()
	cfg.KillSwitch = true
	cfg.Rules[0].KillSwitch = &off // curl.exe opts out
	cfg.Rules[2].TCPOnly = true    // browser.exe
	inj := &memInj{}
	e, _ := newEngine(t, cfg, fixedRes{p: rules.Process{PID: 5, Name: "curl.exe"}, ok: true}, &fakeDial{}, inj)
	data, _ := packet.BuildTCP(packet.V4(10, 0, 0, 2, 3000), packet.V4(1, 2, 3, 4, 443), 0x18)
	if res := e.HandlePacket(data, Meta{}, true); res.Action != ActionPass || inj.count() != 0 {
		t.Fatalf("rule without kill switch was reset: %v", res.Action)
	}

	b, _ := newEngine(t, cfg, fixedRes{p: rules.Process{PID: 3, Name: "browser.exe", Path: `C:\Apps\browser.exe`}, ok: true}, &fakeDial{}, nil)
	quic, _ := packet.BuildUDP(packet.V4(10, 0, 0, 4, 4444), packet.V4(1, 2, 3, 4, 443), []byte("q"))
	if res := b.HandlePacket(quic, Meta{}, true); res.Action != ActionDrop {
		t.Fatalf("tcp-only rule let udp through: %v", res.Action)
	}
	dns, _ := packet.BuildUDP(packet.V4(10, 0, 0, 4, 5353), packet.V4(1, 1, 1, 1, 53), []byte{1, 2, 3, 4})
	if res := b.HandlePacket(dns, Meta{}, true); res.Action != ActionUDP {
		t.Fatalf("tcp-only must still proxy dns: %v", res.Action)
	}
}

func TestRuleStatsCountFlows(t *testing.T) {
	e, _ := newEngine(t, testConfig(), fixedRes{p: rules.Process{PID: 5, Name: "curl.exe"}, ok: true}, &fakeDial{}, nil)
	for i := 0; i < 3; i++ {
		syn, _ := packet.BuildTCP(packet.V4(10, 0, 0, 2, uint16(3200+i)), packet.V4(1, 2, 3, 4, 443), 0x02)
		e.HandlePacket(syn, Meta{}, true)
	}
	st := e.RuleStats()["curl.exe"]
	if st.Flows != 3 {
		t.Fatalf("flows %d (%+v)", st.Flows, e.RuleStats())
	}
	e.closeAll()
	if st := e.RuleStats()["curl.exe"]; st.Flows != 0 {
		t.Fatalf("flows after close %d", st.Flows)
	}
}

// A proxy given as an IP literal is never looked up in DNS: the lookup
// would go to the system resolver outside the tunnel.
func TestRefreshBypassSkipsDNSForIPLiterals(t *testing.T) {
	var looked []string
	old := lookupIP
	lookupIP = func(_ context.Context, _, host string) ([]net.IP, error) {
		looked = append(looked, host)
		return []net.IP{net.ParseIP("198.51.100.7")}, nil
	}
	t.Cleanup(func() { lookupIP = old })
	cfg := config.Default()
	cfg.Proxies = []config.Proxy{
		{Name: "v4", Type: "socks5", Address: "203.0.113.10:1080"},
		{Name: "v6", Type: "socks5", Address: "[2001:db8::1]:1080"},
		{Name: "named", Type: "socks5", Address: "proxy.example.com:1080"},
	}
	e, _ := newEngine(t, cfg, nil, nil, nil)
	e.RefreshBypass(context.Background())
	if len(looked) != 1 || looked[0] != "proxy.example.com" {
		t.Fatalf("looked up %v, want only proxy.example.com", looked)
	}
	for _, ip := range []string{"203.0.113.10", "2001:db8::1", "198.51.100.7"} {
		if !e.proxyServer(packet.FromIP(net.ParseIP(ip), 1080)) {
			t.Errorf("%s:1080 not in the set of proxy servers", ip)
		}
		if e.proxyServer(packet.FromIP(net.ParseIP(ip), 443)) {
			t.Errorf("%s:443 counts as a proxy server", ip)
		}
	}
}

// switchRes finds the process until the test says it exited.
type switchRes struct {
	mu sync.Mutex
	p  rules.Process
	ok bool
}

func (s *switchRes) Lookup(uint8, packet.Addr) (rules.Process, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.p, s.ok
}

func (s *switchRes) set(ok bool) { s.mu.Lock(); s.ok = ok; s.mu.Unlock() }

// A proxied connection's last packets (FIN, keepalive, retransmits) come
// after the relay closed, often after the app exited. They must not go out
// directly with the app's address, also not after Apply.
func TestLatePacketsOfClosedFlowAreDropped(t *testing.T) {
	res := &switchRes{p: rules.Process{PID: 5, Name: "curl.exe"}, ok: true}
	e, _ := newEngine(t, testConfig(), res, &fakeDial{}, nil)
	app, dst := packet.V4(10, 0, 0, 2, 3200), packet.V4(1, 2, 3, 4, 443)
	syn, _ := packet.BuildTCP(app, dst, 0x02)
	if r := e.HandlePacket(syn, Meta{}, true); r.Action != ActionModified {
		t.Fatalf("SYN went %v", r.Action)
	}
	e.mu.Lock()
	flow := e.byClient[app]
	e.mu.Unlock()
	if flow == nil {
		t.Fatal("no flow")
	}
	e.finishTCP(flow)
	// For a short grace the mapping stays, so the last FIN and ACKs of both
	// ends are still translated and the app's socket can close cleanly.
	fin, _ := packet.BuildTCP(app, dst, 0x11)
	if r := e.HandlePacket(fin, Meta{}, true); r.Action != ActionModified {
		t.Fatalf("FIN right after the relay closed went %v, want it translated to the relay", r.Action)
	}
	if e.Active() != 0 {
		t.Fatalf("an ended flow still counts as active: %d", e.Active())
	}
	e.sweep(time.Now().Add(tcpCloseGrace + time.Second))
	res.set(false)                                         // the app has exited
	for _, flags := range []byte{0x11, 0x10, 0x18, 0x04} { // FIN+ACK, ACK, PSH+ACK, RST
		pkt, _ := packet.BuildTCP(app, dst, flags)
		if r := e.HandlePacket(pkt, Meta{}, true); r.Action != ActionDrop {
			t.Fatalf("late packet %#x of a closed proxied flow went %v", flags, r.Action)
		}
	}
	again := testConfig()
	again.ApplyDefaults()
	if err := e.Apply(again); err != nil {
		t.Fatal(err)
	}
	ack, _ := packet.BuildTCP(app, dst, 0x10)
	if r := e.HandlePacket(ack, Meta{}, true); r.Action != ActionDrop {
		t.Fatalf("after Apply a late packet went %v", r.Action)
	}
	// A new connection from the same port is decided afresh.
	res.set(true)
	syn2, _ := packet.BuildTCP(app, dst, 0x02)
	if r := e.HandlePacket(syn2, Meta{}, true); r.Action != ActionModified {
		t.Fatalf("new SYN on a reused port went %v", r.Action)
	}
}
