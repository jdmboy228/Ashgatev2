package engine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"ashgate/internal/config"
	"ashgate/internal/dialer"
	"ashgate/internal/packet"
	"ashgate/internal/rules"
)

// scriptSession returns its replies in order, then io.EOF.
type scriptSession struct {
	mu      sync.Mutex
	replies [][]byte
}

func (s *scriptSession) Send(context.Context, *net.UDPAddr, []byte) error { return nil }

func (s *scriptSession) Recv(context.Context) (*net.UDPAddr, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.replies) == 0 {
		return nil, nil, io.EOF
	}
	p := s.replies[0]
	s.replies = s.replies[1:]
	return nil, p, nil
}

func (s *scriptSession) Close() error { return nil }

// flakyInj fails its first injection.
type flakyInj struct {
	memInj
	calls int
}

func (f *flakyInj) InjectInbound(pkt []byte, a, b uint32) error {
	f.calls++
	if f.calls == 1 {
		return errors.New("host unreachable")
	}
	return f.memInj.InjectInbound(pkt, a, b)
}

func TestReadUDPSurvivesInjectErrors(t *testing.T) {
	inj := &flakyInj{}
	e, _ := newEngine(t, testConfig(), fixedRes{}, &fakeDial{}, inj)
	flow := &udpFlow{
		app:   packet.V4(10, 0, 0, 2, 5000),
		orig:  packet.V4(9, 9, 9, 9, 3478),
		proxy: config.Proxy{Name: "socks"},
	}
	big := make([]byte, 65001) // BuildUDP refuses it
	sess := &scriptSession{replies: [][]byte{big, []byte("lost"), []byte("ok")}}
	e.readUDP(flow, sess)
	if inj.calls != 2 || inj.count() != 1 {
		t.Fatalf("%d injections, %d delivered", inj.calls, inj.count())
	}
	var h packet.Header
	got := inj.packet(0)
	if err := packet.Parse(got, &h); err != nil || !bytes.Equal(got[h.PayloadOff:h.PayloadOff+h.PayloadLen], []byte("ok")) {
		t.Fatalf("delivered %x, %v", got, err)
	}
	if want := int64(len(big) + len("lost") + len("ok")); flow.down.Load() != want || e.bytesDown.Load() != want {
		t.Fatalf("down %d, engine %d, want %d", flow.down.Load(), e.bytesDown.Load(), want)
	}
	if !flow.closed {
		t.Fatal("flow not retired after the session ended")
	}
}

// slowDial hands out a session whose Send blocks until release closes, and
// can block the dial itself.
type slowDial struct {
	fakeDial
	blockDial bool
	release   chan struct{}
	sending   chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
}

func (d *slowDial) DialUDP(context.Context, config.Proxy) (dialer.Session, error) {
	if d.blockDial {
		d.sending <- struct{}{}
		<-d.release
	}
	return &slowSession{d: d}, nil
}

type slowSession struct{ d *slowDial }

func (s *slowSession) Send(context.Context, *net.UDPAddr, []byte) error {
	s.d.sending <- struct{}{}
	<-s.d.release
	return nil
}

func (s *slowSession) Recv(context.Context) (*net.UDPAddr, []byte, error) {
	<-s.d.closed
	return nil, nil, io.EOF
}

func (s *slowSession) Close() error {
	s.d.closeOnce.Do(func() { close(s.d.closed) })
	return nil
}

// A session or dial stuck in I/O must not make the Janitor or Stop wait.
func TestUDPSweepAndCloseAllDoNotWaitForIO(t *testing.T) {
	for _, blockDial := range []bool{false, true} {
		d := &slowDial{blockDial: blockDial, release: make(chan struct{}), sending: make(chan struct{}, 2), closed: make(chan struct{})}
		cfg := testConfig()
		cfg.DNS.Mode = "original"
		e, _ := newEngine(t, cfg, fixedRes{p: rules.Process{Name: "curl.exe", PID: 5}, ok: true}, d, nil)
		pkt, _ := packet.BuildUDP(packet.V4(10, 9, 8, 7, 1900), packet.V4(9, 9, 9, 9, 3478), []byte{1})
		res := e.HandlePacket(pkt, Meta{}, true)
		if res.Action != ActionUDP {
			t.Fatal(res.Action)
		}
		fwd := make(chan struct{})
		go func() {
			defer close(fwd)
			_ = e.ForwardUDP(context.Background(), *res.UDP)
		}()
		<-d.sending // the dial or the send is now stuck
		for name, fn := range map[string]func(){
			"sweep":    func() { e.sweep(e.now().Add(time.Hour)) },
			"closeAll": e.closeAll,
		} {
			done := make(chan struct{})
			go func() { fn(); close(done) }()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatalf("blockDial=%v: %s waits for a stuck send", blockDial, name)
			}
		}
		close(d.release)
		<-fwd
		if blockDial {
			// The session that came after the flow was retired is closed.
			select {
			case <-d.closed:
			case <-time.After(3 * time.Second):
				t.Fatal("session dialed for a retired flow stays open")
			}
		}
	}
}

type waitDial struct {
	fakeDial
	sess *waitSession
}

func (d *waitDial) DialUDP(context.Context, config.Proxy) (dialer.Session, error) {
	return d.sess, nil
}

type waitSession struct {
	closed        chan struct{}
	closeOnce     sync.Once
	recvUnblocked chan struct{}
	allowExit     chan struct{}
}

func (s *waitSession) Send(context.Context, *net.UDPAddr, []byte) error { return nil }

func (s *waitSession) Recv(context.Context) (*net.UDPAddr, []byte, error) {
	<-s.closed
	close(s.recvUnblocked)
	<-s.allowExit
	return nil, nil, io.EOF
}

func (s *waitSession) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

func TestEngineWaitWaitsForReadUDP(t *testing.T) {
	ws := &waitSession{
		closed:        make(chan struct{}),
		recvUnblocked: make(chan struct{}),
		allowExit:     make(chan struct{}),
	}
	cfg := testConfig()
	cfg.DNS.Mode = "original"
	e, _ := newEngine(t, cfg, fixedRes{p: rules.Process{Name: "curl.exe", PID: 5}, ok: true}, &waitDial{sess: ws}, nil)
	pkt, _ := packet.BuildUDP(packet.V4(10, 9, 8, 7, 1901), packet.V4(9, 9, 9, 9, 3478), []byte{1})
	res := e.HandlePacket(pkt, Meta{}, true)
	if res.Action != ActionUDP {
		t.Fatal(res.Action)
	}
	if err := e.ForwardUDP(context.Background(), *res.UDP); err != nil {
		t.Fatal(err)
	}
	e.closeAll()
	<-ws.recvUnblocked
	waitDone := make(chan struct{})
	go func() {
		e.Wait()
		close(waitDone)
	}()
	select {
	case <-waitDone:
		t.Fatal("Engine.Wait returned before readUDP exited")
	case <-time.After(30 * time.Millisecond):
	}
	close(ws.allowExit)
	select {
	case <-waitDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Engine.Wait did not return after readUDP exited")
	}
}

type dnsPipeDial struct {
	fakeDial
	dialed chan string
}

func (d *dnsPipeDial) DialTCP(_ context.Context, p config.Proxy, host string, port uint16) (net.Conn, error) {
	d.dialed <- p.Address + "->" + net.JoinHostPort(host, strconv.Itoa(int(port)))
	near, far := net.Pipe()
	go func() {
		defer far.Close()
		buf := make([]byte, 512)
		n, err := far.Read(buf)
		if err != nil || n < 5 {
			return
		}
		reply := append([]byte(nil), buf[:n]...)
		reply[4] |= 0x80
		_, _ = far.Write(reply)
	}()
	return near, nil
}

func TestApplyInvalidatesSystemDNSOnProxyOrServerChange(t *testing.T) {
	cfg := testConfig()
	dd := &dnsPipeDial{dialed: make(chan string, 8)}
	inj := &memInj{}
	e, _ := newEngine(t, cfg, fixedRes{p: rules.Process{PID: 900, Name: "svchost.exe"}, ok: true}, dd, inj)
	defer func() {
		e.closeAll()
		e.Wait()
	}()

	src := packet.V4(10, 0, 0, 2, 55001)
	router := packet.V4(192, 168, 1, 1, 53)
	sendQuery := func(name string) Result {
		q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
		for _, part := range bytes.Split([]byte(name), []byte(".")) {
			q = append(q, byte(len(part)))
			q = append(q, part...)
		}
		q = append(q, 0, 0, 1, 0, 1)
		pkt, err := packet.BuildUDP(src, router, q)
		if err != nil {
			t.Fatal(err)
		}
		return e.HandlePacket(pkt, Meta{}, true)
	}

	r1 := sendQuery("one.example.com")
	if r1.Action != ActionUDP || r1.UDP == nil {
		t.Fatalf("step 1 action = %v", r1.Action)
	}
	if err := e.ForwardUDP(context.Background(), *r1.UDP); err != nil {
		t.Fatal(err)
	}
	if got := <-dd.dialed; got != "127.0.0.1:1080->1.1.1.1:53" {
		t.Fatalf("step 1 dialed %q", got)
	}

	// Change proxy address: active system DNS flow must be retired immediately.
	cfg2 := testConfig()
	cfg2.Proxies[0].Address = "127.0.0.1:1081"
	cfg2.ApplyDefaults()
	if err := e.Apply(cfg2); err != nil {
		t.Fatal(err)
	}
	if e.Active() != 0 {
		t.Fatalf("active flows after proxy change = %d, want 0", e.Active())
	}
	r2 := sendQuery("two.example.com")
	if r2.Action != ActionUDP || r2.UDP == nil {
		t.Fatalf("step 2 action = %v", r2.Action)
	}
	if err := e.ForwardUDP(context.Background(), *r2.UDP); err != nil {
		t.Fatal(err)
	}
	if got := <-dd.dialed; got != "127.0.0.1:1081->1.1.1.1:53" {
		t.Fatalf("step 2 dialed %q, want updated proxy address", got)
	}

	// Change DNS servers: active flow must be retired and switch to 8.8.8.8:53.
	cfg3 := testConfig()
	cfg3.Proxies[0].Address = "127.0.0.1:1081"
	cfg3.DNS.Servers = []string{"8.8.8.8:53"}
	cfg3.ApplyDefaults()
	if err := e.Apply(cfg3); err != nil {
		t.Fatal(err)
	}
	if e.Active() != 0 {
		t.Fatalf("active flows after DNS server change = %d, want 0", e.Active())
	}
	r3 := sendQuery("three.example.com")
	if r3.Action != ActionUDP || r3.UDP == nil || r3.UDP.RelayDst.String() != "8.8.8.8:53" {
		t.Fatalf("step 3 result = %+v", r3)
	}
	if err := e.ForwardUDP(context.Background(), *r3.UDP); err != nil {
		t.Fatal(err)
	}
	if got := <-dd.dialed; got != "127.0.0.1:1081->8.8.8.8:53" {
		t.Fatalf("step 3 dialed %q", got)
	}

	// Switch SystemResolver to direct: active flow must retire and next query pass.
	cfg4 := testConfig()
	cfg4.Proxies[0].Address = "127.0.0.1:1081"
	cfg4.DNS.SystemResolver = "direct"
	cfg4.ApplyDefaults()
	if err := e.Apply(cfg4); err != nil {
		t.Fatal(err)
	}
	if e.Active() != 0 {
		t.Fatalf("active flows after SystemResolver=direct = %d, want 0", e.Active())
	}
	if r4 := sendQuery("four.example.com"); r4.Action != ActionPass {
		t.Fatalf("step 4 action = %v, want ActionPass", r4.Action)
	}
}

type trackSession struct {
	closed    chan struct{}
	closeOnce sync.Once
	sent      int
	mu        sync.Mutex
}

func newTrackSession() *trackSession {
	return &trackSession{closed: make(chan struct{})}
}

func (s *trackSession) Send(context.Context, *net.UDPAddr, []byte) error {
	s.mu.Lock()
	s.sent++
	s.mu.Unlock()
	return nil
}

func (s *trackSession) Recv(context.Context) (*net.UDPAddr, []byte, error) {
	<-s.closed
	return nil, nil, io.EOF
}

func (s *trackSession) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

type vlessFailoverDial struct {
	fakeDial
	mu     sync.Mutex
	dialed []string
	sess   *trackSession
}

func (d *vlessFailoverDial) DialUDP(_ context.Context, p config.Proxy) (dialer.Session, error) {
	d.mu.Lock()
	d.dialed = append(d.dialed, p.Local)
	d.mu.Unlock()
	if p.Local == "127.0.0.1:50001" {
		return nil, errors.New("bridge down")
	}
	return d.sess, nil
}

func TestApplyInvalidatesFailedVLESSUDPOnFailover(t *testing.T) {
	now := time.Unix(2000, 0)
	vlessConfig := func(local string) *config.Config {
		cfg := &config.Config{
			Proxies: []config.Proxy{{
				Name:  "sub",
				Type:  "vless",
				Link:  "vless://b7e2c1a0-4f3a-4c2b-9a11-111111111111@203.0.113.10:443?encryption=none&type=tcp#a",
				Local: local,
			}},
			Rules: []config.Rule{{Process: "curl.exe", Action: "proxy", Proxy: "sub"}},
			DNS:   config.DNS{Mode: "original"},
		}
		cfg.ApplyDefaults()
		return cfg
	}

	fd := &vlessFailoverDial{sess: newTrackSession()}
	e, err := New(vlessConfig("127.0.0.1:50001"), Options{
		Resolver: fixedRes{p: rules.Process{PID: 5, Name: "curl.exe"}, ok: true},
		Alloc:    &seqAlloc{},
		Dialer:   fd,
		Now:      func() time.Time { return now },
		SkipSelf: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		e.closeAll()
		e.Wait()
	}()

	src, dst := packet.V4(10, 0, 0, 5, 55010), packet.V4(9, 9, 9, 9, 3478)
	pkt, _ := packet.BuildUDP(src, dst, []byte("hello"))
	r1 := e.HandlePacket(pkt, Meta{}, true)
	if r1.Action != ActionUDP {
		t.Fatal(r1.Action)
	}
	if err := e.ForwardUDP(context.Background(), *r1.UDP); err == nil {
		t.Fatal("expected initial dial failure")
	}

	// Within udpRetry (3 s), failover switches Local to 127.0.0.1:50002.
	now = now.Add(100 * time.Millisecond)
	if err := e.Apply(vlessConfig("127.0.0.1:50002")); err != nil {
		t.Fatal(err)
	}
	pkt2, _ := packet.BuildUDP(src, dst, []byte("after-failover"))
	r2 := e.HandlePacket(pkt2, Meta{}, true)
	if r2.Action != ActionUDP {
		t.Fatalf("after failover action = %v", r2.Action)
	}
	if err := e.ForwardUDP(context.Background(), *r2.UDP); err != nil {
		t.Fatalf("after failover ForwardUDP failed: %v", err)
	}
	fd.mu.Lock()
	defer fd.mu.Unlock()
	if len(fd.dialed) != 2 || fd.dialed[0] != "127.0.0.1:50001" || fd.dialed[1] != "127.0.0.1:50002" {
		t.Fatalf("dialed = %v", fd.dialed)
	}
}

type procMapRes struct {
	byPort map[uint16]rules.Process
}

func (r *procMapRes) Lookup(_ uint8, src packet.Addr) (rules.Process, bool) {
	p, ok := r.byPort[src.Port]
	return p, ok
}

type mapDial struct {
	fakeDial
	mu       sync.Mutex
	sessions map[string]*trackSession
	dials    map[string]int
}

func (d *mapDial) DialUDP(_ context.Context, p config.Proxy) (dialer.Session, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dials[p.Name]++
	return d.sessions[p.Name], nil
}

func TestApplyInvalidatesChangedUDPRuleAndKeepsUnchanged(t *testing.T) {
	cfg := &config.Config{
		Proxies: []config.Proxy{
			{Name: "socks1", Type: "socks5", Address: "127.0.0.1:1080"},
			{Name: "socks2", Type: "socks5", Address: "127.0.0.1:1082"},
		},
		Rules: []config.Rule{
			{Process: "curl.exe", Action: "proxy", Proxy: "socks1"},
			{Process: "app2.exe", Action: "proxy", Proxy: "socks2"},
		},
		DNS: config.DNS{Mode: "original"},
	}
	s1, s2 := newTrackSession(), newTrackSession()
	md := &mapDial{
		sessions: map[string]*trackSession{"socks1": s1, "socks2": s2},
		dials:    map[string]int{},
	}
	res := &procMapRes{byPort: map[uint16]rules.Process{
		55020: {PID: 5, Name: "curl.exe"},
		55021: {PID: 6, Name: "app2.exe"},
	}}
	e, _ := newEngine(t, cfg, res, md, nil)
	defer func() {
		e.closeAll()
		e.Wait()
	}()

	p1, _ := packet.BuildUDP(packet.V4(10, 0, 0, 5, 55020), packet.V4(9, 9, 9, 9, 3478), []byte("a"))
	p2, _ := packet.BuildUDP(packet.V4(10, 0, 0, 5, 55021), packet.V4(9, 9, 9, 9, 3479), []byte("b"))
	r1 := e.HandlePacket(p1, Meta{}, true)
	r2 := e.HandlePacket(p2, Meta{}, true)
	if r1.Action != ActionUDP || r2.Action != ActionUDP {
		t.Fatalf("initial actions: %v %v", r1.Action, r2.Action)
	}
	if err := e.ForwardUDP(context.Background(), *r1.UDP); err != nil {
		t.Fatal(err)
	}
	if err := e.ForwardUDP(context.Background(), *r2.UDP); err != nil {
		t.Fatal(err)
	}
	if e.Active() != 2 {
		t.Fatalf("active = %d, want 2", e.Active())
	}

	// Change curl.exe to block; keep app2.exe unchanged.
	cfg2 := &config.Config{
		Proxies: cfg.Proxies,
		Rules: []config.Rule{
			{Process: "curl.exe", Action: "block"},
			{Process: "app2.exe", Action: "proxy", Proxy: "socks2"},
		},
		DNS: config.DNS{Mode: "original"},
	}
	cfg2.ApplyDefaults()
	if err := e.Apply(cfg2); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s1.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("curl.exe UDP session was not closed on rule change to block")
	}
	select {
	case <-s2.closed:
		t.Fatal("unchanged app2.exe UDP session was closed")
	default:
	}
	if e.Active() != 1 {
		t.Fatalf("active after partial invalidate = %d, want 1", e.Active())
	}
	if r := e.HandlePacket(p1, Meta{}, true); r.Action != ActionDrop {
		t.Fatalf("blocked curl.exe packet went %v, want ActionDrop", r.Action)
	}
	r2Next := e.HandlePacket(p2, Meta{}, true)
	if r2Next.Action != ActionUDP {
		t.Fatalf("unchanged app2.exe went %v", r2Next.Action)
	}
	if err := e.ForwardUDP(context.Background(), *r2Next.UDP); err != nil {
		t.Fatal(err)
	}
	md.mu.Lock()
	dials2 := md.dials["socks2"]
	md.mu.Unlock()
	if dials2 != 1 {
		t.Fatalf("socks2 dialed %d times, want 1 (reused active session)", dials2)
	}

	// Change app2.exe to TCPOnly: true -> active non-DNS UDP flow must close.
	cfg3 := &config.Config{
		Proxies: cfg.Proxies,
		Rules: []config.Rule{
			{Process: "curl.exe", Action: "block"},
			{Process: "app2.exe", Action: "proxy", Proxy: "socks2", TCPOnly: true},
		},
		DNS: config.DNS{Mode: "original"},
	}
	cfg3.ApplyDefaults()
	if err := e.Apply(cfg3); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s2.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("app2.exe UDP session was not closed on TCPOnly=true")
	}
	if e.Active() != 0 {
		t.Fatalf("active after TCPOnly = %d, want 0", e.Active())
	}
	if r := e.HandlePacket(p2, Meta{}, true); r.Action != ActionDrop {
		t.Fatalf("TCPOnly app2.exe UDP went %v, want ActionDrop", r.Action)
	}
}
