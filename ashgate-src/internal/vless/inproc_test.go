package vless

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport/internet"
)

// pipeDialer hands out in-memory connections and keeps their far ends,
// so the test can make the "server" answer on a given connection.
type pipeDialer struct {
	mu   sync.Mutex
	fail error
	far  map[net.Conn]net.Conn
}

func (d *pipeDialer) Dial(context.Context, xnet.Address, xnet.Destination, *internet.SocketConfig) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fail != nil {
		return nil, d.fail
	}
	near, far := net.Pipe()
	if d.far == nil {
		d.far = map[net.Conn]net.Conn{}
	}
	d.far[near] = far
	return near, nil
}

func (*pipeDialer) DestIpAddress() net.IP { return nil }

// answer makes the server send its first bytes on c and reads them.
func (d *pipeDialer) answer(t *testing.T, c net.Conn) {
	t.Helper()
	d.mu.Lock()
	far := d.far[c.(*gatedConn).Conn]
	d.mu.Unlock()
	go func() { _, _ = far.Write([]byte{0x16}) }()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
}

// dialMany starts n dials and returns the channel the connections come on.
func dialMany(t *testing.T, d gateDialer, dest xnet.Destination, n int) chan net.Conn {
	out := make(chan net.Conn, n)
	for i := 0; i < n; i++ {
		go func() {
			c, err := d.Dial(context.Background(), nil, dest, nil)
			if err != nil {
				t.Error(err)
				return
			}
			out <- c
		}()
	}
	return out
}

func take(t *testing.T, ch chan net.Conn, n int) []net.Conn {
	t.Helper()
	var got []net.Conn
	for len(got) < n {
		select {
		case c := <-ch:
			got = append(got, c)
		case <-time.After(3 * time.Second):
			t.Fatalf("only %d of %d handshakes started", len(got), n)
		}
	}
	return got
}

func none(t *testing.T, ch chan net.Conn, why string) {
	t.Helper()
	select {
	case c := <-ch:
		_ = c.Close()
		t.Fatal(why)
	case <-time.After(200 * time.Millisecond):
	}
}

// While a VLESS server answers, eight new connections to it handshake at
// once; a slot frees when the server's first bytes arrive. After a failed
// dial, or a handshake that got nothing within gateHold, only two may,
// until a handshake completes again. Other destinations are not limited.
func TestHandshakeGate(t *testing.T) {
	const server = "203.0.113.10:443"
	gateAdd(server)
	t.Cleanup(func() { gateRemove(server) })
	oldHold := gateHold
	t.Cleanup(func() { gateHold = oldHold })
	pd := &pipeDialer{}
	d := gateDialer{base: pd}
	dest := xnet.TCPDestination(xnet.ParseAddress("203.0.113.10"), 443)
	closeAll := func(cs []net.Conn) {
		for _, c := range cs {
			_ = c.Close()
		}
	}

	ch := dialMany(t, d, dest, gateHigh+1)
	first := take(t, ch, gateHigh)
	none(t, ch, "a ninth handshake started while eight were in flight")
	if n := gateInUse(server); n != gateHigh {
		t.Fatalf("slots in use = %d, want %d", n, gateHigh)
	}
	pd.answer(t, first[0])
	closeAll(append(first, take(t, ch, 1)...))
	if n := gateInUse(server); n != 0 {
		t.Fatalf("slots in use after close = %d", n)
	}

	// A refused dial: two at a time.
	pd.mu.Lock()
	pd.fail = errors.New("connection refused")
	pd.mu.Unlock()
	if _, err := d.Dial(context.Background(), nil, dest, nil); err == nil {
		t.Fatal("dial did not fail")
	}
	pd.mu.Lock()
	pd.fail = nil
	pd.mu.Unlock()
	if l := gateLimit(server); l != gateLow {
		t.Fatalf("limit after a failed dial = %d, want %d", l, gateLow)
	}
	ch = dialMany(t, d, dest, 3)
	low := take(t, ch, gateLow)
	none(t, ch, "a third handshake started on a failing server")
	// One completes: back to eight, the waiting one goes.
	pd.answer(t, low[0])
	low = append(low, take(t, ch, 1)...)
	if l := gateLimit(server); l != gateHigh {
		t.Fatalf("limit after an answer = %d, want %d", l, gateHigh)
	}
	closeAll(low)

	// A handshake that hears nothing within gateHold frees its slot and
	// lowers the limit; its late answer lifts it again.
	gateHold = 100 * time.Millisecond
	slow := take(t, dialMany(t, d, dest, 1), 1)[0]
	deadline := time.Now().Add(3 * time.Second)
	for gateInUse(server) != 0 || gateLimit(server) != gateLow {
		if time.Now().After(deadline) {
			t.Fatalf("after gateHold: in use %d, limit %d", gateInUse(server), gateLimit(server))
		}
		time.Sleep(10 * time.Millisecond)
	}
	pd.answer(t, slow)
	if l := gateLimit(server); l != gateHigh {
		t.Fatalf("limit after a late answer = %d, want %d", l, gateHigh)
	}
	_ = slow.Close()
	if n := gateInUse(server); n != 0 {
		t.Fatalf("a timed-out slot was freed twice or not at all: %d", n)
	}

	// Another destination is not gated.
	other := xnet.TCPDestination(xnet.ParseAddress("198.51.100.1"), 443)
	for i := 0; i < gateHigh+2; i++ {
		c, err := d.Dial(context.Background(), nil, other, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}
}

// A bridge's dispatch context is the one Xray's SOCKS inbound would give:
// the instance (sniffing needs it), the inbound tag, sniffing only with
// Direct domains, and the policy's timeouts.
func TestBridgeContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	p := Params{UUID: sampleUUID, Network: "tcp", Security: "none"}
	br, err := ListenWith(ctx, "127.0.0.1:9", p, Inbound{}, Routing{Direct: []string{"direct.test"}})
	if err != nil {
		t.Fatal(err)
	}
	defer br.Close()
	pm := br.inst.GetFeature(policy.ManagerType()).(policy.Manager)
	if idle := pm.ForLevel(0).Timeouts.ConnectionIdle; idle != 30*time.Minute {
		t.Fatalf("connIdle %v", idle)
	}
	if to := pm.ForLevel(0).Timeouts; to.UplinkOnly != 2*time.Second || to.DownlinkOnly != 5*time.Second {
		t.Fatalf("uplinkOnly %v downlinkOnly %v", to.UplinkOnly, to.DownlinkOnly)
	}
	if hs := pm.ForLevel(0).Timeouts.Handshake; hs != 60*time.Second {
		t.Fatalf("other timeouts changed: handshake %v", hs)
	}
	got := br.inboundContext(context.Background(), "tls")
	if core.FromContext(got) != br.inst {
		t.Fatal("the instance is not in the context")
	}
	if in := session.InboundFromContext(got); in == nil || in.Tag != tagAshgate {
		t.Fatalf("inbound %+v", in)
	}
	if c := session.ContentFromContext(got); c == nil || !c.SniffingRequest.Enabled || !c.SniffingRequest.RouteOnly {
		t.Fatalf("content %+v", c)
	}
	br.routing.Direct = nil
	if session.ContentFromContext(br.inboundContext(context.Background(), "tls")) != nil {
		t.Fatal("sniffing without Direct domains")
	}
}

func TestDNSServers(t *testing.T) {
	got := DNSServers([]string{"1.1.1.1:53", "8.8.8.8:53", "192.0.2.53:53", "dns.example:53", "1.1.1.1:5353"})
	want := []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query", "tcp://192.0.2.53:53", "tcp://1.1.1.1:5353"}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%v, want %v", got, want)
		}
	}
}
