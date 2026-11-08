package engine

import (
	"sync"
	"testing"
	"time"

	"ashgate/internal/packet"
	"ashgate/internal/rules"
)

// ownerRes answers with whatever program owns the port right now.
type ownerRes struct {
	mu sync.Mutex
	p  rules.Process
}

func (r *ownerRes) Lookup(uint8, packet.Addr) (rules.Process, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.p, true
}

func (r *ownerRes) set(p rules.Process) { r.mu.Lock(); r.p = p; r.mu.Unlock() }

// A routed program whose new UDP socket gets the port another program just
// closed must not inherit that program's cached "direct" for the same
// destination: the socket's CLOSE event drops the port's decisions.
func TestClosedUDPPortForgetsDirect(t *testing.T) {
	res := &ownerRes{p: rules.Process{PID: 7, Name: "other.exe"}}
	e, _ := newEngine(t, testConfig(), res, &fakeDial{}, nil)
	src, dst := packet.V4(10, 0, 0, 4, 4444), packet.V4(1, 2, 3, 4, 443)
	pkt := func() []byte {
		b, err := packet.BuildUDP(src, dst, []byte("quic"))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if r := e.HandlePacket(pkt(), Meta{}, true); r.Action != ActionPass {
		t.Fatalf("program without a rule: %v", r.Action)
	}
	// other.exe closes the socket; curl.exe (routed) binds the same port.
	e.ForgetUDPPort(src.Port)
	res.set(rules.Process{PID: 9, Name: "curl.exe"})
	if r := e.HandlePacket(pkt(), Meta{}, true); r.Action != ActionUDP {
		t.Fatalf("routed program on the reused port went %v, want the proxy", r.Action)
	}
}

// Other ports keep their decisions, and the index forgets keys the cache
// aged out.
func TestUDPPortIndexFollowsTheCache(t *testing.T) {
	res := &ownerRes{p: rules.Process{PID: 7, Name: "other.exe"}}
	e, _ := newEngine(t, testConfig(), res, &fakeDial{}, nil)
	for _, port := range []uint16{5001, 5002} {
		b, _ := packet.BuildUDP(packet.V4(10, 0, 0, 4, port), packet.V4(1, 2, 3, 4, 443), []byte("q"))
		if r := e.HandlePacket(b, Meta{}, true); r.Action != ActionPass {
			t.Fatalf("port %d: %v", port, r.Action)
		}
	}
	e.ForgetUDPPort(5001)
	if n := e.directUDP.len(); n != 1 {
		t.Fatalf("cache has %d entries, want the other port's 1", n)
	}
	start := time.Unix(1000, 0)
	e.sweep(start)
	e.sweep(start.Add(cacheAge))
	e.sweep(start.Add(2 * cacheAge))
	if n := e.directUDP.len(); n != 0 {
		t.Fatalf("idle entries kept: %d", n)
	}
	if n := len(e.directPorts); n != 0 {
		t.Fatalf("index keeps %d ports the cache dropped", n)
	}
}
