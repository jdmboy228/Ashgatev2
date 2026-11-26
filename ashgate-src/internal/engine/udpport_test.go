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

// The port's blocked and unknown-owner entries go with its direct ones; other
// ports keep theirs.
func TestClosedUDPPortForgetsBlockAndUnknown(t *testing.T) {
	e, _ := newEngine(t, testConfig(), &ownerRes{}, &fakeDial{}, nil)
	dst := packet.V4(1, 2, 3, 4, 443)
	mine, other := packet.V4(10, 0, 0, 4, 4444), packet.V4(10, 0, 0, 4, 4445)
	e.mu.Lock()
	e.blockUDP.add(udpKey{Src: mine, Dst: dst})
	e.unknownUDP.add(udpKey{Src: mine, Dst: dst})
	e.blockUDP.add(udpKey{Src: other, Dst: dst})
	e.unknownUDP.add(udpKey{Src: other, Dst: dst})
	e.blockUDP.rotate() // the old generation is scanned too
	e.unknownUDP.rotate()
	e.blockUDP.add(udpKey{Src: mine, Dst: packet.V4(5, 6, 7, 8, 443)})
	e.mu.Unlock()
	e.ForgetUDPPort(mine.Port)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.blockUDP.has(udpKey{Src: mine, Dst: dst}) || e.unknownUDP.has(udpKey{Src: mine, Dst: dst}) ||
		e.blockUDP.has(udpKey{Src: mine, Dst: packet.V4(5, 6, 7, 8, 443)}) {
		t.Fatal("entries of the closed port survive")
	}
	if !e.blockUDP.has(udpKey{Src: other, Dst: dst}) || !e.unknownUDP.has(udpKey{Src: other, Dst: dst}) {
		t.Fatal("another port lost its entries")
	}
}

func TestForgetUDPPortDrainsActiveFlowAndReDecidesPort(t *testing.T) {
	res := &ownerRes{p: rules.Process{PID: 9, Name: "curl.exe"}}
	dial := &fakeDial{}
	e, _ := newEngine(t, testConfig(), res, dial, nil)
	src, dst := packet.V4(10, 0, 0, 4, 4455), packet.V4(1, 2, 3, 4, 443)
	pkt := func() []byte {
		b, err := packet.BuildUDP(src, dst, []byte("hello"))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	r1 := e.HandlePacket(pkt(), Meta{}, true)
	if r1.Action != ActionUDP || r1.UDP == nil {
		t.Fatalf("initial proxied UDP: %v", r1.Action)
	}
	// Socket closes: ForgetUDPPort detaches the flow into draining.
	e.ForgetUDPPort(src.Port)
	// Already-queued datagram still carries its flow pointer.
	if r1.UDP.flow == nil {
		t.Fatal("UDPDatagram missing flow pointer")
	}
	// A new unrouted process reuses the port and must be decided fresh (Pass).
	res.set(rules.Process{PID: 10, Name: "other.exe"})
	if r2 := e.HandlePacket(pkt(), Meta{}, true); r2.Action != ActionPass {
		t.Fatalf("new app on reused UDP port went %v, want ActionPass", r2.Action)
	}
	// Sweep past udpIdle retires the draining flow and compacts e.draining.
	e.sweep(time.Now().Add(udpIdle + time.Second))
	e.mu.Lock()
	drainingLen := len(e.draining)
	e.mu.Unlock()
	if drainingLen != 0 {
		t.Fatalf("draining not compacted: %d", drainingLen)
	}
	if e.Active() != 0 {
		t.Fatalf("active flows after draining sweep: %d", e.Active())
	}
}

func TestTCPFlowsSameSrcDifferentDstDoNotCollide(t *testing.T) {
	res := &ownerRes{p: rules.Process{PID: 9, Name: "curl.exe"}}
	e, _ := newEngine(t, testConfig(), res, &fakeDial{}, nil)
	src := packet.V4(10, 0, 0, 4, 5555)
	dst1 := packet.V4(1, 2, 3, 4, 443)
	dst2 := packet.V4(5, 6, 7, 8, 443)
	syn1, _ := packet.BuildTCP(src, dst1, 0x02)
	syn2, _ := packet.BuildTCP(src, dst2, 0x02)
	if r := e.HandlePacket(syn1, Meta{}, true); r.Action != ActionModified {
		t.Fatalf("syn1: %v", r.Action)
	}
	if r := e.HandlePacket(syn2, Meta{}, true); r.Action != ActionModified {
		t.Fatalf("syn2: %v", r.Action)
	}
	if e.Active() != 2 {
		t.Fatalf("expected 2 independent TCP flows for same src / different dst, got %d", e.Active())
	}
}
