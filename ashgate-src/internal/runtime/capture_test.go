package runtime

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"ashgate/internal/engine"
	"ashgate/internal/packet"
	"ashgate/internal/windivert"
)

// fakeEngine decides packets by their UDP source port.
type fakeEngine struct {
	decide func(port uint16, final bool) engine.Result
	calls  []string
}

func (f *fakeEngine) HandlePacket(pkt []byte, _ engine.Meta, final bool) engine.Result {
	var h packet.Header
	_ = packet.Parse(pkt, &h)
	f.calls = append(f.calls, fmt.Sprintf("%d/%v", h.Src.Port, final))
	return f.decide(h.Src.Port, final)
}

// fakeOut records what reaches the driver, one line per call.
type fakeOut struct {
	log []string
}

func (f *fakeOut) send(pkt []byte, _ *windivert.Address) error {
	f.log = append(f.log, "one "+portsOf(pkt))
	return nil
}

func (f *fakeOut) sendBatch(b *windivert.Batch) error {
	var ports []string
	for i, p := range windivert.SplitBatch(b.Buf, b.Len(), nil) {
		ports = append(ports, portsOf(p))
		if b.Addrs[i].Impostor() {
			ports[i] += "*"
		}
	}
	f.log = append(f.log, "batch "+strings.Join(ports, ","))
	return nil
}

func portsOf(pkt []byte) string {
	var h packet.Header
	if err := packet.Parse(pkt, &h); err != nil {
		return "bad"
	}
	return fmt.Sprint(h.Src.Port)
}

func pktFrom(t *testing.T, port uint16) []byte {
	t.Helper()
	pkt, err := packet.BuildUDP(packet.V4(10, 0, 0, 1, port), packet.V4(1, 2, 3, 4, 443), []byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	return pkt
}

func batchOf(t *testing.T, ports ...uint16) netBatch {
	t.Helper()
	var b netBatch
	for _, p := range ports {
		b.pkts = append(b.pkts, pktFrom(t, p))
		var addr windivert.Address
		addr.SetOutbound(true)
		b.addrs = append(b.addrs, addr)
	}
	return b
}

func wantLog(t *testing.T, out *fakeOut, want ...string) {
	t.Helper()
	if strings.Join(out.log, "; ") != strings.Join(want, "; ") {
		t.Fatalf("sent %q, want %q", out.log, want)
	}
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func newTestCapture(eng *fakeEngine, out *fakeOut, udp *udpQueue) (*capture, *fakeClock) {
	clock := &fakeClock{t: time.Unix(1000, 0)}
	c := newCapture(eng, out, udp)
	c.now = clock.now
	return c, clock
}

func TestCaptureSendsBatchInOrder(t *testing.T) {
	got := make(chan engine.UDPDatagram, 1)
	udp := newUDPQueue(1, 4, nil, func(d engine.UDPDatagram) { got <- d })
	eng := &fakeEngine{decide: func(port uint16, _ bool) engine.Result {
		switch port {
		case 2:
			return engine.Result{Action: engine.ActionModified, Inbound: true, IfIdx: 7, SubIfIdx: 8}
		case 3:
			return engine.Result{Action: engine.ActionDrop}
		case 4:
			return engine.Result{Action: engine.ActionUDP, UDP: &engine.UDPDatagram{ProxyName: "p"}}
		}
		return engine.Result{Action: engine.ActionPass}
	}}
	out := &fakeOut{}
	c, _ := newTestCapture(eng, out, udp)
	c.handle(batchOf(t, 1, 2, 3, 4, 5))
	wantLog(t, out, "batch 1,2*,5")
	if d := <-got; d.ProxyName != "p" {
		t.Fatalf("datagram %+v", d)
	}
	udp.close()

	// The rewritten packet's address is the one apply builds; the
	// passed ones keep what WinDivert returned.
	c.handle(batchOf(t, 2, 1))
	if a := c.batch.Addrs; len(a) != 0 {
		t.Fatal("batch not reset after flush")
	}
	var b windivert.Batch
	eng.decide = func(uint16, bool) engine.Result {
		return engine.Result{Action: engine.ActionModified, Inbound: true, IfIdx: 7, SubIfIdx: 8}
	}
	c.out = recordBatch{&b}
	c.handle(batchOf(t, 2))
	if a := b.Addrs[0]; !a.Impostor() || a.Outbound() || a.IfIdx() != 7 || a.SubIfIdx() != 8 {
		t.Fatalf("modified address %x", a[:24])
	}
}

// recordBatch keeps a copy of the last batch.
type recordBatch struct{ b *windivert.Batch }

func (r recordBatch) send([]byte, *windivert.Address) error { return nil }

func (r recordBatch) sendBatch(b *windivert.Batch) error {
	r.b.Buf = append([]byte(nil), b.Buf...)
	r.b.Addrs = append([]windivert.Address(nil), b.Addrs...)
	return nil
}

func TestCaptureHoldsUntilKnown(t *testing.T) {
	known := map[uint16]bool{}
	eng := &fakeEngine{decide: func(port uint16, final bool) engine.Result {
		if known[port] || final {
			return engine.Result{Action: engine.ActionPass}
		}
		return engine.Result{Action: engine.ActionUnknown}
	}}
	out := &fakeOut{}
	c, clock := newTestCapture(eng, out, nil)
	known[1] = true
	b := batchOf(t, 1, 2, 3)
	c.handle(b)
	wantLog(t, out, "batch 1")
	if len(c.pending) != 2 {
		t.Fatalf("%d held", len(c.pending))
	}
	if &c.pending[0].pkt[0] == &b.pkts[1][0] {
		t.Fatal("a held packet shares the received batch")
	}
	b.pkts[1][0] = 0 // the batch may be reused
	// Port 3's socket event arrives: it goes on the next tick, 2 waits.
	known[3] = true
	clock.t = clock.t.Add(holdTick)
	c.release(false)
	wantLog(t, out, "batch 1", "batch 3")
	// After holdFor, 2 is decided as final.
	clock.t = clock.t.Add(holdFor)
	eng.calls = nil
	c.release(false)
	wantLog(t, out, "batch 1", "batch 3", "batch 2")
	if strings.Join(eng.calls, " ") != "2/true" || len(c.pending) != 0 {
		t.Fatalf("calls %v, %d held", eng.calls, len(c.pending))
	}
	c.release(false) // nothing held: nothing sent
	wantLog(t, out, "batch 1", "batch 3", "batch 2")
}

func TestCaptureFullHoldDecidesOldest(t *testing.T) {
	eng := &fakeEngine{decide: func(_ uint16, final bool) engine.Result {
		if final {
			return engine.Result{Action: engine.ActionPass}
		}
		return engine.Result{Action: engine.ActionUnknown}
	}}
	out := &fakeOut{}
	c, _ := newTestCapture(eng, out, nil)
	c.limit = 3
	c.handle(batchOf(t, 1, 2, 3))
	wantLog(t, out)
	eng.calls = nil
	c.handle(batchOf(t, 4, 5))
	// Each new packet makes room by deciding only the oldest one.
	wantLog(t, out, "batch 1,2")
	if strings.Join(eng.calls, " ") != "4/false 1/true 5/false 2/true" {
		t.Fatalf("calls %v", eng.calls)
	}
	var ports []string
	for _, h := range c.pending {
		ports = append(ports, portsOf(h.pkt))
	}
	if strings.Join(ports, ",") != "3,4,5" {
		t.Fatalf("held %v", ports)
	}
	c.release(true)
	wantLog(t, out, "batch 1,2", "batch 3,4,5")
}

func TestCaptureMislabelledPacketGoesAlone(t *testing.T) {
	eng := &fakeEngine{decide: func(uint16, bool) engine.Result { return engine.Result{Action: engine.ActionPass} }}
	out := &fakeOut{}
	c, _ := newTestCapture(eng, out, nil)
	b := batchOf(t, 1, 2, 3)
	b.pkts[1] = append(b.pkts[1], 0) // one byte past its IP length
	c.handle(b)
	wantLog(t, out, "batch 1", "one 2", "batch 3")
}

func TestCaptureSplitsLongSendBatch(t *testing.T) {
	eng := &fakeEngine{decide: func(uint16, bool) engine.Result { return engine.Result{Action: engine.ActionPass} }}
	out := &fakeOut{}
	c, _ := newTestCapture(eng, out, nil)
	var ports []uint16
	for i := 0; i < windivert.BatchMax+2; i++ {
		ports = append(ports, uint16(1000+i))
	}
	c.handle(batchOf(t, ports...))
	if len(out.log) != 2 || !strings.HasSuffix(out.log[1], "1255,1256") {
		t.Fatalf("%d sends, last %q", len(out.log), out.log[len(out.log)-1])
	}
	if !strings.HasPrefix(out.log[0], "batch 1000,1001,") {
		t.Fatalf("first send %.40q", out.log[0])
	}
}
