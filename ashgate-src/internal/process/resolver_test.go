package process

import (
	"testing"
	"time"

	"ashgate/internal/packet"
	"ashgate/internal/rules"
)

func testResolver(now time.Time) (*Resolver, *time.Time) {
	clock := now
	r := New()
	r.SetClock(func() time.Time { return clock })
	r.SetImage(func(pid uint32) rules.Process {
		return rules.Process{PID: pid, Name: "app.exe", Path: `C:\apps\app.exe`}
	})
	// On Windows New() installs the real exit check, which reports the
	// made-up PIDs of these tests as gone.
	r.SetExited(func(uint32) bool { return false })
	return r, &clock
}

func TestObserveExactAndWildcard(t *testing.T) {
	r, _ := testResolver(time.Unix(1000, 0))
	r.Observe(packet.ProtoTCP, packet.V4(10, 0, 0, 5, 40000), 9, false)
	r.Observe(packet.ProtoUDP, packet.V4(0, 0, 0, 0, 53), 4, false)

	p, ok := r.Lookup(packet.ProtoTCP, packet.V4(10, 0, 0, 5, 40000))
	if !ok || p.PID != 9 || p.Name != "app.exe" {
		t.Fatalf("%+v %v", p, ok)
	}
	p, ok = r.Lookup(packet.ProtoUDP, packet.V4(192, 168, 1, 9, 53))
	if !ok || p.PID != 4 {
		t.Fatalf("wildcard %+v %v", p, ok)
	}
	if _, ok = r.Lookup(packet.ProtoTCP, packet.V4(10, 0, 0, 5, 53)); ok {
		t.Fatal("udp wildcard matched tcp")
	}
}

func TestExactBeatsWildcard(t *testing.T) {
	r, _ := testResolver(time.Unix(1000, 0))
	r.SetImage(func(pid uint32) rules.Process {
		return rules.Process{PID: pid, Name: "p.exe"}
	})
	r.Observe(packet.ProtoTCP, packet.V4(0, 0, 0, 0, 80), 1, false)
	r.Observe(packet.ProtoTCP, packet.V4(10, 1, 1, 1, 80), 2, false)
	p, ok := r.Lookup(packet.ProtoTCP, packet.V4(10, 1, 1, 1, 80))
	if !ok || p.PID != 2 {
		t.Fatalf("%+v", p)
	}
}

func TestCloseGrace(t *testing.T) {
	start := time.Unix(1000, 0)
	r, clock := testResolver(start)
	local := packet.V4(10, 0, 0, 8, 1234)
	r.Observe(packet.ProtoTCP, local, 3, false)
	r.Observe(packet.ProtoTCP, local, 3, true)
	if _, ok := r.Lookup(packet.ProtoTCP, local); !ok {
		t.Fatal("closed socket should stay visible")
	}
	*clock = start.Add(closeGrace + time.Millisecond)
	if _, ok := r.Lookup(packet.ProtoTCP, local); ok {
		t.Fatal("grace elapsed")
	}
}

// A DNS socket's port is soon another program's: a live lookup does not
// credit it to the program whose socket on it just closed.
func TestLookupLiveSkipsClosedSockets(t *testing.T) {
	r, _ := testResolver(time.Unix(1000, 0))
	exact, wild := packet.V4(10, 0, 0, 8, 50000), packet.V4(0, 0, 0, 0, 50001)
	r.Observe(packet.ProtoUDP, exact, 3, true)
	r.Observe(packet.ProtoUDP, wild, 3, true)
	for _, a := range []packet.Addr{exact, packet.V4(10, 0, 0, 8, 50001)} {
		if _, ok := r.Lookup(packet.ProtoUDP, a); !ok {
			t.Fatalf("Lookup %s: the closed socket should stay visible", a)
		}
		if p, ok := r.LookupLive(packet.ProtoUDP, a); ok {
			t.Fatalf("LookupLive %s found the closed socket of PID %d", a, p.PID)
		}
	}
	r.Observe(packet.ProtoUDP, exact, 4, false)
	if p, ok := r.LookupLive(packet.ProtoUDP, exact); !ok || p.PID != 4 {
		t.Fatalf("new socket on the port: %+v %v", p, ok)
	}
}

func TestHelperDoesNotOverrideSocket(t *testing.T) {
	r, _ := testResolver(time.Unix(1000, 0))
	local := packet.V4(10, 0, 0, 2, 5555)
	r.Observe(packet.ProtoUDP, local, 9, false)
	r.SetHelper(func() ([]Endpoint, error) {
		return []Endpoint{{Proto: packet.ProtoUDP, Addr: local, PID: 2}}, nil
	})
	p, ok := r.Lookup(packet.ProtoUDP, local)
	if !ok || p.PID != 9 {
		t.Fatalf("socket lost to helper: %+v", p)
	}
}

func TestHelperFallback(t *testing.T) {
	r, _ := testResolver(time.Unix(1000, 0))
	local := packet.V4(172, 16, 0, 4, 443)
	r.SetHelper(func() ([]Endpoint, error) {
		return []Endpoint{{Proto: packet.ProtoTCP, Addr: local, PID: 15}}, nil
	})
	p, ok := r.Lookup(packet.ProtoTCP, local)
	if !ok || p.PID != 15 || p.Name != "app.exe" {
		t.Fatalf("%+v %v", p, ok)
	}
}

func TestUnnamedProcessIsUnknown(t *testing.T) {
	r, _ := testResolver(time.Unix(1000, 0))
	r.SetImage(func(uint32) rules.Process { return rules.Process{} })
	r.Observe(packet.ProtoTCP, packet.V4(1, 2, 3, 4, 9), 8, false)
	if _, ok := r.Lookup(packet.ProtoTCP, packet.V4(1, 2, 3, 4, 9)); ok {
		t.Fatal("empty image should look unknown so the capture loop can retry")
	}
}

func TestReusedPIDGetsNewName(t *testing.T) {
	r, _ := testResolver(time.Unix(1000, 0))
	name := "old.exe"
	dead := false
	r.SetImage(func(pid uint32) rules.Process { return rules.Process{PID: pid, Name: name} })
	r.SetExited(func(uint32) bool { return dead })
	a := packet.V4(10, 0, 0, 1, 1000)
	r.Observe(packet.ProtoTCP, a, 7, false)
	if p, _ := r.Lookup(packet.ProtoTCP, a); p.Name != "old.exe" {
		t.Fatalf("%+v", p)
	}
	// PID 7 exits and Windows hands it to another program.
	name, dead = "new.exe", true
	b := packet.V4(10, 0, 0, 1, 2000)
	r.Observe(packet.ProtoTCP, b, 7, false)
	if p, _ := r.Lookup(packet.ProtoTCP, b); p.Name != "new.exe" {
		t.Fatalf("reused pid kept the old name: %+v", p)
	}
}

func TestPruneDropsExpiredSockets(t *testing.T) {
	start := time.Unix(1000, 0)
	r, clock := testResolver(start)
	for i := 0; i < 100; i++ {
		r.Observe(packet.ProtoTCP, packet.V4(10, 0, 0, 1, uint16(1000+i)), 5, true)
	}
	*clock = start.Add(pruneEvery + closeGrace)
	r.Observe(packet.ProtoTCP, packet.V4(10, 0, 0, 1, 9), 5, false)
	r.mu.Lock()
	n := len(r.exact)
	r.mu.Unlock()
	if n != 1 {
		t.Fatalf("expired sockets kept: %d entries", n)
	}
}

func TestParentChain(t *testing.T) {
	r, _ := testResolver(time.Unix(1000, 0))
	procs := map[uint32]rules.Process{
		1:  {Name: "explorer.exe", Started: 10},
		20: {Name: "code.exe", PPID: 1, Started: 20},
		30: {Name: "node.exe", PPID: 20, Started: 30},
		40: {Name: "late.exe", PPID: 50, Started: 40},
		50: {Name: "reused.exe", PPID: 1, Started: 99}, // started after its "child"
	}
	r.SetImage(func(pid uint32) rules.Process { p := procs[pid]; p.PID = pid; return p })
	a := packet.V4(10, 0, 0, 1, 1000)
	r.Observe(packet.ProtoTCP, a, 30, false)
	p, _ := r.Lookup(packet.ProtoTCP, a)
	if len(p.Parents) != 2 || p.Parents[0].Name != "code.exe" || p.Parents[1].Name != "explorer.exe" {
		t.Fatalf("chain %+v", p.Parents)
	}
	b := packet.V4(10, 0, 0, 1, 2000)
	r.Observe(packet.ProtoTCP, b, 40, false)
	if p, _ := r.Lookup(packet.ProtoTCP, b); len(p.Parents) != 0 {
		t.Fatalf("reused parent pid accepted: %+v", p.Parents)
	}
}

func TestWithParents(t *testing.T) {
	got := WithParents([]rules.Process{
		{PID: 1, Name: "explorer.exe", Started: 1},
		{PID: 2, Name: "code.exe", PPID: 1, Started: 2},
		{PID: 3, Name: "node.exe", PPID: 2, Started: 3},
		{PID: 4, Name: "orphan.exe", PPID: 9, Started: 4},
		{PID: 5, Name: "loop.exe", PPID: 5, Started: 5},
	})
	if n := got[2].Parents; len(n) != 2 || n[0].Name != "code.exe" || n[1].Name != "explorer.exe" {
		t.Fatalf("%+v", n)
	}
	if len(got[3].Parents) != 0 || len(got[4].Parents) != 0 {
		t.Fatal("orphan or self-parent got a chain")
	}
}
