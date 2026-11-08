package process

import (
	"sync"
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

// A running process whose image cannot be read (System, a protected
// process) is known: with a proxy rule an unknown owner is dropped. A
// process that is gone stays unknown.
func TestUnreadableProcesses(t *testing.T) {
	r, _ := testResolver(time.Unix(1000, 0))
	r.SetImage(func(uint32) rules.Process { return rules.Process{} })
	r.SetPresent(func(pid uint32) bool { return pid != 66 })
	for i, pid := range []uint32{4, 1234, 66} {
		r.Observe(packet.ProtoTCP, packet.V4(1, 2, 3, 4, uint16(100+i)), pid, false)
	}
	if p, ok := r.Lookup(packet.ProtoTCP, packet.V4(1, 2, 3, 4, 100)); !ok || p.PID != 4 || p.Name != "System" {
		t.Fatalf("PID 4: %+v %v", p, ok)
	}
	if p, ok := r.Lookup(packet.ProtoTCP, packet.V4(1, 2, 3, 4, 101)); !ok || p.PID != 1234 || p.Name != "" {
		t.Fatalf("protected process: %+v %v", p, ok)
	}
	if p, ok := r.Lookup(packet.ProtoTCP, packet.V4(1, 2, 3, 4, 102)); ok {
		t.Fatalf("an exited process was found: %+v", p)
	}
}

// waitLoad waits for a table read in progress.
func waitLoad(r *Resolver) {
	r.mu.Lock()
	ch := r.loading
	r.mu.Unlock()
	if ch != nil {
		<-ch
	}
}

// Before the last try a lookup never waits for the tables: it starts one
// read in the background and answers "unknown"; the packet is asked about
// again and then finds the new table.
func TestTableReadIsBackgroundAndSingle(t *testing.T) {
	start := time.Unix(1000, 0)
	r, clock := testResolver(start)
	a, b := packet.V4(10, 0, 0, 4, 5000), packet.V4(10, 0, 0, 4, 5001)
	release := make(chan struct{})
	var mu sync.Mutex
	reads := 0
	r.SetHelper(func() ([]Endpoint, error) {
		mu.Lock()
		reads++
		mu.Unlock()
		<-release
		return []Endpoint{{Proto: packet.ProtoTCP, Addr: a, PID: 21}, {Proto: packet.ProtoTCP, Addr: b, PID: 22}}, nil
	})
	for _, src := range []packet.Addr{a, a, a, b, b} {
		if _, ok := r.Owner(packet.ProtoTCP, src, NewFlow, false); ok {
			t.Fatal("found before any table was read")
		}
	}
	close(release)
	waitLoad(r)
	*clock = start.Add(15 * time.Millisecond)
	if p, ok := r.Owner(packet.ProtoTCP, b, NewFlow, false); !ok || p.PID != 22 {
		t.Fatalf("retry after the read: %+v %v", p, ok)
	}
	// The last try of a packet held since the read began needs no new one.
	*clock = start.Add(60 * time.Millisecond)
	if p, ok := r.Owner(packet.ProtoTCP, a, NewFlow, true); !ok || p.PID != 21 {
		t.Fatalf("last try: %+v %v", p, ok)
	}
	mu.Lock()
	defer mu.Unlock()
	if reads != 1 {
		t.Fatalf("%d table reads, want 1", reads)
	}
}

// A new flow is never credited to the program whose socket on the port
// just closed: not through its closed entry, and not through a table read
// before the close, which may still list that socket.
func TestLiveLookupDistrustsTableFromBeforeClose(t *testing.T) {
	start := time.Unix(1000, 0)
	r, clock := testResolver(start)
	local := packet.V4(10, 0, 0, 4, 5300)
	owner := uint32(3)
	r.SetHelper(func() ([]Endpoint, error) {
		return []Endpoint{{Proto: packet.ProtoUDP, Addr: local, PID: owner}}, nil
	})
	if p, ok := r.Lookup(packet.ProtoUDP, local); !ok || p.PID != 3 {
		t.Fatalf("table: %+v %v", p, ok)
	}
	*clock = start.Add(10 * time.Millisecond)
	r.Observe(packet.ProtoUDP, local, 3, true)
	// Within helperGap no new read may start; the old table must not answer.
	*clock = start.Add(20 * time.Millisecond)
	if p, ok := r.Owner(packet.ProtoUDP, local, NewFlow, true); ok {
		t.Fatalf("credited to the closed socket's program: %+v", p)
	}
	// The mid-connection lookup still finds the closing socket's owner.
	if p, ok := r.Owner(packet.ProtoUDP, local, Continuing, true); !ok || p.PID != 3 {
		t.Fatalf("grace lookup: %+v %v", p, ok)
	}
	// A program binds the port; its event is late, a new table lists it.
	owner = 8
	*clock = start.Add(70 * time.Millisecond)
	if _, ok := r.Owner(packet.ProtoUDP, local, NewFlow, false); ok {
		t.Fatal("answered from the old table")
	}
	waitLoad(r)
	*clock = start.Add(85 * time.Millisecond)
	if p, ok := r.Owner(packet.ProtoUDP, local, NewFlow, false); !ok || p.PID != 8 {
		t.Fatalf("new owner: %+v %v", p, ok)
	}
}

// The last try for a packet that came after the newest table (the queue
// was full, no miss was recorded) reads the tables once more.
func TestLastTryReadsStaleTable(t *testing.T) {
	start := time.Unix(1000, 0)
	r, clock := testResolver(start)
	local := packet.V4(10, 0, 0, 4, 5400)
	var rows []Endpoint
	reads := 0
	r.SetHelper(func() ([]Endpoint, error) { reads++; return rows, nil })
	if _, ok := r.Lookup(packet.ProtoTCP, local); ok || reads != 1 {
		t.Fatalf("empty table: ok %v, reads %d", ok, reads)
	}
	rows = []Endpoint{{Proto: packet.ProtoTCP, Addr: local, PID: 30}}
	*clock = start.Add(100 * time.Millisecond)
	if p, ok := r.LookupLive(packet.ProtoTCP, local); !ok || p.PID != 30 || reads != 2 {
		t.Fatalf("stale table: %+v %v, reads %d", p, ok, reads)
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

// A program that sends one datagram and closes has its socket closed before
// the packet is decided. A NewDatagram lookup still finds it for
// recentClose; later, and for a NewFlow, it does not.
func TestOwnerNewDatagramKeepsRecentlyClosedSocket(t *testing.T) {
	start := time.Unix(1000, 0)
	r, clock := testResolver(start)
	exact, wild := packet.V4(10, 0, 0, 8, 50000), packet.V4(0, 0, 0, 0, 50001)
	r.Observe(packet.ProtoUDP, exact, 3, true)
	r.Observe(packet.ProtoUDP, wild, 3, true)
	for _, a := range []packet.Addr{exact, packet.V4(10, 0, 0, 8, 50001)} {
		if p, ok := r.Owner(packet.ProtoUDP, a, NewDatagram, false); !ok || p.PID != 3 {
			t.Fatalf("%s: datagram right after the close: %+v %v", a, p, ok)
		}
		if _, ok := r.Owner(packet.ProtoUDP, a, NewFlow, false); ok {
			t.Fatalf("%s: a new flow found the closed socket", a)
		}
	}
	*clock = start.Add(recentClose + time.Millisecond)
	for _, a := range []packet.Addr{exact, packet.V4(10, 0, 0, 8, 50001)} {
		if _, ok := r.Owner(packet.ProtoUDP, a, NewDatagram, false); ok {
			t.Fatalf("%s: datagram after recentClose found the closed socket", a)
		}
		if p, ok := r.Owner(packet.ProtoUDP, a, Continuing, true); !ok || p.PID != 3 {
			t.Fatalf("%s: grace lookup: %+v %v", a, p, ok)
		}
	}
	// A new socket on the port wins at once.
	*clock = start.Add(time.Second)
	r.Observe(packet.ProtoUDP, exact, 4, false)
	if p, ok := r.Owner(packet.ProtoUDP, exact, NewDatagram, false); !ok || p.PID != 4 {
		t.Fatalf("new socket: %+v %v", p, ok)
	}
}

// A process whose image cannot be read (PID 4, a protected one) has no
// handle, so exited says true for it. Its live sockets must survive a prune;
// those of a process that is gone do not.
func TestPruneKeepsSocketsOfUnreadablePIDs(t *testing.T) {
	start := time.Unix(1000, 0)
	r, clock := testResolver(start)
	r.SetImage(func(pid uint32) rules.Process {
		if pid == 4 || pid == 6 {
			return rules.Process{PID: pid} // unreadable
		}
		return rules.Process{PID: pid, Name: "app.exe", Path: `C:\apps\app.exe`}
	})
	r.SetExited(func(pid uint32) bool { return pid == 4 || pid == 6 || pid == 7 })
	r.SetPresent(func(pid uint32) bool { return pid == 4 })
	sys, prot, app := packet.V4(10, 0, 0, 1, 445), packet.V4(10, 0, 0, 1, 446), packet.V4(10, 0, 0, 1, 447)
	r.Observe(packet.ProtoTCP, sys, 4, false)  // unreadable, runs
	r.Observe(packet.ProtoTCP, prot, 6, false) // unreadable, gone
	r.Observe(packet.ProtoTCP, app, 7, false)  // readable, exited by its handle
	*clock = start.Add(pruneEvery)
	r.Observe(packet.ProtoTCP, packet.V4(10, 0, 0, 1, 448), 8, false)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.exact[exactKey{packet.ProtoTCP, sys}]; !ok {
		t.Fatal("the socket of a running unreadable PID was pruned")
	}
	if _, ok := r.exact[exactKey{packet.ProtoTCP, prot}]; ok {
		t.Fatal("the socket of a gone PID was kept")
	}
	if _, ok := r.exact[exactKey{packet.ProtoTCP, app}]; ok {
		t.Fatal("the socket of an exited process was kept")
	}
}
