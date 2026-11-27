package engine

import (
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"ashgate/internal/config"
	"ashgate/internal/packet"
	"ashgate/internal/rules"
)

// TestDirectRecordsUnmatchedTraffic: TCP and UDP packets of a known program
// with no matching rule land in DirectSnapshot with exact counters, and not
// in the main log.
func TestDirectRecordsUnmatchedTraffic(t *testing.T) {
	proc := rules.Process{Name: "other.exe", Path: `C:\Other\other.exe`, PID: 4242}
	e, logs := newEngine(t, testConfig(), fixedRes{p: proc, ok: true}, &fakeDial{}, nil)

	syn, err := packet.BuildTCP(packet.V4(10, 0, 0, 9, 40000), packet.V4(1, 2, 3, 4, 80), 0x02)
	if err != nil {
		t.Fatal(err)
	}
	if res := e.HandlePacket(syn, Meta{}, true); res.Action != ActionPass {
		t.Fatalf("tcp action %v", res.Action)
	}
	udp, err := packet.BuildUDP(packet.V4(10, 0, 0, 9, 40001), packet.V4(5, 6, 7, 8, 3478), []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if res := e.HandlePacket(udp, Meta{}, true); res.Action != ActionPass {
		t.Fatalf("udp action %v", res.Action)
	}

	procs, evs, gen := e.DirectSnapshot()
	if len(procs) != 1 {
		t.Fatalf("%d direct procs, want 1: %+v", len(procs), procs)
	}
	p := procs[0]
	if p.Name != "other.exe" || p.Path != proc.Path || p.PID != proc.PID {
		t.Fatalf("proc %+v", p)
	}
	if p.Conns != 2 || p.Bytes != int64(len(syn)+len(udp)) {
		t.Fatalf("conns %d, bytes %d, want 2, %d", p.Conns, p.Bytes, len(syn)+len(udp))
	}
	if want := []string{"1.2.3.4:80", "5.6.7.8:3478"}; !reflect.DeepEqual(p.SampleDests, want) {
		t.Fatalf("dests %v, want %v", p.SampleDests, want)
	}
	if p.System {
		t.Fatal("other.exe marked system")
	}
	if len(evs) != 2 || gen != 2 {
		t.Fatalf("%d events, gen %d, want 2, 2", len(evs), gen)
	}
	if evs[0].Process != "other.exe" || evs[0].Path != proc.Path || evs[0].Via != "direct" || evs[0].Status != "unmatched" || evs[0].Proto != "TCP" {
		t.Fatalf("event %+v", evs[0])
	}
	if evs[1].Proto != "UDP" || evs[1].Dest != "5.6.7.8:3478" {
		t.Fatalf("event %+v", evs[1])
	}
	if got := logs.Snapshot(); len(got) != 0 {
		t.Fatalf("main log got %d unmatched events: %+v", len(got), got)
	}
}

// TestDirectMarksSystem: the Windows DNS client's own traffic is marked
// system, so the window can hide it.
func TestDirectMarksSystem(t *testing.T) {
	proc := rules.Process{Name: "svchost.exe", Path: `C:\Windows\System32\svchost.exe`, PID: 1200}
	e, _ := newEngine(t, testConfig(), fixedRes{p: proc, ok: true}, &fakeDial{}, nil)

	pkt, err := packet.BuildUDP(packet.V4(10, 0, 0, 2, 40010), packet.V4(1, 2, 3, 4, 123), []byte{1})
	if err != nil {
		t.Fatal(err)
	}
	e.HandlePacket(pkt, Meta{}, true)
	procs, evs, _ := e.DirectSnapshot()
	if len(procs) != 1 || !procs[0].System {
		t.Fatalf("procs %+v", procs)
	}
	if len(evs) != 0 {
		t.Fatalf("system process polluted unmatched event feed: %+v", evs)
	}
}

// TestDirectCachedFlowCountsBytes: repeated packets on a cached direct flow
// add to the program's bytes without another owner lookup.
func TestDirectCachedFlowCountsBytes(t *testing.T) {
	proc := rules.Process{Name: "other.exe", Path: `C:\Other\other.exe`, PID: 4242}
	e, _ := newEngine(t, testConfig(), fixedRes{p: proc, ok: true}, &fakeDial{}, nil)

	pkt, err := packet.BuildTCP(packet.V4(10, 0, 0, 9, 40020), packet.V4(1, 2, 3, 4, 80), 0x10)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if res := e.HandlePacket(pkt, Meta{}, true); res.Action != ActionPass {
			t.Fatalf("packet %d: action %v", i, res.Action)
		}
	}
	procs, _, _ := e.DirectSnapshot()
	if len(procs) != 1 {
		t.Fatalf("%d procs", len(procs))
	}
	if procs[0].Conns != 1 {
		t.Fatalf("conns %d, want 1", procs[0].Conns)
	}
	if want := int64(3 * len(pkt)); procs[0].Bytes != want {
		t.Fatalf("bytes %d, want %d", procs[0].Bytes, want)
	}
}

// TestApplyCompanionMovesProcessToProxy: adding a process as a companion
// drops it from DirectSnapshot and the direct cache, and its new traffic is
// proxied and counted per process under the rule.
func TestApplyCompanionMovesProcessToProxy(t *testing.T) {
	cfg := &config.Config{
		Proxies: []config.Proxy{{Name: "socks", Type: "socks5", Address: "127.0.0.1:1080"}},
		Rules:   []config.Rule{{Process: "app.exe", Action: "proxy", Proxy: "socks"}},
		DNS:     config.DNS{Mode: "original"},
	}
	proc := rules.Process{Name: "comp.exe", Path: `C:\Apps\Comp\comp.exe`, PID: 7}
	e, _ := newEngine(t, cfg, fixedRes{p: proc, ok: true}, &fakeDial{}, &memInj{})

	first, err := packet.BuildTCP(packet.V4(10, 0, 0, 4, 41000), packet.V4(1, 2, 3, 4, 80), 0x02)
	if err != nil {
		t.Fatal(err)
	}
	if res := e.HandlePacket(first, Meta{}, true); res.Action != ActionPass {
		t.Fatalf("before companion: action %v", res.Action)
	}
	if procs, _, _ := e.DirectSnapshot(); len(procs) != 1 {
		t.Fatalf("%d direct procs before Apply", len(procs))
	}

	cfg.Rules[0].Companions = []string{"comp.exe"}
	if err := e.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	if procs, _, _ := e.DirectSnapshot(); len(procs) != 0 {
		t.Fatalf("percent still direct after Apply: %+v", procs)
	}
	e.mu.Lock()
	cached := e.directTCP.len() + e.directUDP.len()
	e.mu.Unlock()
	if cached != 0 {
		t.Fatalf("%d direct cache entries after Apply", cached)
	}

	second, err := packet.BuildTCP(packet.V4(10, 0, 0, 4, 41000), packet.V4(1, 2, 3, 4, 80), 0x02)
	if err != nil {
		t.Fatal(err)
	}
	if res := e.HandlePacket(second, Meta{}, true); res.Action != ActionModified {
		t.Fatalf("after companion: action %v", res.Action)
	}
	st, ok := e.RuleStats()["app.exe"]
	if !ok {
		t.Fatal("no stats for app.exe")
	}
	if len(st.Procs) != 1 {
		t.Fatalf("procs %+v", st.Procs)
	}
	p := st.Procs[0]
	if p.Name != "comp.exe" || p.Path != proc.Path || p.Kind != rules.MatchCompanion {
		t.Fatalf("proc stat %+v", p)
	}
	if p.Flows != 1 {
		t.Fatalf("flows %d, want 1", p.Flows)
	}
}

// TestClearDirectEvents: the feed empties and its generation grows.
func TestClearDirectEvents(t *testing.T) {
	proc := rules.Process{Name: "other.exe", Path: `C:\Other\other.exe`, PID: 4242}
	e, _ := newEngine(t, testConfig(), fixedRes{p: proc, ok: true}, &fakeDial{}, nil)

	pkt, err := packet.BuildUDP(packet.V4(10, 0, 0, 9, 40030), packet.V4(1, 2, 3, 4, 123), []byte{1})
	if err != nil {
		t.Fatal(err)
	}
	e.HandlePacket(pkt, Meta{}, true)
	_, evs, before := e.DirectSnapshot()
	if len(evs) != 1 {
		t.Fatalf("%d events before clear", len(evs))
	}
	e.ClearDirectEvents()
	procs, evs, after := e.DirectSnapshot()
	if len(evs) != 0 {
		t.Fatalf("%d events after clear", len(evs))
	}
	if after <= before {
		t.Fatalf("gen %d after clear, was %d", after, before)
	}
	if len(procs) != 1 {
		t.Fatalf("clear removed the programs: %+v", procs)
	}
	// After clear, throttle map must be reset so the same destination logs again immediately.
	e.HandlePacket(pkt, Meta{}, true)
	// First packet on cached directUDP won't re-record; a fresh source port triggers record().
	pkt2, err := packet.BuildUDP(packet.V4(10, 0, 0, 9, 40031), packet.V4(1, 2, 3, 4, 123), []byte{2})
	if err != nil {
		t.Fatal(err)
	}
	e.HandlePacket(pkt2, Meta{}, true)
	_, evs2, _ := e.DirectSnapshot()
	if len(evs2) != 1 {
		t.Fatalf("expected immediate re-log after clear, got %d events", len(evs2))
	}
}

func TestAgeMapRotationAndPromotion(t *testing.T) {
	m := newAgeMap[string, int]()
	m.set("keep", 1)
	m.set("drop", 2)
	m.rotate()
	if v, ok := m.get("keep"); !ok || v != 1 {
		t.Fatalf("keep after 1st rotate: (%d, %v)", v, ok)
	}
	m.rotate()
	if v, ok := m.get("keep"); !ok || v != 1 {
		t.Fatalf("promoted key lost after 2nd rotate: (%d, %v)", v, ok)
	}
	if _, ok := m.get("drop"); ok {
		t.Fatal("untouched key survived 2 rotations")
	}
}

func TestDirectTrackerRingWrapThrottleEvictionAndSweep(t *testing.T) {
	var dt directTracker
	dt.init()
	base := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)

	// Ring wrap-around (> maxDirectEvents=200) must keep newest 200 oldest-first.
	proc := rules.Process{Name: "app.exe", Path: `C:\App\app.exe`, PID: 100}
	for i := 0; i < maxDirectEvents+25; i++ {
		dt.record(proc, "TCP", fmt.Sprintf("1.2.3.4:%d", 1000+i), 64, base.Add(time.Duration(i)*time.Millisecond))
	}
	procs, evs, _ := dt.snapshot()
	if len(evs) != maxDirectEvents {
		t.Fatalf("ring len = %d, want %d", len(evs), maxDirectEvents)
	}
	if evs[0].Dest != "1.2.3.4:1025" || evs[len(evs)-1].Dest != fmt.Sprintf("1.2.3.4:%d", 1000+maxDirectEvents+24) {
		t.Fatalf("ring bounds = [%s .. %s]", evs[0].Dest, evs[len(evs)-1].Dest)
	}
	// SampleDests bounded to maxDirectDests=4 with newest destinations.
	if len(procs) != 1 || len(procs[0].SampleDests) != maxDirectDests {
		t.Fatalf("sampleDests = %v", procs[0].SampleDests)
	}

	// Throttle: duplicate (proc, dest) within 2s is suppressed, after 2s is recorded.
	dt.clearEvents()
	t0 := base.Add(time.Minute)
	dt.record(proc, "TCP", "9.9.9.9:443", 100, t0)
	dt.record(proc, "TCP", "9.9.9.9:443", 100, t0.Add(time.Second))
	_, evs, _ = dt.snapshot()
	if len(evs) != 1 {
		t.Fatalf("throttle failed: got %d events, want 1", len(evs))
	}
	dt.record(proc, "TCP", "9.9.9.9:443", 100, t0.Add(directEventEvery))
	_, evs, _ = dt.snapshot()
	if len(evs) != 2 {
		t.Fatalf("post-throttle event missing: got %d", len(evs))
	}

	// Eviction beyond maxDirectProcs marks evicted entry so fastPath drops stale pointer.
	firstEntry := dt.procs[rules.NormalizePath(proc.Path)]
	for i := 0; i < maxDirectProcs+10; i++ {
		p := rules.Process{Name: fmt.Sprintf("p%d.exe", i), Path: fmt.Sprintf(`C:\Churn\p%d.exe`, i), PID: uint32(200 + i)}
		dt.record(p, "UDP", "8.8.8.8:443", 50, t0.Add(time.Duration(i+10)*time.Second))
	}
	if !firstEntry.evicted.Load() {
		t.Fatal("evicted entry was not marked evicted")
	}
	if got := dt.countRecent(t0.Add(time.Duration(maxDirectProcs+15)*time.Second), 2*time.Minute); got == 0 || got > maxDirectProcs {
		t.Fatalf("countRecent = %d", got)
	}
	// Sweep drops idle entries past directIdle.
	dt.sweep(t0.Add(20 * time.Minute))
	procs, _, _ = dt.snapshot()
	if len(procs) != 0 {
		t.Fatalf("sweep left %d idle procs", len(procs))
	}
}

func TestEvictedDirectEntryReRegistersOnFastPath(t *testing.T) {
	proc := rules.Process{Name: "active.exe", Path: `C:\Apps\active.exe`, PID: 500}
	e, _ := newEngine(t, testConfig(), fixedRes{p: proc, ok: true}, &fakeDial{}, nil)

	pkt, err := packet.BuildTCP(packet.V4(10, 0, 0, 9, 45000), packet.V4(1, 2, 3, 4, 80), 0x10)
	if err != nil {
		t.Fatal(err)
	}
	e.HandlePacket(pkt, Meta{}, true)

	// Simulate eviction (e.g. > maxDirectProcs churn).
	e.direct.mu.Lock()
	for k, entry := range e.direct.procs {
		entry.evicted.Store(true)
		delete(e.direct.procs, k)
	}
	e.direct.mu.Unlock()

	// Next packet on the cached flow must see evicted=true and re-register active.exe.
	if res := e.HandlePacket(pkt, Meta{}, true); res.Action != ActionPass {
		t.Fatalf("action %v", res.Action)
	}
	procs, _, _ := e.DirectSnapshot()
	if len(procs) != 1 || procs[0].Name != "active.exe" || procs[0].Bytes != int64(len(pkt)) {
		t.Fatalf("re-registered procs = %+v", procs)
	}
}

func TestStartUDPNoGhostSubProcOnUnsupportedAndMaxSubProcsEvictsIdle(t *testing.T) {
	cfg := &config.Config{
		Proxies:        []config.Proxy{{Name: "http", Type: "http", Address: "127.0.0.1:8080"}},
		Rules:          []config.Rule{{Process: "app.exe", Action: "proxy", Proxy: "http"}},
		DNS:            config.DNS{Mode: "original"},
		UDPUnsupported: "block",
	}
	proc := rules.Process{Name: "app.exe", Path: `C:\App\app.exe`, PID: 10}
	e, _ := newEngine(t, cfg, fixedRes{p: proc, ok: true}, &fakeDial{}, &memInj{})
	udp, err := packet.BuildUDP(packet.V4(10, 0, 0, 2, 42000), packet.V4(1, 2, 3, 4, 443), []byte("quic"))
	if err != nil {
		t.Fatal(err)
	}
	if res := e.HandlePacket(udp, Meta{}, true); res.Action != ActionDrop {
		t.Fatalf("expected drop on http unsupported udp, got %v", res.Action)
	}
	if st := e.RuleStats()["app.exe"]; len(st.Procs) != 0 {
		t.Fatalf("dropped udp created ghost subProc entry: %+v", st.Procs)
	}

	// Verify maxSubProcs evicts the oldest idle entry instead of dropping new sub-processes.
	rs := &ruleStat{}
	for i := 0; i < maxSubProcs; i++ {
		p := rules.Process{Name: fmt.Sprintf("s%d.exe", i), Path: fmt.Sprintf(`C:\App\s%d.exe`, i)}
		sub := rs.procFor(p, rules.MatchChild)
		if sub == nil {
			t.Fatalf("procFor returned nil at %d", i)
		}
		sub.lastSeen.Store(int64(1000 + i))
	}
	newer := rs.procFor(rules.Process{Name: "newest.exe", Path: `C:\App\newest.exe`}, rules.MatchChild)
	if newer == nil {
		t.Fatal("procFor failed to evict oldest idle sub-process")
	}
	if _, stillOldest := rs.procs[`c:\app\s0.exe`]; stillOldest {
		t.Fatal("oldest idle sub-process was not evicted")
	}
}

func TestDirectTrackerConcurrentRace(t *testing.T) {
	cfg := testConfig()
	proc := rules.Process{Name: "race.exe", Path: `C:\Apps\race.exe`, PID: 77}
	e, _ := newEngine(t, cfg, fixedRes{p: proc, ok: true}, &fakeDial{}, &memInj{})

	var wg sync.WaitGroup
	wg.Add(4)
	go func() {
		defer wg.Done()
		for i := 0; i < 60; i++ {
			pkt, _ := packet.BuildUDP(packet.V4(10, 0, 0, 2, uint16(43000+i%10)), packet.V4(1, 2, 3, 4, uint16(5000+i%5)), []byte("x"))
			e.HandlePacket(pkt, Meta{}, true)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 40; i++ {
			_, _, _ = e.DirectSnapshot()
			_ = e.DirectCount(time.Now(), 2*time.Minute)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			e.ClearDirectEvents()
			e.direct.sweep(time.Now())
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 15; i++ {
			_ = e.Apply(cfg)
		}
	}()
	wg.Wait()
}
