package engine

import (
	"reflect"
	"testing"

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
	procs, _, _ := e.DirectSnapshot()
	if len(procs) != 1 || !procs[0].System {
		t.Fatalf("procs %+v", procs)
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
}
