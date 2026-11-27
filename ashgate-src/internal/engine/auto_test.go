package engine

import (
	"strings"
	"sync"
	"testing"
	"time"

	"ashgate/internal/config"
	"ashgate/internal/packet"
	"ashgate/internal/process"
	"ashgate/internal/rules"
)

// --- test doubles ---------------------------------------------------------

// fakeAutoInspector answers the auto matcher's three questions from tables the
// test fills in; no system call is made.
type fakeAutoInspector struct {
	mu      sync.Mutex
	files   map[string]process.FileMeta
	cmds    map[uint32]string
	modules map[uint32][]string
}

func newFakeAutoInspector() *fakeAutoInspector {
	return &fakeAutoInspector{
		files:   map[string]process.FileMeta{},
		cmds:    map[uint32]string{},
		modules: map[uint32][]string{},
	}
}

func (f *fakeAutoInspector) setFile(path, signer, thumb string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[rules.NormalizePath(path)] = process.FileMeta{Signer: signer, CertThumbprint: thumb}
}

func (f *fakeAutoInspector) setCmd(pid uint32, cmd string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cmds[pid] = cmd
}

func (f *fakeAutoInspector) setModules(pid uint32, dirs ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.modules[pid] = dirs
}

func (f *fakeAutoInspector) FileMetadata(path string) process.FileMeta {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.files[rules.NormalizePath(path)]
}

func (f *fakeAutoInspector) CommandLine(pid uint32, _ int64) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cmds[pid]
}

func (f *fakeAutoInspector) HasModuleInDirs(pid uint32, _ int64, dirs []string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, md := range f.modules[pid] {
		md = strings.TrimSuffix(rules.NormalizePath(md), `\`)
		for _, d := range dirs {
			d = strings.TrimSuffix(rules.NormalizePath(d), `\`)
			if d == "" {
				continue
			}
			if md == d || strings.HasPrefix(md, d+`\`) {
				return true
			}
		}
	}
	return false
}

// autoSnapshot is the process list the matcher reads; the test replaces it.
type autoSnapshot struct {
	mu    sync.Mutex
	procs []rules.Process
}

func newAutoSnapshot() *autoSnapshot { return &autoSnapshot{} }

func (s *autoSnapshot) set(procs ...rules.Process) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.procs = append([]rules.Process(nil), procs...)
}

func (s *autoSnapshot) get() []rules.Process {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]rules.Process(nil), s.procs...)
}

// --- fixtures -------------------------------------------------------------

const (
	autoThumb  = "feedfacecafe0001"
	autoSigner = "JUST OKAY LIMITED"

	ldRuleExe     = `C:\LDPlayer\ldmutiplayer\dnmultiplayerex.exe`
	ldPlayerExe   = `C:\LDPlayer\LDPlayer9\dnplayer.exe`
	ldBoxDir      = `C:\Program Files\ldplayer9box`
	ldBoxHeadless = ldBoxDir + `\Ld9BoxHeadless.exe`
)

// autoBase is a fixed clock base so start-time differences are explicit.
var autoBase = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC).UnixNano()

func boolPtr(v bool) *bool { return &v }

func autoConfig(list ...config.Rule) *config.Config {
	return &config.Config{
		Proxies: []config.Proxy{{Name: "socks", Type: "socks5", Address: "127.0.0.1:1080"}},
		Rules:   list,
		DNS:     config.DNS{Mode: "proxy", Servers: []string{"1.1.1.1:53"}},
	}
}

// ldLiveProcs is the rule's application and a live child in a sibling folder.
// Built from the rule alone, neither would name the emulator's own folder, so
// the child is what teaches the profile where the emulator lives.
func ldLiveProcs() []rules.Process {
	root := rules.Process{
		PID: 100, Name: "dnmultiplayerex.exe", Path: ldRuleExe,
		PPID: 1, Started: autoBase - int64(2*time.Hour),
	}
	child := rules.Process{
		PID: 101, Name: "dnplayer.exe", Path: ldPlayerExe,
		PPID: 100, Started: autoBase,
		Parents: []rules.Process{{PID: 100, Name: "dnmultiplayerex.exe", Path: ldRuleExe}},
	}
	svc := rules.Process{PID: 201, Name: "Ld9BoxSVC.exe", Path: ldBoxDir + `\Ld9BoxSVC.exe`}
	return []rules.Process{root, child, svc}
}

// ldHeadless is the service-started emulator process: svchost → Ld9BoxSVC →
// Ld9BoxHeadless, so rules.IsServiceOrCOMAncestor is true.
func ldHeadless(name, path string, started int64) rules.Process {
	return rules.Process{
		PID: 200, Name: name, Path: path, PPID: 201, Started: started,
		Parents: []rules.Process{
			{PID: 201, Name: "Ld9BoxSVC.exe", Path: ldBoxDir + `\Ld9BoxSVC.exe`},
			{PID: 500, Name: "svchost.exe"},
			{PID: 600, Name: "services.exe"},
		},
	}
}

func newAutoEngine(t *testing.T, cfg *config.Config, ins AutoInspector, snap *autoSnapshot) *Engine {
	t.Helper()
	return newAutoEngineRes(t, cfg, ins, snap, fixedRes{})
}

func newAutoEngineRes(t *testing.T, cfg *config.Config, ins AutoInspector, snap *autoSnapshot, res Resolver) *Engine {
	t.Helper()
	e, err := New(cfg, Options{
		Resolver:    res,
		Alloc:       &seqAlloc{},
		Dialer:      &fakeDial{},
		SkipSelf:    true,
		Inspector:   ins,
		Snapshot:    snap.get,
		AutoRefresh: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e
}

// --- waiting helpers ------------------------------------------------------

// waitAuto waits for cond, polling until timeout. It fails the test instead of
// sleeping a fixed time.
func waitAuto(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("condition not met within timeout")
}

// waitMatch waits for cand to be auto-matched and returns the match.
func waitMatch(t *testing.T, e *Engine, pid uint32) AutoMatch {
	t.Helper()
	var got AutoMatch
	waitAuto(t, func() bool {
		for _, am := range e.AutoMatches() {
			if am.Proc.PID == pid {
				got = am
				return true
			}
		}
		return false
	})
	return got
}

// waitDecided waits until the matcher has classified cand, and asserts it was
// not matched.
func waitDecidedUnmatched(t *testing.T, e *Engine, cand rules.Process) {
	t.Helper()
	waitAuto(t, func() bool {
		am, ok, decided, _ := e.auto.lookup(cand)
		if ok {
			t.Fatalf("%s was auto-matched unexpectedly: %+v", cand.Name, am)
		}
		return decided
	})
	for _, am := range e.AutoMatches() {
		if am.Proc.PID == cand.PID {
			t.Fatalf("%s was auto-matched unexpectedly: %+v", cand.Name, am)
		}
	}
}

// --- LDPlayer end-to-end --------------------------------------------------

// TestAutoLDPlayerModuleSignal: a module loaded from the child's folder is the
// strongest signal; it works even with no signature and no start-time
// closeness.
func TestAutoLDPlayerModuleSignal(t *testing.T) {
	ins := newFakeAutoInspector()
	cand := ldHeadless("Ld9BoxHeadless.exe", ldBoxHeadless, autoBase+int64(3*time.Hour))
	ins.setModules(cand.PID, `c:\ldplayer\ldplayer9`)
	snap := newAutoSnapshot()
	snap.set(append(ldLiveProcs(), cand)...)

	e := newAutoEngine(t, autoConfig(config.Rule{Process: ldRuleExe, Action: "proxy", Proxy: "socks"}), ins, snap)

	am := waitMatch(t, e, cand.PID)
	if am.Reason != "загружает модуль из папки программы" {
		t.Fatalf("reason = %q", am.Reason)
	}
	if am.RuleIndex != 0 || am.Action != "proxy" || am.Proxy != "socks" {
		t.Fatalf("match = %+v", am)
	}
	if am.RuleName != "dnmultiplayerex.exe" {
		t.Fatalf("rule name = %q", am.RuleName)
	}
	if am.RuleKey != RuleKey(ldRuleExe) {
		t.Fatalf("rule key = %q", am.RuleKey)
	}
	if am.KillSwitch || am.TCPOnly {
		t.Fatalf("unexpected flags: %+v", am)
	}
}

// TestAutoLDPlayerThumbprintTokenSignal: a shared uncommon signer plus a
// service origin plus a shared path token, with the processes started hours
// apart.
func TestAutoLDPlayerThumbprintTokenSignal(t *testing.T) {
	ins := newFakeAutoInspector()
	ins.setFile(ldRuleExe, autoSigner, autoThumb)
	ins.setFile(ldPlayerExe, autoSigner, autoThumb)
	cand := ldHeadless("Ld9BoxHeadless.exe", ldBoxHeadless, autoBase+int64(3*time.Hour))
	ins.setFile(cand.Path, autoSigner, autoThumb)
	snap := newAutoSnapshot()
	snap.set(append(ldLiveProcs(), cand)...)

	e := newAutoEngine(t, autoConfig(config.Rule{Process: ldRuleExe, Action: "proxy", Proxy: "socks"}), ins, snap)

	am := waitMatch(t, e, cand.PID)
	if am.Reason != "общая подпись + служба/COM" {
		t.Fatalf("reason = %q", am.Reason)
	}
}

// TestAutoLDPlayerStartTimeSignal: the same signature and a service origin,
// but no shared path token; the launch 0.8 s after dnplayer.exe decides. The
// launcher started two hours earlier.
func TestAutoLDPlayerStartTimeSignal(t *testing.T) {
	ins := newFakeAutoInspector()
	ins.setFile(ldRuleExe, autoSigner, autoThumb)
	ins.setFile(ldPlayerExe, autoSigner, autoThumb)
	cand := ldHeadless("dnplayerbox.exe", `C:\Program Files\ThirdParty\dnplayerbox.exe`, autoBase+int64(800*time.Millisecond))
	ins.setFile(cand.Path, autoSigner, autoThumb)
	snap := newAutoSnapshot()
	snap.set(append(ldLiveProcs(), cand)...)

	e := newAutoEngine(t, autoConfig(config.Rule{Process: ldRuleExe, Action: "proxy", Proxy: "socks"}), ins, snap)

	am := waitMatch(t, e, cand.PID)
	if am.Reason != "общая подпись + служба/COM + время запуска" {
		t.Fatalf("reason = %q", am.Reason)
	}
}

// TestAutoEphemeral: a match outlives its rule only as long as the candidate
// runs; the path entry goes when the rule's application exits, and the PID
// entry goes when the candidate exits.
func TestAutoEphemeral(t *testing.T) {
	ins := newFakeAutoInspector()
	ins.setModules(200, `c:\ldplayer\ldplayer9`)
	cand := ldHeadless("Ld9BoxHeadless.exe", ldBoxHeadless, autoBase+int64(3*time.Hour))
	snap := newAutoSnapshot()
	snap.set(append(ldLiveProcs(), cand)...)
	e := newAutoEngine(t, autoConfig(config.Rule{Process: ldRuleExe, Action: "proxy", Proxy: "socks"}), ins, snap)
	waitMatch(t, e, cand.PID)
	path := rules.NormalizePath(cand.Path)
	key := pidKey{pid: cand.PID, started: cand.Started}

	// The rule's application exits: the candidate lives, its path entry dies.
	snap.set(cand)
	waitAuto(t, func() bool {
		tbl := e.auto.table()
		if tbl == nil {
			return false
		}
		_, hasPath := tbl.byPath[path]
		_, hasPID := tbl.byPID[key]
		return !hasPath && hasPID
	})

	// The candidate exits too: nothing is kept.
	snap.set()
	waitAuto(t, func() bool {
		tbl := e.auto.table()
		return tbl != nil && len(tbl.byPID) == 0 && len(tbl.byPath) == 0
	})
	if got := e.AutoMatches(); len(got) != 0 {
		t.Fatalf("matches after exit: %+v", got)
	}
}

// --- command line ---------------------------------------------------------

func TestAutoCommandLineSiblingFolder(t *testing.T) {
	ins := newFakeAutoInspector()
	worker := rules.Process{PID: 300, Name: "worker.exe", Path: `C:\Tools\worker.exe`}
	ins.setCmd(worker.PID, `C:\Tools\worker.exe --config "C:\LDPlayer\LDPlayer9\vms\machine"`)
	snap := newAutoSnapshot()
	snap.set(append(ldLiveProcs(), worker)...)
	e := newAutoEngine(t, autoConfig(config.Rule{Process: ldRuleExe, Action: "proxy", Proxy: "socks"}), ins, snap)

	e.auto.enqueue(worker)
	am := waitMatch(t, e, worker.PID)
	if am.Reason != "ссылка в командной строке" {
		t.Fatalf("reason = %q", am.Reason)
	}
}

// TestAutoCommandLinePathBoundary: «ldplayer9x» is another folder and must not
// match «ldplayer9».
func TestAutoCommandLinePathBoundary(t *testing.T) {
	ins := newFakeAutoInspector()
	worker := rules.Process{PID: 301, Name: "worker2.exe", Path: `C:\Tools\worker2.exe`}
	ins.setCmd(worker.PID, `C:\Tools\worker2.exe --config "C:\LDPlayer\LDPlayer9x\vms\machine"`)
	snap := newAutoSnapshot()
	snap.set(append(ldLiveProcs(), worker)...)
	e := newAutoEngine(t, autoConfig(config.Rule{Process: ldRuleExe, Action: "proxy", Proxy: "socks"}), ins, snap)

	e.auto.enqueue(worker)
	waitDecidedUnmatched(t, e, worker)
}

// TestAutoGenericHostNotLearned: an application that starts node.exe or
// cmd.exe must not teach the profile that exe name. Otherwise any unrelated
// process whose command line mentions the host would look like a companion.
func TestAutoGenericHostNotLearned(t *testing.T) {
	cases := []struct{ name, host, hostPath string }{
		{"node", "node.exe", `C:\Program Files\nodejs\node.exe`},
		{"cmd", "cmd.exe", `C:\Windows\System32\cmd.exe`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ins := newFakeAutoInspector()
			root := rules.Process{PID: 100, Name: "myapp.exe", Path: `C:\Apps\MyApp\myapp.exe`, Started: autoBase}
			host := rules.Process{
				PID: 150, Name: tc.host, Path: tc.hostPath, PPID: 100,
				Started: autoBase + int64(time.Second),
				Parents: []rules.Process{root},
			}
			cand := rules.Process{
				PID: 300, Name: "tool.exe", Path: `C:\Tools\Tool\tool.exe`,
				Started: autoBase + int64(2*time.Second),
				Parents: []rules.Process{{PID: 900, Name: "explorer.exe"}},
			}
			ins.setCmd(cand.PID, `C:\Tools\Tool\tool.exe --spawn `+tc.host+` --run C:\Tools\Tool\payload.bin`)
			snap := newAutoSnapshot()
			snap.set(root, host, cand)
			cfg := autoConfig(config.Rule{Process: root.Path, Action: "proxy", Proxy: "socks"})
			e := newAutoEngine(t, cfg, ins, snap)
			e.auto.enqueue(cand)
			waitDecidedUnmatched(t, e, cand)
		})
	}
}

// --- no false positives ---------------------------------------------------

func TestAutoNoFalsePositives(t *testing.T) {
	socks := []config.Proxy{{Name: "socks", Type: "socks5", Address: "127.0.0.1:1080"}}
	newCfg := func(rule config.Rule) *config.Config {
		return &config.Config{Proxies: socks, Rules: []config.Rule{rule}, DNS: config.DNS{Mode: "proxy", Servers: []string{"1.1.1.1:53"}}}
	}
	underExplorer := []rules.Process{{PID: 900, Name: "explorer.exe"}}

	cases := []struct {
		name string
		cfg  *config.Config
		live rules.Process
		cand rules.Process
		ins  func(*fakeAutoInspector)
	}{
		{
			name: "pycharm vs intellij",
			cfg:  newCfg(config.Rule{Process: `C:\Program Files\JetBrains\PyCharm\bin\pycharm64.exe`, Action: "proxy", Proxy: "socks"}),
			live: rules.Process{PID: 400, Name: "pycharm64.exe", Path: `C:\Program Files\JetBrains\PyCharm\bin\pycharm64.exe`, Started: autoBase},
			cand: rules.Process{PID: 401, Name: "idea64.exe", Path: `C:\Program Files\JetBrains\IntelliJ IDEA\bin\idea64.exe`, Parents: underExplorer},
			ins: func(f *fakeAutoInspector) {
				f.setFile(`C:\Program Files\JetBrains\PyCharm\bin\pycharm64.exe`, "JetBrains s.r.o.", "thumb-jetbrains")
				f.setFile(`C:\Program Files\JetBrains\IntelliJ IDEA\bin\idea64.exe`, "JetBrains s.r.o.", "thumb-jetbrains")
			},
		},
		{
			name: "acme sibling products",
			cfg:  newCfg(config.Rule{Process: `C:\Program Files\Acme\AppA\a.exe`, Action: "proxy", Proxy: "socks"}),
			live: rules.Process{PID: 410, Name: "a.exe", Path: `C:\Program Files\Acme\AppA\a.exe`, Started: autoBase},
			cand: rules.Process{PID: 411, Name: "b.exe", Path: `C:\Program Files\Acme\AppB\b.exe`, Parents: underExplorer},
			ins: func(f *fakeAutoInspector) {
				f.setFile(`C:\Program Files\Acme\AppA\a.exe`, "Acme Corp", "thumb-acme")
				f.setFile(`C:\Program Files\Acme\AppB\b.exe`, "Acme Corp", "thumb-acme")
			},
		},
		{
			name: "chrome vs google drive",
			cfg:  newCfg(config.Rule{Process: `C:\Program Files\Google\Chrome\Application\chrome.exe`, Action: "proxy", Proxy: "socks"}),
			live: rules.Process{PID: 420, Name: "chrome.exe", Path: `C:\Program Files\Google\Chrome\Application\chrome.exe`, Started: autoBase},
			cand: rules.Process{PID: 421, Name: "GoogleDriveFS.exe", Path: `C:\Program Files\Google\Drive File Stream\GoogleDriveFS.exe`, Parents: underExplorer},
			ins: func(f *fakeAutoInspector) {
				f.setFile(`C:\Program Files\Google\Chrome\Application\chrome.exe`, "Google LLC", "thumb-google")
				f.setFile(`C:\Program Files\Google\Drive File Stream\GoogleDriveFS.exe`, "Google LLC", "thumb-google")
			},
		},
		{
			name: "edge vs onedrive",
			cfg:  newCfg(config.Rule{Process: `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`, Action: "proxy", Proxy: "socks"}),
			live: rules.Process{PID: 430, Name: "msedge.exe", Path: `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`, Started: autoBase},
			cand: rules.Process{PID: 431, Name: "OneDrive.exe", Path: `C:\Users\me\AppData\Local\Microsoft\OneDrive\OneDrive.exe`, Parents: underExplorer},
			ins: func(f *fakeAutoInspector) {
				f.setFile(`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`, "Microsoft Corporation", "thumb-ms")
				f.setFile(`C:\Users\me\AppData\Local\Microsoft\OneDrive\OneDrive.exe`, "Microsoft Corporation", "thumb-ms")
			},
		},
		{
			name: "ldplayer vs virtualbox",
			cfg:  newCfg(config.Rule{Process: ldRuleExe, Action: "proxy", Proxy: "socks"}),
			live: rules.Process{PID: 100, Name: "dnmultiplayerex.exe", Path: ldRuleExe, Started: autoBase},
			cand: ldHeadless("VirtualBoxVM.exe", `C:\Program Files\Oracle\VirtualBox\VirtualBoxVM.exe`, autoBase+int64(time.Second)),
			ins: func(f *fakeAutoInspector) {
				f.setFile(ldRuleExe, autoSigner, autoThumb)
				f.setFile(`C:\Program Files\Oracle\VirtualBox\VirtualBoxVM.exe`, "Oracle Corporation", "thumb-oracle")
			},
		},
		{
			name: "system process",
			cfg:  newCfg(config.Rule{Process: ldRuleExe, Action: "proxy", Proxy: "socks"}),
			live: rules.Process{PID: 100, Name: "dnmultiplayerex.exe", Path: ldRuleExe, Started: autoBase},
			cand: rules.Process{
				PID: 500, Name: "svchost.exe", Path: `C:\Windows\System32\svchost.exe`,
				Parents: []rules.Process{{PID: 600, Name: "services.exe"}},
			},
			ins: func(f *fakeAutoInspector) {
				f.setFile(ldRuleExe, autoSigner, autoThumb)
				f.setFile(`C:\Windows\System32\svchost.exe`, autoSigner, autoThumb)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ins := newFakeAutoInspector()
			tc.ins(ins)
			snap := newAutoSnapshot()
			snap.set(append([]rules.Process{tc.live, tc.cand}, tc.cand.Parents...)...)
			e := newAutoEngine(t, tc.cfg, ins, snap)
			e.auto.enqueue(tc.cand)
			waitDecidedUnmatched(t, e, tc.cand)
		})
	}
}

// TestAutoChildrenOff: a rule that does not cover children never learns a
// profile.
func TestAutoChildrenOff(t *testing.T) {
	ins := newFakeAutoInspector()
	ins.setFile(ldRuleExe, autoSigner, autoThumb)
	cand := ldHeadless("Ld9BoxHeadless.exe", ldBoxHeadless, autoBase+int64(3*time.Hour))
	ins.setFile(cand.Path, autoSigner, autoThumb)
	snap := newAutoSnapshot()
	snap.set(append(ldLiveProcs(), cand)...)
	cfg := autoConfig(config.Rule{Process: ldRuleExe, Action: "proxy", Proxy: "socks", Children: boolPtr(false)})
	e := newAutoEngine(t, cfg, ins, snap)

	if tbl := e.auto.table(); tbl != nil && tbl.hasAutoRules {
		t.Fatalf("hasAutoRules = true with Children: false")
	}
	e.auto.enqueue(cand)
	waitDecidedUnmatched(t, e, cand)
}

// TestAutoExcludedCompanion: ExcludeCompanions keeps a process out of the
// folder-based auto attribution.
func TestAutoExcludedCompanion(t *testing.T) {
	ins := newFakeAutoInspector()
	ins.setModules(200, `c:\ldplayer\ldplayer9`)
	cand := ldHeadless("Ld9BoxHeadless.exe", ldBoxHeadless, autoBase+int64(3*time.Hour))
	snap := newAutoSnapshot()
	snap.set(append(ldLiveProcs(), cand)...)
	cfg := autoConfig(config.Rule{
		Process: ldRuleExe, Action: "proxy", Proxy: "socks",
		ExcludeCompanions: []string{"Ld9BoxHeadless.exe"},
	})
	e := newAutoEngine(t, cfg, ins, snap)

	e.auto.enqueue(cand)
	waitDecidedUnmatched(t, e, cand)
}

// TestAutoExplicitRuleWins: an explicit rule on the candidate keeps the auto
// matcher away.
func TestAutoExplicitRuleWins(t *testing.T) {
	ins := newFakeAutoInspector()
	ins.setFile(ldRuleExe, autoSigner, autoThumb)
	cand := ldHeadless("Ld9BoxHeadless.exe", ldBoxHeadless, autoBase+int64(3*time.Hour))
	ins.setFile(cand.Path, autoSigner, autoThumb)
	snap := newAutoSnapshot()
	snap.set(append(ldLiveProcs(), cand)...)
	cfg := autoConfig(
		config.Rule{Process: ldRuleExe, Action: "proxy", Proxy: "socks"},
		config.Rule{Process: "Ld9BoxHeadless.exe", Action: "direct"},
	)
	e := newAutoEngine(t, cfg, ins, snap)

	e.auto.enqueue(cand)
	waitDecidedUnmatched(t, e, cand)
}

// --- packet path ----------------------------------------------------------

// TestAutoHandlePacketHoldsFirstPacket: the first packet of a candidate in a
// service's tree is held while the matcher classifies it, then the next packet
// is routed by the auto match (MatchAuto), with stats and no DIRECT entry.
func TestAutoHandlePacketHoldsFirstPacket(t *testing.T) {
	ins := newFakeAutoInspector()
	ins.setFile(ldRuleExe, autoSigner, autoThumb)
	cand := rules.Process{
		PID: 200, Name: "Ld9BoxHeadless.exe", Path: ldBoxHeadless, Started: autoBase + int64(time.Second),
		Parents: []rules.Process{{PID: 900, Name: "explorer.exe"}},
	}
	ins.setFile(cand.Path, autoSigner, autoThumb)
	snap := newAutoSnapshot()
	snap.set(append(ldLiveProcs(), cand)...)
	cfg := autoConfig(config.Rule{Process: ldRuleExe, Action: "proxy", Proxy: "socks"})
	e := newAutoEngineRes(t, cfg, ins, snap, fixedRes{p: cand, ok: true})

	build := func() []byte {
		pkt, err := packet.BuildTCP(packet.V4(10, 0, 0, 8, 41000), packet.V4(9, 9, 9, 9, 443), 0x02)
		if err != nil {
			t.Fatal(err)
		}
		return pkt
	}

	if res := e.HandlePacket(build(), Meta{IfIdx: 7}, false); res.Action != ActionUnknown {
		t.Fatalf("first packet = %+v, want ActionUnknown", res)
	}
	waitAuto(t, func() bool {
		am, ok, _, _ := e.auto.lookup(cand)
		return ok && am.Action == "proxy"
	})

	res := e.HandlePacket(build(), Meta{IfIdx: 7}, false)
	if res.Action != ActionModified {
		t.Fatalf("second packet = %+v, want ActionModified", res)
	}

	key := RuleKey(ldRuleExe)
	st, ok := e.RuleStats()[key]
	if !ok {
		t.Fatalf("no stats for %q", key)
	}
	if st.Flows != 1 {
		t.Fatalf("flows = %d, want 1", st.Flows)
	}
	found := false
	for _, p := range st.Procs {
		if p.Name == "Ld9BoxHeadless.exe" {
			found = true
			if p.Kind != rules.MatchAuto {
				t.Fatalf("kind = %q, want %q", p.Kind, rules.MatchAuto)
			}
		}
	}
	if !found {
		t.Fatalf("candidate missing from rule stats: %+v", st.Procs)
	}
	if procs, _, _ := e.DirectSnapshot(); len(procs) != 0 {
		t.Fatalf("DIRECT snapshot = %+v, want empty", procs)
	}
	ams := e.AutoMatches()
	if len(ams) != 1 || ams[0].Proc.PID != cand.PID || ams[0].RuleIndex != 0 {
		t.Fatalf("AutoMatches = %+v", ams)
	}
}

// TestAutoCloseAndConcurrency exercises Apply, the packet path and the readers
// at once, then checks that Close is clean and idempotent.
func TestAutoCloseAndConcurrency(t *testing.T) {
	ins := newFakeAutoInspector()
	ins.setModules(200, `c:\ldplayer\ldplayer9`)
	cand := ldHeadless("Ld9BoxHeadless.exe", ldBoxHeadless, autoBase+int64(3*time.Hour))
	snap := newAutoSnapshot()
	snap.set(append(ldLiveProcs(), cand)...)
	cfg := autoConfig(config.Rule{Process: ldRuleExe, Action: "proxy", Proxy: "socks"})
	e := newAutoEngineRes(t, cfg, ins, snap, fixedRes{p: cand, ok: true})

	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(port uint16) {
			defer wg.Done()
			for j := 0; j < 40; j++ {
				if err := e.Apply(cfg); err != nil {
					t.Errorf("Apply: %v", err)
					return
				}
				_ = e.AutoMatches()
				pkt, err := packet.BuildTCP(packet.V4(10, 0, 0, 8, port), packet.V4(9, 9, 9, 9, 443), 0x02)
				if err != nil {
					t.Errorf("BuildTCP: %v", err)
					return
				}
				_ = e.HandlePacket(pkt, Meta{}, j%2 == 0)
			}
		}(uint16(41000 + i))
	}
	wg.Wait()

	e.Close()
	e.Close()
	if got := e.AutoMatches(); got != nil && len(got) != 0 && got[0].Proc.PID != cand.PID {
		t.Fatalf("unexpected match after close: %+v", got)
	}
}

// TestAutoReevaluatesWhenChildFolderAppears checks that a service process that
// was already checked and rejected while only the launcher (C:\LDPlayer\ldmutiplayer)
// was running gets re-evaluated as soon as the child (C:\LDPlayer\LDPlayer9\dnplayer.exe)
// starts and brings its sibling install folder into the rule profile.
func TestAutoReevaluatesWhenChildFolderAppears(t *testing.T) {
	ins := newFakeAutoInspector()
	ins.setModules(200, `c:\ldplayer\ldplayer9`)
	launcher := ldLiveProcs()[0] // dnmultiplayerex.exe only, no dnplayer.exe yet
	cand := ldHeadless("Ld9BoxHeadless.exe", ldBoxHeadless, autoBase+int64(3*time.Hour))
	snap := newAutoSnapshot()
	snap.set(launcher, cand)

	cfg := autoConfig(config.Rule{Process: ldRuleExe, Action: "proxy", Proxy: "socks"})
	e := newAutoEngineRes(t, cfg, ins, snap, fixedRes{p: cand, ok: true})

	// Wait until cand has been evaluated and marked decided (unmatched) against launcher alone.
	waitAuto(t, func() bool {
		_, ok, decided, _ := e.auto.lookup(cand)
		return !ok && decided
	})

	// Now dnplayer.exe starts in sibling folder C:\LDPlayer\LDPlayer9\.
	snap.set(append(ldLiveProcs(), cand)...)
	waitAuto(t, func() bool {
		am, ok, _, _ := e.auto.lookup(cand)
		return ok && am.RuleIndex == 0 && am.Reason == "загружает модуль из папки программы"
	})
}

type slowAutoInspector struct {
	started chan struct{}
	once    sync.Once
	delay   time.Duration
}

func (s *slowAutoInspector) FileMetadata(string) process.FileMeta { return process.FileMeta{} }
func (s *slowAutoInspector) CommandLine(uint32, int64) string     { return "" }
func (s *slowAutoInspector) HasModuleInDirs(uint32, int64, []string) bool {
	s.once.Do(func() { close(s.started) })
	time.Sleep(s.delay)
	return false
}

// TestAutoCloseIsFastWhileBusy checks that Engine.Close aborts an active
// background pass between candidates instead of waiting for all queued
// processes to finish slow WinAPI inspections.
func TestAutoCloseIsFastWhileBusy(t *testing.T) {
	ins := &slowAutoInspector{started: make(chan struct{}), delay: 40 * time.Millisecond}
	procs := append([]rules.Process(nil), ldLiveProcs()...)
	for i := 0; i < 60; i++ {
		procs = append(procs, rules.Process{
			PID:     uint32(1000 + i),
			Name:    "svc.exe",
			Path:    `C:\Other\svc.exe`,
			Started: autoBase + int64(i),
			Parents: []rules.Process{{PID: 500, Name: "svchost.exe"}},
		})
	}
	snap := newAutoSnapshot()
	snap.set(procs...)
	e := newAutoEngine(t, autoConfig(config.Rule{Process: ldRuleExe, Action: "proxy", Proxy: "socks"}), ins, snap)

	select {
	case <-ins.started:
	case <-time.After(3 * time.Second):
		t.Fatal("autoMatcher did not start inspecting candidates")
	}

	t0 := time.Now()
	e.Close()
	if elapsed := time.Since(t0); elapsed > 500*time.Millisecond {
		t.Fatalf("Engine.Close took %s while busy, want <= 500ms", elapsed)
	}
}
