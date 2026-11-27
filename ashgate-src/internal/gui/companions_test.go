package gui

import (
	"strings"
	"testing"
	"time"

	"ashgate/internal/config"
	"ashgate/internal/engine"
	"ashgate/internal/logbuf"
	"ashgate/internal/process"
	"ashgate/internal/rules"
)

// fakeInspector answers from fixed maps, without touching real files.
type fakeInspector struct {
	meta map[string]process.FileMeta
	cmds map[uint32]string
	// mods maps a PID to the folders of the modules it loaded.
	mods map[uint32][]string
}

func (f *fakeInspector) FileMetadata(path string) process.FileMeta {
	return f.meta[strings.ToLower(path)]
}

func (f *fakeInspector) CommandLine(pid uint32, _ int64) string { return f.cmds[pid] }

func (f *fakeInspector) HasModuleInDirs(pid uint32, _ int64, dirs []string) bool {
	for _, loaded := range f.mods[pid] {
		got := rules.NormalizePath(loaded)
		for _, want := range dirs {
			if got == rules.NormalizePath(want) {
				return true
			}
		}
	}
	return false
}

func hasReason(c companionCandidate, part string) bool {
	for _, r := range c.Reasons {
		if strings.Contains(r, part) {
			return true
		}
	}
	return false
}

// LDPlayer's service-started box process has an unrelated name and folder,
// but shares the product path word and publisher with the rule's exe.
func TestRankCandidatesLDPlayer(t *testing.T) {
	now := time.Now()
	const ruleExe = `C:\LDPlayer\ldmutiplayer\dnmultiplayerex.exe`
	const boxExe = `C:\Program Files\ldplayer9box\Ld9BoxHeadless.exe`
	const signer = "XUANZHI INTERNATIONAL CO., LIMITED"
	ins := &fakeInspector{meta: map[string]process.FileMeta{
		strings.ToLower(ruleExe): {Signer: signer, Company: "XUANZHI"},
		strings.ToLower(boxExe):  {Signer: signer, Company: "XUANZHI"},
	}}
	rule := config.Rule{Process: ruleExe, Action: "proxy"}
	running := []rules.Process{{Name: "dnmultiplayerex.exe", Path: ruleExe, PID: 100, Started: now.Add(-time.Hour).UnixNano()}}
	direct := []engine.DirectProc{{
		Name: "Ld9BoxHeadless.exe", Path: boxExe, PID: 200,
		Conns: 3, Bytes: 100_000, LastSeen: now.Add(-3 * time.Second).UnixMilli(),
	}}
	running = append(running, rules.Process{Name: "Ld9BoxHeadless.exe", Path: boxExe, PID: 200, Started: now.UnixNano()})
	got := rankCandidates(rule, []config.Rule{rule}, running, direct, running, ins, nil, now)
	if len(got) == 0 {
		t.Fatal("no candidates")
	}
	top := got[0]
	if top.Name != "Ld9BoxHeadless.exe" {
		t.Fatalf("first = %q, want Ld9BoxHeadless.exe (%+v)", top.Name, got)
	}
	if !hasReason(top, "Похожий путь (ldplayer)") && !hasReason(top, "Тот же издатель") {
		t.Fatalf("reasons = %v", top.Reasons)
	}
	if top.Score < 45 {
		t.Fatalf("score = %d", top.Score)
	}
	if !top.Running {
		t.Fatal("a direct process that is still running should be marked Running")
	}
}

// A Microsoft-signed match is weak evidence: it must not outrank a real
// candidate that shares the rule's path word.
func TestRankCandidatesCommonVendorIsWeak(t *testing.T) {
	now := time.Now()
	const ruleExe = `C:\Vendor\ProxyApp\proxy.exe`
	const msExe = `C:\Windows\System32\mstsc.exe`
	ins := &fakeInspector{meta: map[string]process.FileMeta{
		strings.ToLower(ruleExe):                   {Signer: "Microsoft Corporation", Company: "Microsoft Corporation"},
		strings.ToLower(msExe):                     {Signer: "Microsoft Corporation", Company: "Microsoft Corporation"},
		strings.ToLower(`C:\Vendor\Tool\tool.exe`): {Signer: "Contoso Ltd", Company: "Contoso Ltd"},
	}}
	rule := config.Rule{Process: ruleExe, Action: "proxy"}
	direct := []engine.DirectProc{
		{Name: "mstsc.exe", Path: msExe, PID: 1},
		{Name: "tool.exe", Path: `C:\Vendor\Tool\tool.exe`, PID: 2, Conns: 1, Bytes: 100, LastSeen: now.UnixMilli()},
	}
	got := rankCandidates(rule, []config.Rule{rule}, nil, direct, nil, ins, nil, now)
	var ms, tool *companionCandidate
	for i := range got {
		switch got[i].Name {
		case "mstsc.exe":
			ms = &got[i]
		case "tool.exe":
			tool = &got[i]
		}
	}
	if ms == nil || tool == nil {
		t.Fatalf("missing candidates: %+v", got)
	}
	// 10, not 50: the publisher is a platform vendor that signs everything.
	if ms.Score != 10 {
		t.Fatalf("Microsoft signer score = %d, want 10", ms.Score)
	}
	if !hasReason(*ms, "Тот же издатель") {
		t.Fatalf("reasons = %v", ms.Reasons)
	}
	if got[0].Name != "tool.exe" {
		t.Fatalf("first = %q, want the real candidate", got[0].Name)
	}
	if tool.Score <= ms.Score {
		t.Fatalf("tool %d <= ms %d", tool.Score, ms.Score)
	}
}

// Electron and anti-detect builds reuse a browser binary but point it at
// their own data folder; the command line reveals the application.
func TestRankCandidatesCommandLine(t *testing.T) {
	now := time.Now()
	const ruleExe = `C:\Users\portable\Dolphin\Dolphin.exe`
	const chromeExe = `C:\Program Files\Google\Chrome\Application\chrome.exe`
	ins := &fakeInspector{cmds: map[uint32]string{
		555: `"` + chromeExe + `" --user-data-dir="C:\Users\portable\Dolphin\profile" --no-first-run`,
	}}
	rule := config.Rule{Process: ruleExe, Action: "proxy"}
	running := []rules.Process{{Name: "chrome.exe", Path: chromeExe, PID: 555, Started: now.UnixNano()}}
	got := rankCandidates(rule, []config.Rule{rule}, nil, nil, running, ins, nil, now)
	if len(got) == 0 {
		t.Fatal("no candidates")
	}
	var chrome *companionCandidate
	for i := range got {
		if got[i].Name == "chrome.exe" {
			chrome = &got[i]
		}
	}
	if chrome == nil {
		t.Fatalf("chrome.exe missing: %+v", got)
	}
	if !hasReason(*chrome, "Запущен с путём программы") {
		t.Fatalf("reasons = %v", chrome.Reasons)
	}
	if chrome.Score < 60 {
		t.Fatalf("score = %d", chrome.Score)
	}
}

// System processes are listed last, flagged, and never become a suggestion.
func TestRankCandidatesSystemAreNeverSuggested(t *testing.T) {
	now := time.Now()
	const ruleExe = `C:\Apps\MyApp\myapp.exe`
	rule := config.Rule{Process: ruleExe, Action: "proxy"}
	direct := []engine.DirectProc{
		{Name: "helper.exe", Path: `C:\Other\myapp-tool\helper.exe`, PID: 3, Conns: 2, Bytes: 50_000, LastSeen: now.UnixMilli()},
	}
	running := []rules.Process{
		{Name: "svchost.exe", Path: `C:\Windows\System32\svchost.exe`, PID: 4},
		{Name: "explorer.exe", Path: `C:\Windows\explorer.exe`, PID: 5},
	}
	got := rankCandidates(rule, []config.Rule{rule}, nil, direct, running, &fakeInspector{}, nil, now)
	system := map[string]bool{}
	for _, c := range got {
		if c.Name == "svchost.exe" || c.Name == "explorer.exe" {
			if !c.System {
				t.Fatalf("%s not marked system", c.Name)
			}
			if c.Score != 0 {
				t.Fatalf("%s scored %d", c.Name, c.Score)
			}
			system[c.Name] = true
		}
	}
	if len(system) != 2 {
		t.Fatalf("system candidates missing: %+v", got)
	}
	best := topCandidate(got, nil)
	if best == nil {
		t.Fatal("the real candidate should be suggested")
	}
	if best.System || best.Name != "helper.exe" {
		t.Fatalf("suggested %+v", best)
	}
	// A pool of system processes only must suggest nothing.
	if topCandidate([]companionCandidate{{Name: "svchost.exe", System: true, Score: 90}}, nil) != nil {
		t.Fatal("system candidate suggested")
	}
}

// buildRuleMembers merges the saved companions, the live matches, and the
// engine's per-process counters, without repeating the rule's own process.
func TestBuildRuleMembers(t *testing.T) {
	const ruleExe = `C:\LDPlayer\ldmutiplayer\dnmultiplayerex.exe`
	const svcExe = `C:\LDPlayer\ldmutiplayer\Ld9BoxSVC.exe`
	const boxExe = `C:\Program Files\ldplayer9box\Ld9BoxHeadless.exe`
	cfg := &config.Config{Rules: []config.Rule{{
		Process:    ruleExe,
		Companions: []string{svcExe, "legacyplayer"},
	}}}
	key := ruleKey(ruleExe)
	live := map[string][]liveMember{key: {
		{Name: "Ld9BoxSVC.exe", Path: svcExe, Kind: "companion", PID: 10},
		{Name: "Ld9BoxHeadless.exe", Path: boxExe, Kind: "child", PID: 11},
		{Name: "helper.exe", Path: `C:\LDPlayer\ldmutiplayer\helper.exe`, Kind: "folder", PID: 12},
	}}
	stats := map[string]engine.RuleStat{key: {Procs: []engine.RuleProcStat{
		{Name: "dnmultiplayerex.exe", Path: ruleExe, Kind: rules.MatchExact, Flows: 9, Up: 100, Down: 200},
		{Name: "Ld9BoxHeadless.exe", Path: boxExe, Kind: rules.MatchChild, Flows: 2, Up: 10, Down: 20},
	}}}
	got := buildRuleMembers(cfg, stats, live, nil)[key]
	if len(got) == 0 {
		t.Fatal("no members")
	}
	if got[0].Kind != "companion" {
		t.Fatalf("companions must come first: %+v", got)
	}
	seen := map[string]ruleMemberView{}
	for _, m := range got {
		if strings.EqualFold(m.Name, "dnmultiplayerex.exe") {
			t.Fatal("the rule's own process must not be a member")
		}
		seen[strings.ToLower(m.Name)] = m
	}
	svc, ok := seen["ld9boxsvc.exe"]
	if !ok || !svc.Alive || svc.Pattern != svcExe {
		t.Fatalf("saved companion not merged with the live process: %+v", seen)
	}
	if _, ok := seen["legacyplayer"]; !ok {
		t.Fatalf("a saved companion that is not running must still be listed: %+v", seen)
	}
	box, ok := seen["ld9boxheadless.exe"]
	if !ok || !box.Alive || box.Kind != "child" || box.Flows != 2 || box.Down != 20 {
		t.Fatalf("live child counters not merged: %+v", box)
	}
	if helper, ok := seen["helper.exe"]; !ok || helper.Kind != "folder" {
		t.Fatalf("folder member missing: %+v", seen)
	}
}

// scanRules reports companions, inherited children, and folder matches, and
// still finds a rule whose process another overlapping rule caught first.
func TestScanRules(t *testing.T) {
	const exe = `C:\App\app.exe`
	procs := []rules.Process{
		{Name: "app.exe", Path: exe, PID: 1},
		{Name: "helper.exe", Path: `C:\App\helper.exe`, PID: 2, Parents: []rules.Process{{Name: "app.exe", Path: exe}}},
		{Name: "svc.exe", Path: `C:\Elsewhere\svc.exe`, PID: 3},
	}
	rs := []config.Rule{
		{Process: exe, Companions: []string{"svc"}},
		// Also names app.exe explicitly; the first rule takes it.
		{Process: "app"},
	}
	alive, members, running := scanRules(rs, procs)
	first := ruleKey(exe)
	if !alive[first] || !alive["app"] {
		t.Fatalf("alive = %v", alive)
	}
	if len(running[first]) != 3 { // app.exe, the child, and the companion
		t.Fatalf("running = %v", running[first])
	}
	var child, companion bool
	for _, m := range members[first] {
		switch m.Kind {
		case "child":
			child = true
		case "companion":
			companion = true
		}
	}
	if !child || !companion {
		t.Fatalf("members = %+v", members[first])
	}
}

func TestCountDirectRecentOnly(t *testing.T) {
	now := time.Now()
	procs := []engine.DirectProc{
		{Name: "a.exe", LastSeen: now.Add(-30 * time.Second).UnixMilli()},
		{Name: "b.exe", LastSeen: now.Add(-90 * time.Second).UnixMilli()},
		{Name: "c.exe", LastSeen: now.Add(-30 * time.Minute).UnixMilli()},
		{Name: "svchost.exe", LastSeen: now.Add(-time.Second).UnixMilli(), System: true},
	}
	if got := countDirect(procs, now); got != 2 {
		t.Fatalf("countDirect = %d, want 2", got)
	}
}

func TestTopCandidateSkipsIdleAndOtherRule(t *testing.T) {
	cands := []companionCandidate{
		{Name: "idle.exe", Score: 80, Conns: 0, Bytes: 0},
		{Name: "taken.exe", Score: 70, Conns: 5, Bytes: 4096, OtherRule: "other.exe"},
		{Name: "Ld9BoxHeadless.exe", Score: 60, Conns: 3, Bytes: 2048},
		{Name: "weak.exe", Score: 30, Conns: 10, Bytes: 9999},
	}
	got := topCandidate(cands, nil)
	if got == nil || got.Name != "Ld9BoxHeadless.exe" {
		t.Fatalf("topCandidate = %+v, want Ld9BoxHeadless.exe", got)
	}
	if topCandidate([]companionCandidate{{Name: "weak.exe", Score: 44, Conns: 5, Bytes: 1024}}, nil) != nil {
		t.Fatal("expected nil for candidate below score threshold")
	}
}

func TestBuildRuleMembersGlobCompanionAndDedup(t *testing.T) {
	const ruleExe = `C:\Apps\Discord\app-*\Discord.exe`
	const compMask = `C:\Apps\Discord\app-*\DiscordHelper.exe`
	cfg := &config.Config{Rules: []config.Rule{{
		Process:    ruleExe,
		Companions: []string{compMask, compMask, "helper", "helper.exe"},
	}}}
	key := ruleKey(ruleExe)
	// Neither version is currently live, but stats saw traffic from two versions.
	stats := map[string]engine.RuleStat{key: {Procs: []engine.RuleProcStat{
		{Name: "DiscordHelper.exe", Path: `C:\Apps\Discord\app-1.0\DiscordHelper.exe`, Kind: rules.MatchCompanion, Flows: 1, Up: 100, Down: 200},
		{Name: "DiscordHelper.exe", Path: `C:\Apps\Discord\app-2.0\DiscordHelper.exe`, Kind: rules.MatchCompanion, Flows: 2, Up: 300, Down: 400},
	}}}
	got := buildRuleMembers(cfg, stats, nil, nil)[key]
	if len(got) != 2 {
		t.Fatalf("want 2 deduplicated companion rows, got %d: %+v", len(got), got)
	}
	var merged *ruleMemberView
	for i := range got {
		if got[i].Pattern == compMask {
			merged = &got[i]
		}
	}
	if merged == nil || merged.Flows != 3 || merged.Up != 400 || merged.Down != 600 {
		t.Fatalf("glob companion stats not merged: %+v", got)
	}
}

func TestRankCandidatesSkipsSharedUserDirAndPrefersLivePID(t *testing.T) {
	now := time.Now()
	// Rule in Downloads must NOT put C:\Users\me\Downloads in ruleDirs (no false +60 cmdline boost).
	rule := config.Rule{Process: `C:\Users\me\Downloads\portable.exe`, Action: "proxy"}
	ins := &fakeInspector{cmds: map[uint32]string{
		// Live PID 200 references Downloads in its cmdline.
		200: `other.exe --cwd "C:\Users\me\Downloads"`,
		// Stale exited PID 100 would have matched if not overwritten by live runningProcs PID.
		100: `other.exe --from-old-pid`,
	}}
	direct := []engine.DirectProc{{
		Name: "other.exe", Path: `C:\Tools\Other\other.exe`, PID: 100, Started: 111,
		Conns: 1, Bytes: 512, LastSeen: now.UnixMilli(),
	}}
	running := []rules.Process{{
		Name: "other.exe", Path: `C:\Tools\Other\other.exe`, PID: 200, Started: 222,
	}}
	got := rankCandidates(rule, []config.Rule{rule}, nil, direct, running, ins, nil, now)
	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	if got[0].PID != 200 {
		t.Fatalf("PID = %d, want live running PID 200", got[0].PID)
	}
	if hasReason(got[0], "Запущен с путём программы") {
		t.Fatalf("shared Downloads folder gave false cmdline match: %+v", got[0])
	}
}

// An auto match becomes one row with its reason, takes the engine's counters,
// and is not repeated when the same process is also a live child match.
func TestBuildRuleMembersAuto(t *testing.T) {
	const ruleExe = `C:\LDPlayer\ldmutiplayer\dnmultiplayerex.exe`
	const boxExe = `C:\Program Files\ldplayer9box\Ld9BoxHeadless.exe`
	cfg := &config.Config{Rules: []config.Rule{{Process: ruleExe}}}
	key := ruleKey(ruleExe)
	auto := []engine.AutoMatch{{
		RuleKey: key,
		Reason:  "загружает модуль из папки программы",
		Proc:    rules.Process{Name: "Ld9BoxHeadless.exe", Path: boxExe, PID: 200},
	}}
	live := map[string][]liveMember{key: {
		{Name: "Ld9BoxHeadless.exe", Path: boxExe, Kind: "child", PID: 200},
	}}
	stats := map[string]engine.RuleStat{key: {Procs: []engine.RuleProcStat{
		{Name: "Ld9BoxHeadless.exe", Path: boxExe, Kind: rules.MatchAuto, Flows: 2, Up: 10, Down: 20},
	}}}
	got := buildRuleMembers(cfg, stats, live, auto)[key]
	if len(got) != 1 {
		t.Fatalf("want one auto row, got %d: %+v", len(got), got)
	}
	m := got[0]
	if m.Kind != rules.MatchAuto || !m.Alive || m.Reason == "" {
		t.Fatalf("auto row = %+v", m)
	}
	if m.Flows != 2 || m.Up != 10 || m.Down != 20 {
		t.Fatalf("auto row stats not merged: %+v", m)
	}
}

// A process the user already saved as a companion is not listed again as an
// auto match; the saved row just goes alive.
func TestBuildRuleMembersAutoSavedCompanionNoDuplicate(t *testing.T) {
	const ruleExe = `C:\App\app.exe`
	const compExe = `C:\App\svc.exe`
	cfg := &config.Config{Rules: []config.Rule{{Process: ruleExe, Companions: []string{compExe}}}}
	key := ruleKey(ruleExe)
	auto := []engine.AutoMatch{{
		RuleKey: key,
		Reason:  "ссылка в командной строке",
		Proc:    rules.Process{Name: "svc.exe", Path: compExe, PID: 9},
	}}
	got := buildRuleMembers(cfg, nil, nil, auto)[key]
	if len(got) != 1 {
		t.Fatalf("want one saved companion row, got %d: %+v", len(got), got)
	}
	if got[0].Kind != "companion" || !got[0].Alive {
		t.Fatalf("saved companion not merged: %+v", got[0])
	}
}

// HasModuleInDirs is strong, independent evidence: the process loads a DLL
// from the rule's install folder.
func TestRankCandidatesHasModuleInDirs(t *testing.T) {
	now := time.Now()
	const ruleExe = `C:\Games\MyGame\launcher.exe`
	const candExe = `C:\Other\helper.exe`
	ins := &fakeInspector{mods: map[uint32][]string{321: {`C:\Games\MyGame`}}}
	rule := config.Rule{Process: ruleExe, Action: "proxy"}
	ruleRunning := []rules.Process{{Name: "launcher.exe", Path: ruleExe, PID: 100}}
	running := append(ruleRunning, rules.Process{Name: "helper.exe", Path: candExe, PID: 321})
	got := rankCandidates(rule, []config.Rule{rule}, ruleRunning, nil, running, ins, nil, now)
	var cand *companionCandidate
	for i := range got {
		if got[i].Name == "helper.exe" {
			cand = &got[i]
		}
	}
	if cand == nil {
		t.Fatalf("helper.exe missing: %+v", got)
	}
	if !hasReason(*cand, "Загружает модуль программы") {
		t.Fatalf("reasons = %v", cand.Reasons)
	}
	if cand.Score != 60 {
		t.Fatalf("score = %d, want 60", cand.Score)
	}
}

// The rule's own process may have run for hours while a child started a
// second ago; the closest start time must still count.
func TestRankCandidatesRuleStartedFromChild(t *testing.T) {
	now := time.Now()
	const ruleExe = `C:\Android\dnplayer.exe`
	const childExe = `C:\Android\engine.exe`
	const candExe = `C:\Other\cand.exe`
	rule := config.Rule{Process: ruleExe, Action: "proxy"}
	ruleRunning := []rules.Process{
		{Name: "dnplayer.exe", Path: ruleExe, PID: 100, Started: now.Add(-2 * time.Hour).UnixNano()},
		{Name: "engine.exe", Path: childExe, PID: 101, Started: now.Add(-time.Second).UnixNano()},
	}
	running := append(append([]rules.Process(nil), ruleRunning...),
		rules.Process{Name: "cand.exe", Path: candExe, PID: 200, Started: now.UnixNano()})
	got := rankCandidates(rule, []config.Rule{rule}, ruleRunning, nil, running, &fakeInspector{}, nil, now)
	var cand *companionCandidate
	for i := range got {
		if got[i].Name == "cand.exe" {
			cand = &got[i]
		}
	}
	if cand == nil {
		t.Fatalf("cand.exe missing: %+v", got)
	}
	if !hasReason(*cand, "Запущен вместе с программой") {
		t.Fatalf("reasons = %v", cand.Reasons)
	}
	if cand.Score != 15 {
		t.Fatalf("score = %d, want 15", cand.Score)
	}
}

// A shared certificate thumbprint is a strong publisher match even when the
// printed signer strings differ.
func TestRankCandidatesCertThumbprint(t *testing.T) {
	now := time.Now()
	const ruleExe = `C:\Apps\App\app.exe`
	const candExe = `C:\Elsewhere\tool.exe`
	const thumb = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	ins := &fakeInspector{meta: map[string]process.FileMeta{
		strings.ToLower(ruleExe): {Signer: "One Name Inc", CertThumbprint: thumb},
		strings.ToLower(candExe): {Signer: "Other Name LLC", CertThumbprint: strings.ToUpper(thumb)},
	}}
	rule := config.Rule{Process: ruleExe, Action: "proxy"}
	running := []rules.Process{{Name: "tool.exe", Path: candExe, PID: 200}}
	got := rankCandidates(rule, []config.Rule{rule}, nil, nil, running, ins, nil, now)
	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	if !hasReason(got[0], "Тот же издатель") {
		t.Fatalf("reasons = %v", got[0].Reasons)
	}
	if got[0].Score != 50 {
		t.Fatalf("score = %d, want 50", got[0].Score)
	}
}

// A vendor name is compared in whole tokens: "Amdocs" contains "amd" but is
// not the AMD platform vendor, so the publisher stays a strong signal.
func TestRankCandidatesVendorTokenNotSubstring(t *testing.T) {
	now := time.Now()
	const ruleExe = `C:\Apps\Billing\billing.exe`
	const candExe = `C:\Other\helper.exe`
	const signer = "Amdocs Ltd"
	ins := &fakeInspector{meta: map[string]process.FileMeta{
		strings.ToLower(ruleExe): {Signer: signer},
		strings.ToLower(candExe): {Signer: signer},
	}}
	rule := config.Rule{Process: ruleExe, Action: "proxy"}
	running := []rules.Process{{Name: "helper.exe", Path: candExe, PID: 200}}
	got := rankCandidates(rule, []config.Rule{rule}, nil, nil, running, ins, nil, now)
	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	if got[0].Score != 50 {
		t.Fatalf("score = %d, want 50 (a common-vendor substring would give 10)", got[0].Score)
	}
}

// Strong direct traffic is suggested even while the rule is not quiet: a
// launcher may already have sent a burst of its own.
func TestStrongCandidateWhileRuleNotQuiet(t *testing.T) {
	cands := []companionCandidate{
		{Name: "Ld9BoxHeadless.exe", Score: 70, Conns: 3, Bytes: 864 * 1024},
	}
	if got := strongCandidate(cands, nil); got == nil || got.Name != "Ld9BoxHeadless.exe" {
		t.Fatalf("strongCandidate = %+v", got)
	}
	if strongCandidate([]companionCandidate{{Name: "x", Score: 64, Conns: 5, Bytes: 99999}}, nil) != nil {
		t.Fatal("a below-threshold score must not be suggested")
	}
	if strongCandidate([]companionCandidate{{Name: "x", Score: 80, Conns: 1, Bytes: 1024}}, nil) != nil {
		t.Fatal("too little traffic must not be suggested")
	}
}

// A process the user excluded from the rule's auto-pickup is never suggested,
// by either hint path.
func TestCandidatesSkipExcluded(t *testing.T) {
	rule := config.Rule{Process: `C:\App\app.exe`, ExcludeCompanions: []string{`C:\Other\excluded.exe`}}
	set := rules.Compile([]config.Rule{rule})
	cands := []companionCandidate{
		{Name: "excluded.exe", Path: `C:\Other\excluded.exe`, Score: 90, Conns: 5, Bytes: 50000},
		{Name: "ok.exe", Path: `C:\Other\ok.exe`, Score: 60, Conns: 2, Bytes: 4096},
	}
	got := topCandidate(cands, set)
	if got == nil || got.Name != "ok.exe" {
		t.Fatalf("topCandidate = %+v, want ok.exe", got)
	}
	if strongCandidate(cands[:1], set) != nil {
		t.Fatal("an excluded candidate must not be suggested as strong")
	}
}

// A process the auto matcher already attributes to the rule is not offered
// again as a candidate.
func TestRankCandidatesSkipsAutoCovered(t *testing.T) {
	now := time.Now()
	const ruleExe = `C:\LDPlayer\ldmutiplayer\dnmultiplayerex.exe`
	const boxExe = `C:\Program Files\ldplayer9box\Ld9BoxHeadless.exe`
	rule := config.Rule{Process: ruleExe, Action: "proxy"}
	auto := []engine.AutoMatch{{
		RuleKey: ruleKey(ruleExe),
		Reason:  "загружает модуль из папки программы",
		Proc:    rules.Process{Name: "Ld9BoxHeadless.exe", Path: boxExe, PID: 200},
	}}
	direct := []engine.DirectProc{{
		Name: "Ld9BoxHeadless.exe", Path: boxExe, PID: 200,
		Conns: 3, Bytes: 100_000, LastSeen: now.UnixMilli(),
	}}
	running := []rules.Process{{Name: "Ld9BoxHeadless.exe", Path: boxExe, PID: 200}}
	got := rankCandidates(rule, []config.Rule{rule}, nil, direct, running, &fakeInspector{}, auto, now)
	for _, c := range got {
		if strings.EqualFold(c.Name, "Ld9BoxHeadless.exe") {
			t.Fatalf("an auto-covered process was offered: %+v", c)
		}
	}
}

func TestEventsToViewsNewestFirst(t *testing.T) {
	t0 := time.Date(2026, 11, 27, 12, 0, 1, 0, time.UTC)
	evs := []logbuf.Event{
		{Time: t0, Process: "first.exe", Dest: "1.1.1.1:80"},
		{Time: t0.Add(time.Second), Process: "second.exe", Dest: "2.2.2.2:80"},
	}
	views := eventsToViews(evs)
	if len(views) != 2 || views[0].Process != "second.exe" || views[1].Process != "first.exe" {
		t.Fatalf("eventsToViews order = %+v, want newest first", views)
	}
}
