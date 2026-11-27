package engine

import (
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ashgate/internal/config"
	"ashgate/internal/process"
	"ashgate/internal/rules"
)

// The auto matcher picks up the processes a rule's application starts or
// shares its installation with but that neither the process tree nor the
// install-folder match can attribute to it: a headless VM started by a
// service, a helper in a sibling folder. It learns a profile from the
// processes the rules already match and asks the inspector for the three
// signals that survive PID churn: loaded modules, the command line, and the
// code signature.
//
// It never changes the configuration on disk and never writes the config in
// memory. Its whole state is one immutable table published atomically, so
// the packet path reads a match with a single atomic load.

// AutoInspector is the metadata source of the auto matcher. process.Inspector
// implements it; tests replace it.
type AutoInspector interface {
	FileMetadata(path string) process.FileMeta
	CommandLine(pid uint32, started int64) string
	HasModuleInDirs(pid uint32, started int64, dirs []string) bool
}

// AutoMatch is one process the auto matcher attributed to a rule.
type AutoMatch struct {
	RuleIndex  int
	RuleKey    string
	RuleName   string
	Action     string
	Proxy      string
	KillSwitch bool
	TCPOnly    bool
	// Reason is the signal that matched, for the window and the log.
	Reason string
	// Proc is the matched candidate, not the rule's own process.
	Proc rules.Process
}

// pidKey identifies a running process even after Windows reuses its PID.
type pidKey struct {
	pid     uint32
	started int64
}

// autoTable is the matcher's immutable state. It is replaced, never mutated.
type autoTable struct {
	gen          uint64
	hasAutoRules bool
	byPID        map[pidKey]AutoMatch
	byPath       map[string]AutoMatch
	decided      map[pidKey]struct{}
}

// autoState is one configuration generation; configure bumps it.
type autoState struct {
	raw  []config.Rule
	set  *rules.Set
	keys []string
	gen  uint64
}

// autoNote is one process a rule matched, sent by the packet path so its
// install folder reaches the profile without waiting for a fresh snapshot.
type autoNote struct {
	rule int
	proc rules.Process
	at   time.Time
}

// ruleProfile is what the live processes of one rule teach about the
// application: where it lives, what it is called, who signed it, and when it
// started.
type ruleProfile struct {
	ruleIndex   int
	ruleKey     string
	ruleName    string
	action      string
	proxy       string
	killSwitch  bool
	tcpOnly     bool
	dirs        []string
	exes        []string
	tokens      map[string]struct{}
	thumbprints map[string]string
	started     []int64
}

const (
	// defaultAutoRefresh is how often the matcher re-reads the process list.
	defaultAutoRefresh = 2 * time.Second
	// autoSnapStale is how old a snapshot may be when a candidate needs one.
	autoSnapStale = time.Second
	// autoTimeWindow is how close two start times must be to count as one
	// application launch.
	autoTimeWindow = 30 * time.Second
	// autoNoteKeep bounds how long an unmatched note is kept when its process
	// does not appear in a snapshot.
	autoNoteKeep = 10 * time.Second
	autoPendBuf  = 256
	autoNoteBuf  = 256
	autoNotesMax = 512
)

// autoMatcher owns the background pass that classifies candidates. The zero
// value is not usable; call newAutoMatcher.
type autoMatcher struct {
	ins     AutoInspector
	snapFn  func() []rules.Process
	refresh time.Duration
	onMatch func(AutoMatch)

	tbl atomic.Pointer[autoTable]

	wake     chan struct{}
	pend     chan rules.Process
	note     chan autoNote
	stopCh   chan struct{}
	done     chan struct{}
	stopOnce sync.Once

	mu  sync.Mutex
	st  *autoState
	gen uint64

	// The fields below belong to the run goroutine.
	procs       []rules.Process
	lastSnap    time.Time
	snapGen     uint64
	lastProfSig string
	notes       map[pidKey]autoNote
}

// newAutoMatcher starts the background pass. onMatch, when not nil, is called
// outside all matcher locks for every newly matched process.
func newAutoMatcher(ins AutoInspector, snapFn func() []rules.Process, refresh time.Duration, onMatch func(AutoMatch)) *autoMatcher {
	if snapFn == nil {
		snapFn = process.Snapshot
	}
	if refresh <= 0 {
		refresh = defaultAutoRefresh
	}
	m := &autoMatcher{
		ins:     ins,
		snapFn:  snapFn,
		refresh: refresh,
		onMatch: onMatch,
		wake:    make(chan struct{}, 1),
		pend:    make(chan rules.Process, autoPendBuf),
		note:    make(chan autoNote, autoNoteBuf),
		stopCh:  make(chan struct{}),
		done:    make(chan struct{}),
		notes:   map[pidKey]autoNote{},
	}
	go m.run()
	return m
}

// stop ends the background goroutine and waits for it. It is idempotent.
func (m *autoMatcher) stop() {
	if m == nil {
		return
	}
	m.stopOnce.Do(func() { close(m.stopCh) })
	<-m.done
}

// poke wakes the run goroutine without blocking; a burst collapses to one
// wake because the channel holds one value.
func (m *autoMatcher) poke() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// configure installs a new rule generation and drops everything learned from
// the previous one. It publishes an empty table at once, so the packet path
// knows an auto rule exists before the first background pass finishes.
func (m *autoMatcher) configure(raw []config.Rule, set *rules.Set, keys []string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.gen++
	st := &autoState{raw: raw, set: set, keys: keys, gen: m.gen}
	m.st = st
	m.tbl.Store(&autoTable{
		gen:          st.gen,
		hasAutoRules: hasAutoRules(raw),
		byPID:        map[pidKey]AutoMatch{},
		byPath:       map[string]AutoMatch{},
		decided:      map[pidKey]struct{}{},
	})
	m.mu.Unlock()
	m.poke()
}

// table returns the current immutable table (nil before the first configure).
func (m *autoMatcher) table() *autoTable {
	if m == nil {
		return nil
	}
	return m.tbl.Load()
}

// lookup is the packet-path read: one atomic load, then map reads on the
// immutable table.
func (m *autoMatcher) lookup(p rules.Process) (am AutoMatch, ok, decided, hasRules bool) {
	if m == nil {
		return AutoMatch{}, false, false, false
	}
	t := m.tbl.Load()
	if t == nil {
		return AutoMatch{}, false, false, false
	}
	hasRules = t.hasAutoRules
	k := pidKey{pid: p.PID, started: p.Started}
	if am, ok = t.byPID[k]; ok {
		return am, true, true, hasRules
	}
	if path := rules.NormalizePath(p.Path); path != "" {
		if am, ok = t.byPath[path]; ok {
			return am, true, true, hasRules
		}
	}
	_, decided = t.decided[k]
	return AutoMatch{}, false, decided, hasRules
}

// enqueue asks the background pass to classify p. It never blocks: a full
// queue drops the request, and the candidate is offered again by its next
// packet because it is not yet in decided.
func (m *autoMatcher) enqueue(p rules.Process) {
	if m == nil {
		return
	}
	select {
	case m.pend <- p:
	default:
		return
	}
	m.poke()
}

// noteRuleProc records a process the rules already matched, so its install
// folder joins the rule's profile without waiting for a new snapshot.
func (m *autoMatcher) noteRuleProc(ruleIdx int, p rules.Process) {
	if m == nil || ruleIdx < 0 {
		return
	}
	select {
	case m.note <- autoNote{rule: ruleIdx, proc: p, at: time.Now()}:
	default:
	}
}

// run is the matcher's single background goroutine. Periodic wakes happen
// only while some enabled rule covers children; otherwise only configure and
// enqueue wake it.
func (m *autoMatcher) run() {
	defer close(m.done)
	tick := time.NewTicker(m.refresh)
	defer tick.Stop()
	for {
		has := false
		if t := m.tbl.Load(); t != nil {
			has = t.hasAutoRules
		}
		var ticks <-chan time.Time
		if has {
			ticks = tick.C
		}
		select {
		case <-m.stopCh:
			return
		case <-m.wake:
		case <-ticks:
		}
		m.pass()
	}
}

// pass classifies this generation's candidates against the live rules.
func (m *autoMatcher) pass() {
	m.mu.Lock()
	st := m.st
	m.mu.Unlock()
	if st == nil || st.set == nil {
		return
	}
	prev := m.tbl.Load()
	var prevByPID map[pidKey]AutoMatch
	var prevDecided map[pidKey]struct{}
	if prev != nil && prev.gen == st.gen {
		prevByPID = prev.byPID
		prevDecided = prev.decided
	}

	now := time.Now()
	m.drainNotes()

	var pending []rules.Process
	for {
		select {
		case p := <-m.pend:
			pending = append(pending, p)
		default:
			goto drained
		}
	}
drained:

	refreshedSnap := false
	if m.lastSnap.IsZero() || m.snapGen != st.gen || now.Sub(m.lastSnap) >= m.refresh ||
		(len(pending) > 0 && now.Sub(m.lastSnap) >= autoSnapStale) {
		m.procs = m.snapFn()
		m.lastSnap = now
		m.snapGen = st.gen
		refreshedSnap = true
	}
	procs := m.procs

	alive := make(map[pidKey]rules.Process, len(procs))
	for _, p := range procs {
		alive[pidKey{pid: p.PID, started: p.Started}] = p
	}
	// A note whose process is in the snapshot is already covered by it; an
	// old note that never showed up belongs to a process already gone.
	for k, n := range m.notes {
		if _, ok := alive[k]; ok || now.Sub(n.at) > autoNoteKeep {
			delete(m.notes, k)
		}
	}

	autoRules := autoRuleIndexes(st.raw)
	autoSet := make(map[int]bool, len(autoRules))
	for _, ridx := range autoRules {
		autoSet[ridx] = true
	}
	liveProcs := make(map[int][]rules.Process, len(autoRules))
	for _, p := range procs {
		dec := st.set.Match(p)
		if dec.Action == "" || !autoSet[dec.RuleIndex] {
			continue
		}
		liveProcs[dec.RuleIndex] = append(liveProcs[dec.RuleIndex], p)
	}
	for k, n := range m.notes {
		if !autoSet[n.rule] {
			continue
		}
		dup := false
		for _, p := range liveProcs[n.rule] {
			if (pidKey{pid: p.PID, started: p.Started}) == k {
				dup = true
				break
			}
		}
		if !dup {
			liveProcs[n.rule] = append(liveProcs[n.rule], n.proc)
		}
	}

	profiles := make(map[int]*ruleProfile, len(autoRules))
	for _, ridx := range autoRules {
		if len(liveProcs[ridx]) == 0 {
			continue
		}
		profiles[ridx] = m.buildProfile(st, ridx, liveProcs[ridx])
	}

	next := &autoTable{
		gen:          st.gen,
		hasAutoRules: len(autoRules) > 0,
		byPID:        make(map[pidKey]AutoMatch, len(prevByPID)),
		byPath:       make(map[string]AutoMatch),
		decided:      make(map[pidKey]struct{}, len(prevDecided)),
	}
	liveRules := make(map[int]bool, len(profiles))
	for ridx := range profiles {
		liveRules[ridx] = true
	}
	// decided is per generation, but when the active rule profiles change (a
	// rule's app starts, or a child process adds a new install folder like
	// C:\LDPlayer\LDPlayer9), drop negative decisions so pre-running services
	// are re-evaluated against the new profile.
	profSig := profileSignature(st.gen, profiles)
	if profSig == m.lastProfSig {
		for k := range prevDecided {
			if !refreshedSnap {
				next.decided[k] = struct{}{}
				continue
			}
			if _, ok := alive[k]; ok {
				next.decided[k] = struct{}{}
			}
		}
	}
	m.lastProfSig = profSig
	// A match stays while its candidate lives (pruned only against a fresh
	// snapshot so a newly started PID is never dropped by a stale one). Its
	// path entry is only kept for rules that are still live: a rule whose
	// application exited no longer attributes anything.
	for k, am := range prevByPID {
		if refreshedSnap {
			if _, ok := alive[k]; !ok {
				continue
			}
		}
		next.byPID[k] = am
		next.decided[k] = struct{}{}
		if liveRules[am.RuleIndex] {
			if path := rules.NormalizePath(am.Proc.Path); path != "" {
				next.byPath[path] = am
			}
		}
	}

	var added []AutoMatch
	classify := func(cand rules.Process) {
		k := pidKey{pid: cand.PID, started: cand.Started}
		if _, done := next.decided[k]; done {
			return
		}
		next.decided[k] = struct{}{}
		if m.reject(st.set, cand) {
			return
		}
		am, ok := m.classifyOne(st, cand, profiles)
		if !ok {
			return
		}
		next.byPID[k] = am
		if path := rules.NormalizePath(am.Proc.Path); path != "" {
			next.byPath[path] = am
		}
		if _, existed := prevByPID[k]; !existed {
			added = append(added, am)
		}
	}
	for _, p := range pending {
		classify(p)
	}
	// A candidate is decided once per generation, so a service process is only
	// judged when some rule has a profile to judge it against: marking it
	// rejected while every rule's application is stopped would keep it from
	// ever being attributed after the application starts.
	if len(profiles) > 0 {
		for _, p := range procs {
			if !rules.IsServiceOrCOMAncestor(p) {
				continue
			}
			classify(p)
		}
	}

	m.mu.Lock()
	current := m.st
	if current == nil || current.gen != st.gen {
		m.mu.Unlock()
		return
	}
	m.tbl.Store(next)
	m.mu.Unlock()

	for _, am := range added {
		if m.onMatch != nil {
			m.onMatch(am)
		}
	}
}

// drainNotes folds the packet path's rule matches into m.notes.
func (m *autoMatcher) drainNotes() {
	for {
		select {
		case n := <-m.note:
			k := pidKey{pid: n.proc.PID, started: n.proc.Started}
			if len(m.notes) >= autoNotesMax {
				clear(m.notes)
			}
			m.notes[k] = n
		default:
			return
		}
	}
}

// hasAutoRules reports whether any enabled rule covers children and does
// something.
func hasAutoRules(raw []config.Rule) bool {
	for _, r := range raw {
		if r.IsEnabled() && r.CoversChildren() && r.Action != "" {
			return true
		}
	}
	return false
}

// autoRuleIndexes lists the positions of the rules that take part.
func autoRuleIndexes(raw []config.Rule) []int {
	out := make([]int, 0, len(raw))
	for i, r := range raw {
		if r.IsEnabled() && r.CoversChildren() && r.Action != "" {
			out = append(out, i)
		}
	}
	return out
}

// buildProfile learns from the rule itself and from every live process the
// rule already matches. Collecting from the matched children is what brings
// a sibling install folder (the emulator in C:\LDPlayer\LDPlayer9 next to the
// launcher in C:\LDPlayer\ldmutiplayer) into the profile.
func (m *autoMatcher) buildProfile(st *autoState, ridx int, live []rules.Process) *ruleProfile {
	r := st.raw[ridx]
	prof := &ruleProfile{
		ruleIndex:   ridx,
		action:      r.Action,
		proxy:       r.Proxy,
		killSwitch:  r.RuleKillSwitch(),
		tcpOnly:     r.TCPOnly,
		tokens:      map[string]struct{}{},
		thumbprints: map[string]string{},
	}
	if ridx < len(st.keys) {
		prof.ruleKey = st.keys[ridx]
	}
	if prof.ruleKey == "" {
		prof.ruleKey = RuleKey(r.Process)
	}
	prof.ruleName = rules.Base(r.Process)
	if prof.ruleName == "" {
		prof.ruleName = r.Process
	}

	dirSeen := map[string]bool{}
	exeSeen := map[string]bool{}
	addDir := func(raw string) {
		d := rules.CompanionDir(raw)
		if d == "" || dirSeen[d] {
			return
		}
		dirSeen[d] = true
		prof.dirs = append(prof.dirs, d)
	}
	addExe := func(raw string) {
		if raw == "" || strings.ContainsAny(raw, "*?") {
			return
		}
		name := rules.Base(raw)
		if name == "" || strings.ContainsAny(name, "*?") || exeSeen[name] {
			return
		}
		// A generic host runs other programs' code: its name on a command line
		// says nothing about the rule's application.
		if genericHostExes[name] {
			return
		}
		exeSeen[name] = true
		prof.exes = append(prof.exes, name)
	}
	addTokens := func(raw string) {
		for _, t := range rules.ProductTokens(raw) {
			prof.tokens[t] = struct{}{}
		}
	}
	addThumb := func(raw string) {
		path := strings.Trim(strings.TrimSpace(raw), `"`)
		if path == "" || strings.ContainsAny(path, "*?") || !rules.IsPath(path) {
			return
		}
		meta := m.ins.FileMetadata(path)
		if meta.CertThumbprint == "" || rules.IsCommonVendor(meta.Signer) {
			return
		}
		prof.thumbprints[meta.CertThumbprint] = meta.Signer
	}

	addDir(r.Process)
	addExe(r.Process)
	addTokens(r.Process)
	addThumb(r.Process)
	for _, c := range r.Companions {
		addDir(c)
		addExe(c)
		addTokens(c)
		addThumb(c)
	}
	for _, p := range live {
		// System and shell processes run on behalf of everything; a helper they
		// start (cmd.exe, powershell.exe, conhost.exe) must not teach the
		// profile its own folder or name.
		if p.PID <= 4 || rules.IsShellOrSystem(p) || rules.IsSystemPath(p.Path) || rules.IsSystemDNS(p.Name) {
			continue
		}
		addDir(p.Path)
		addExe(p.Name)
		addExe(p.Path)
		addTokens(p.Path)
		addTokens(p.Name)
		addThumb(p.Path)
		if p.Started != 0 {
			prof.started = append(prof.started, p.Started)
		}
	}
	return prof
}

// reject applies the gates that keep the auto matcher away from system
// processes and from anything a rule already names.
func (m *autoMatcher) reject(set *rules.Set, p rules.Process) bool {
	if p.PID <= 4 {
		return true
	}
	if rules.IsShellOrSystem(p) {
		return true
	}
	if rules.IsSystemDNS(p.Name) {
		return true
	}
	if rules.IsSystemPath(p.Path) {
		return true
	}
	if set != nil && set.Match(p).Action != "" {
		return true
	}
	return false
}

// classifyOne picks the strongest signal among the live rule profiles. On a
// tie the lower rule index wins.
func (m *autoMatcher) classifyOne(st *autoState, cand rules.Process, profiles map[int]*ruleProfile) (AutoMatch, bool) {
	best, bestRank, bestReason := -1, 0, ""
	var meta process.FileMeta
	metaDone := false
	cmd := ""
	cmdDone := false
	for ridx := 0; ridx < len(st.raw); ridx++ {
		prof := profiles[ridx]
		if prof == nil {
			continue
		}
		if st.set.IsExcluded(ridx, cand) {
			continue
		}
		rank, reason := m.rankOf(prof, cand, &meta, &metaDone, &cmd, &cmdDone)
		if rank > bestRank {
			best, bestRank, bestReason = ridx, rank, reason
		}
	}
	if best < 0 {
		return AutoMatch{}, false
	}
	prof := profiles[best]
	return AutoMatch{
		RuleIndex:  prof.ruleIndex,
		RuleKey:    prof.ruleKey,
		RuleName:   prof.ruleName,
		Action:     prof.action,
		Proxy:      prof.proxy,
		KillSwitch: prof.killSwitch,
		TCPOnly:    prof.tcpOnly,
		Reason:     bestReason,
		Proc:       cand,
	}, true
}

// rankOf returns the strongest signal prof gives for cand, or 0.
//
//	4  a module loaded from the rule's or a matched child's folder
//	3  a path to the folder, or an executable name, on the command line
//	2  a shared uncommon signer plus a service/COM origin plus a path token
//	   or a launch time within autoTimeWindow
//	1  a shared uncommon signer plus a non-vendor path token
func (m *autoMatcher) rankOf(prof *ruleProfile, cand rules.Process, meta *process.FileMeta, metaDone *bool, cmd *string, cmdDone *bool) (int, string) {
	if len(prof.dirs) > 0 && m.ins.HasModuleInDirs(cand.PID, cand.Started, prof.dirs) {
		return 4, "загружает модуль из папки программы"
	}
	if len(prof.dirs) > 0 || len(prof.exes) > 0 {
		if !*cmdDone {
			*cmd = m.ins.CommandLine(cand.PID, cand.Started)
			*cmdDone = true
		}
		if rules.CommandLineMatches(*cmd, prof.dirs, prof.exes) {
			return 3, "ссылка в командной строке"
		}
	}
	if len(prof.thumbprints) == 0 || cand.Path == "" {
		return 0, ""
	}
	if !*metaDone {
		*meta = m.ins.FileMetadata(cand.Path)
		*metaDone = true
	}
	if meta.CertThumbprint == "" || rules.IsCommonVendor(meta.Signer) || prof.thumbprints[meta.CertThumbprint] == "" {
		return 0, ""
	}
	if rules.IsServiceOrCOMAncestor(cand) {
		if tokensOverlap(candTokens(cand), prof.tokens) {
			return 2, "общая подпись + служба/COM"
		}
		if withinStartWindow(cand.Started, prof.started) {
			return 2, "общая подпись + служба/COM + время запуска"
		}
		return 0, ""
	}
	if tokensOverlap(rules.NonVendorTokens(cand.Path, meta.Signer), prof.tokens) {
		return 1, "общая подпись + имя пути"
	}
	return 0, ""
}

// genericHostExes are interpreters and utilities many unrelated programs
// start. Learning one of them from a rule's process tree would make any
// process whose command line mentions it look like a companion.
var genericHostExes = map[string]bool{
	"cmd.exe": true, "powershell.exe": true, "pwsh.exe": true, "conhost.exe": true,
	"wscript.exe": true, "cscript.exe": true, "rundll32.exe": true, "regsvr32.exe": true,
	"msiexec.exe": true, "node.exe": true, "java.exe": true, "javaw.exe": true,
	"python.exe": true, "pythonw.exe": true, "ffmpeg.exe": true, "curl.exe": true,
	"tar.exe": true, "git.exe": true, "bash.exe": true, "sh.exe": true,
}

// candTokens is the path's tokens plus the image name's, so a process whose
// path is unreadable still matches by name.
func candTokens(p rules.Process) []string {
	out := rules.ProductTokens(p.Path)
	if p.Name != "" {
		out = append(out, rules.ProductTokens(p.Name)...)
	}
	return out
}

// tokensOverlap reports one shared token.
func tokensOverlap(tokens []string, profile map[string]struct{}) bool {
	for _, t := range tokens {
		if _, ok := profile[t]; ok {
			return true
		}
	}
	return false
}

// withinStartWindow reports that started is close to one of the launch
// times. started == 0 is unknown and never matches.
func withinStartWindow(started int64, times []int64) bool {
	if started == 0 {
		return false
	}
	for _, ts := range times {
		if ts == 0 {
			continue
		}
		d := started - ts
		if d < 0 {
			d = -d
		}
		if d <= int64(autoTimeWindow) {
			return true
		}
	}
	return false
}

// autoProcKey is the key directTracker gives proc; the engine prunes it when
// the auto matcher attributes the process to a rule.
func autoProcKey(p rules.Process) string {
	key := rules.NormalizePath(p.Path)
	if key == "" {
		key = rules.NormalizeName(p.Name)
	}
	return key
}

// profileSignature summarizes the active rule profiles for one generation so
// that when a new app starts or a child adds a sibling folder, negative
// decisions are cleared and pre-running services get another look.
func profileSignature(gen uint64, profiles map[int]*ruleProfile) string {
	if len(profiles) == 0 {
		return strconv.FormatUint(gen, 10)
	}
	idxs := make([]int, 0, len(profiles))
	for ridx := range profiles {
		idxs = append(idxs, ridx)
	}
	sort.Ints(idxs)
	var b strings.Builder
	b.WriteString(strconv.FormatUint(gen, 10))
	for _, ridx := range idxs {
		prof := profiles[ridx]
		b.WriteByte('|')
		b.WriteString(strconv.Itoa(ridx))
		b.WriteByte(':')
		dirs := append([]string(nil), prof.dirs...)
		sort.Strings(dirs)
		for _, d := range dirs {
			b.WriteString(d)
			b.WriteByte(',')
		}
		b.WriteByte(';')
		thumbs := make([]string, 0, len(prof.thumbprints))
		for tp := range prof.thumbprints {
			thumbs = append(thumbs, tp)
		}
		sort.Strings(thumbs)
		for _, tp := range thumbs {
			b.WriteString(tp)
			b.WriteByte(',')
		}
		b.WriteByte('#')
		b.WriteString(strconv.Itoa(len(prof.started)))
	}
	return b.String()
}
