package gui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"ashgate/internal/config"
	"ashgate/internal/engine"
	"ashgate/internal/process"
	"ashgate/internal/rules"
)

// metaInspector is the part of process.Inspector companion scoring needs.
// An interface keeps the scoring testable without touching real files.
type metaInspector interface {
	FileMetadata(path string) process.FileMeta
	CommandLine(pid uint32, started int64) string
	HasModuleInDirs(pid uint32, started int64, dirs []string) bool
}

// ruleMemberView is one companion, auto-matched, child, or folder member of a
// rule, as the Apps tab shows it under the rule's row.
type ruleMemberView struct {
	Name    string `json:"name"`
	Path    string `json:"path,omitempty"`
	Pattern string `json:"pattern,omitempty"`
	Kind    string `json:"kind"` // "companion" | "auto" | "child" | "folder"
	Alive   bool   `json:"alive"`
	Flows   int64  `json:"flows"`
	Up      int64  `json:"up"`
	Down    int64  `json:"down"`
	Mask    string `json:"mask,omitempty"`
	// Reason is the signal that auto-attributed the process, if it was.
	Reason string `json:"reason,omitempty"`
}

// companionCandidate is a running or recently direct program the user can
// attach to a rule as a companion, with the signals that suggest it.
type companionCandidate struct {
	Name        string   `json:"name"`
	Path        string   `json:"path"`
	PID         uint32   `json:"pid,omitempty"`
	Mask        string   `json:"mask,omitempty"`
	Conns       int64    `json:"conns"`
	Bytes       int64    `json:"bytes"`
	LastSeen    int64    `json:"lastSeen,omitempty"`
	SampleDests []string `json:"sampleDests,omitempty"`
	Score       int      `json:"score"`
	Reasons     []string `json:"reasons,omitempty"`
	System      bool     `json:"system,omitempty"`
	Running     bool     `json:"running"`
	OtherRule   string   `json:"otherRule,omitempty"`
}

// ruleHintView is the suggestion the Apps tab shows for a rule whose app is
// running but silent: a candidate companion, or a plain "quiet" mark.
type ruleHintView struct {
	Quiet        bool                `json:"quiet,omitempty"`
	TopCandidate *companionCandidate `json:"topCandidate,omitempty"`
}

const (
	// quietRuleDelay is how long a proxy rule must have been running with no
	// traffic before the page looks for a missing companion.
	quietRuleDelay = 10 * time.Second
	// hintsEvery is how often the background hint scan may run.
	hintsEvery = 2 * time.Second
	// directRecent is the window of direct traffic that counts as current.
	directRecent = 2 * time.Minute
	// candidateLimit bounds the list the page receives.
	candidateLimit = 80
)

// buildRuleMembers merges what the config saved, what the auto matcher
// attributed, what is running now, and what the engine counted into one list
// per rule. The rule's own process is not repeated in the list (the engine
// reports it as an exact match).
func buildRuleMembers(cfg *config.Config, stats map[string]engine.RuleStat, live map[string][]liveMember, auto []engine.AutoMatch) map[string][]ruleMemberView {
	if cfg == nil {
		return nil
	}
	out := map[string][]ruleMemberView{}
	for _, r := range cfg.Rules {
		key := ruleKey(r.Process)
		if key == "" {
			continue
		}
		var list []ruleMemberView
		var comps []*rules.Set
		seenComp := map[string]bool{}
		for _, raw := range r.Companions {
			comp := strings.Trim(strings.TrimSpace(raw), `"`)
			if comp == "" {
				continue
			}
			ck := procKey("", comp)
			if rules.IsPath(comp) {
				ck = rules.NormalizePath(comp)
			}
			if seenComp[ck] {
				continue
			}
			seenComp[ck] = true
			v := ruleMemberView{Name: displayBase(comp), Kind: "companion", Pattern: comp}
			if rules.IsPath(comp) {
				v.Path = comp
			}
			if mask, ok := rules.VersionMask(comp); ok {
				v.Mask = mask
			}
			list = append(list, v)
			comps = append(comps, rules.Compile([]config.Rule{{Process: comp, Action: "direct"}}))
		}
		savedFor := func(name, path string) int {
			for i, set := range comps {
				// Only a companion itself, not a process that merely lives in
				// its folder: that one is a child and keeps its own row.
				dec := set.Match(rules.Process{Name: name, Path: path})
				if dec.Action != "" && (dec.MatchKind == rules.MatchExact || dec.MatchKind == rules.MatchCompanion) {
					return i
				}
			}
			return -1
		}
		// autoFor finds the auto row an auto match or a live/stat process
		// still belongs to, so it is not listed twice.
		autoFor := func(name, path string) int {
			for i := range list {
				if list[i].Kind != rules.MatchAuto {
					continue
				}
				if sameProc(list[i].Path, list[i].Name, path, name) {
					return i
				}
			}
			return -1
		}
		autoReason := func(name, path string) string {
			for _, am := range auto {
				if am.RuleKey != key {
					continue
				}
				if sameProc(am.Proc.Path, am.Proc.Name, path, name) {
					return am.Reason
				}
			}
			return ""
		}
		for _, am := range auto {
			if am.RuleKey != key {
				continue
			}
			p := am.Proc
			if i := savedFor(p.Name, p.Path); i >= 0 {
				v := &list[i]
				v.Alive = true
				if p.Path != "" {
					v.Path = p.Path
				}
				if p.Name != "" {
					v.Name = p.Name
				}
				continue
			}
			i := autoFor(p.Name, p.Path)
			if i < 0 {
				i = len(list)
				list = append(list, ruleMemberView{Kind: rules.MatchAuto})
			}
			v := &list[i]
			v.Kind = rules.MatchAuto
			v.Alive = true
			v.Reason = am.Reason
			if p.Path != "" {
				v.Path = p.Path
				if mask, ok := rules.VersionMask(p.Path); ok {
					v.Mask = mask
				}
			}
			if p.Name != "" {
				v.Name = p.Name
			} else if v.Name == "" {
				v.Name = displayBase(p.Path)
			}
		}
		for _, m := range live[key] {
			if i := savedFor(m.Name, m.Path); i >= 0 {
				v := &list[i]
				v.Alive = true
				if m.Path != "" {
					v.Path = m.Path
				}
				if m.Name != "" {
					v.Name = m.Name
				}
				continue
			}
			// A process the auto matcher already attributed keeps its auto
			// row; a live match only confirms it is running.
			if i := autoFor(m.Name, m.Path); i >= 0 {
				list[i].Alive = true
				continue
			}
			name := m.Name
			if name == "" {
				name = displayBase(m.Path)
			}
			list = append(list, ruleMemberView{Name: name, Path: m.Path, Kind: memberKind(m.Kind), Alive: true})
		}
		for _, p := range stats[key].Procs {
			if p.Kind == rules.MatchExact {
				continue
			}
			// Match against compiled saved companions first so glob companions
			// (e.g. app-*\helper.exe) merge stats even when not currently live.
			idx := savedFor(p.Name, p.Path)
			if idx < 0 {
				idx = autoFor(p.Name, p.Path)
			}
			if idx < 0 {
				for i := range list {
					if sameProc(list[i].Path, list[i].Name, p.Path, p.Name) {
						idx = i
						break
					}
				}
			}
			if idx >= 0 {
				list[idx].Flows += p.Flows
				list[idx].Up += p.Up
				list[idx].Down += p.Down
				if list[idx].Path == "" && p.Path != "" {
					list[idx].Path = p.Path
				}
				if list[idx].Kind == "" {
					list[idx].Kind = memberKind(p.Kind)
				}
				if list[idx].Reason == "" {
					list[idx].Reason = autoReason(p.Name, p.Path)
				}
				continue
			}
			name := p.Name
			if name == "" {
				name = displayBase(p.Path)
			}
			var mask string
			if p.Path != "" {
				mask, _ = rules.VersionMask(p.Path)
			}
			list = append(list, ruleMemberView{
				Name: name, Path: p.Path, Kind: memberKind(p.Kind), Reason: autoReason(p.Name, p.Path), Mask: mask,
				Flows: p.Flows, Up: p.Up, Down: p.Down,
			})
		}
		if len(list) == 0 {
			continue
		}
		sortRuleMembers(list)
		out[key] = list
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// memberKind normalizes an engine or live match kind for the page.
func memberKind(kind string) string {
	switch kind {
	case "companion", "child", "folder", rules.MatchAuto:
		return kind
	}
	return "child"
}

// memberKindRank puts saved companions first (what the user chose), then the
// processes the auto matcher found unprompted, then the inherited children.
func memberKindRank(kind string) int {
	switch kind {
	case "companion":
		return 0
	case rules.MatchAuto:
		return 1
	case "child":
		return 2
	case "folder":
		return 3
	}
	return 4
}

func sortRuleMembers(list []ruleMemberView) {
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if ra, rb := memberKindRank(a.Kind), memberKindRank(b.Kind); ra != rb {
			return ra < rb
		}
		if a.Alive != b.Alive {
			return a.Alive
		}
		if a.Flows != b.Flows {
			return a.Flows > b.Flows
		}
		if at, bt := a.Up+a.Down, b.Up+b.Down; at != bt {
			return at > bt
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
}

// displayBase is the file name of a path or mask, keeping its case.
func displayBase(p string) string {
	p = strings.Trim(strings.TrimSpace(p), `"`)
	p = strings.ReplaceAll(p, "/", `\`)
	if i := strings.LastIndex(p, `\`); i >= 0 {
		p = p[i+1:]
	}
	return p
}

// nameKey is a process name comparable across the config ("chrome") and the
// process list ("chrome.exe").
func nameKey(name string) string {
	n := strings.ToLower(displayBase(name))
	if n != "" && !strings.Contains(n, ".") && !strings.HasSuffix(n, "*") {
		n += ".exe"
	}
	return n
}

// procKey identifies a candidate by path, falling back to its file name.
func procKey(path, name string) string {
	if p := rules.NormalizePath(path); p != "" {
		return p
	}
	return nameKey(name)
}

// sameProc reports whether two process descriptions name the same program.
func sameProc(pathA, nameA, pathB, nameB string) bool {
	pa, pb := rules.NormalizePath(pathA), rules.NormalizePath(pathB)
	if pa != "" && pb != "" {
		return pa == pb
	}
	na := nameKey(nameA)
	return na != "" && na == nameKey(nameB)
}

// rankCandidates scores the programs that could be a missing companion of
// rule. directProcs carried traffic no rule matched; runningProcs is the
// whole process list. Processes the rule already covers, and those the auto
// matcher already attributes to it, are left out.
func rankCandidates(rule config.Rule, allRules []config.Rule, ruleRunning []rules.Process, directProcs []engine.DirectProc, runningProcs []rules.Process, ins metaInspector, autoMatches []engine.AutoMatch, now time.Time) []companionCandidate {
	if ins == nil {
		ins = process.NewInspector()
	}
	on := true
	rc := rule
	rc.Enabled, rc.Action, rc.Proxy = &on, "direct", ""
	ruleSet := rules.Compile([]config.Rule{rc})
	ruleKeyNow := ruleKey(rule.Process)
	autoCovered := func(p rules.Process) bool {
		for _, am := range autoMatches {
			if am.RuleKey != ruleKeyNow {
				continue
			}
			if am.Proc.PID != 0 && p.PID != 0 && am.Proc.PID == p.PID {
				return true
			}
			if sameProc(am.Proc.Path, am.Proc.Name, p.Path, p.Name) {
				return true
			}
		}
		return false
	}

	var others []config.Rule
	for _, r := range allRules {
		if ruleKey(r.Process) == ruleKey(rule.Process) {
			continue
		}
		o := r
		o.Enabled, o.Action = &on, "direct"
		others = append(others, o)
	}
	otherSet := rules.Compile(others)

	type cand struct {
		view    companionCandidate
		started int64
		parents []rules.Process
	}
	pool := map[string]*cand{}
	covered := func(p rules.Process) bool { return ruleSet.Match(p).Action != "" }
	isSelf := func(path, name string) bool {
		return nameKey(name) == "ashgate.exe" || nameKey(path) == "ashgate.exe"
	}
	for _, dp := range directProcs {
		if dp.Path == "" && dp.Name == "" {
			continue
		}
		p := rules.Process{Name: dp.Name, Path: dp.Path, PID: dp.PID, Started: dp.Started}
		if isSelf(dp.Path, dp.Name) || covered(p) || autoCovered(p) {
			continue
		}
		key := procKey(dp.Path, dp.Name)
		if key == "" {
			continue
		}
		c := pool[key]
		if c == nil {
			c = &cand{}
			pool[key] = c
		}
		v := &c.view
		if v.Name == "" {
			v.Name = dp.Name
		}
		if v.Path == "" {
			v.Path = dp.Path
		}
		if v.PID == 0 {
			v.PID = dp.PID
		}
		if c.started == 0 {
			c.started = dp.Started
		}
		v.Conns += dp.Conns
		v.Bytes += dp.Bytes
		if dp.LastSeen > v.LastSeen {
			v.LastSeen = dp.LastSeen
		}
		if len(v.SampleDests) == 0 {
			v.SampleDests = append([]string(nil), dp.SampleDests...)
		}
		v.System = v.System || dp.System || rules.IsShellOrSystem(p) || rules.IsSystemDNS(p.Name)
	}
	for _, p := range runningProcs {
		if p.Path == "" && p.Name == "" {
			continue
		}
		if isSelf(p.Path, p.Name) || covered(p) || autoCovered(p) {
			continue
		}
		key := procKey(p.Path, p.Name)
		if key == "" {
			continue
		}
		c := pool[key]
		if c == nil {
			c = &cand{}
			pool[key] = c
		}
		v := &c.view
		v.Running = true
		if v.Name == "" {
			v.Name = p.Name
		}
		if v.Path == "" {
			v.Path = p.Path
		}
		// Prefer the live running process's PID and start time over an older
		// (possibly exited) PID recorded earlier in directProcs.
		if p.PID != 0 {
			v.PID = p.PID
			if p.Started != 0 {
				c.started = p.Started
			}
		}
		if len(c.parents) == 0 {
			c.parents = p.Parents
		}
		v.System = v.System || rules.IsShellOrSystem(p) || rules.IsSystemDNS(p.Name)
	}

	// Reference signals of the rule's application.
	var rulePaths []string
	if pp := strings.Trim(strings.TrimSpace(rule.Process), `"`); rules.IsPath(pp) {
		rulePaths = append(rulePaths, pp)
	}
	for _, comp := range rule.Companions {
		if cp := strings.Trim(strings.TrimSpace(comp), `"`); rules.IsPath(cp) {
			rulePaths = append(rulePaths, cp)
		}
	}
	for _, p := range ruleRunning {
		if p.Path != "" {
			rulePaths = append(rulePaths, p.Path)
		}
	}
	var ruleDirs []string
	dirSeen := map[string]bool{}
	for _, p := range rulePaths {
		d := rules.CompanionDir(p)
		if d == "" || dirSeen[d] {
			continue
		}
		dirSeen[d] = true
		ruleDirs = append(ruleDirs, d)
	}
	ruleTokens := map[string]bool{}
	for _, t := range rules.PathTokens(rule.Process) {
		ruleTokens[t] = true
	}
	for _, comp := range rule.Companions {
		for _, t := range rules.PathTokens(comp) {
			ruleTokens[t] = true
		}
	}
	for _, p := range ruleRunning {
		for _, t := range rules.PathTokens(p.Path) {
			ruleTokens[t] = true
		}
		for _, t := range rules.PathTokens(p.Name) {
			ruleTokens[t] = true
		}
	}
	var ruleMeta process.FileMeta
	metaDone := false
	takeMeta := func(path string) {
		if metaDone || path == "" {
			return
		}
		m := ins.FileMetadata(path)
		if m.Signer != "" || m.Company != "" || m.Product != "" {
			ruleMeta, metaDone = m, true
		}
	}
	takeMeta(rule.Process)
	for _, p := range ruleRunning {
		takeMeta(p.Path)
	}
	// Every start time the rule's processes have, the rule's own and its
	// running children alike: a helper the launcher starts one second after
	// itself is still "started with the program", even when the launcher has
	// been up for hours.
	var ruleStarts []int64
	for _, p := range ruleRunning {
		if p.Started != 0 {
			ruleStarts = append(ruleStarts, p.Started)
		}
	}
	ruleExe := nameKey(rule.Process)
	ruleExeUsable := ruleExe != "" && !strings.ContainsAny(ruleExe, "*?")

	out := make([]companionCandidate, 0, len(pool))
	for _, c := range pool {
		v := c.view
		if v.Name == "" {
			v.Name = displayBase(v.Path)
		}
		v.Mask, _ = rules.VersionMask(v.Path)
		if !v.System {
			score, reasons := 0, []string(nil)
			var candMeta process.FileMeta
			if v.Path != "" {
				candMeta = ins.FileMetadata(v.Path)
			}
			if v.PID != 0 {
				if cmd := ins.CommandLine(v.PID, c.started); cmd != "" {
					low := strings.ToLower(cmd)
					hit := false
					for _, d := range ruleDirs {
						if strings.Contains(low, d) {
							hit = true
							break
						}
					}
					if !hit && ruleExeUsable && strings.Contains(low, ruleExe) {
						hit = true
					}
					if hit {
						score += 60
						reasons = append(reasons, "Запущен с путём программы")
					}
				}
			}
			if len(ruleDirs) > 0 && v.PID > 4 && ins != nil && ins.HasModuleInDirs(v.PID, c.started, ruleDirs) {
				score += 60
				reasons = append(reasons, "Загружает модуль программы")
			}
			signer := strings.TrimSpace(ruleMeta.Signer)
			candSigner := strings.TrimSpace(candMeta.Signer)
			common := rules.IsCommonVendor(ruleMeta.Signer) || rules.IsCommonVendor(ruleMeta.Company) || rules.IsCommonVendor(ruleMeta.Product)
			// A shared certificate thumbprint is stronger than a shared
			// publisher string: two programs may print the same vendor name
			// without sharing a signing certificate.
			sameCert := ruleMeta.CertThumbprint != "" && candMeta.CertThumbprint != "" &&
				strings.EqualFold(ruleMeta.CertThumbprint, candMeta.CertThumbprint)
			sameSigner := sameCert || (signer != "" && candSigner != "" && strings.EqualFold(signer, candSigner))
			if sameSigner {
				if common {
					score += 10
				} else {
					score += 50
				}
				reasons = append(reasons, "Тот же издатель")
			} else {
				sameCompany := ruleMeta.Company != "" && candMeta.Company != "" && strings.EqualFold(ruleMeta.Company, candMeta.Company)
				sameProduct := ruleMeta.Product != "" && candMeta.Product != "" && strings.EqualFold(ruleMeta.Product, candMeta.Product)
				if sameCompany || sameProduct {
					if common {
						score += 5
					} else {
						score += 30
					}
					reasons = append(reasons, "Та же компания")
				}
			}
			if v.Path != "" && len(ruleTokens) > 0 {
				for _, t := range rules.PathTokens(v.Path) {
					if ruleTokens[t] {
						score += 35
						reasons = append(reasons, fmt.Sprintf("Похожий путь (%s)", t))
						break
					}
				}
			}
			if v.Conns > 0 {
				age := now.UnixMilli() - v.LastSeen
				switch {
				case age >= 0 && age <= 60_000:
					score += 25
					if v.Bytes >= 16*1024 {
						score += 10
					}
					reasons = append(reasons, "Активный трафик напрямую")
				case age >= 0 && age <= 5*60_000:
					score += 15
					reasons = append(reasons, "Недавний трафик напрямую")
				}
			}
			if c.started > 0 && len(ruleStarts) > 0 {
				best := int64(-1)
				for _, ts := range ruleStarts {
					d := c.started - ts
					if d < 0 {
						d = -d
					}
					if best < 0 || d < best {
						best = d
					}
				}
				if best >= 0 && best <= int64(90*time.Second) {
					score += 15
					reasons = append(reasons, "Запущен вместе с программой")
				}
			}
			v.Score, v.Reasons = score, reasons
		}
		if otherSet != nil {
			dec := otherSet.Match(rules.Process{Name: v.Name, Path: v.Path, PID: v.PID, Started: c.started, Parents: c.parents})
			if dec.Action != "" && dec.RuleIndex >= 0 && dec.RuleIndex < len(others) {
				v.OtherRule = others[dec.RuleIndex].Process
			}
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].System != out[j].System {
			return !out[i].System
		}
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		if out[i].Bytes != out[j].Bytes {
			return out[i].Bytes > out[j].Bytes
		}
		if out[i].Conns != out[j].Conns {
			return out[i].Conns > out[j].Conns
		}
		if out[i].LastSeen != out[j].LastSeen {
			return out[i].LastSeen > out[j].LastSeen
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	if len(out) > candidateLimit {
		out = out[:candidateLimit]
	}
	return out
}

// candidateExcluded reports that the user excluded the candidate from this
// rule's auto-pickup, so it must not be suggested again.
func candidateExcluded(ruleSet *rules.Set, c companionCandidate) bool {
	if ruleSet == nil {
		return false
	}
	return ruleSet.IsExcluded(0, rules.Process{Name: c.Name, Path: c.Path, PID: c.PID})
}

// topCandidate returns the best non-system candidate when it is strong
// enough to suggest, and nil otherwise. System entries are last, but are
// skipped explicitly so they never become a suggestion. Candidates with
// high affinity but zero traffic, already bound to another rule, or
// excluded from this rule are skipped rather than stopping the search, so
// the best active direct candidate still surfaces.
func topCandidate(cands []companionCandidate, ruleSet *rules.Set) *companionCandidate {
	for i := range cands {
		if cands[i].System {
			continue
		}
		c := cands[i]
		if c.Score < 45 {
			return nil
		}
		if candidateExcluded(ruleSet, c) {
			continue
		}
		if (c.Conns > 0 || c.Bytes > 0) && c.OtherRule == "" {
			return &c
		}
	}
	return nil
}

// strongCandidate returns a candidate strong enough to suggest even while
// the rule's own application still moves a little traffic (a launcher that
// sent a burst before its child took over). It needs a high score and real
// traffic, so a merely quiet rule does not turn every stray program into a
// hint.
func strongCandidate(cands []companionCandidate, ruleSet *rules.Set) *companionCandidate {
	for i := range cands {
		if cands[i].System {
			continue
		}
		c := cands[i]
		if c.Score < 65 {
			return nil
		}
		if c.OtherRule != "" || candidateExcluded(ruleSet, c) {
			continue
		}
		if c.Conns >= 2 || c.Bytes >= 16384 {
			return &c
		}
	}
	return nil
}

// countDirect is the number of programs sending direct traffic right now;
// the Apps tab shows it as a badge.
func countDirect(procs []engine.DirectProc, now time.Time) int {
	nowMs := now.UnixMilli()
	n := 0
	for _, dp := range procs {
		if dp.System || dp.LastSeen <= 0 {
			continue
		}
		if age := nowMs - dp.LastSeen; age >= 0 && age <= directRecent.Milliseconds() {
			n++
		}
	}
	return n
}

// refreshHints looks, in the background, for rules whose app runs but sends
// no traffic and for a direct program that looks like its missing companion.
// It runs only while the window is visible and capture is on; a tray window
// has nobody to show the hint to.
func (c *controller) refreshHints() {
	c.mu.Lock()
	if c.hintsBusy || time.Since(c.hintsAt) < hintsEvery {
		c.mu.Unlock()
		return
	}
	sess := c.sess
	if sess == nil || !sess.Running() {
		c.hintsCache, c.hintsAt, c.hintsBusy = nil, time.Now(), false
		c.mu.Unlock()
		return
	}
	c.hintsBusy = true
	gen := c.hintsGen
	rs := c.cfg.EffectiveRules()
	alive := make(map[string]bool, len(c.alive))
	for k, v := range c.alive {
		alive[k] = v
	}
	since := make(map[string]time.Time, len(c.aliveSince))
	for k, v := range c.aliveSince {
		since[k] = v
	}
	ruleProcs := make(map[string][]rules.Process, len(c.liveRuleProcs))
	for k, v := range c.liveRuleProcs {
		ruleProcs[k] = append([]rules.Process(nil), v...)
	}
	procs := append([]rules.Process(nil), c.liveProcs...)
	ins := c.inspector
	if ins == nil {
		ins = process.NewInspector()
		c.inspector = ins
	}
	c.mu.Unlock()

	go func() {
		now := time.Now()
		autoMatches := sess.AutoMatches()
		directProcs, _, _ := sess.DirectSnapshot()
		recent := make([]engine.DirectProc, 0, len(directProcs))
		for _, dp := range directProcs {
			if dp.System || dp.LastSeen <= 0 {
				continue
			}
			if age := now.UnixMilli() - dp.LastSeen; age < 0 || age > directRecent.Milliseconds() {
				continue
			}
			recent = append(recent, dp)
		}
		var hints map[string]ruleHintView
		if len(recent) > 0 {
			// Limit running process enrichment to processes that actually sent
			// recent direct traffic, avoiding metadata/cmdline queries on idle
			// background processes during periodic 2 s hint scans.
			recentKeys := make(map[string]bool, len(recent))
			for _, dp := range recent {
				if k := procKey(dp.Path, dp.Name); k != "" {
					recentKeys[k] = true
				}
			}
			var recentRunning []rules.Process
			for _, p := range procs {
				if recentKeys[procKey(p.Path, p.Name)] {
					recentRunning = append(recentRunning, p)
				}
			}
			stats := sess.RuleStats()
			hints = map[string]ruleHintView{}
			for _, r := range rs {
				if !r.IsEnabled() || r.Action != "proxy" {
					continue
				}
				k := ruleKey(r.Process)
				if k == "" || !alive[k] {
					continue
				}
				at, ok := since[k]
				if !ok || now.Sub(at) < quietRuleDelay {
					continue
				}
				st := stats[k]
				quiet := st.Flows == 0 && st.Up+st.Down < 4096
				cands := rankCandidates(r, rs, ruleProcs[k], recent, recentRunning, ins, autoMatches, now)
				set := rules.Compile([]config.Rule{r})
				if quiet {
					if best := topCandidate(cands, set); best != nil {
						hints[k] = ruleHintView{TopCandidate: best}
					} else {
						hints[k] = ruleHintView{Quiet: true}
					}
					continue
				}
				// The rule is not quiet, but a launcher may already have sent a
				// burst of its own before the child took over. A strong direct
				// candidate is still worth suggesting; "quiet" never is.
				if best := strongCandidate(cands, set); best != nil {
					hints[k] = ruleHintView{TopCandidate: best}
				}
			}
		}
		c.mu.Lock()
		if c.hintsGen == gen {
			c.hintsCache = hints
			c.hintsAt = time.Now()
		}
		c.hintsBusy = false
		c.mu.Unlock()
	}()
}
