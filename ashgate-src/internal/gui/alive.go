package gui

import (
	"strings"
	"time"

	"ashgate/internal/config"
	"ashgate/internal/process"
	"ashgate/internal/rules"
)

// aliveEvery is how often the list of running rule apps is rebuilt. The
// snapshotter reads the process table cheaply and opens only new processes,
// so a short interval is affordable and a launch or exit is seen in under a
// second.
const aliveEvery = 600 * time.Millisecond

// defaultSnapshotter keeps the image cache across polls.
var defaultSnapshotter = process.NewSnapshotter()

// snapshotProcs is an indirection so tests can run without a Windows process
// list; it is also swapped in tests that fake process snapshots.
var snapshotProcs = defaultSnapshotter.Snapshot

// ruleKey is how the page keys a rule: the process field, trimmed, without
// quotes, lower case (apKey in apps.js).
func ruleKey(p string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(p), `"`))
}

// ruleMasks maps every rule whose path still names one Squirrel version to
// the mask that would survive an update. The page shows a badge and offers
// the change; the config is never rewritten here.
func ruleMasks(cfg *config.Config) map[string]string {
	if cfg == nil {
		return nil
	}
	var out map[string]string
	for _, r := range cfg.Rules {
		mask, ok := rules.VersionMask(r.Process)
		if !ok {
			continue
		}
		if out == nil {
			out = map[string]string{}
		}
		out[ruleKey(r.Process)] = mask
	}
	return out
}

// aliveRules reports, for every rule, whether a process it names is running
// now. Only the process itself counts, not its children.
func aliveRules(rs []config.Rule, procs []rules.Process) map[string]bool {
	out := make(map[string]bool, len(rs))
	flat := flatProcs(procs)
	for _, r := range rs {
		k := ruleKey(r.Process)
		if k == "" || out[k] {
			continue
		}
		one := rules.Compile([]config.Rule{{Process: r.Process, Action: "direct"}})
		hit := false
		for _, p := range flat {
			if one.Match(p).Action != "" {
				hit = true
				break
			}
		}
		out[k] = hit
	}
	return out
}

// liveMember is a process a rule caught without naming it: a companion, a
// child that inherited the rule, or one that lives in the rule's folder.
// ParentKey names the nearest ancestor that is also a member of the same rule,
// so the page can draw the process tree; it is empty for a direct child of the
// rule's root process or when no member ancestor exists.
type liveMember struct {
	Name      string
	Path      string
	Kind      string // "companion" | "child" | "folder"
	PID       uint32
	PPID      uint32
	ParentPID uint32
	ParentKey string
	Count     int // live instances collapsed into this image entry
}

// scanRules matches every running process against the rules, keeping a rule
// enabled and direct for the purpose: whether its application runs must not
// depend on the action or on a group's switch. It returns:
//
//   - alive: rule key -> a process of the rule is running;
//   - members: rule key -> the processes the rule caught without naming them;
//   - running: rule key -> every process the rule caught (the row itself
//     included), for companion scoring.
//
// Ancestors are read from p.Parents, which process.Snapshot fills.
func scanRules(rs []config.Rule, procs []rules.Process) (map[string]bool, map[string][]liveMember, map[string][]rules.Process) {
	alive := make(map[string]bool, len(rs))
	members := map[string][]liveMember{}
	running := map[string][]rules.Process{}
	for _, r := range rs {
		if k := ruleKey(r.Process); k != "" {
			if _, ok := alive[k]; !ok {
				alive[k] = false
			}
		}
	}
	if len(rs) == 0 {
		return alive, members, running
	}

	all := make([]config.Rule, len(rs))
	for i, r := range rs {
		on := true
		r.Enabled = &on
		r.Action = "direct"
		r.Proxy = ""
		all[i] = r
	}
	set := rules.Compile(all)

	// One hit list per rule, in process order, plus a PID index for walking
	// ancestors. Every process matches at most one rule here.
	type ruleHit struct {
		proc  rules.Process
		kind  string
		exact bool
	}
	hits := map[string][]ruleHit{}
	byPID := map[string]map[uint32]ruleHit{}
	for _, p := range procs {
		dec := set.Match(p)
		if dec.Action == "" || dec.RuleIndex < 0 || dec.RuleIndex >= len(rs) {
			continue
		}
		key := ruleKey(rs[dec.RuleIndex].Process)
		if key == "" {
			continue
		}
		alive[key] = true
		running[key] = append(running[key], p)
		h := ruleHit{proc: p, kind: dec.MatchKind, exact: dec.MatchKind == rules.MatchExact}
		hits[key] = append(hits[key], h)
		if p.PID != 0 {
			if byPID[key] == nil {
				byPID[key] = map[uint32]ruleHit{}
			}
			byPID[key][p.PID] = h
		}
	}
	// Attach every caught process to the nearest ancestor that the same rule
	// also caught, and collapse equal images into one row with a count.
	for key, list := range hits {
		idxByID := map[string]int{}
		for _, h := range list {
			if h.exact {
				continue
			}
			p := h.proc
			var parentKey string
			var parentPID uint32
			for _, a := range p.Parents {
				if a.PID == 0 || rules.IsShellOrSystem(a) {
					break
				}
				ah, ok := byPID[key][a.PID]
				if !ok {
					continue // not caught by this rule; keep climbing
				}
				if ah.exact {
					parentPID = ah.proc.PID // a direct child of the rule's root
					break
				}
				aKey := procKey(ah.proc.Path, ah.proc.Name)
				if aKey != "" && aKey != procKey(p.Path, p.Name) {
					parentKey, parentPID = aKey, ah.proc.PID
					break
				}
				// The same image spawned itself (chrome.exe -> chrome.exe):
				// keep climbing so the group attaches to the ancestor image.
			}
			id := procKey(p.Path, p.Name)
			if id == "" {
				continue
			}
			if i, ok := idxByID[id]; ok {
				m := &members[key][i]
				m.Count++
				if m.PID == 0 {
					m.PID, m.PPID = p.PID, p.PPID
				}
				// Prefer the shallower attachment: a second instance that is a
				// direct child of the root must not hang off another image.
				if m.ParentKey != "" && parentKey == "" {
					m.ParentKey, m.ParentPID = "", parentPID
					m.PID, m.PPID = p.PID, p.PPID
				}
				continue
			}
			idxByID[id] = len(members[key])
			members[key] = append(members[key], liveMember{
				Name: p.Name, Path: p.Path, Kind: h.kind,
				PID: p.PID, PPID: p.PPID, ParentPID: parentPID, ParentKey: parentKey,
				Count: 1,
			})
		}
	}

	// Two rules can overlap (one names a folder another's process lives in),
	// so the first rule took the process. Check the remaining rules directly,
	// the way aliveRules does, so their app still counts as running.
	flat := flatProcs(procs)
	for _, r := range rs {
		key := ruleKey(r.Process)
		if key == "" || alive[key] {
			continue
		}
		one := rules.Compile([]config.Rule{{Process: r.Process, Companions: r.Companions, Action: "direct"}})
		for _, p := range flat {
			dec := one.Match(p)
			if dec.Action == "" || dec.MatchKind == rules.MatchFolder || dec.MatchKind == rules.MatchChild {
				continue
			}
			alive[key] = true
			running[key] = append(running[key], p)
			if dec.MatchKind == rules.MatchCompanion {
				if p.Path != "" || p.Name != "" {
					members[key] = append(members[key], liveMember{
						Name: p.Name, Path: p.Path, Kind: rules.MatchCompanion,
						PID: p.PID, PPID: p.PPID, Count: 1,
					})
				}
			}
			break
		}
	}
	return alive, members, running
}

// refreshAlive rebuilds the running-apps map in the background when it is
// old. Polls get the last map; nil until the first scan is done.
func (c *controller) refreshAlive() {
	c.mu.Lock()
	stale := time.Since(c.aliveAt) >= aliveEvery && !c.aliveBusy
	if stale {
		c.aliveBusy = true
	}
	rs := append([]config.Rule(nil), c.cfg.Rules...)
	c.mu.Unlock()
	if !stale {
		return
	}
	if len(rs) == 0 {
		c.mu.Lock()
		c.alive, c.aliveSince, c.liveMembers = map[string]bool{}, nil, nil
		c.liveProcs, c.liveRuleProcs = nil, nil
		c.aliveAt, c.aliveBusy = time.Now(), false
		c.mu.Unlock()
		return
	}
	go func() {
		procs := snapshotProcs()
		a, mem, run := scanRules(rs, procs)
		now := time.Now()
		c.mu.Lock()
		since := c.aliveSince
		if since == nil {
			since = map[string]time.Time{}
		}
		for k, v := range a {
			if !v {
				delete(since, k)
				continue
			}
			if _, ok := since[k]; !ok {
				since[k] = now
			}
		}
		for k := range since {
			if !a[k] {
				delete(since, k)
			}
		}
		c.alive, c.aliveSince, c.liveMembers = a, since, mem
		c.liveProcs, c.liveRuleProcs = procs, run
		c.aliveAt, c.aliveBusy = now, false
		c.mu.Unlock()
	}()
}

// flatProcs drops ancestors and normalizes names and paths once. A rule is
// matched against every process; normalized input makes each match
// allocation-free instead of lower-casing every path again per rule. The
// other fields are kept, so a fallback match still knows the start time.
func flatProcs(procs []rules.Process) []rules.Process {
	out := make([]rules.Process, len(procs))
	for i, p := range procs {
		p.Name, p.Path, p.Parents = rules.NormalizeName(p.Name), rules.NormalizePath(p.Path), nil
		out[i] = p
	}
	return out
}
