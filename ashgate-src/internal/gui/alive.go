package gui

import (
	"strings"
	"time"

	"ashgate/internal/config"
	"ashgate/internal/process"
	"ashgate/internal/rules"
)

// aliveEvery is how often the list of running rule apps is rebuilt. It opens
// every process, which is too slow for each status poll.
const aliveEvery = 3 * time.Second

// Indirection so tests can run without a Windows process list.
var snapshotProcs = process.Snapshot

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
type liveMember struct {
	Name string
	Path string
	Kind string // "companion" | "child" | "folder"
	PID  uint32
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

	// One dedup set per rule. A folder can catch many processes with the same
	// image path; the row shows it once.
	seen := map[string]map[string]bool{}
	addMember := func(key string, p rules.Process, kind string) {
		if key == "" || (p.Path == "" && p.Name == "") {
			return
		}
		id := rules.NormalizePath(p.Path)
		if id == "" {
			id = rules.NormalizeName(p.Name)
		}
		byID := seen[key]
		if byID == nil {
			byID = map[string]bool{}
			seen[key] = byID
		}
		if byID[id] {
			return
		}
		byID[id] = true
		members[key] = append(members[key], liveMember{Name: p.Name, Path: p.Path, Kind: kind, PID: p.PID})
	}

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
		if dec.MatchKind != rules.MatchExact {
			addMember(key, p, dec.MatchKind)
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
				addMember(key, p, rules.MatchCompanion)
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
