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
	go func() {
		m := aliveRules(rs, snapshotProcs())
		c.mu.Lock()
		c.alive, c.aliveAt, c.aliveBusy = m, time.Now(), false
		c.mu.Unlock()
	}()
}

// flatProcs drops ancestors and normalizes names and paths once. A rule is
// matched against every process; normalized input makes each match
// allocation-free instead of lower-casing every path again per rule.
func flatProcs(procs []rules.Process) []rules.Process {
	out := make([]rules.Process, len(procs))
	for i, p := range procs {
		out[i] = rules.Process{Name: rules.NormalizeName(p.Name), Path: rules.NormalizePath(p.Path)}
	}
	return out
}
