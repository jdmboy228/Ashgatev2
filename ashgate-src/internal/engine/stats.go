package engine

import (
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ashgate/internal/rules"
)

// ruleStat counts the traffic of one rule, including child processes that
// inherited it. The window shows it on the rule's row.
type ruleStat struct {
	flows    atomic.Int64
	up, down atomic.Int64
	mu       sync.Mutex
	err      string
	errAt    time.Time
	// procs splits the counters by the processes that produced them. It is
	// bounded to maxSubProcs entries and guarded by mu.
	procs map[string]*subProcStat
}

// maxSubProcs caps the per-process breakdown of one rule. A rule that
// catches a folder of unrelated programs must not keep growing its stats.
const maxSubProcs = 64

// subProcStat is one process's share of a rule's traffic.
type subProcStat struct {
	name     string
	path     string
	kind     string
	flows    atomic.Int64
	up, down atomic.Int64
	lastSeen atomic.Int64
}

// upCounter and downCounter are the atomic counters of a sub-process; nil
// is allowed so callers need not check.
func (s *subProcStat) upCounter() *atomic.Int64 {
	if s == nil {
		return nil
	}
	return &s.up
}

func (s *subProcStat) downCounter() *atomic.Int64 {
	if s == nil {
		return nil
	}
	return &s.down
}

func (s *subProcStat) seenCounter() *atomic.Int64 {
	if s == nil {
		return nil
	}
	return &s.lastSeen
}

// kindRank orders match kinds: a rule's own process and its companions are
// more specific than a child or a folder match.
func kindRank(kind string) int {
	switch kind {
	case rules.MatchExact, rules.MatchCompanion:
		return 2
	case rules.MatchChild, rules.MatchFolder:
		return 1
	}
	return 0
}

// procFor returns the counters of proc under this rule, creating them when
// there is room. The kind of an existing entry is upgraded when the new
// match is more specific (exact/companion over child/folder).
func (s *ruleStat) procFor(proc rules.Process, kind string) *subProcStat {
	if s == nil {
		return nil
	}
	key := rules.NormalizePath(proc.Path)
	if key == "" {
		key = rules.NormalizeName(proc.Name)
	}
	if key == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.procs == nil {
		s.procs = map[string]*subProcStat{}
	}
	sub := s.procs[key]
	if sub == nil {
		if len(s.procs) >= maxSubProcs {
			return nil
		}
		sub = &subProcStat{name: display(proc), path: proc.Path, kind: kind}
		s.procs[key] = sub
	} else {
		if name := display(proc); name != "" {
			sub.name = name
		}
		if proc.Path != "" {
			sub.path = proc.Path
		}
		if kind != "" && kindRank(kind) > kindRank(sub.kind) {
			sub.kind = kind
		}
	}
	sub.lastSeen.Store(time.Now().UnixMilli())
	return sub
}

func (s *ruleStat) fail(msg string, at time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.err, s.errAt = msg, at
	s.mu.Unlock()
}

// RuleProcStat is a snapshot of one process's traffic under a rule.
type RuleProcStat struct {
	Name     string `json:"name"`
	Path     string `json:"path,omitempty"`
	Kind     string `json:"kind"` // exact, companion, child, folder
	Flows    int64  `json:"flows"`
	Up       int64  `json:"up"`
	Down     int64  `json:"down"`
	LastSeen int64  `json:"lastSeen"` // Unix ms
}

// RuleStat is a copy of one rule's counters.
type RuleStat struct {
	Flows int64
	Up    int64
	Down  int64
	Err   string
	ErrAt time.Time
	// Procs splits the counters by process, most traffic first.
	Procs []RuleProcStat
}

// RuleKey identifies a rule for statistics: its process field, lower-case.
// It stays the same when rules are reordered.
func RuleKey(process string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(process), `"`))
}

// statFor returns the counters for key. Callers hold e.mu.
func (e *Engine) statFor(key string) *ruleStat {
	if key == "" {
		return nil
	}
	s := e.stats[key]
	if s == nil {
		s = &ruleStat{}
		e.stats[key] = s
	}
	return s
}

// RuleStats returns every rule's counters since the engine started.
func (e *Engine) RuleStats() map[string]RuleStat {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[string]RuleStat, len(e.stats))
	for k, s := range e.stats {
		s.mu.Lock()
		st := RuleStat{Flows: s.flows.Load(), Up: s.up.Load(), Down: s.down.Load(), Err: s.err, ErrAt: s.errAt}
		if len(s.procs) > 0 {
			st.Procs = make([]RuleProcStat, 0, len(s.procs))
			for _, p := range s.procs {
				st.Procs = append(st.Procs, RuleProcStat{
					Name:     p.name,
					Path:     p.path,
					Kind:     p.kind,
					Flows:    p.flows.Load(),
					Up:       p.up.Load(),
					Down:     p.down.Load(),
					LastSeen: p.lastSeen.Load(),
				})
			}
			sort.Slice(st.Procs, func(i, j int) bool {
				a, b := st.Procs[i], st.Procs[j]
				if a.Flows != b.Flows {
					return a.Flows > b.Flows
				}
				if ta, tb := a.Up+a.Down, b.Up+b.Down; ta != tb {
					return ta > tb
				}
				return a.Name < b.Name
			})
		}
		out[k] = st
		s.mu.Unlock()
	}
	return out
}
