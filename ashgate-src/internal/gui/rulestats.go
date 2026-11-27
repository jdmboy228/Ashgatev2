package gui

import (
	"time"

	"ashgate/internal/engine"
)

// ruleStatView is one rule's live traffic as the Apps tab shows it.
type ruleStatView struct {
	Flows    int64  `json:"flows"`
	Up       int64  `json:"up"`
	Down     int64  `json:"down"`
	UpRate   int64  `json:"upRate"`   // bytes per second
	DownRate int64  `json:"downRate"` // bytes per second
	Error    string `json:"error,omitempty"`
}

// rateEvery is the shortest window for a speed sample; the window polls
// more often than that.
const rateEvery = time.Second

// errShown keeps a rule's last proxy error on its row for this long.
const errShown = time.Minute

// ruleStatsLocked turns the engine's counters into rows with speeds.
// cur is the snapshot already read by the caller (or read here if nil).
// Callers hold c.mu.
func (c *controller) ruleStatsLocked(now time.Time, cur map[string]engine.RuleStat) map[string]ruleStatView {
	out := map[string]ruleStatView{}
	if c.sess == nil {
		return out
	}
	if c.statSess != c.sess {
		c.statSess = c.sess
		c.statPrev, c.statAt, c.statRates = nil, time.Time{}, nil
	}
	if cur == nil {
		cur = c.sess.RuleStats()
	}
	if dt := now.Sub(c.statAt); c.statPrev == nil || dt >= rateEvery {
		rates := map[string][2]int64{}
		if c.statPrev != nil && dt > 0 {
			for k, s := range cur {
				p := c.statPrev[k]
				rates[k] = [2]int64{perSec(s.Up-p.Up, dt), perSec(s.Down-p.Down, dt)}
			}
		}
		c.statPrev, c.statAt, c.statRates = cur, now, rates
	}
	running := c.sess.Running()
	for k, s := range cur {
		v := ruleStatView{Flows: s.Flows, Up: s.Up, Down: s.Down}
		if running {
			r := c.statRates[k]
			v.UpRate, v.DownRate = r[0], r[1]
		} else {
			v.Flows = 0
		}
		if s.Err != "" && now.Sub(s.ErrAt) < errShown {
			v.Error = s.Err
		}
		out[k] = v
	}
	return out
}

func perSec(n int64, dt time.Duration) int64 {
	if n <= 0 {
		return 0
	}
	return int64(float64(n) / dt.Seconds())
}
