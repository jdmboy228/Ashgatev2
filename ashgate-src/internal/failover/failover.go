// Package failover decides which server of a subscription carries traffic.
// It only keeps state; the caller runs the health checks (always through
// the tunnel) and the timers, and reports results here.
package failover

import (
	"math/rand/v2"
	"time"
)

// Result is one health check through the active entry's tunnel.
type Result int

const (
	// OK: generate_204 answered.
	OK Result = iota
	// Failed: the tunnel refused or closed without an answer.
	Failed
	// Frozen: the tunnel took the request but sent nothing for ~15 s.
	Frozen
)

// Config holds the timings. Defaults is what Ashgate uses.
type Config struct {
	CheckEvery    time.Duration // health check period
	CheckJitter   float64       // ± fraction of CheckEvery
	FailsToSwitch int           // failed checks in a row before switching
	RetryBase     time.Duration // first re-check after a failure
	RetryMax      time.Duration // backoff cap
	PrimaryEvery  time.Duration // probe of the primary while on a backup
	PrimaryNeed   int           // successful probes in a row to return
	MinReturn     time.Duration // no return to the primary sooner than this after a switch
}

// Defaults: a check every 60 s ±20 %; two failures in a row or one freeze
// switch; re-checks back off from 10 s to 5 min; the primary is probed every
// 10 min and taken back after two good probes, at most once per 5 min.
var Defaults = Config{
	CheckEvery:    time.Minute,
	CheckJitter:   0.2,
	FailsToSwitch: 2,
	RetryBase:     10 * time.Second,
	RetryMax:      5 * time.Minute,
	PrimaryEvery:  10 * time.Minute,
	PrimaryNeed:   2,
	MinReturn:     5 * time.Minute,
}

// Jitter spreads d by ±frac using r in [0, 1).
func Jitter(d time.Duration, frac, r float64) time.Duration {
	return d + time.Duration((2*r-1)*frac*float64(d))
}

// Backoff is an exponential delay with ±20 % jitter: Base, 2×Base, … Max.
type Backoff struct {
	Base, Max time.Duration
	Rand      func() float64
	n         int
}

// Next returns the next delay and doubles the following one.
func (b *Backoff) Next() time.Duration {
	d := b.Base
	for i := 0; i < b.n && d < b.Max; i++ {
		d *= 2
	}
	if d > b.Max {
		d = b.Max
	}
	b.n++
	return Jitter(d, 0.2, b.Rand())
}

// Reset starts again from Base.
func (b *Backoff) Reset() { b.n = 0 }

// Group is the failover state of one subscription; entry 0 is the primary
// (XHTTP when the subscription has one). It is not safe for concurrent use.
type Group struct {
	cfg  Config
	rand func() float64
	n    int

	Active     int
	Reason     string    // why the active entry was chosen; "" at start
	SwitchedAt time.Time // last switch

	fails     int
	verified  bool         // the active entry passed its last check
	failed    map[int]bool // entries that failed in this round
	primaryOK int
	nextCheck time.Time
	nextProbe time.Time
	backoff   Backoff
}

// New starts on the primary of n entries. rnd may be nil.
func New(n int, now time.Time, cfg Config, rnd func() float64) *Group {
	if rnd == nil {
		rnd = rand.Float64
	}
	g := &Group{cfg: cfg, rand: rnd, n: n, failed: map[int]bool{}}
	g.backoff = Backoff{Base: cfg.RetryBase, Max: cfg.RetryMax, Rand: rnd}
	g.nextCheck = now.Add(g.checkDelay())
	return g
}

func (g *Group) checkDelay() time.Duration {
	return Jitter(g.cfg.CheckEvery, g.cfg.CheckJitter, g.rand())
}

// Reset adopts a new list of n entries with active chosen by the caller
// (see subs.Apply). switched records a forced switch with reason.
func (g *Group) Reset(n, active int, now time.Time, switched bool, reason string) {
	if switched || n == 0 {
		g.verified = false
	}
	g.n, g.Active = n, active
	g.fails, g.primaryOK = 0, 0
	g.failed = map[int]bool{}
	g.backoff.Reset()
	if switched {
		g.Reason, g.SwitchedAt = reason, now
		g.nextCheck = now.Add(g.checkDelay())
	}
	if g.Active != 0 {
		g.nextProbe = now.Add(g.cfg.PrimaryEvery)
	}
}

// Verified reports that the active entry passed its last health check:
// the tunnel is known to work right now.
func (g *Group) Verified() bool { return g.verified }

// CheckDue reports whether the active entry should be checked now.
func (g *Group) CheckDue(now time.Time) bool { return g.n > 0 && !now.Before(g.nextCheck) }

// NextCheck is when the next health check is due.
func (g *Group) NextCheck() time.Time { return g.nextCheck }

// Check records a health check of the active entry and reports whether the
// active entry changed. label names entries for the switch reason.
func (g *Group) Check(now time.Time, r Result, label func(int) string) bool {
	switch r {
	case OK:
		g.verified = true
		g.fails = 0
		g.backoff.Reset()
		delete(g.failed, g.Active)
		g.nextCheck = now.Add(g.checkDelay())
		return false
	case Failed:
		g.verified = false
		g.fails++
		if g.fails < g.cfg.FailsToSwitch {
			// Look again soon instead of a full period later.
			g.nextCheck = now.Add(g.backoff.Next())
			return false
		}
		return g.switchAway(now, label(g.Active)+": не отвечает (2 проверки подряд)", label)
	default:
		return g.switchAway(now, label(g.Active)+": нет данных 15 с", label)
	}
}

// switchAway moves to the next entry by priority that has not failed in
// this round. When every entry has failed, a new round starts, and the
// next check waits on the exponential backoff, so the servers never see a
// reconnect storm.
func (g *Group) switchAway(now time.Time, why string, label func(int) string) bool {
	g.verified = false
	g.failed[g.Active] = true
	g.fails = 0
	g.primaryOK = 0
	if g.n < 2 {
		g.Reason = why
		g.nextCheck = now.Add(g.backoff.Next())
		return false
	}
	next := -1
	for i := 1; i < g.n; i++ {
		if c := (g.Active + i) % g.n; !g.failed[c] {
			next = c
			break
		}
	}
	if next < 0 {
		// Every server failed: start over from the primary, slowly.
		g.failed = map[int]bool{}
		next = 0
		if g.Active == 0 {
			next = 1
		}
		g.nextCheck = now.Add(g.backoff.Next())
	} else {
		g.nextCheck = now.Add(g.checkDelay())
	}
	g.Active = next
	g.Reason = why + " → " + label(next)
	g.SwitchedAt = now
	g.nextProbe = now.Add(g.cfg.PrimaryEvery)
	return true
}

// ProbeDue reports whether the primary should be probed now: only while a
// backup carries traffic.
func (g *Group) ProbeDue(now time.Time) bool {
	return g.Active != 0 && g.n > 1 && !now.Before(g.nextProbe)
}

// Probe records a probe of the primary through its own tunnel and reports
// whether traffic returns to it: after PrimaryNeed good probes in a row,
// and never sooner than MinReturn after the last switch.
func (g *Group) Probe(now time.Time, ok bool, label func(int) string) bool {
	g.nextProbe = now.Add(g.cfg.PrimaryEvery)
	if !ok {
		g.primaryOK = 0
		return false
	}
	g.primaryOK++
	if g.primaryOK < g.cfg.PrimaryNeed || now.Sub(g.SwitchedAt) < g.cfg.MinReturn {
		return false
	}
	g.Active = 0
	g.verified = false
	g.Reason = label(0) + ": основной сервер снова отвечает"
	g.SwitchedAt = now
	g.primaryOK, g.fails = 0, 0
	g.failed = map[int]bool{}
	g.backoff.Reset()
	g.nextCheck = now.Add(g.checkDelay())
	return true
}
