// Package failover decides which server of a subscription carries traffic.
// It only keeps state. The caller watches the real traffic through the
// active server (Evidence), runs the checks this package asks for (always
// through the tunnel) and reports their results here.
//
// No timer checks a server that nobody uses. A check runs only when
// traffic through the active server goes unanswered; an idle tunnel makes
// no connections of its own, so there is no rhythm for an observer to
// find. One check that also gets no answer switches to the next server; a
// refused one is repeated once first.
//
// While a backup carries traffic, the primary is probed through a tunnel
// of its own, with pauses that double (and vary) while it fails and only
// while programs use the tunnel. Traffic returns after several good probes
// in a row and a minimum stay on the backup, which doubles each time the
// primary fails soon after a return.
package failover

import (
	"math/rand/v2"
	"time"
)

// Result is one check through the active entry's tunnel.
type Result int

const (
	// OK: generate_204 answered.
	OK Result = iota
	// Failed: the tunnel refused or closed without an answer.
	Failed
	// Frozen: the tunnel took the request but sent nothing in time.
	Frozen
	// NoNetwork: the check failed and this machine has no route to the
	// server at all (Wi-Fi is reconnecting, the cable is out). That says
	// nothing about the server.
	NoNetwork
)

// Config holds the timings. Defaults is what Ashgate uses.
type Config struct {
	SuspectAfter  time.Duration // traffic unanswered for this long starts a check
	FailsToSwitch int           // refused checks in a row before switching
	RetryAfter    time.Duration // second check after a refused one
	RecheckBase   time.Duration // pause after a check that found the server alive
	RecheckMax    time.Duration // that pause doubles up to this while alarms repeat
	RetryBase     time.Duration // pause after every server failed
	RetryMax      time.Duration // cap of that pause
	ProbeBase     time.Duration // first probe of the primary after a switch
	ProbeMax      time.Duration // cap of the pause between failed probes
	ConfirmEvery  time.Duration // pause between probes once one succeeded
	PrimaryNeed   int           // good probes in a row to return
	MinReturn     time.Duration // shortest stay on a backup
	MaxHold       time.Duration // cap of that stay after repeated returns
	FlapWindow    time.Duration // a primary that fails this soon after a return doubles the stay
	UseWithin     time.Duration // probe only if programs used the tunnel this recently
	ProvenFor     time.Duration // how long an answer keeps the tunnel "proven"
}

// Defaults: traffic unanswered for 2 s starts a check; a check with no
// answer switches at once, a refused one after a second refusal 0.5 s
// later.
// A false alarm pauses the next check for 5 s, doubling to 1 min while
// alarms repeat. When every server failed the pause grows from 10 s to
// 5 min. The primary is probed 15 s after a switch, then after pauses that
// double up to 5 min; three good probes 8 s apart and at least 30 s on the
// backup bring traffic back. A primary that fails within 10 min of a
// return doubles that stay, up to 15 min.
var Defaults = Config{
	SuspectAfter:  2 * time.Second,
	FailsToSwitch: 2,
	RetryAfter:    500 * time.Millisecond,
	RecheckBase:   5 * time.Second,
	RecheckMax:    time.Minute,
	RetryBase:     10 * time.Second,
	RetryMax:      5 * time.Minute,
	ProbeBase:     15 * time.Second,
	ProbeMax:      5 * time.Minute,
	ConfirmEvery:  8 * time.Second,
	PrimaryNeed:   3,
	MinReturn:     30 * time.Second,
	MaxHold:       15 * time.Minute,
	FlapWindow:    10 * time.Minute,
	UseWithin:     3 * time.Minute,
	ProvenFor:     2 * time.Minute,
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

// Evidence is what the traffic of programs through the active server shows
// right now. The connection times count only connections opened at or
// after Group.Since: older ones used another server or were judged before.
type Evidence struct {
	// WaitingSince is when the oldest open connection that sent something
	// and has no answer yet sent it. Zero: there is none.
	WaitingSince time.Time
	// LastDead is when a connection last ended without an answer. Zero:
	// none did.
	LastDead time.Time
	// LastGood is when a connection last got its first bytes back through
	// the server (not from a domain that goes direct).
	LastGood time.Time
	// SilentSince and SilentLast are the first and the latest moment
	// programs sent bytes (UDP and open connections too) with nothing at
	// all coming back since. Zero: the last thing that happened was an
	// answer.
	SilentSince, SilentLast time.Time
	// LastUse is when programs last sent something through the server.
	LastUse time.Time
}

// Group is the failover state of one subscription; entry 0 is the primary
// (XHTTP when the subscription has one). It is not safe for concurrent use.
type Group struct {
	cfg  Config
	rand func() float64
	n    int

	Active     int
	Reason     string    // why the active entry was chosen; "" at start
	SwitchedAt time.Time // last switch

	// from: evidence older than this says nothing about the active entry
	// as it is now (see Since). provenAt is its last answer.
	from     time.Time
	provenAt time.Time
	verified bool
	lastUse  time.Time

	// A check may start at notBefore or later. wanted asks for one
	// without new evidence: the second after a refusal.
	notBefore time.Time
	// roundAt holds the checks back after every entry failed; an answer
	// lifts it.
	roundAt time.Time
	wanted  bool
	alarm   bool      // the running check is one Observe asked for
	checkAt time.Time // when the running check started
	fails   int
	// gap is the pause after the last check that found the server alive,
	// okAt when that was.
	gap  time.Duration
	okAt time.Time

	failed  map[int]bool // entries that failed in this round
	backoff Backoff      // every entry failed

	primaryOK  int
	nextProbe  time.Time
	probes     Backoff
	returnedAt time.Time // last return to the primary after good probes
	flaps      int       // returns that did not last FlapWindow, in a row
}

// New starts on the primary of n entries. rnd may be nil.
func New(n int, now time.Time, cfg Config, rnd func() float64) *Group {
	if rnd == nil {
		rnd = rand.Float64
	}
	g := &Group{cfg: cfg, rand: rnd, n: n, failed: map[int]bool{}, from: now}
	g.backoff = Backoff{Base: cfg.RetryBase, Max: cfg.RetryMax, Rand: rnd}
	g.probes = Backoff{Base: cfg.ProbeBase, Max: cfg.ProbeMax, Rand: rnd}
	return g
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
		g.from, g.notBefore, g.roundAt, g.gap, g.wanted = now, time.Time{}, time.Time{}, 0, false
	}
	if g.Active != 0 {
		g.probes.Reset()
		g.nextProbe = now.Add(g.firstProbe())
	}
}

// Since is the oldest moment evidence may come from: the last switch, the
// moment the new server's tunnel was ready, or its last answer.
func (g *Group) Since() time.Time { return g.from }

// Ready tells the group that the active entry's tunnel is up after a
// switch. Connections made while it was being replaced say nothing.
func (g *Group) Ready(now time.Time) {
	if now.After(g.from) {
		g.from = now
	}
}

// Proven reports that the active entry answered within ProvenFor: the
// tunnel is known to work right now.
func (g *Group) Proven(now time.Time) bool {
	return g.verified && now.Sub(g.provenAt) < g.cfg.ProvenFor
}

// Observe takes the current evidence and reports whether a check of the
// active entry should start now. The caller then calls Begin, runs the
// check and reports it with Check; it does not call Observe for a group
// whose check is running.
func (g *Group) Observe(now time.Time, ev Evidence) bool {
	if g.n == 0 {
		return false
	}
	if ev.LastUse.After(g.lastUse) {
		g.lastUse = ev.LastUse
	}
	if !ev.LastGood.Before(g.from) && !ev.LastGood.IsZero() {
		g.alive(ev.LastGood)
	}
	if now.Before(g.notBefore) || now.Before(g.roundAt) {
		return false
	}
	return g.wanted || g.suspect(now, ev)
}

// suspect reports traffic that the active entry left unanswered.
func (g *Group) suspect(now time.Time, ev Evidence) bool {
	fresh := func(t time.Time) bool { return !t.IsZero() && !t.Before(g.from) }
	switch {
	case fresh(ev.LastDead):
		// It already failed; there is nothing to wait for.
		return true
	case fresh(ev.WaitingSince) && now.Sub(ev.WaitingSince) >= g.cfg.SuspectAfter:
		return true
	case fresh(ev.SilentSince) && ev.SilentLast.Sub(ev.SilentSince) >= g.cfg.SuspectAfter:
		// Programs sent, and sent again this much later, into silence. One
		// request that waits for a slow answer (a long poll) is not that.
		return true
	}
	return false
}

// Begin records that the check Observe asked for starts now.
func (g *Group) Begin(now time.Time) {
	g.checkAt = now
	g.wanted = false
	g.alarm = true
}

// BeginOwn is Begin for a check the caller runs on its own account, to
// know that the tunnel works before it relies on it. Nothing through the
// server went unanswered, so whatever this check finds, it switches
// nothing: without a failing program behind it, a check that fails may be
// the machine's own network coming up.
func (g *Group) BeginOwn(now time.Time) {
	g.Begin(now)
	g.alarm = false
}

// Check records the check started with Begin and reports whether the
// active entry changed. lastGood is Evidence.LastGood as it is now: when
// real traffic was answered while the check ran, the server is alive
// whatever the check says (its target may be the one in trouble). label
// names entries for the switch reason.
func (g *Group) Check(now time.Time, r Result, lastGood time.Time, label func(int) string) bool {
	if r != OK && !lastGood.IsZero() && !lastGood.Before(g.checkAt) {
		r = OK
	}
	if !g.alarm {
		// The caller's own check: see BeginOwn.
		if r == OK {
			g.alive(now)
		} else {
			g.verified = false
		}
		return false
	}
	switch r {
	case NoNetwork:
		// Ask again when the network may be back; the server is not
		// judged, and what went unanswered meanwhile is not held
		// against it.
		g.verified = false
		g.wanted, g.fails = false, 0
		g.from = now
		g.notBefore = now.Add(Jitter(g.cfg.RecheckBase, 0.2, g.rand()))
		return false
	case OK:
		g.alive(now)
		// A false alarm. While they repeat, check less and less often.
		if g.gap == 0 || now.Sub(g.okAt) >= 2*g.cfg.RecheckMax {
			g.gap = g.cfg.RecheckBase
		} else if g.gap *= 2; g.gap > g.cfg.RecheckMax {
			g.gap = g.cfg.RecheckMax
		}
		g.okAt = now
		g.notBefore = now.Add(Jitter(g.gap, 0.2, g.rand()))
		return false
	case Failed:
		g.verified = false
		g.fails++
		if g.fails < g.cfg.FailsToSwitch {
			g.wanted = true
			g.notBefore = now.Add(g.cfg.RetryAfter)
			return false
		}
		return g.switchAway(now, label(g.Active)+": соединение отклонено", label)
	default:
		return g.switchAway(now, label(g.Active)+": нет ответа", label)
	}
}

// alive records an answer through the active entry at at.
func (g *Group) alive(at time.Time) {
	g.verified = true
	if at.After(g.provenAt) {
		g.provenAt = at
	}
	if at.After(g.from) {
		g.from = at
	}
	g.fails, g.wanted = 0, false
	delete(g.failed, g.Active)
	g.backoff.Reset()
	g.roundAt = time.Time{}
}

// switchAway moves to the next entry by priority that has not failed in
// this round. When every entry has failed, a new round starts, and the
// next check waits on the exponential backoff, so the servers never see a
// reconnect storm.
func (g *Group) switchAway(now time.Time, why string, label func(int) string) bool {
	g.verified = false
	g.failed[g.Active] = true
	g.fails, g.primaryOK, g.wanted = 0, 0, false
	g.gap, g.okAt = 0, time.Time{}
	g.from = now
	g.notBefore = time.Time{}
	if g.n < 2 {
		g.Reason = why
		g.roundAt = now.Add(g.backoff.Next())
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
		g.roundAt = now.Add(g.backoff.Next())
	}
	if g.Active == 0 {
		// Leaving the primary. Soon after a return, that return was a
		// mistake: the next one waits twice as long.
		if !g.returnedAt.IsZero() && now.Sub(g.returnedAt) < g.cfg.FlapWindow {
			g.flaps++
		} else {
			g.flaps = 0
		}
		g.probes.Reset()
		g.nextProbe = now.Add(g.firstProbe())
	}
	g.Active = next
	g.Reason = why + " → " + label(next)
	g.SwitchedAt = now
	return true
}

// hold is the shortest stay on a backup before a return: MinReturn,
// doubled for every return that did not last.
func (g *Group) hold() time.Duration {
	d := g.cfg.MinReturn
	for i := 0; i < g.flaps && d < g.cfg.MaxHold; i++ {
		d *= 2
	}
	if d > g.cfg.MaxHold {
		d = g.cfg.MaxHold
	}
	return d
}

// firstProbe is the pause before the first probe after a switch: ProbeBase
// (±20 %), or later when the stay is long, so that the probes that confirm
// the primary end when the stay does.
func (g *Group) firstProbe() time.Duration {
	d := Jitter(g.cfg.ProbeBase, 0.2, g.rand())
	if late := g.hold() - time.Duration(g.cfg.PrimaryNeed-1)*g.cfg.ConfirmEvery; late > d {
		d = late
	}
	return d
}

// ProbeDue reports whether the primary should be probed now: only while a
// backup carries traffic, and only while programs use the tunnel, so that
// an idle machine does not knock on a blocked server all night.
func (g *Group) ProbeDue(now time.Time) bool {
	if g.Active == 0 || g.n < 2 || now.Before(g.nextProbe) {
		return false
	}
	return !g.lastUse.IsZero() && now.Sub(g.lastUse) < g.cfg.UseWithin
}

// Probe records a probe of the primary through its own tunnel and reports
// whether traffic returns to it: after PrimaryNeed good probes in a row,
// and never sooner than the stay on the backup allows.
func (g *Group) Probe(now time.Time, ok bool, label func(int) string) bool {
	if !ok {
		g.primaryOK = 0
		g.nextProbe = now.Add(g.probes.Next())
		return false
	}
	g.primaryOK++
	left := g.hold() - now.Sub(g.SwitchedAt)
	if g.primaryOK < g.cfg.PrimaryNeed || left > 0 {
		next := Jitter(g.cfg.ConfirmEvery, 0.2, g.rand())
		if g.primaryOK >= g.cfg.PrimaryNeed && left > next {
			next = left // confirmed already: once more when the stay ends
		}
		g.nextProbe = now.Add(next)
		return false
	}
	g.Active = 0
	g.verified = false
	g.Reason = label(0) + ": основной сервер снова отвечает"
	g.SwitchedAt, g.returnedAt, g.from = now, now, now
	g.primaryOK, g.fails, g.wanted = 0, 0, false
	g.gap, g.okAt, g.notBefore, g.roundAt = 0, time.Time{}, time.Time{}, time.Time{}
	g.failed = map[int]bool{}
	g.backoff.Reset()
	return true
}
