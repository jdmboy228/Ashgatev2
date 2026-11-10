package failover

import (
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func label(i int) string { return []string{"x1 · XHTTP", "raw1 · RAW", "g1 · GRPC"}[i] }

func fixed(r float64) func() float64 { return func() float64 { return r } }

func at(d time.Duration) time.Time { return t0.Add(d) }

const sec = time.Second

// check runs one check that Observe asked for at now and reports a switch.
func check(t *testing.T, g *Group, now time.Time, ev Evidence, r Result) bool {
	t.Helper()
	if !g.Observe(now, ev) {
		t.Fatalf("no check wanted at %v", now.Sub(t0))
	}
	g.Begin(now)
	return g.Check(now, r, ev.LastGood, label)
}

// An idle tunnel is never checked: nothing but traffic, or the start of
// capture, asks for a check.
func TestNoCheckWithoutTraffic(t *testing.T) {
	g := New(2, t0, Defaults, fixed(0.5))
	for d := time.Duration(0); d < 24*time.Hour; d += 7 * sec {
		if g.Observe(at(d), Evidence{}) {
			t.Fatalf("a check of an idle tunnel after %v", d)
		}
		if g.ProbeDue(at(d)) {
			t.Fatalf("a probe while on the primary after %v", d)
		}
	}
	// Answered traffic asks for nothing either.
	if g.Observe(at(25*time.Hour), Evidence{LastGood: at(25*time.Hour - sec), LastUse: at(25*time.Hour - sec)}) {
		t.Fatal("a check while traffic is answered")
	}
	if !g.Proven(at(25 * time.Hour)) {
		t.Fatal("answered traffic did not prove the tunnel")
	}
	if g.Proven(at(26 * time.Hour)) {
		t.Fatal("an hour-old answer still proves the tunnel")
	}
}

// A check the caller makes on its own account (before a subscription
// update) proves the tunnel or not, and never switches: no program's
// traffic went unanswered.
func TestOwnCheckNeverSwitches(t *testing.T) {
	g := New(2, t0, Defaults, fixed(0.5))
	g.BeginOwn(t0)
	if g.Check(at(sec), OK, time.Time{}, label) || !g.Proven(at(2*sec)) {
		t.Fatal("a good check of the caller's own did not prove the tunnel")
	}
	// It sets no pause for a real alarm.
	if !g.Observe(at(4*sec), Evidence{WaitingSince: at(2 * sec)}) {
		t.Fatal("the caller's own check delayed a real alarm")
	}
	for _, r := range []Result{Frozen, Failed, NoNetwork} {
		g := New(2, t0, Defaults, fixed(0.5))
		g.BeginOwn(t0)
		if g.Check(at(4*sec), r, time.Time{}, label) || g.Active != 0 || g.Proven(at(4*sec)) {
			t.Fatalf("result %v of the caller's own check: active %d", r, g.Active)
		}
		if g.Observe(at(5*sec), Evidence{}) {
			t.Fatalf("result %v of the caller's own check asked for another", r)
		}
	}
}

// The machine itself has no network: the server is not judged, the check
// comes again 5 s later, and what went unanswered meanwhile is forgotten.
func TestNoNetworkDoesNotSwitch(t *testing.T) {
	g := New(2, t0, Defaults, fixed(0.5))
	ev := Evidence{WaitingSince: at(10 * sec), LastDead: at(11 * sec)}
	for i := 0; i < 20; i++ {
		now := at(12*sec + time.Duration(i)*5*sec)
		if check(t, g, now, Evidence{WaitingSince: now.Add(-3 * sec), LastDead: now}, NoNetwork) || g.Active != 0 {
			t.Fatalf("switched with no network (round %d)", i)
		}
		if g.Observe(now.Add(4*sec), ev) {
			t.Fatal("the next check came within 5 s")
		}
		// Evidence from before that check does not count afterwards.
		if g.Observe(now.Add(5*sec), Evidence{WaitingSince: now.Add(-sec), LastDead: now.Add(-sec)}) {
			t.Fatal("traffic that failed while the network was down was held against the server")
		}
	}
}

// A connection that sent and has waited 2 s starts a check; no answer to
// the check either switches at once.
func TestStallSwitchesAfterOneCheck(t *testing.T) {
	g := New(2, t0, Defaults, fixed(0.5))
	ev := Evidence{WaitingSince: at(10 * sec), LastUse: at(10 * sec)}
	if g.Observe(at(11*sec), ev) {
		t.Fatal("a check after 1 s of waiting")
	}
	if !check(t, g, at(12*sec), ev, Frozen) || g.Active != 1 {
		t.Fatalf("active %d after a frozen check", g.Active)
	}
	if !strings.Contains(g.Reason, "x1 · XHTTP: нет ответа") || !strings.HasSuffix(g.Reason, "→ raw1 · RAW") {
		t.Fatalf("reason %q", g.Reason)
	}
	if !g.SwitchedAt.Equal(at(12*sec)) || !g.Since().Equal(at(12*sec)) {
		t.Fatalf("switched at %v, evidence from %v", g.SwitchedAt, g.Since())
	}
	// What the old server left unanswered says nothing about the new one.
	if g.Observe(at(13*sec), ev) {
		t.Fatal("the old server's waiting connection started a check of the new one")
	}
}

// A refused check is repeated a second later; two in a row switch. A
// connection that already ended unanswered needs no 2 s of waiting.
func TestRefusedSwitchesAfterTwoChecks(t *testing.T) {
	g := New(3, t0, Defaults, fixed(0.5))
	ev := Evidence{LastDead: at(5 * sec)}
	if check(t, g, at(5*sec), ev, Failed) {
		t.Fatal("switched after one refusal")
	}
	if g.Observe(at(5*sec+400*time.Millisecond), Evidence{}) {
		t.Fatal("the second check came within half a second")
	}
	// The second check comes even when the evidence is gone.
	if !check(t, g, at(5*sec+500*time.Millisecond), Evidence{}, Failed) || g.Active != 1 {
		t.Fatalf("active %d after two refusals", g.Active)
	}
	if !strings.Contains(g.Reason, "соединение отклонено") {
		t.Fatalf("reason %q", g.Reason)
	}
	// An answer between two refusals starts the count again.
	g = New(3, t0, Defaults, fixed(0.5))
	check(t, g, at(5*sec), ev, Failed)
	if g.Observe(at(6*sec), Evidence{LastGood: at(5*sec + 800*time.Millisecond)}) {
		t.Fatal("a check although traffic was answered since the refusal")
	}
	if check(t, g, at(20*sec), Evidence{LastDead: at(20 * sec)}, Failed) || g.Active != 0 {
		t.Fatal("a refusal after an answer switched at once")
	}
}

// Traffic answered while the check ran outweighs a check that failed: the
// server works, the check's target does not.
func TestAnswerDuringCheckWins(t *testing.T) {
	g := New(2, t0, Defaults, fixed(0.5))
	now := at(12 * sec)
	if !g.Observe(now, Evidence{WaitingSince: at(10 * sec)}) {
		t.Fatal("no check")
	}
	g.Begin(now)
	if g.Check(at(15*sec), Frozen, at(13*sec), label) || g.Active != 0 || !g.Proven(at(15*sec)) {
		t.Fatalf("switched although traffic was answered: active %d", g.Active)
	}
}

// Programs sending into silence (UDP, requests on open connections) start
// a check once they have sent again 2 s after the first time. One request
// that waits for a slow answer does not.
func TestSilenceStartsACheck(t *testing.T) {
	g := New(2, t0, Defaults, fixed(0.5))
	if g.Observe(at(60*sec), Evidence{SilentSince: at(10 * sec), SilentLast: at(10 * sec)}) {
		t.Fatal("one unanswered request (a long poll) started a check")
	}
	if g.Observe(at(11*sec), Evidence{SilentSince: at(10 * sec), SilentLast: at(11 * sec)}) {
		t.Fatal("a check after 1 s of silence")
	}
	ev := Evidence{SilentSince: at(10 * sec), SilentLast: at(12 * sec)}
	if check(t, g, at(12*sec), ev, OK) {
		t.Fatal("a good check switched")
	}
	// The same silence was judged: no second check for it.
	ev.SilentLast = at(5 * time.Minute)
	if g.Observe(at(5*time.Minute), ev) {
		t.Fatal("silence that a check already answered started another")
	}
}

// False alarms that repeat are checked less and less often: 5 s, 10 s, …
// 1 min; after two quiet minutes the pause starts from 5 s again.
func TestFalseAlarmsBackOff(t *testing.T) {
	g := New(2, t0, Defaults, fixed(0.5))
	now := t0
	var gaps []time.Duration
	last := now
	for i := 0; i < 7; i++ {
		// A new dead connection every 100 ms, as from a program that
		// keeps retrying a site that is down.
		for ; !g.Observe(now, Evidence{LastDead: now}); now = now.Add(100 * time.Millisecond) {
		}
		g.Begin(now)
		g.Check(now, OK, time.Time{}, label)
		if i > 0 {
			gaps = append(gaps, now.Sub(last).Round(sec))
		}
		last = now
	}
	want := []time.Duration{5 * sec, 10 * sec, 20 * sec, 40 * sec, 60 * sec, 60 * sec}
	for i := range want {
		if gaps[i] != want[i] {
			t.Fatalf("pauses %v, want %v", gaps, want)
		}
	}
	now = now.Add(3 * time.Minute)
	check(t, g, now, Evidence{LastDead: now}, OK)
	if g.Observe(now.Add(4*sec), Evidence{LastDead: now.Add(4 * sec)}) {
		t.Fatal("no pause after a false alarm")
	}
	if !g.Observe(now.Add(6*sec), Evidence{LastDead: now.Add(6 * sec)}) {
		t.Fatal("the pause did not start from 5 s after two quiet minutes")
	}
}

// When every server failed, a new round starts from the primary after an
// exponential backoff (with jitter), so the servers see no reconnect storm.
// Within a round the next untried server is checked without a pause.
func TestAllFailedBacksOff(t *testing.T) {
	g := New(2, t0, Defaults, fixed(0.5))
	now := t0
	var waits []time.Duration
	for i := 0; i < 16; i++ {
		start := now
		for ; !g.Observe(now, Evidence{LastDead: now}); now = now.Add(sec) {
		}
		g.Begin(now)
		if !g.Check(now, Frozen, time.Time{}, label) {
			t.Fatalf("step %d: no switch", i)
		}
		waits = append(waits, now.Sub(start))
	}
	backoff := []time.Duration{10, 20, 40, 80, 160, 300, 300, 300}
	for i, w := range waits {
		want := time.Duration(0) // the untried server: at once
		if i > 0 && i%2 == 0 {
			want = backoff[i/2-1] * sec // the round is over: back off
		}
		if w != want {
			t.Fatalf("waits %v; step %d = %v, want %v", waits, i, w, want)
		}
	}
	// An answer ends the backoff: the next alarm is checked at once.
	if g.Observe(now.Add(sec), Evidence{LastGood: now.Add(sec)}) {
		t.Fatal("a check while traffic is answered")
	}
	now = now.Add(2 * sec)
	if !check(t, g, now, Evidence{LastDead: now}, Frozen) {
		t.Fatal("no switch after the answer")
	}
	if !g.Observe(now, Evidence{LastDead: now.Add(sec)}) {
		t.Fatal("the next server of a new round waited")
	}
}

func TestBackoffJitter(t *testing.T) {
	for _, r := range []float64{0, 0.999} {
		b := Backoff{Base: 10 * time.Second, Max: 5 * time.Minute, Rand: fixed(r)}
		for i := 0; i < 12; i++ {
			d := b.Next()
			base := 10 * time.Second << i
			if base > 5*time.Minute || base <= 0 {
				base = 5 * time.Minute
			}
			if d < base*8/10 || d > base*12/10 {
				t.Fatalf("r=%v step %d: %v not within ±20 %% of %v", r, i, d, base)
			}
		}
		b.Reset()
		if d := b.Next(); d > 12*time.Second {
			t.Fatalf("after Reset: %v", d)
		}
	}
}

// toBackup moves a new group to the backup at t0.
func toBackup(t *testing.T, n int) *Group {
	t.Helper()
	g := New(n, t0, Defaults, fixed(0.5))
	if !check(t, g, t0, Evidence{LastDead: t0, LastUse: t0}, Frozen) || g.Active != 1 {
		t.Fatal("no switch to the backup")
	}
	return g
}

// used keeps the tunnel in use at now, as the caller's evidence would.
func used(g *Group, now time.Time) { g.Observe(now, Evidence{LastUse: now, LastGood: now}) }

// On a backup the primary is probed 15 s after the switch, then after
// pauses that double up to 5 min; nothing has a fixed period.
func TestProbePausesDouble(t *testing.T) {
	g := toBackup(t, 3)
	if g.ProbeDue(at(14 * sec)) {
		t.Fatal("probe before 15 s")
	}
	now := at(15 * sec)
	var gaps []time.Duration
	for i := 0; i < 7; i++ {
		used(g, now)
		if !g.ProbeDue(now) {
			t.Fatalf("probe %d not due at %v", i, now.Sub(t0))
		}
		g.Probe(now, false, label)
		start := now
		for ; !g.ProbeDue(now); now = now.Add(sec) {
			used(g, now)
		}
		gaps = append(gaps, now.Sub(start))
	}
	want := []time.Duration{15 * sec, 30 * sec, 60 * sec, 120 * sec, 240 * sec, 300 * sec, 300 * sec}
	for i := range want {
		if gaps[i] != want[i] {
			t.Fatalf("pauses %v, want %v", gaps, want)
		}
	}
}

// The primary is probed only while programs use the tunnel.
func TestNoProbesWhileIdle(t *testing.T) {
	g := toBackup(t, 2)
	for d := 4 * time.Minute; d < 12*time.Hour; d += time.Minute {
		if g.ProbeDue(at(d)) {
			t.Fatalf("a probe of the primary %v after the last use", d)
		}
	}
	used(g, at(12*time.Hour))
	if !g.ProbeDue(at(12*time.Hour + sec)) {
		t.Fatal("no probe when the tunnel is used again")
	}
}

// Three good probes in a row, 8 s apart, and at least 30 s on the backup
// bring traffic back; a bad probe starts the count again.
func TestReturnToPrimary(t *testing.T) {
	g := toBackup(t, 3)
	now := at(15 * sec)
	used(g, now)
	if g.Probe(now, true, label) {
		t.Fatal("returned after one good probe")
	}
	if g.ProbeDue(now.Add(7*sec)) || !g.ProbeDue(now.Add(8*sec)) {
		t.Fatal("the confirming probe is not 8 s later")
	}
	now = at(23 * sec)
	if g.Probe(now, false, label) {
		t.Fatal("a failed probe returned")
	}
	now = at(40 * sec)
	g.Probe(now, true, label)
	g.Probe(at(48*sec), true, label)
	if !g.Probe(at(56*sec), true, label) || g.Active != 0 || !strings.Contains(g.Reason, "основной сервер снова отвечает") {
		t.Fatalf("active %d reason %q", g.Active, g.Reason)
	}
	if g.ProbeDue(at(time.Hour)) {
		t.Fatal("probing the primary while on it")
	}
	if g.Proven(at(57 * sec)) {
		t.Fatal("the primary counts as proven before any traffic through it")
	}
}

// No return sooner than 30 s after the switch, however the probes go.
func TestReturnNotTooSoon(t *testing.T) {
	g := toBackup(t, 2)
	g.Probe(at(5*sec), true, label)
	g.Probe(at(10*sec), true, label)
	if g.Probe(at(15*sec), true, label) {
		t.Fatal("returned 15 s after a switch")
	}
	// Confirmed already: the next probe waits for the stay to end.
	used(g, at(29*sec))
	if g.ProbeDue(at(29*sec)) || !g.ProbeDue(at(30*sec)) {
		t.Fatal("the last probe is not at the end of the stay")
	}
	if !g.Probe(at(30*sec), true, label) {
		t.Fatal("did not return after 30 s")
	}
}

// A primary that fails again within 10 min of a return doubles the stay
// on the backup: 30 s, 1 min, 2 min, … 15 min. A return that lasted
// starts from 30 s again.
func TestFlappingPrimaryStaysAwayLonger(t *testing.T) {
	g := New(2, t0, Defaults, fixed(0.5))
	now := t0
	var stays []time.Duration
	for i := 0; i < 8; i++ {
		// The primary fails a minute after traffic came (back) to it.
		now = now.Add(time.Minute)
		if !check(t, g, now, Evidence{LastDead: now, LastUse: now}, Frozen) {
			t.Fatalf("round %d: no switch away", i)
		}
		left := now
		// It answers every probe from then on.
		for g.Active != 0 {
			for ; !g.ProbeDue(now); now = now.Add(sec) {
				used(g, now)
			}
			g.Probe(now, true, label)
		}
		stays = append(stays, now.Sub(left).Round(10*sec))
	}
	want := []time.Duration{30 * sec, 60 * sec, 120 * sec, 240 * sec, 480 * sec, 900 * sec, 900 * sec, 900 * sec}
	for i := range want {
		if stays[i] != want[i] {
			t.Fatalf("stays %v, want %v", stays, want)
		}
	}
	// It then holds for 10 min: the next failure is a first one again.
	now = now.Add(11 * time.Minute)
	check(t, g, now, Evidence{LastDead: now, LastUse: now}, Frozen)
	left := now
	for g.Active != 0 {
		for ; !g.ProbeDue(now); now = now.Add(sec) {
			used(g, now)
		}
		g.Probe(now, true, label)
	}
	if d := now.Sub(left).Round(10 * sec); d != 30*sec {
		t.Fatalf("stay after a return that lasted: %v, want 30 s", d)
	}
}

func TestSingleEntryNeverSwitches(t *testing.T) {
	g := New(1, t0, Defaults, fixed(0.5))
	if check(t, g, t0, Evidence{LastDead: t0}, Frozen) || g.Active != 0 {
		t.Fatal("switched with one entry")
	}
	if g.Reason == "" {
		t.Fatal("no reason shown for the only server")
	}
	if g.Observe(at(9*sec), Evidence{LastDead: at(9 * sec)}) || !g.Observe(at(10*sec), Evidence{LastDead: at(10 * sec)}) {
		t.Fatal("the next check is not 10 s later")
	}
}

// A new list with the active link still present keeps it; a forced move
// records why and judges the new server from then on.
func TestReset(t *testing.T) {
	g := toBackup(t, 3)
	g.Reset(4, 2, at(time.Minute), false, "")
	used(g, at(time.Minute+20*sec))
	if g.Active != 2 || !g.ProbeDue(at(time.Minute+20*sec)) {
		t.Fatalf("active %d", g.Active)
	}
	g.Reset(2, 0, at(2*time.Minute), true, "подписка обновлена")
	if g.Active != 0 || g.Reason != "подписка обновлена" || g.ProbeDue(at(time.Hour)) || !g.Since().Equal(at(2*time.Minute)) {
		t.Fatalf("active %d reason %q", g.Active, g.Reason)
	}
}

// The tunnel of a new server is ready a moment after the switch: what
// connections showed in between does not count.
func TestReadyMovesTheCutoff(t *testing.T) {
	g := toBackup(t, 2)
	g.Ready(at(700 * time.Millisecond))
	if g.Observe(at(sec), Evidence{LastDead: at(500 * time.Millisecond)}) {
		t.Fatal("a connection refused while the tunnel was replaced started a check")
	}
	if !g.Observe(at(sec), Evidence{LastDead: at(900 * time.Millisecond)}) {
		t.Fatal("a dead connection on the new server did not start a check")
	}
}
