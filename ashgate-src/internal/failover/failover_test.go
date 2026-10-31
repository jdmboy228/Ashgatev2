package failover

import (
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func label(i int) string { return []string{"x1 · XHTTP", "raw1 · RAW", "g1 · GRPC"}[i] }

func fixed(r float64) func() float64 { return func() float64 { return r } }

func TestChecksEveryMinuteWithJitter(t *testing.T) {
	for _, r := range []float64{0, 0.5, 0.999} {
		g := New(3, t0, Defaults, fixed(r))
		d := g.NextCheck().Sub(t0)
		if d < 48*time.Second || d > 72*time.Second {
			t.Fatalf("r=%v: first check after %v, want 60 s ±20 %%", r, d)
		}
		g.Check(t0.Add(d), OK, label)
		if gap := g.NextCheck().Sub(t0.Add(d)); gap < 48*time.Second || gap > 72*time.Second {
			t.Fatalf("r=%v: next check after %v", r, gap)
		}
	}
}

func TestTwoFailuresSwitch(t *testing.T) {
	g := New(3, t0, Defaults, fixed(0.5))
	if g.Check(t0, Failed, label) {
		t.Fatal("switched after one failure")
	}
	if d := g.NextCheck().Sub(t0); d != 10*time.Second {
		t.Fatalf("re-check after %v, want 10 s", d)
	}
	if !g.Check(t0.Add(10*time.Second), Failed, label) || g.Active != 1 {
		t.Fatalf("active %d after two failures", g.Active)
	}
	if !strings.Contains(g.Reason, "x1 · XHTTP: не отвечает") || !strings.HasSuffix(g.Reason, "→ raw1 · RAW") {
		t.Fatalf("reason %q", g.Reason)
	}
	// A success in between resets the count.
	g.Check(t0.Add(time.Minute), Failed, label)
	g.Check(t0.Add(2*time.Minute), OK, label)
	if g.Check(t0.Add(3*time.Minute), Failed, label) || g.Active != 1 {
		t.Fatal("a failure after a success switched at once")
	}
}

func TestFreezeSwitchesAtOnce(t *testing.T) {
	g := New(2, t0, Defaults, fixed(0.5))
	if !g.Check(t0, Frozen, label) || g.Active != 1 || !strings.Contains(g.Reason, "нет данных 15 с") {
		t.Fatalf("active %d reason %q", g.Active, g.Reason)
	}
}

// When every server failed, a new round starts from the primary after an
// exponential backoff (with jitter), so the servers see no reconnect storm.
// Within a round the next untried server is checked at the normal pace.
func TestAllFailedBacksOff(t *testing.T) {
	g := New(2, t0, Defaults, fixed(0.5))
	now := t0
	var waits []time.Duration
	for i := 0; i < 16; i++ {
		g.Check(now, Frozen, label)
		waits = append(waits, g.NextCheck().Sub(now))
		now = g.NextCheck()
	}
	backoff := []time.Duration{10, 20, 40, 80, 160, 300, 300, 300}
	for i, w := range waits {
		want := time.Minute // primary failed: try the untried backup
		if i%2 == 1 {
			want = backoff[i/2] * time.Second // round over: back off
		}
		if w != want {
			t.Fatalf("waits %v; step %d = %v, want %v", waits, i, w, want)
		}
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

// While on a backup, the primary is probed every 10 min; two good probes in
// a row bring traffic back; a bad probe starts the count again.
func TestReturnToPrimary(t *testing.T) {
	g := New(3, t0, Defaults, fixed(0.5))
	g.Check(t0, Frozen, label) // now on the RAW backup
	if g.ProbeDue(t0.Add(9 * time.Minute)) {
		t.Fatal("probe before 10 min")
	}
	at := t0.Add(10 * time.Minute)
	if !g.ProbeDue(at) || g.Probe(at, true, label) {
		t.Fatal("first good probe must not switch back")
	}
	at = at.Add(10 * time.Minute)
	if g.Probe(at, false, label) {
		t.Fatal("a failed probe switched")
	}
	at = at.Add(10 * time.Minute)
	g.Probe(at, true, label)
	at = at.Add(10 * time.Minute)
	if !g.Probe(at, true, label) || g.Active != 0 || !strings.Contains(g.Reason, "основной сервер снова отвечает") {
		t.Fatalf("active %d reason %q", g.Active, g.Reason)
	}
	if g.ProbeDue(at.Add(time.Hour)) {
		t.Fatal("probing the primary while on it")
	}
}

// No return sooner than 5 min after the last switch, however the probes go.
func TestReturnNotTooSoon(t *testing.T) {
	g := New(2, t0, Defaults, fixed(0.5))
	g.Check(t0, Frozen, label)
	g.Probe(t0.Add(time.Minute), true, label)
	if g.Probe(t0.Add(2*time.Minute), true, label) {
		t.Fatal("returned 2 min after a switch")
	}
	if !g.Probe(t0.Add(6*time.Minute), true, label) {
		t.Fatal("did not return after 5 min")
	}
}

func TestSingleEntryNeverSwitches(t *testing.T) {
	g := New(1, t0, Defaults, fixed(0.5))
	if g.Check(t0, Frozen, label) || g.Active != 0 {
		t.Fatal("switched with one entry")
	}
	if d := g.NextCheck().Sub(t0); d != 10*time.Second {
		t.Fatalf("re-check after %v", d)
	}
}

// A new list with the active link still present keeps it; a forced move
// records why.
func TestReset(t *testing.T) {
	g := New(3, t0, Defaults, fixed(0.5))
	g.Check(t0, Frozen, label)
	g.Reset(4, 2, t0.Add(time.Minute), false, "")
	if g.Active != 2 || !g.ProbeDue(t0.Add(11*time.Minute)) {
		t.Fatalf("active %d", g.Active)
	}
	g.Reset(2, 0, t0.Add(2*time.Minute), true, "подписка обновлена")
	if g.Active != 0 || g.Reason != "подписка обновлена" || g.ProbeDue(t0.Add(time.Hour)) {
		t.Fatalf("active %d reason %q", g.Active, g.Reason)
	}
}
