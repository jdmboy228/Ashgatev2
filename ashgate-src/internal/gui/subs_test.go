package gui

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ashgate/internal/config"
	"ashgate/internal/engine"
	"ashgate/internal/failover"
	"ashgate/internal/logbuf"
	"ashgate/internal/subs"
	"ashgate/internal/testkit"
	"ashgate/internal/vless"
)

// Fake values only.
const (
	subUUID = "b7e2c1a0-4f3a-4c2b-9a11-111111111111"
	subPBK  = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
)

func subLink(network, name string) string {
	extra := "&path=%2Fx&mode=auto"
	if network == "tcp" {
		extra = "&flow=xtls-rprx-vision"
	}
	return "vless://" + subUUID + "@203.0.113.10:443?type=" + network + "&security=reality&pbk=" + subPBK +
		"&fp=firefox&sni=example.com&sid=abcd" + extra + "#" + name
}

// subServer serves a subscription whose body and status the test changes.
type subServer struct {
	mu     sync.Mutex
	body   string
	status int
	hits   int
	srv    *httptest.Server
}

func newSubServer(t *testing.T, links ...string) *subServer {
	s := &subServer{status: http.StatusOK}
	s.set(links...)
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.hits++
		w.WriteHeader(s.status)
		_, _ = w.Write([]byte(s.body))
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *subServer) set(links ...string) {
	s.mu.Lock()
	s.body = base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))
	s.mu.Unlock()
}

func (s *subServer) fail(status int) {
	s.mu.Lock()
	s.status = status
	s.mu.Unlock()
}

func activeOf(t *testing.T, c *controller, name string) (label string, local string) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	g := c.subs[name]
	if g == nil || len(g.entries) == 0 {
		t.Fatalf("no servers for %s", name)
	}
	return g.label(g.fo.Active), c.bridgeSt[name].SOCKS
}

func TestSubscriptionLifecycle(t *testing.T) {
	old := subRand
	subRand = func() float64 { return 0.5 }
	t.Cleanup(func() { subRand = old })

	srv := newSubServer(t, subLink("tcp", "raw1"), subLink("xhttp", "x1"))
	url := srv.srv.URL + "/sub/secret-token"
	path := filepath.Join(t.TempDir(), "config.json")
	logs, _ := logbuf.New(200, "")
	c := newController(path, config.Default(), logs, hooks{})
	t.Cleanup(c.shutdown)
	const name = "Моя подписка"

	if err := c.addSub(name, url); err != nil {
		t.Fatal(err)
	}
	p, ok := c.cfg.ProxyByName(name)
	if !ok || p.Sub == nil || p.Sub.Count != 2 || p.Sub.Host != "http://"+srv.srv.Listener.Addr().String()+"/…" || p.Type != "vless" {
		t.Fatalf("%+v %+v", p, p.Sub)
	}
	file, _ := os.ReadFile(path)
	if strings.Contains(string(file), "secret-token") || strings.Contains(string(file), "vless://") {
		t.Fatal("the subscription URL or its links are stored in plain text")
	}

	// XHTTP is the primary even though the subscription lists RAW first.
	label, local1 := activeOf(t, c, name)
	if label != "x1 · XHTTP" || local1 == "" {
		t.Fatalf("active %q, bridge %q", label, local1)
	}
	if v := c.runtimeCfg(); v.Proxies[0].VLESS == nil || v.Proxies[0].VLESS.Network != "xhttp" || v.Proxies[0].Address != "203.0.113.10:443" {
		t.Fatalf("runtime proxy %+v", v.Proxies[0])
	}

	// The primary freezes: traffic moves to the RAW backup.
	c.mu.Lock()
	g := c.subs[name]
	g.fo.Begin(time.Now())
	switched := g.fo.Check(time.Now(), failover.Frozen, time.Time{}, g.label)
	c.mu.Unlock()
	if !switched {
		t.Fatal("no switch on a freeze")
	}
	c.switched(g)
	label, local2 := activeOf(t, c, name)
	if label != "raw1 · RAW" || local2 == local1 {
		t.Fatalf("after freeze: active %q bridge %q (was %q)", label, local2, local1)
	}

	// An update that still has the active link: no reconnect.
	srv.set(subLink("xhttp", "x2"), subLink("tcp", "raw1"), subLink("xhttp", "x1"))
	if err := c.refreshSub(name); err != nil {
		t.Fatal(err)
	}
	label, local3 := activeOf(t, c, name)
	if label != "raw1 · RAW" || local3 != local2 {
		t.Fatalf("reconnected although the active link stayed: %q %q", label, local3)
	}
	if p, _ := c.cfg.ProxyByName(name); p.Sub.Count != 3 || p.Sub.Error != "" {
		t.Fatalf("%+v", p.Sub)
	}

	// The active link is gone: the best entry by priority takes over.
	srv.set(subLink("tcp", "raw9"), subLink("xhttp", "x9"))
	if err := c.refreshSub(name); err != nil {
		t.Fatal(err)
	}
	label, local4 := activeOf(t, c, name)
	c.mu.Lock()
	reason := c.subs[name].fo.Reason
	c.mu.Unlock()
	if label != "x9 · XHTTP" || local4 == local3 || !strings.Contains(reason, "прежнего сервера") {
		t.Fatalf("active %q bridge %q reason %q", label, local4, reason)
	}

	// A failed update keeps the list: one retry after 30 min, then the
	// next daily update.
	srv.fail(http.StatusNotFound)
	before := time.Now()
	if err := c.refreshSub(name); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("%v", err)
	}
	c.mu.Lock()
	next := c.subs[name].nextFetch
	c.mu.Unlock()
	if d := next.Sub(before); d < 29*time.Minute || d > 31*time.Minute {
		t.Fatalf("retry in %v, want 30 min", d)
	}
	if p, _ := c.cfg.ProxyByName(name); p.Sub.Count != 2 || !strings.Contains(p.Sub.Error, "404") {
		t.Fatalf("%+v", p.Sub)
	}
	if label, _ := activeOf(t, c, name); label != "x9 · XHTTP" {
		t.Fatalf("a failed update changed the server: %q", label)
	}
	_ = c.refreshSub(name)
	c.mu.Lock()
	next = c.subs[name].nextFetch
	c.mu.Unlock()
	if d := next.Sub(before); d < 23*time.Hour || d > 25*time.Hour {
		t.Fatalf("after the retry: next update in %v, want ~24 h", d)
	}

	// Never two fetches at once.
	c.mu.Lock()
	c.subFetching = true
	c.mu.Unlock()
	if err := c.refreshSub(name); err == nil || !strings.Contains(err.Error(), "уже обновляется") {
		t.Fatalf("%v", err)
	}
	c.mu.Lock()
	c.subFetching = false
	c.mu.Unlock()

	// The window's copy of the subscription may be stale; the server's wins.
	stale := cloneCfg(c.cfg)
	stale.Proxies[0].Sub.Count = 99
	if err := c.replace(stale); err != nil {
		t.Fatal(err)
	}
	if p, _ := c.cfg.ProxyByName(name); p.Sub.Count != 2 {
		t.Fatalf("stale window state overwrote the subscription: %+v", p.Sub)
	}

	for _, e := range logs.Snapshot() {
		if strings.Contains(e.Error+e.Dest, "secret-token") || strings.Contains(e.Error, "vless://") {
			t.Fatalf("a log line shows the subscription: %+v", e)
		}
	}

	// Reloaded from disk, the subscription opens with its last list.
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	c2 := newController(path, loaded, nil, hooks{})
	t.Cleanup(c2.shutdown)
	if label, _ := activeOf(t, c2, name); label != "x9 · XHTTP" {
		t.Fatalf("after reload: %q", label)
	}
}

func TestAddSubscriptionRejectsBadInput(t *testing.T) {
	srv := newSubServer(t, "vmess://nothing-usable")
	c := newController(filepath.Join(t.TempDir(), "config.json"), config.Default(), nil, hooks{})
	t.Cleanup(c.shutdown)
	for _, tc := range []struct{ url, want string }{
		{"ftp://x/y", "https://"},
		{srv.srv.URL + "/sub/tok", "нет ни одной"},
	} {
		if err := c.addSub("s", tc.url); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.url, err)
		}
	}
	if len(c.cfg.Proxies) != 0 {
		t.Fatal("a failed subscription was added")
	}
}

// checkTunnel tells a working tunnel, a refused one and a frozen one apart.
func TestCheckTunnel(t *testing.T) {
	oldFreeze, oldHost, oldPort := checkTimeout, healthHost, healthPort
	checkTimeout = 300 * time.Millisecond
	t.Cleanup(func() { checkTimeout, healthHost, healthPort = oldFreeze, oldHost, oldPort })

	px, err := testkit.ListenSOCKS("u", "p")
	if err != nil {
		t.Fatal(err)
	}
	defer px.Close()
	serve := func(h http.HandlerFunc) {
		s := httptest.NewServer(h)
		t.Cleanup(s.Close)
		host, port, _ := net.SplitHostPort(s.Listener.Addr().String())
		n, _ := strconv.Atoi(port)
		healthHost, healthPort = host, uint16(n)
	}
	ctx := context.Background()

	serve(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/generate_204" && strings.Contains(r.UserAgent(), "Firefox") {
			w.WriteHeader(http.StatusNoContent)
		}
	})
	if got := checkTunnel(ctx, px.Addr, "u", "p"); got != failover.OK {
		t.Fatalf("working tunnel: %v", got)
	}
	if got := checkTunnel(ctx, px.Addr, "u", "wrong"); got != failover.Failed {
		t.Fatalf("wrong login: %v", got)
	}
	serve(func(w http.ResponseWriter, r *http.Request) {
		hj, _ := w.(http.Hijacker)
		conn, _, _ := hj.Hijack()
		_ = conn.Close()
	})
	if got := checkTunnel(ctx, px.Addr, "u", "p"); got != failover.Failed {
		t.Fatalf("closed tunnel: %v", got)
	}
	serve(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	if got := checkTunnel(ctx, px.Addr, "u", "p"); got != failover.Frozen {
		t.Fatalf("silent tunnel: %v", got)
	}
	serve(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	if got := checkTunnel(ctx, px.Addr, "u", "p"); got != failover.Failed {
		t.Fatalf("captive portal answer: %v", got)
	}
}

// fakeTunnel is a running capture session whose relays and byte counters
// the test scripts.
type fakeTunnel struct {
	mu    sync.Mutex
	h     engine.RelayHealth
	stats map[string]engine.RuleStat
	since []time.Time // the cutoffs RelayHealth was asked with
}

func (f *fakeTunnel) Running() bool { return true }

func (f *fakeTunnel) RelayHealth(_ string, since time.Time) engine.RelayHealth {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.since = append(f.since, since)
	h := f.h
	// Like the engine: what started before the cutoff is left out.
	if h.WaitingSince.Before(since) {
		h.Waiting, h.WaitingSince = 0, time.Time{}
	}
	if h.LastDead.Before(since) {
		h.Dead, h.LastDead = 0, time.Time{}
	}
	return h
}

func (f *fakeTunnel) RuleStats() map[string]engine.RuleStat {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]engine.RuleStat{}
	for k, v := range f.stats {
		out[k] = v
	}
	return out
}

func (f *fakeTunnel) set(h engine.RelayHealth) {
	f.mu.Lock()
	f.h = h
	f.mu.Unlock()
}

// foRig is a controller with one two-server subscription, a scripted
// capture session and scripted checks.
type foRig struct {
	t      *testing.T
	c      *controller
	g      *subGroup
	ft     *fakeTunnel
	logs   *logbuf.Buffer
	mu     sync.Mutex
	check  failover.Result // what a check of the active server finds
	checks int
	probe  bool // what a probe of the primary finds
	probes int
	// noRoute: the machine has no route to the server.
	noRoute bool
}

const rigSub = "sub"

func newFoRig(t *testing.T, cfg failover.Config) *foRig {
	t.Helper()
	r := &foRig{t: t, ft: &fakeTunnel{}}
	oldRand, oldSess, oldCfg, oldCheck, oldProbe, oldRoute := subRand, sessionOf, foConfig, checkActive, probeEntry, routeTo
	routeTo = func(string) bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return !r.noRoute
	}
	subRand = func() float64 { return 0.5 }
	sessionOf = func(*controller) tunnelSession { return r.ft }
	foConfig = cfg
	checkActive = func(vless.Status) failover.Result {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.checks++
		return r.check
	}
	probeEntry = func(subs.Entry) bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.probes++
		return r.probe
	}
	t.Cleanup(func() {
		subRand, sessionOf, foConfig, checkActive, probeEntry, routeTo = oldRand, oldSess, oldCfg, oldCheck, oldProbe, oldRoute
	})

	r.logs, _ = logbuf.New(50, "")
	r.c = newController(filepath.Join(t.TempDir(), "config.json"), config.Default(), r.logs, hooks{})
	t.Cleanup(r.c.shutdown)
	r.g = &subGroup{entries: subs.Entries([]string{subLink("xhttp", "x1"), subLink("tcp", "raw1")}),
		fo: failover.New(2, time.Now(), cfg, subRand), nextFetch: time.Now().Add(24 * time.Hour)}
	r.c.mu.Lock()
	r.c.subs = map[string]*subGroup{rigSub: r.g}
	r.c.mu.Unlock()
	return r
}

// tick runs one loop round at now and waits for what it started.
func (r *foRig) tick(now time.Time) {
	r.t.Helper()
	r.c.subsTick(now)
	deadline := time.Now().Add(5 * time.Second)
	for {
		r.c.mu.Lock()
		busy := r.g.checking || r.g.probing || r.g.applying
		r.c.mu.Unlock()
		if !busy {
			return
		}
		if time.Now().After(deadline) {
			r.t.Fatal("the check did not finish")
		}
		time.Sleep(time.Millisecond)
	}
}

func (r *foRig) active() int {
	r.c.mu.Lock()
	defer r.c.mu.Unlock()
	return r.g.fo.Active
}

func (r *foRig) counts() (checks, probes int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.checks, r.probes
}

func (r *foRig) set(check failover.Result, probe bool) {
	r.mu.Lock()
	r.check, r.probe = check, probe
	r.mu.Unlock()
}

// fastFo is failover.Defaults with the waits cut to milliseconds, so that
// the loop can be driven in real time.
func fastFo() failover.Config {
	cfg := failover.Defaults
	cfg.SuspectAfter = 200 * time.Millisecond
	cfg.RetryAfter = 200 * time.Millisecond
	cfg.RecheckBase = 200 * time.Millisecond
	cfg.ProbeBase = 30 * time.Millisecond
	cfg.ConfirmEvery = 10 * time.Millisecond
	cfg.MinReturn = 60 * time.Millisecond
	return cfg
}

// An idle tunnel is never checked, however long it stays idle: there is
// no timer, and Ashgate sends nothing of its own through it.
func TestIdleTunnelIsNeverChecked(t *testing.T) {
	r := newFoRig(t, failover.Defaults)
	r.set(failover.OK, false)
	base := time.Now()
	for d := time.Duration(0); d < 12*time.Hour; d += 5 * time.Second {
		r.tick(base.Add(d))
	}
	if checks, probes := r.counts(); checks != 0 || probes != 0 {
		t.Fatalf("%d checks and %d probes of an idle tunnel in 12 h", checks, probes)
	}
	if r.active() != 0 {
		t.Fatal("the idle tunnel changed its server")
	}
}

// A connection that sent and waits, and a check that gets no answer
// either: the backup takes over after that one check, and what the old
// server left behind is not held against the new one.
func TestStallSwitchesAfterOneCheck(t *testing.T) {
	r := newFoRig(t, fastFo())
	r.set(failover.Frozen, false)
	asked := time.Now()
	r.ft.set(engine.RelayHealth{Waiting: 1, WaitingSince: asked, LastAsk: asked})
	r.tick(time.Now())
	if checks, _ := r.counts(); checks != 0 {
		t.Fatalf("%d checks before the connection waited long enough", checks)
	}
	time.Sleep(210 * time.Millisecond)
	r.tick(time.Now())
	if checks, _ := r.counts(); checks != 1 || r.active() != 1 {
		t.Fatalf("after the stall: %d checks, active %d; want one check and the backup", checks, r.active())
	}
	// The same waiting relay is still reported: it started before the
	// switch, so the cutoff leaves it out and no check follows.
	r.tick(time.Now())
	r.tick(time.Now())
	if checks, _ := r.counts(); checks != 1 || r.active() != 1 {
		t.Fatalf("the old server's relay was held against the new one: %d checks, active %d", checks, r.active())
	}
	r.ft.mu.Lock()
	last := r.ft.since[len(r.ft.since)-1]
	r.ft.mu.Unlock()
	if !last.After(asked) {
		t.Fatal("after the switch the engine was still asked for relays of the old server")
	}
	n := 0
	for _, e := range r.logs.Snapshot() {
		if strings.Contains(e.Error, "Переключение сервера") && strings.Contains(e.Error, "нет ответа") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d switch lines in the log, want 1", n)
	}
}

// A refused check is repeated once before the switch.
func TestRefusedSwitchesAfterTwoChecks(t *testing.T) {
	r := newFoRig(t, fastFo())
	r.set(failover.Failed, false)
	now := time.Now()
	r.ft.set(engine.RelayHealth{Dead: 1, LastDead: now, LastAsk: now})
	r.tick(time.Now())
	if checks, _ := r.counts(); checks != 1 || r.active() != 0 {
		t.Fatalf("after one refusal: %d checks, active %d", checks, r.active())
	}
	r.ft.set(engine.RelayHealth{})
	r.tick(time.Now())
	if checks, _ := r.counts(); checks != 1 {
		t.Fatal("the second check did not wait")
	}
	time.Sleep(210 * time.Millisecond)
	r.tick(time.Now())
	if checks, _ := r.counts(); checks != 2 || r.active() != 1 {
		t.Fatalf("after two refusals: %d checks, active %d", checks, r.active())
	}
}

// The machine has no route to the server (Wi-Fi is reconnecting): a check
// that fails then says nothing about the server, and nothing switches.
func TestNoNetworkKeepsServer(t *testing.T) {
	r := newFoRig(t, fastFo())
	r.set(failover.Frozen, false)
	r.mu.Lock()
	r.noRoute = true
	r.mu.Unlock()
	for i := 0; i < 3; i++ {
		now := time.Now()
		r.ft.set(engine.RelayHealth{Dead: 1, LastDead: now, LastAsk: now})
		r.tick(time.Now())
		time.Sleep(260 * time.Millisecond)
	}
	if checks, _ := r.counts(); checks != 3 || r.active() != 0 {
		t.Fatalf("with no network: %d checks, active %d; want 3 checks and the same server", checks, r.active())
	}
	// The network is back and the server still does not answer: switch.
	r.mu.Lock()
	r.noRoute = false
	r.mu.Unlock()
	now := time.Now()
	r.ft.set(engine.RelayHealth{Dead: 1, LastDead: now, LastAsk: now})
	r.tick(time.Now())
	if r.active() != 1 {
		t.Fatal("no switch once the network was back")
	}
}

// Traffic answered while the check ran keeps the server, whatever the
// check found.
func TestAnswerDuringCheckKeepsServer(t *testing.T) {
	r := newFoRig(t, fastFo())
	asked := time.Now()
	r.ft.set(engine.RelayHealth{Waiting: 1, WaitingSince: asked, LastAsk: asked})
	time.Sleep(210 * time.Millisecond)
	checkActive = func(vless.Status) failover.Result {
		// A relay gets its first bytes while the check waits in vain.
		r.ft.set(engine.RelayHealth{LastGood: time.Now(), LastAsk: asked})
		return failover.Frozen
	}
	r.tick(time.Now())
	if r.active() != 0 {
		t.Fatal("switched although traffic was answered during the check")
	}
}

// The byte counters of the subscription's rules: bytes that go up again
// and again with none coming down are silence; any byte down ends it.
func TestSilenceFromByteCounters(t *testing.T) {
	cfg := config.Default()
	on, off := true, false
	cfg.Groups = []config.Group{{Name: "g", Action: "proxy", Proxy: rigSub}}
	cfg.Rules = []config.Rule{
		{Enabled: &on, Process: `C:\Apps\One.exe`, Action: "proxy", Proxy: rigSub},
		{Enabled: &on, Process: "two.exe", Group: "g"},
		{Enabled: &on, Process: "other.exe", Action: "proxy", Proxy: "another"},
		{Enabled: &off, Process: "off.exe", Action: "proxy", Proxy: rigSub},
		{Enabled: &on, Process: "direct.exe", Action: "direct"},
	}
	stats := map[string]engine.RuleStat{
		engine.RuleKey(`C:\Apps\One.exe`): {Up: 10, Down: 100},
		"two.exe":                         {Up: 5, Down: 50},
		"other.exe":                       {Up: 1000, Down: 1000},
		"off.exe":                         {Up: 1000, Down: 1000},
		"direct.exe":                      {Up: 1000, Down: 1000},
	}
	if up, down := ruleBytes(cfg, rigSub, stats); up != 15 || down != 150 {
		t.Fatalf("bytes of the subscription's rules: %d up, %d down", up, down)
	}

	g := &subGroup{}
	t0 := time.Now()
	at := func(ms int) time.Time { return t0.Add(time.Duration(ms) * time.Millisecond) }
	ev := g.evidence(at(0), engine.RelayHealth{}, 100, 100) // the first reading only sets the base
	if !ev.SilentSince.IsZero() || !ev.LastUse.IsZero() {
		t.Fatalf("first reading: %+v", ev)
	}
	ev = g.evidence(at(250), engine.RelayHealth{}, 150, 300) // up and down: answered
	if !ev.SilentSince.IsZero() || !ev.LastUse.Equal(at(250)) {
		t.Fatalf("answered traffic: %+v", ev)
	}
	ev = g.evidence(at(500), engine.RelayHealth{}, 200, 300)
	ev = g.evidence(at(750), engine.RelayHealth{}, 200, 300) // nothing moved
	ev = g.evidence(at(2750), engine.RelayHealth{}, 260, 300)
	if !ev.SilentSince.Equal(at(500)) || !ev.SilentLast.Equal(at(2750)) || !ev.LastUse.Equal(at(2750)) {
		t.Fatalf("bytes up into silence: %+v", ev)
	}
	ev = g.evidence(at(3000), engine.RelayHealth{}, 260, 301)
	if !ev.SilentSince.IsZero() || !ev.SilentLast.IsZero() {
		t.Fatalf("a byte came down: %+v", ev)
	}
	// An upload the server is reading: megabytes go up and the answer
	// comes when it ends. That is not silence.
	g.evidence(at(3100), engine.RelayHealth{}, 261, 301)
	ev = g.evidence(at(5200), engine.RelayHealth{}, 260+silentLimit, 301)
	if !ev.SilentSince.Equal(at(3100)) || !ev.SilentLast.Equal(at(5200)) {
		t.Fatalf("256 KiB sent into silence do not count: %+v", ev)
	}
	ev = g.evidence(at(5300), engine.RelayHealth{}, 261+silentLimit, 301)
	if !ev.SilentSince.IsZero() || !ev.LastUse.Equal(at(5300)) {
		t.Fatalf("a large upload counts as silence: %+v", ev)
	}
	g.evidence(at(5400), engine.RelayHealth{}, 261+silentLimit, 400)
	// A new capture session counts from zero.
	g.evidence(at(5500), engine.RelayHealth{}, 400+silentLimit, 400)
	ev = g.evidence(at(5600), engine.RelayHealth{}, 20, 0)
	if !ev.SilentSince.IsZero() {
		t.Fatalf("counters that started over: %+v", ev)
	}
	// The engine's relays come through as they are.
	h := engine.RelayHealth{Waiting: 2, WaitingSince: at(1), Dead: 1, LastDead: at(2), LastGood: at(3), LastAsk: at(9000)}
	ev = g.evidence(at(5700), h, 20, 0)
	if !ev.WaitingSince.Equal(at(1)) || !ev.LastDead.Equal(at(2)) || !ev.LastGood.Equal(at(3)) || !ev.LastUse.Equal(at(9000)) {
		t.Fatalf("relay health: %+v", ev)
	}
}

// On the backup the primary is probed only while the tunnel is used;
// three good probes and the shortest stay bring traffic back.
func TestProbesReturnToPrimary(t *testing.T) {
	r := newFoRig(t, fastFo())
	r.set(failover.Frozen, false)
	now := time.Now()
	r.ft.set(engine.RelayHealth{Dead: 1, LastDead: now, LastAsk: now})
	r.tick(time.Now())
	if r.active() != 1 {
		t.Fatal("no switch to the backup")
	}
	switchedAt := time.Now()
	// The tunnel is used, and the backup answers.
	use := func() {
		n := time.Now()
		r.ft.set(engine.RelayHealth{LastGood: n, LastAsk: n})
	}
	// The primary stays down: probes come, less and less often, and
	// nothing changes.
	deadline := time.Now().Add(250 * time.Millisecond)
	for time.Now().Before(deadline) {
		use()
		r.tick(time.Now())
		time.Sleep(5 * time.Millisecond)
	}
	if _, probes := r.counts(); probes < 1 || probes > 4 || r.active() != 1 {
		t.Fatalf("%d probes of a dead primary in 250 ms (first after 30 ms, then pauses of 30, 60, 120 ms), active %d", probes, r.active())
	}
	// It comes back.
	r.set(failover.Frozen, true)
	deadline = time.Now().Add(5 * time.Second)
	for r.active() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("no return to the primary")
		}
		use()
		r.tick(time.Now())
		time.Sleep(5 * time.Millisecond)
	}
	if d := time.Since(switchedAt); d < 60*time.Millisecond {
		t.Fatalf("returned after %v, sooner than the shortest stay", d)
	}
	r.c.mu.Lock()
	reason := r.g.fo.Reason
	r.c.mu.Unlock()
	if !strings.Contains(reason, "основной сервер снова отвечает") {
		t.Fatalf("reason %q", reason)
	}
	// Back on the primary: no more probes.
	_, before := r.counts()
	for i := 0; i < 20; i++ {
		use()
		r.tick(time.Now())
		time.Sleep(5 * time.Millisecond)
	}
	if _, after := r.counts(); after != before {
		t.Fatal("the primary is probed while it carries traffic")
	}
}

// Nobody uses the tunnel: the dead primary is left alone.
func TestNoProbesWhileUnused(t *testing.T) {
	cfg := fastFo()
	cfg.UseWithin = 50 * time.Millisecond
	r := newFoRig(t, cfg)
	r.set(failover.Frozen, false)
	now := time.Now()
	r.ft.set(engine.RelayHealth{Dead: 1, LastDead: now, LastAsk: now})
	r.tick(time.Now())
	if r.active() != 1 {
		t.Fatal("no switch to the backup")
	}
	r.ft.set(engine.RelayHealth{LastAsk: now})
	time.Sleep(60 * time.Millisecond)
	_, before := r.counts()
	for i := 0; i < 30; i++ {
		r.tick(time.Now())
		time.Sleep(5 * time.Millisecond)
	}
	if _, after := r.counts(); after != before {
		t.Fatalf("%d probes of the primary with the tunnel unused", after-before)
	}
}
