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
	switched := g.fo.Check(time.Now(), failover.Frozen, g.label)
	c.mu.Unlock()
	if !switched {
		t.Fatal("no switch on a freeze")
	}
	c.applySubs()
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
	oldFreeze, oldHost, oldPort := freezeAfter, healthHost, healthPort
	freezeAfter = 300 * time.Millisecond
	t.Cleanup(func() { freezeAfter, healthHost, healthPort = oldFreeze, oldHost, oldPort })

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

// fakeTunnel is a running capture session whose relays the test scripts.
type fakeTunnel struct {
	mu sync.Mutex
	h  engine.RelayHealth
}

func (f *fakeTunnel) Running() bool { return true }

func (f *fakeTunnel) RelayHealth(string) engine.RelayHealth {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.h
}

func (f *fakeTunnel) set(h engine.RelayHealth) {
	f.mu.Lock()
	f.h = h
	f.mu.Unlock()
}

// Relays through the active server keep dying: a health check starts at
// once, not at the next 60 s timer, and no more than once per 15 s.
// Switching still takes the second failed check, 10 s later.
func TestDeadRelaysStartAnEarlyCheck(t *testing.T) {
	old, oldSess := subRand, sessionOf
	subRand = func() float64 { return 0.5 }
	ft := &fakeTunnel{}
	sessionOf = func(*controller) tunnelSession { return ft }
	t.Cleanup(func() { subRand, sessionOf = old, oldSess })

	logs, _ := logbuf.New(50, "")
	c := newController(filepath.Join(t.TempDir(), "config.json"), config.Default(), logs, hooks{})
	t.Cleanup(c.shutdown)
	const name = "sub"
	base := time.Now()
	g := &subGroup{entries: subs.Entries([]string{subLink("xhttp", "x1"), subLink("tcp", "raw1")}),
		fo: failover.New(2, base, failover.Defaults, subRand), nextFetch: base.Add(24 * time.Hour)}
	c.mu.Lock()
	c.subs = map[string]*subGroup{name: g}
	c.mu.Unlock()

	// tick runs one loop round and waits for the check it started.
	tick := func(now time.Time) (checked bool) {
		t.Helper()
		c.subsTick(now)
		deadline := time.Now().Add(5 * time.Second)
		for {
			c.mu.Lock()
			busy, at := g.checking, g.earlyAt
			c.mu.Unlock()
			if !busy {
				return at.Equal(now)
			}
			if time.Now().After(deadline) {
				t.Fatal("the health check did not finish")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	active := func() int {
		c.mu.Lock()
		defer c.mu.Unlock()
		return g.fo.Active
	}

	ft.set(engine.RelayHealth{Dead: 2, Since: base.Add(-2 * time.Second)})
	if tick(base) {
		t.Fatal("two dead relays started a check")
	}
	ft.set(engine.RelayHealth{Dead: 3, Since: base.Add(-2 * time.Second)})
	if !tick(base) {
		t.Fatal("three dead relays did not start a check")
	}
	if active() != 0 {
		t.Fatal("one failed check switched the server")
	}
	// New dead relays right after: no second early check within 15 s.
	ft.set(engine.RelayHealth{Dead: 5, Since: base.Add(time.Second)})
	if tick(base.Add(5 * time.Second)) {
		t.Fatal("a second early check within 15 s")
	}
	// The regular re-check after the 10 s backoff fails too: switch.
	tick(base.Add(16 * time.Second))
	if active() != 1 {
		t.Fatal("two failed checks did not switch the server")
	}

	early := 0
	for _, e := range logs.Snapshot() {
		if strings.Contains(e.Error, "проверяю его сейчас") {
			early++
		}
	}
	if early != 1 {
		t.Fatalf("%d early check log lines, want 1", early)
	}

	// Dead relays opened before the switch belong to the old server.
	c.mu.Lock()
	defer c.mu.Unlock()
	g.fo.SwitchedAt = base.Add(16 * time.Second)
	if g.earlyCheck(base.Add(40*time.Second), engine.RelayHealth{Dead: 4, Since: base.Add(10 * time.Second)}) {
		t.Fatal("relays of the previous server counted")
	}
	if !g.earlyCheck(base.Add(40*time.Second), engine.RelayHealth{Dead: 4, Since: base.Add(30 * time.Second)}) {
		t.Fatal("relays of the new server did not count")
	}
}
