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
	"ashgate/internal/failover"
	"ashgate/internal/logbuf"
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
