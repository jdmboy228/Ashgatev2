package gui

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"ashgate/internal/config"
	"ashgate/internal/killswitch"
	"ashgate/internal/logbuf"
	"ashgate/internal/probe"
	"ashgate/internal/process"
	"ashgate/internal/rules"
	rt "ashgate/internal/runtime"
	"ashgate/internal/vless"
)

func TestControllerSavesBlockRule(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	logs, err := logbuf.New(8, "")
	if err != nil {
		t.Fatal(err)
	}
	c := newController(path, config.Default(), logs, hooks{})
	on := true
	next := config.Default()
	next.Rules = []config.Rule{{
		Enabled: &on,
		Process: "telemetry.exe",
		Action:  "block",
	}}
	if err := c.replace(next); err != nil {
		t.Fatal(err)
	}
	got, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rules) != 1 || got.Rules[0].Action != "block" || got.Rules[0].Proxy != "" {
		t.Fatalf("%+v", got.Rules)
	}
	if got.Version != 1 {
		t.Fatalf("version %d", got.Version)
	}

	bad := config.Default()
	bad.Proxies = []config.Proxy{{Name: "local", Type: "socks5", Address: "127.0.0.1:1080"}}
	bad.Rules = []config.Rule{{Process: "telemetry.exe", Action: "block", Proxy: "local"}}
	err = c.replace(bad)
	if err == nil || !strings.Contains(err.Error(), "пустым") {
		t.Fatal(err)
	}
}

func TestUIShellServed(t *testing.T) {
	c := newController(filepath.Join(t.TempDir(), "config.json"), config.Default(), nil, hooks{})
	h := c.Handler()
	for _, tc := range []struct {
		path string
		want string
	}{
		{"/", `id="app"`},
		{"/app.js", "Вставить ссылку"},
		{"/app.js", "Локальный SOCKS5-порт"},
		{"/apps.js", "Блокировать"}, // the block route in the Apps tab
		{"/", `src="apps.js"`},
		{"/apps.js", "Создать группу приложений"},
		{"/app.css", "#FF7A45"},
		{"/", `src="icons.js"`},
		{"/icons.js", "const FLUENT"},
		{"/logo.svg", "svg"},
	} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), tc.want) {
			t.Fatalf("%s: %d %q", tc.path, rr.Code, rr.Body.String()[:min(80, rr.Body.Len())])
		}
	}
}

// 0.7.3 removed the Home tab and the VLESS-for-Dolphin note on Proxies.
func TestUIHasNoHomeOrDolphinNote(t *testing.T) {
	c := newController(filepath.Join(t.TempDir(), "config.json"), config.Default(), nil, hooks{})
	h := c.Handler()
	for _, path := range []string{"/", "/app.js", "/apps.js"} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		body := rr.Body.String()
		for _, gone := range []string{"Главная", "homeHTML", "VLESS для Dolphin"} {
			if strings.Contains(body, gone) {
				t.Fatalf("%s still has %q", path, gone)
			}
		}
	}
}

func TestParseVLESSAPI(t *testing.T) {
	c := newController(filepath.Join(t.TempDir(), "config.json"), config.Default(), nil, hooks{})
	h := c.Handler()
	const link = "vless://b7e2c1a0-4f3a-4c2b-9a11-111111111111@203.0.113.10:443?encryption=none&security=reality&type=xhttp&path=%2Fxhttp&mode=auto&sni=www.microsoft.com&fp=chrome&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&sid=ab12#aeza-se"
	req := httptest.NewRequest(http.MethodPost, "/api/vless/parse", strings.NewReader(`{"link":"`+link+`"}`))
	req.Header.Set(tokenHeader, c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Host = "127.0.0.1:5000"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"network":"xhttp"`) || !strings.Contains(rr.Body.String(), "203.0.113.10:443") {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	bad := httptest.NewRequest(http.MethodPost, "/api/vless/parse", strings.NewReader(`{"link":"https://example"}`))
	bad.Header.Set(tokenHeader, c.token)
	bad.Header.Set("Content-Type", "application/json")
	bad.Host = "127.0.0.1:5000"
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, bad)
	if rr.Code == http.StatusOK || !strings.Contains(rr.Body.String(), "Не удалось разобрать ссылку VLESS") {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
}

func TestAPIRequiresToken(t *testing.T) {
	c := newController(filepath.Join(t.TempDir(), "config.json"), config.Default(), nil, hooks{})
	h := c.Handler()
	for _, tc := range []struct {
		name  string
		host  string
		token string
		query string
		want  int
	}{
		{"no token", "127.0.0.1:5000", "", "", http.StatusForbidden},
		{"wrong token", "127.0.0.1:5000", "nope", "", http.StatusForbidden},
		{"rebinding host", "evil.example:5000", c.token, "", http.StatusForbidden},
		{"header", "127.0.0.1:5000", c.token, "", http.StatusOK},
		// Only the icon, an <img>, may carry the token in the URL.
		{"query", "127.0.0.1:5000", "", "?t=" + c.token, http.StatusForbidden},
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/state"+tc.query, nil)
		req.Host = tc.host
		if tc.token != "" {
			req.Header.Set(tokenHeader, tc.token)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != tc.want {
			t.Fatalf("%s: got %d want %d", tc.name, rr.Code, tc.want)
		}
	}
}

// The token in the URL, the Origin and the body type: what a page from
// elsewhere, holding the token or not, cannot get past.
func TestAPIAuthRules(t *testing.T) {
	oldPNG, oldRun, oldInst := iconPNG, listRunning, listInstalled
	defer func() { iconPNG, listRunning, listInstalled = oldPNG, oldRun, oldInst }()
	iconPNG = func(string) ([]byte, error) { return []byte("png"), nil }
	listRunning = func() ([]process.App, error) { return nil, nil }
	listInstalled = func() []process.Installed { return nil }
	icons = &iconCache{m: map[string]iconEntry{}}
	c := newController(filepath.Join(t.TempDir(), "config.json"), config.Default(), nil, hooks{})
	h := c.Handler()
	const host = "127.0.0.1:5000"
	for _, tc := range []struct {
		name, method, path, token, origin, ctype, body string
		want                                           int
	}{
		{"icon with the token in the URL", "GET", `/api/icon?path=C:\a.exe&t=` + c.token, "", "", "", "", http.StatusOK},
		{"icon without a token", "GET", `/api/icon?path=C:\a.exe`, "", "", "", "", http.StatusForbidden},
		{"icon by POST with the token in the URL", "POST", "/api/icon?t=" + c.token, "", "", "application/json", "{}", http.StatusForbidden},
		{"start with the token in the URL", "POST", "/api/start?t=" + c.token, "", "", "application/json", "{}", http.StatusForbidden},
		{"log clear with the token in the URL", "POST", "/api/log/clear?t=" + c.token, "", "", "application/json", "{}", http.StatusForbidden},
		{"POST without a body type", "POST", "/api/log/clear", c.token, "", "", "{}", http.StatusUnsupportedMediaType},
		{"POST as a form", "POST", "/api/log/clear", c.token, "", "application/x-www-form-urlencoded", "a=b", http.StatusUnsupportedMediaType},
		{"POST as text", "POST", "/api/log/clear", c.token, "", "text/plain", "{}", http.StatusUnsupportedMediaType},
		{"POST as JSON", "POST", "/api/log/clear", c.token, "", "application/json; charset=utf-8", "{}", http.StatusOK},
		{"own origin", "POST", "/api/log/clear", c.token, "http://" + host, "application/json", "{}", http.StatusOK},
		{"foreign origin", "POST", "/api/log/clear", c.token, "https://evil.example", "application/json", "{}", http.StatusForbidden},
		{"null origin", "GET", "/api/state", c.token, "null", "", "", http.StatusForbidden},
		{"other port", "GET", "/api/state", c.token, "http://127.0.0.1:5001", "", "", http.StatusForbidden},
		{"GET needs no body type", "GET", "/api/state", c.token, "", "", "", http.StatusOK},
	} {
		var body io.Reader
		if tc.body != "" {
			body = strings.NewReader(tc.body)
		}
		req := httptest.NewRequest(tc.method, tc.path, body)
		req.Host = host
		if tc.token != "" {
			req.Header.Set(tokenHeader, tc.token)
		}
		if tc.origin != "" {
			req.Header.Set("Origin", tc.origin)
		}
		if tc.ctype != "" {
			req.Header.Set("Content-Type", tc.ctype)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != tc.want {
			t.Errorf("%s: got %d want %d (%s)", tc.name, rr.Code, tc.want, strings.TrimSpace(rr.Body.String()))
		}
	}
}

// apiPost calls a POST endpoint as the window does.
func apiPost(t *testing.T, c *controller, path, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Host = "127.0.0.1:5000"
	req.Header.Set(tokenHeader, c.token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	c.Handler().ServeHTTP(rr, req)
	return rr.Code, rr.Body.String()
}

// A draft from the proxy dialog is checked as typed and not stored under
// the saved proxy's name; an empty address is an error, not the saved one.
func TestProbeDraftIsNotStored(t *testing.T) {
	old := probeCheck
	defer func() { probeCheck = old }()
	var checked []string
	probeCheck = func(_ context.Context, p config.Proxy) probe.Report {
		checked = append(checked, p.Address)
		return probe.Report{OK: true, Label: p.Address}
	}
	cfg := config.Default()
	cfg.Proxies = []config.Proxy{{Name: "local", Type: "socks5", Address: "127.0.0.1:1080"}}
	c := newController(filepath.Join(t.TempDir(), "config.json"), cfg, nil, hooks{})
	code, body := apiPost(t, c, "/api/probe", `{"proxy":{"name":"local","type":"socks5","address":"127.0.0.1:9999"}}`)
	if code != http.StatusOK || !strings.Contains(body, "127.0.0.1:9999") {
		t.Fatalf("draft probe: %d %s", code, body)
	}
	if _, ok := c.checks["local"]; ok {
		t.Fatal("a draft's result was stored under the saved proxy's name")
	}
	code, body = apiPost(t, c, "/api/probe", `{"proxy":{"name":"local","type":"socks5","address":""}}`)
	if code == http.StatusOK || !strings.Contains(body, "Укажите адрес") {
		t.Fatalf("empty draft: %d %s", code, body)
	}
	code, _ = apiPost(t, c, "/api/probe", `{"name":"local"}`)
	if code != http.StatusOK || c.checks["local"].Label != "127.0.0.1:1080" {
		t.Fatalf("named probe: %d %+v", code, c.checks["local"])
	}
	if len(checked) != 2 || checked[0] != "127.0.0.1:9999" || checked[1] != "127.0.0.1:1080" {
		t.Fatalf("checked %v", checked)
	}
}

// Results of deleted or renamed proxies go with the save.
func TestChecksPrunedOnSave(t *testing.T) {
	cfg := config.Default()
	cfg.Proxies = []config.Proxy{{Name: "a", Type: "socks5", Address: "127.0.0.1:1080"}, {Name: "b", Type: "socks5", Address: "127.0.0.1:1081"}}
	c := newController(filepath.Join(t.TempDir(), "config.json"), cfg, nil, hooks{})
	c.checks["a"] = probe.Report{OK: true}
	c.checks["b"] = probe.Report{OK: true}
	next := config.Default()
	next.Proxies = []config.Proxy{{Name: "a", Type: "socks5", Address: "127.0.0.1:1080"}, {Name: "c", Type: "socks5", Address: "127.0.0.1:1081"}}
	if err := c.replace(next); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.checks["b"]; ok || len(c.checks) != 1 {
		t.Fatalf("checks %v", c.checks)
	}
}

// Check all answers with the checks and leaves the one-shot notice alone.
func TestProbeAllKeepsNotice(t *testing.T) {
	old := probeCheck
	defer func() { probeCheck = old }()
	probeCheck = func(_ context.Context, p config.Proxy) probe.Report { return probe.Report{OK: true, Label: p.Name} }
	cfg := config.Default()
	cfg.Proxies = []config.Proxy{{Name: "a", Type: "socks5", Address: "127.0.0.1:1080"}}
	c := newController(filepath.Join(t.TempDir(), "config.json"), cfg, nil, hooks{})
	c.setNotice("старая служба удалена")
	code, body := apiPost(t, c, "/api/probe-all", `{}`)
	if code != http.StatusOK || !strings.Contains(body, `"a":`) {
		t.Fatalf("%d %s", code, body)
	}
	if st := c.snapshot(); st.Notice != "старая служба удалена" {
		t.Fatalf("notice %q", st.Notice)
	}
}

// A save the bridges or the engine did not fully take is still a save.
func TestSavedAnswer(t *testing.T) {
	got, err := savedAnswer(&applyWarning{msg: "порт занят"})
	m, ok := got.(map[string]any)
	if err != nil || !ok || m["warning"] != "порт занят" || m["ok"] != true {
		t.Fatalf("%v %v", got, err)
	}
	if got, err := savedAnswer(errors.New("bad")); got != nil || err == nil {
		t.Fatalf("%v %v", got, err)
	}
	if got, err := savedAnswer(nil); got != nil || err != nil {
		t.Fatalf("%v %v", got, err)
	}
}

// Autostart is read at the first state request and when the Settings page
// asks, never on a timer.
func TestAutostartReadOnDemand(t *testing.T) {
	var mu sync.Mutex
	reads := 0
	c := newController(filepath.Join(t.TempDir(), "config.json"), config.Default(), nil, hooks{autostart: func() (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		reads++
		return reads > 1, nil
	}})
	count := func() int { mu.Lock(); defer mu.Unlock(); return reads }
	if st := c.snapshot(); st.Autostart || count() != 1 {
		t.Fatalf("first read: %v %d", st.Autostart, count())
	}
	c.mu.Lock()
	c.autoAt = time.Now().Add(-time.Hour)
	c.mu.Unlock()
	c.snapshot()
	if count() != 1 {
		t.Fatal("autostart re-read by a plain poll")
	}
	c.askAuto()
	deadline := time.Now().Add(3 * time.Second)
	for !c.snapshot().Autostart && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !c.snapshot().Autostart || count() != 2 {
		t.Fatalf("asked read: %d", count())
	}
}

func TestStateSkipsUnchangedEvents(t *testing.T) {
	logs, _ := logbuf.New(8, "")
	logs.Add(logbuf.Event{Process: "curl.exe", Status: "open"})
	c := newController(filepath.Join(t.TempDir(), "config.json"), config.Default(), logs, hooks{})
	g := logs.Generation()
	if st := c.snapshotSince(g); !st.EventsSame || st.Events != nil {
		t.Fatalf("same generation should skip events: %+v", st.EventsSame)
	}
	logs.Add(logbuf.Event{Process: "curl.exe", Status: "closed"})
	if st := c.snapshotSince(g); st.EventsSame || len(st.Events) != 2 {
		t.Fatalf("new generation should send events: same=%v n=%d", st.EventsSame, len(st.Events))
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestKillSwitchBlocksWhileStopped(t *testing.T) {
	dir := t.TempDir()
	var lines []string
	fw := killswitch.NewWithRunner(filepath.Join(dir, "killswitch.json"), func(l string) error {
		lines = append(lines, l)
		return nil
	})
	cfg := config.Default()
	cfg.KillSwitch = true
	cfg.Proxies = []config.Proxy{{Name: "p", Type: "socks5", Address: "127.0.0.1:1080"}}
	cfg.Rules = []config.Rule{
		{Process: `C:\Apps\app.exe`, Action: "proxy", Proxy: "p"},
		{Process: "nowhere", Action: "proxy", Proxy: "p"},
		{Process: `C:\Apps\direct.exe`, Action: "direct"},
	}
	c := &controller{path: filepath.Join(dir, "config.json"), cfg: cfg, checks: map[string]probe.Report{},
		bridgeSt: map[string]vless.Status{}, hooks: hooks{firewall: fw}}
	c.syncKill()
	if got := fw.Blocked(); len(got) != 1 || got[0] != `C:\Apps\app.exe` {
		t.Fatalf("blocked %v (netsh %v)", got, lines)
	}
	if v := c.ksSnapshot(true); len(v.Missing) != 1 || v.Missing[0] != "nowhere" {
		t.Fatalf("missing %+v", v)
	}
	c.cfg.KillSwitch = false
	c.syncKill()
	if got := fw.Blocked(); len(got) != 0 {
		t.Fatalf("switch off left %v", got)
	}
}

func TestIconPathResolvesNamesAndMasks(t *testing.T) {
	oldRun, oldInst := listRunning, listInstalled
	defer func() { listRunning, listInstalled = oldRun, oldInst }()
	listRunning = func() ([]process.App, error) {
		return []process.App{{Name: "Discord.exe", Path: `C:\U\Discord\app-1.0.9\Discord.exe`}}, nil
	}
	listInstalled = func() []process.Installed {
		return []process.Installed{{Name: "Telegram Desktop", Path: `C:\T\Telegram.exe`}}
	}
	for in, want := range map[string]string{
		`C:\X\a.exe`:                  `C:\X\a.exe`,
		"telegram":                    `C:\T\Telegram.exe`,
		`*\Discord\app-*\Discord.exe`: `C:\U\Discord\app-1.0.9\Discord.exe`,
		"nothere.exe":                 "",
	} {
		if got := iconPath(in); got != want {
			t.Fatalf("iconPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIconPathFallbacks(t *testing.T) {
	oldRun, oldInst, oldLook, oldStat := listRunning, listInstalled, lookPath, statFile
	defer func() { listRunning, listInstalled, lookPath, statFile = oldRun, oldInst, oldLook, oldStat }()
	listRunning = func() ([]process.App, error) { return nil, nil }
	listInstalled = func() []process.Installed {
		return []process.Installed{{Name: "Discord", Path: `C:\U\Discord\app-1.0.10\Discord.exe`}}
	}
	lookPath = func(name string) (string, error) {
		if strings.EqualFold(name, "curl.exe") {
			return `C:\Windows\System32\curl.exe`, nil
		}
		return "", errors.New("not found")
	}
	statFile = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	for in, want := range map[string]string{
		// The rule's path is gone after an update: found by file name.
		`C:\U\Discord\app-1.0.9\Discord.exe`: `C:\U\Discord\app-1.0.10\Discord.exe`,
		// Neither running nor installed: found on PATH.
		"curl":      `C:\Windows\System32\curl.exe`,
		"curl.exe":  `C:\Windows\System32\curl.exe`,
		`*\x\*.exe`: "",
	} {
		if got := iconPath(in); got != want {
			t.Fatalf("iconPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIconCacheRemembersMisses(t *testing.T) {
	oldPNG, oldRun, oldInst := iconPNG, listRunning, listInstalled
	defer func() { iconPNG, listRunning, listInstalled = oldPNG, oldRun, oldInst }()
	calls := 0
	iconPNG = func(string) ([]byte, error) { calls++; return nil, errors.New("no icon") }
	listRunning = func() ([]process.App, error) { return nil, nil }
	listInstalled = func() []process.Installed { return nil }
	icons = &iconCache{m: map[string]iconEntry{}}
	for i := 0; i < 5; i++ {
		if _, ok := icons.get("ghost.exe"); ok {
			t.Fatal("icon for a missing program")
		}
	}
	if calls != 1 {
		t.Fatalf("icon looked up %d times", calls)
	}
}

func TestUIOnlySaveSkipsEngine(t *testing.T) {
	a := config.Default()
	b := config.Default()
	b.UI.Theme = "light"
	b.Groups = nil
	if engineView(a) != engineView(b) {
		t.Fatal("theme change counted as an engine change")
	}
	b.KillSwitch = true
	if engineView(a) == engineView(b) {
		t.Fatal("kill switch change ignored")
	}
}

// TestStartDoesNotDeadlock guards against 0.7.1's freeze: start held the
// controller lock while lifting the kill-switch block, which takes it too.
func TestStartDoesNotDeadlock(t *testing.T) {
	dir := t.TempDir()
	fw := killswitch.NewWithRunner(filepath.Join(dir, "killswitch.json"), func(string) error { return nil })
	c := newController(filepath.Join(dir, "config.json"), config.Default(), nil, hooks{
		firewall: fw,
		guard:    func(string) (func(), error) { return func() {}, nil },
	})
	c.startSession = func(context.Context, *config.Config, *logbuf.Buffer, *vless.Manager) (*rt.Session, error) {
		return &rt.Session{}, nil
	}
	done := make(chan error, 1)
	go func() { done <- c.start() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("start did not return: controller deadlocked")
	}
	snap := make(chan struct{})
	go func() { c.snapshot(); close(snap) }()
	select {
	case <-snap:
	case <-time.After(3 * time.Second):
		t.Fatal("state request hangs after start")
	}
	stopped := make(chan struct{})
	go func() { _ = c.stop(); _ = c.replace(config.Default()); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("stop or save hangs after start")
	}
}

func TestAliveRules(t *testing.T) {
	procs := []rules.Process{
		{Name: "Discord.exe", Path: `C:\U\Discord\app-1.0.9\Discord.exe`},
		{Name: "curl.exe", Path: `C:\Windows\System32\curl.exe`},
	}
	got := aliveRules([]config.Rule{
		{Process: `*\Discord\app-*\Discord.exe`},
		{Process: "curl"},
		{Process: `"C:\T\Telegram.exe"`},
	}, procs)
	want := map[string]bool{`*\discord\app-*\discord.exe`: true, "curl": true, `c:\t\telegram.exe`: false}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%q = %v, want %v (%v)", k, got[k], v, got)
		}
	}
}

// The running-app scan opens every process; it must not run while the
// window is hidden in the tray.
func TestHiddenWindowSkipsAppScan(t *testing.T) {
	visible := false
	c := newController(filepath.Join(t.TempDir(), "config.json"), config.Default(), nil, hooks{visible: func() bool { return visible }})
	scheduled := func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.aliveBusy || !c.aliveAt.IsZero()
	}
	if st := c.snapshot(); !st.Hidden {
		t.Fatal("state should say hidden")
	}
	if scheduled() {
		t.Fatal("app scan started while hidden")
	}
	visible = true
	c.snapshot()
	if !scheduled() {
		t.Fatal("no app scan once visible")
	}
}

// While capturing, the kill-switch sync runs every 15 seconds; the guard's
// target file is rewritten only when the list changes.
func TestKillTargetsSavedOnlyOnChange(t *testing.T) {
	var writes int
	old := saveTargets
	saveTargets = func(string, []string) error { writes++; return nil }
	t.Cleanup(func() { saveTargets = old })
	c := newController(filepath.Join(t.TempDir(), "config.json"), config.Default(), nil, hooks{})
	for _, paths := range [][]string{nil, nil, {`C:\a.exe`}, {`C:\a.exe`}, {`C:\a.exe`, `C:\b.exe`}, nil} {
		if err := c.saveTargetsLocked(paths); err != nil {
			t.Fatal(err)
		}
	}
	if writes != 4 {
		t.Fatalf("writes = %d, want 4", writes)
	}
}

// The name rule shown in the proxy dialog must match the server's message.
func TestProxyNameRuleMatchesUI(t *testing.T) {
	rr := httptest.NewRecorder()
	c := newController(filepath.Join(t.TempDir(), "config.json"), config.Default(), nil, hooks{})
	c.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/app.js", nil))
	msg := ruConfig(errors.New(`proxies[0]: invalid name "x"`))
	if !strings.Contains(rr.Body.String(), `const NAME_RULE = "`+msg+`"`) {
		t.Fatalf("app.js NAME_RULE differs from %q", msg)
	}
}

// Proxy form errors come back in Russian with a prefix the dialog uses to
// show them under the right field.
func TestProxyFormErrors(t *testing.T) {
	c := newController(filepath.Join(t.TempDir(), "config.json"), config.Default(), nil, hooks{})
	for _, tc := range []struct {
		proxies []config.Proxy
		prefix  string
	}{
		{[]config.Proxy{{Name: "a/b", Type: "socks5", Address: "127.0.0.1:1080"}}, "Имя прокси:"},
		{[]config.Proxy{{Name: "a", Type: "socks5", Address: "127.0.0.1:1"}, {Name: "a", Type: "socks5", Address: "127.0.0.1:2"}}, "Имя прокси уже занято"},
		{[]config.Proxy{{Name: "a", Type: "socks5", Address: "127.0.0.1"}}, "Адрес прокси:"},
	} {
		cfg := config.Default()
		cfg.Proxies = tc.proxies
		err := c.replace(cfg)
		if err == nil || !strings.HasPrefix(err.Error(), tc.prefix) {
			t.Errorf("%v: got %v, want prefix %q", tc.proxies, err, tc.prefix)
		}
	}
}

// A Cyrillic name with a space saves, is referenced by a rule, and loads
// back unchanged.
func TestCyrillicProxyNameRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	c := newController(path, config.Default(), nil, hooks{})
	cfg := config.Default()
	cfg.Proxies = []config.Proxy{{Name: "Швеция 1", Type: "socks5", Address: "127.0.0.1:1080"}}
	cfg.Rules = []config.Rule{{Process: "curl.exe", Action: "proxy", Proxy: "Швеция 1"}}
	if err := c.replace(cfg); err != nil {
		t.Fatal(err)
	}
	got, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Proxies[0].Name != "Швеция 1" || got.Rules[0].Proxy != "Швеция 1" {
		t.Fatalf("%+v %+v", got.Proxies, got.Rules)
	}
}

func TestStopWaitsForInFlightStart(t *testing.T) {
	dir := t.TempDir()
	fw := killswitch.NewWithRunner(filepath.Join(dir, "killswitch.json"), func(string) error { return nil })
	cfg := config.Default()
	cfg.KillSwitch = true
	cfg.Proxies = []config.Proxy{{Name: "p", Type: "socks5", Address: "127.0.0.1:1080"}}
	cfg.Rules = []config.Rule{{Process: `C:\Apps\app.exe`, Action: "proxy", Proxy: "p"}}

	c := &controller{
		path:     filepath.Join(dir, "config.json"),
		cfg:      cfg,
		checks:   map[string]probe.Report{},
		bridgeSt: map[string]vless.Status{},
		bridges:  vless.NewManager(),
		done:     make(chan struct{}),
		loopDone: make(chan struct{}),
		hooks: hooks{
			firewall: fw,
			guard:    func(string) (func(), error) { return func() {}, nil },
		},
	}
	defer c.shutdown()

	entered := make(chan struct{})
	release := make(chan struct{})
	sessDone := make(chan struct{})
	var stopOnce sync.Once
	sess := rt.NewFakeSession(func() {
		stopOnce.Do(func() { close(sessDone) })
	}, sessDone)
	c.startSession = func(context.Context, *config.Config, *logbuf.Buffer, *vless.Manager) (*rt.Session, error) {
		close(entered)
		<-release
		return sess, nil
	}

	startErr := make(chan error, 1)
	go func() { startErr <- c.start() }()
	<-entered

	stopErr := make(chan error, 1)
	go func() { stopErr <- c.stop() }()

	// stop() must block behind startMu until start() finishes.
	select {
	case err := <-stopErr:
		t.Fatalf("stop returned early (%v) while start was in flight", err)
	case <-time.After(30 * time.Millisecond):
	}

	close(release)
	if err := <-startErr; err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := <-stopErr; err != nil {
		t.Fatalf("stop: %v", err)
	}
	if sess.Running() {
		t.Fatal("session still running after stop")
	}
	if got := fw.Blocked(); len(got) != 1 || got[0] != `C:\Apps\app.exe` {
		t.Fatalf("kill switch blocked = %v, want app blocked after stop", got)
	}
}

func TestShutdownDuringInFlightStartNeverUnblocksKillSwitch(t *testing.T) {
	dir := t.TempDir()
	var mu sync.Mutex
	var unblocksAfterEnter int
	var trackUnblocks bool
	fw := killswitch.NewWithRunner(filepath.Join(dir, "killswitch.json"), func(line string) error {
		mu.Lock()
		if trackUnblocks && strings.Contains(line, "delete rule") {
			unblocksAfterEnter++
		}
		mu.Unlock()
		return nil
	})
	cfg := config.Default()
	cfg.KillSwitch = true
	cfg.Proxies = []config.Proxy{{Name: "p", Type: "socks5", Address: "127.0.0.1:1080"}}
	cfg.Rules = []config.Rule{{Process: `C:\Apps\app.exe`, Action: "proxy", Proxy: "p"}}

	c := &controller{
		path:     filepath.Join(dir, "config.json"),
		cfg:      cfg,
		checks:   map[string]probe.Report{},
		bridgeSt: map[string]vless.Status{},
		bridges:  vless.NewManager(),
		done:     make(chan struct{}),
		loopDone: make(chan struct{}),
		hooks: hooks{
			firewall: fw,
			guard:    func(string) (func(), error) { return func() {}, nil },
		},
	}
	c.syncKill()
	if got := fw.Blocked(); len(got) != 1 {
		t.Fatalf("initial block = %v", got)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	sessDone := make(chan struct{})
	var stopOnce sync.Once
	sess := rt.NewFakeSession(func() {
		stopOnce.Do(func() { close(sessDone) })
	}, sessDone)
	var starts int
	c.startSession = func(context.Context, *config.Config, *logbuf.Buffer, *vless.Manager) (*rt.Session, error) {
		starts++
		close(entered)
		<-release
		return sess, nil
	}

	startErr := make(chan error, 1)
	go func() { startErr <- c.start() }()
	<-entered

	mu.Lock()
	trackUnblocks = true
	mu.Unlock()

	shutDone := make(chan struct{})
	go func() {
		c.shutdown()
		close(shutDone)
	}()
	time.Sleep(30 * time.Millisecond)
	close(release)

	if err := <-startErr; err == nil {
		t.Fatal("start succeeded after shutdown")
	}
	<-shutDone
	if sess.Running() {
		t.Fatal("in-flight session was left running after shutdown")
	}
	mu.Lock()
	gotUnblocks := unblocksAfterEnter
	mu.Unlock()
	if gotUnblocks != 0 {
		t.Fatalf("kill switch was unblocked %d times during shutdown", gotUnblocks)
	}
	if got := fw.Blocked(); len(got) != 1 || got[0] != `C:\Apps\app.exe` {
		t.Fatalf("kill switch blocked = %v after shutdown", got)
	}
	if err := c.start(); err == nil || starts != 1 {
		t.Fatalf("late start after shutdown: err=%v starts=%d", err, starts)
	}
}

func TestConcurrentStopsKeepStoppingUntilDone(t *testing.T) {
	dir := t.TempDir()
	fw := killswitch.NewWithRunner(filepath.Join(dir, "killswitch.json"), func(string) error { return nil })
	cfg := config.Default()
	cfg.KillSwitch = true
	cfg.Proxies = []config.Proxy{{Name: "p", Type: "socks5", Address: "127.0.0.1:1080"}}
	cfg.Rules = []config.Rule{{Process: `C:\Apps\app.exe`, Action: "proxy", Proxy: "p"}}

	c := &controller{
		path:     filepath.Join(dir, "config.json"),
		cfg:      cfg,
		checks:   map[string]probe.Report{},
		bridgeSt: map[string]vless.Status{},
		bridges:  vless.NewManager(),
		done:     make(chan struct{}),
		loopDone: make(chan struct{}),
		hooks: hooks{
			firewall: fw,
			guard:    func(string) (func(), error) { return func() {}, nil },
		},
	}
	defer c.shutdown()

	stopCalled := make(chan struct{})
	allowDone := make(chan struct{})
	sessDone := make(chan struct{})
	var once sync.Once
	sess := rt.NewFakeSession(func() {
		once.Do(func() {
			close(stopCalled)
			go func() {
				<-allowDone
				close(sessDone)
			}()
		})
	}, sessDone)
	c.startSession = func(context.Context, *config.Config, *logbuf.Buffer, *vless.Manager) (*rt.Session, error) {
		return sess, nil
	}
	if err := c.start(); err != nil {
		t.Fatal(err)
	}

	err1 := make(chan error, 1)
	err2 := make(chan error, 1)
	go func() { err1 <- c.stop() }()
	go func() { err2 <- c.stop() }()

	<-stopCalled
	c.mu.Lock()
	stoppingMid := c.stopping
	c.mu.Unlock()
	if !stoppingMid {
		t.Fatal("c.stopping cleared while stop was still waiting for session")
	}

	// Neither stop() may return before sess.Done() closes.
	select {
	case err := <-err1:
		t.Fatalf("first stop returned early: %v", err)
	case err := <-err2:
		t.Fatalf("second stop returned early: %v", err)
	case <-time.After(30 * time.Millisecond):
	}

	close(allowDone)
	if err := <-err1; err != nil {
		t.Fatalf("stop 1: %v", err)
	}
	if err := <-err2; err != nil {
		t.Fatalf("stop 2: %v", err)
	}
	c.mu.Lock()
	stoppingAfter := c.stopping
	c.mu.Unlock()
	if stoppingAfter {
		t.Fatal("c.stopping remained true after stop completed")
	}
	if got := fw.Blocked(); len(got) != 1 || got[0] != `C:\Apps\app.exe` {
		t.Fatalf("kill switch blocked = %v after stop", got)
	}
}

func TestStartReconcilesBridgeStatusAfterInitialFailure(t *testing.T) {
	dir := t.TempDir()
	// Bind an ephemeral loopback port to force the initial VLESS bridge start to fail.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	busyPort := ln.Addr().(*net.TCPAddr).Port
	const link = "vless://b7e2c1a0-4f3a-4c2b-9a11-111111111111@203.0.113.10:443?encryption=none&security=reality&type=xhttp&path=%2Fxhttp&mode=auto&sni=www.microsoft.com&fp=chrome&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&sid=ab12#v1"
	cfg := config.Default()
	cfg.Proxies = []config.Proxy{{
		Name:      "v1",
		Type:      "vless",
		Address:   "203.0.113.10:443",
		SOCKSPort: busyPort,
		Link:      link,
	}}
	c := newController(filepath.Join(dir, "config.json"), cfg, nil, hooks{})
	defer c.shutdown()

	c.mu.Lock()
	initialSt := c.bridgeSt["v1"]
	c.mu.Unlock()
	if initialSt.Up || initialSt.Err == "" {
		ln.Close()
		t.Fatalf("expected initial bridge failure on busy port %d, got %+v", busyPort, initialSt)
	}

	// Free the port so the bridge can bind when start() reconciles bridges.
	ln.Close()

	sessDone := make(chan struct{})
	var stopOnce sync.Once
	sess := rt.NewFakeSession(func() {
		stopOnce.Do(func() { close(sessDone) })
	}, sessDone)
	c.startSession = func(context.Context, *config.Config, *logbuf.Buffer, *vless.Manager) (*rt.Session, error) {
		return sess, nil
	}
	if err := c.start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	c.mu.Lock()
	afterSt := c.bridgeSt["v1"]
	c.mu.Unlock()
	if !afterSt.Up || afterSt.Err != "" || afterSt.SOCKS == "" {
		t.Fatalf("bridgeSt not reconciled by start(): %+v", afterSt)
	}
}

func TestStartAppliesConcurrentConfigSaveBeforeSyncKill(t *testing.T) {
	dir := t.TempDir()
	var orderMu sync.Mutex
	var events []string
	var appliedRule string

	fw := killswitch.NewWithRunner(filepath.Join(dir, "killswitch.json"), func(line string) error {
		if strings.Contains(line, "delete rule") {
			orderMu.Lock()
			events = append(events, "unblock")
			orderMu.Unlock()
		}
		return nil
	})
	cfg := config.Default()
	cfg.KillSwitch = true
	cfg.Proxies = []config.Proxy{{Name: "p", Type: "socks5", Address: "127.0.0.1:1080"}}
	cfg.Rules = []config.Rule{{Process: `C:\Apps\old.exe`, Action: "proxy", Proxy: "p"}}

	c := &controller{
		path:     filepath.Join(dir, "config.json"),
		cfg:      cfg,
		checks:   map[string]probe.Report{},
		bridgeSt: map[string]vless.Status{},
		bridges:  vless.NewManager(),
		done:     make(chan struct{}),
		loopDone: make(chan struct{}),
		hooks: hooks{
			firewall: fw,
			guard:    func(string) (func(), error) { return func() {}, nil },
		},
	}
	defer c.shutdown()
	c.syncKill()

	entered := make(chan struct{})
	release := make(chan struct{})
	sessDone := make(chan struct{})
	var stopOnce sync.Once
	sess := rt.NewFakeSession(func() {
		stopOnce.Do(func() { close(sessDone) })
	}, sessDone)

	c.startSession = func(context.Context, *config.Config, *logbuf.Buffer, *vless.Manager) (*rt.Session, error) {
		close(entered)
		<-release
		return sess, nil
	}
	c.applySession = func(_ *rt.Session, applied *config.Config) error {
		orderMu.Lock()
		events = append(events, "apply")
		if len(applied.Rules) > 0 {
			appliedRule = applied.Rules[0].Process
		}
		orderMu.Unlock()
		return nil
	}

	startErr := make(chan error, 1)
	go func() { startErr <- c.start() }()
	<-entered

	// Save a newer config while startSession is still running (before c.sess is set).
	next := config.Default()
	next.KillSwitch = true
	next.Proxies = []config.Proxy{{Name: "p", Type: "socks5", Address: "127.0.0.1:1080"}}
	next.Rules = []config.Rule{{Process: `C:\Apps\new.exe`, Action: "proxy", Proxy: "p"}}
	if err := c.replace(next); err != nil {
		t.Fatalf("concurrent replace: %v", err)
	}

	close(release)
	if err := <-startErr; err != nil {
		t.Fatalf("start: %v", err)
	}

	orderMu.Lock()
	gotRule := appliedRule
	gotEvents := append([]string(nil), events...)
	orderMu.Unlock()
	if gotRule != `C:\Apps\new.exe` {
		t.Fatalf("applied rule = %q, want %q", gotRule, `C:\Apps\new.exe`)
	}
	applyIdx, unblockIdx := -1, -1
	for i, ev := range gotEvents {
		if ev == "apply" && applyIdx == -1 {
			applyIdx = i
		}
		if ev == "unblock" && unblockIdx == -1 {
			unblockIdx = i
		}
	}
	if applyIdx == -1 || unblockIdx == -1 || applyIdx > unblockIdx {
		t.Fatalf("expected apply before kill-switch unblock, got events %v", gotEvents)
	}
}

func TestStartAbortsWithoutUnblockingOnApplyError(t *testing.T) {
	dir := t.TempDir()
	var unblocks int
	fw := killswitch.NewWithRunner(filepath.Join(dir, "killswitch.json"), func(line string) error {
		if strings.Contains(line, "delete rule") {
			unblocks++
		}
		return nil
	})
	cfg := config.Default()
	cfg.KillSwitch = true
	cfg.Proxies = []config.Proxy{{Name: "p", Type: "socks5", Address: "127.0.0.1:1080"}}
	cfg.Rules = []config.Rule{{Process: `C:\Apps\app.exe`, Action: "proxy", Proxy: "p"}}

	c := &controller{
		path:     filepath.Join(dir, "config.json"),
		cfg:      cfg,
		checks:   map[string]probe.Report{},
		bridgeSt: map[string]vless.Status{},
		bridges:  vless.NewManager(),
		done:     make(chan struct{}),
		loopDone: make(chan struct{}),
		hooks: hooks{
			firewall: fw,
			guard:    func(string) (func(), error) { return func() {}, nil },
		},
	}
	defer c.shutdown()
	c.syncKill()
	unblocks = 0

	sessDone := make(chan struct{})
	var stopOnce sync.Once
	sess := rt.NewFakeSession(func() {
		stopOnce.Do(func() { close(sessDone) })
	}, sessDone)
	c.startSession = func(context.Context, *config.Config, *logbuf.Buffer, *vless.Manager) (*rt.Session, error) {
		return sess, nil
	}
	c.applySession = func(*rt.Session, *config.Config) error {
		// Simulate a concurrent ksLoop() tick while sess.Apply is in flight:
		// c.sess must not be published yet, so syncKill must keep the block up.
		c.syncKill()
		return errors.New("apply failed")
	}

	if err := c.start(); err == nil || !strings.Contains(err.Error(), "apply failed") {
		t.Fatalf("start err = %v, want apply failed", err)
	}
	c.mu.Lock()
	published := c.sess
	c.mu.Unlock()
	if published != nil {
		t.Fatal("failed session was published on controller")
	}
	if sess.Running() {
		t.Fatal("session still running after apply error")
	}
	if unblocks != 0 {
		t.Fatalf("kill switch unblocked %d times on apply error", unblocks)
	}
	if got := fw.Blocked(); len(got) != 1 || got[0] != `C:\Apps\app.exe` {
		t.Fatalf("kill switch blocked = %v after apply error", got)
	}
}

func TestIconAPIRejectsUNCAndNonExeWithoutStat(t *testing.T) {
	oldPNG, oldRun, oldInst, oldLook, oldStat := iconPNG, listRunning, listInstalled, lookPath, statFile
	defer func() {
		iconPNG, listRunning, listInstalled, lookPath, statFile = oldPNG, oldRun, oldInst, oldLook, oldStat
	}()

	var statCalls []string
	var pngCalls []string
	statFile = func(p string) (os.FileInfo, error) {
		statCalls = append(statCalls, p)
		return nil, os.ErrNotExist
	}
	iconPNG = func(p string) ([]byte, error) {
		pngCalls = append(pngCalls, p)
		if p == "" {
			return nil, errors.New("empty")
		}
		return []byte("png"), nil
	}
	listRunning = func() ([]process.App, error) {
		return []process.App{{Name: "evil.exe", Path: `\\127.0.0.1\share\evil.exe`}}, nil
	}
	listInstalled = func() []process.Installed { return nil }
	lookPath = func(string) (string, error) { return "", errors.New("not found") }
	icons = &iconCache{m: map[string]iconEntry{}}

	c := newController(filepath.Join(t.TempDir(), "config.json"), config.Default(), nil, hooks{})
	defer c.shutdown()
	h := c.Handler()

	for _, bad := range []string{
		`\\127.0.0.1\share\a.exe`,
		`//127.0.0.1/share/a.exe`,
		`\\?\UNC\127.0.0.1\share\a.exe`,
		`C:\Windows\notepad.txt`,
		`evil.exe`,
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/icon?path="+bad+"&t="+c.token, nil)
		req.Host = "127.0.0.1:5000"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("path %q: got status %d, want 404", bad, rr.Code)
		}
	}
	if len(statCalls) != 0 {
		t.Fatalf("statFile was called for rejected paths: %v", statCalls)
	}
	for _, p := range pngCalls {
		if p != "" {
			t.Fatalf("iconPNG called with non-empty rejected path %q", p)
		}
	}
}
