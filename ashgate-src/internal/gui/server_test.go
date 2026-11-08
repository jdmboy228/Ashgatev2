package gui

import (
	"context"
	"errors"
	"io"
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
