//go:build windows && e2e

package harness

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"

	"ashgate/internal/config"
)

// The WebView2 policy key the harness falls back to when the environment
// variable does not reach the runtime. It is removed again at the end of
// the test and, as a safety net, by the workflow.
const (
	policyKey   = `SOFTWARE\Policies\Microsoft\Edge\WebView2\AdditionalBrowserArguments`
	policyValue = "ashgate.exe"
	debugArg    = "--remote-debugging-port=9222"
	debugEnv    = "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"
)

// App is one running Ashgate window driven over its local API.
type App struct {
	t      testing.TB
	env    *Env
	Exe    string
	Args   []string
	PID    int
	UIPort int
	Token  string
	// How remote debugging was turned on: "env" or "policy".
	Mechanism string
	Started   time.Time
	Ready     time.Duration // launch → token readable (UI ready)

	cmd    *exec.Cmd
	exitMu sync.Mutex
	exited bool
	code   int
	done   chan struct{}
	hc     *http.Client
}

// LaunchOpts tunes Launch.
type LaunchOpts struct {
	Args []string
	// NoDebug launches the app exactly as a user would: no debugging
	// variable, no policy. The API is then not reachable.
	NoDebug bool
	Env     []string
	// ReadyTimeout bounds the wait for the page and token.
	ReadyTimeout time.Duration
}

var policyUsed bool

// Launch starts exe and waits until its API answers.
func Launch(t testing.TB, env *Env, exe string, o LaunchOpts) *App {
	t.Helper()
	if o.ReadyTimeout == 0 {
		o.ReadyTimeout = 60 * time.Second
	}
	if pids := PIDsByName("ashgate.exe"); len(pids) > 0 {
		t.Fatalf("ashgate.exe is already running (pid %v); tests run one app at a time", pids)
	}
	a := start(t, env, exe, o, !o.NoDebug && !policyUsed)
	if o.NoDebug {
		return a
	}
	if err := a.connect(o.ReadyTimeout); err != nil {
		if policyUsed {
			t.Fatalf("app API not reachable: %v", err)
		}
		// The variable did not reach WebView2. Use the policy key for
		// this job only, then remove it in Cleanup.
		env.Note("info", "WebView2 ignored "+debugEnv+"; using the AdditionalBrowserArguments policy for this job")
		a.Quit()
		if err := SetDebugPolicy(true); err != nil {
			t.Fatalf("debug policy: %v", err)
		}
		policyUsed = true
		t.Cleanup(func() { _ = SetDebugPolicy(false) })
		a = start(t, env, exe, o, false)
		if err := a.connect(o.ReadyTimeout); err != nil {
			t.Fatalf("app API not reachable with the policy either: %v", err)
		}
		a.Mechanism = "policy"
	}
	return a
}

func start(t testing.TB, env *Env, exe string, o LaunchOpts, withEnv bool) *App {
	t.Helper()
	a := &App{t: t, env: env, Exe: exe, Args: o.Args, done: make(chan struct{}),
		hc: &http.Client{Timeout: 40 * time.Second}}
	a.cmd = exec.Command(exe, o.Args...)
	base := make([]string, 0, len(os.Environ())+2)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(kv), debugEnv+"=") {
			base = append(base, kv)
		}
	}
	if withEnv {
		base = append(base, debugEnv+"="+debugArg)
		a.Mechanism = "env"
	}
	a.cmd.Env = append(base, o.Env...)
	// A Go panic of the GUI goes to stderr; keep it as an artifact.
	if env != nil {
		if f, err := os.Create(env.Path("app", fmt.Sprintf("stderr-%d.log", time.Now().UnixNano()))); err == nil {
			a.cmd.Stdout, a.cmd.Stderr = f, f
		}
	}
	a.Started = time.Now()
	if err := a.cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", exe, err)
	}
	a.PID = a.cmd.Process.Pid
	go func() {
		err := a.cmd.Wait()
		a.exitMu.Lock()
		a.exited = true
		a.code = 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			a.code = ee.ExitCode()
		}
		a.exitMu.Unlock()
		close(a.done)
	}()
	return a
}

// Exited reports whether the process ended, and its exit code.
func (a *App) Exited() (bool, int) {
	a.exitMu.Lock()
	defer a.exitMu.Unlock()
	return a.exited, a.code
}

// Done is closed when the process ends.
func (a *App) Done() <-chan struct{} { return a.done }

func (a *App) connect(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		if ok, code := a.Exited(); ok {
			return fmt.Errorf("ashgate.exe exited with code %d", code)
		}
		page, err := AppPage(DebugPort)
		if err != nil {
			last = err
			time.Sleep(300 * time.Millisecond)
			continue
		}
		u, err := url.Parse(page.URL)
		if err != nil {
			return err
		}
		port, _ := strconv.Atoi(u.Port())
		c, err := DialCDP(page, nil)
		if err != nil {
			last = err
			time.Sleep(300 * time.Millisecond)
			continue
		}
		var tok string
		err = c.Eval("window.__ashgateToken || ''", &tok)
		c.Close()
		if err != nil || tok == "" {
			last = fmt.Errorf("token not ready: %v", err)
			time.Sleep(300 * time.Millisecond)
			continue
		}
		a.UIPort, a.Token = port, tok
		a.Ready = time.Since(a.Started)
		if a.env != nil {
			a.env.Secrets.Add("api-token", tok, false)
		}
		return nil
	}
	if last == nil {
		last = errors.New("timeout")
	}
	return last
}

// SetDebugPolicy adds or removes the WebView2 AdditionalBrowserArguments
// policy for ashgate.exe.
func SetDebugPolicy(on bool) error {
	if !on {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, policyKey, registry.SET_VALUE)
		if err != nil {
			return nil
		}
		defer k.Close()
		if err := k.DeleteValue(policyValue); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return err
		}
		return nil
	}
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, policyKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(policyValue, debugArg)
}

// DebugPolicySet reports whether the policy value exists.
func DebugPolicySet() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, policyKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue(policyValue)
	return err == nil
}

// APIError is the {"error": "..."} body of a rejected call.
type APIError struct {
	Status int
	Text   string
}

func (e *APIError) Error() string { return fmt.Sprintf("api %d: %s", e.Status, e.Text) }

func (a *App) do(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", a.UIPort, path), body)
	if err != nil {
		return err
	}
	req.Header.Set("X-Ashgate-Token", a.Token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(b, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(b))
		}
		return &APIError{Status: resp.StatusCode, Text: e.Error}
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

// Get calls a GET endpoint.
func (a *App) Get(path string, out any) error { return a.do(http.MethodGet, path, nil, out) }

// Post calls a POST endpoint.
func (a *App) Post(path string, in, out any) error {
	if in == nil {
		in = struct{}{}
	}
	return a.do(http.MethodPost, path, in, out)
}

// State is the part of /api/state the tests read.
type State struct {
	Version    string                  `json:"version"`
	Running    bool                    `json:"running"`
	Admin      bool                    `json:"admin"`
	Driver     bool                    `json:"driver"`
	Error      string                  `json:"error"`
	Notice     string                  `json:"notice"`
	Autostart  bool                    `json:"autostart"`
	Config     *config.Config          `json:"config"`
	Bridges    map[string]BridgeStatus `json:"bridges"`
	KillSwitch struct {
		On      bool     `json:"on"`
		Blocked []string `json:"blocked"`
		Missing []string `json:"missing"`
		Error   string   `json:"error"`
	} `json:"killSwitch"`
	Subs       map[string]SubView `json:"subs"`
	Events     []Event            `json:"events"`
	Hidden     bool               `json:"hidden"`
	Generation uint64             `json:"generation"`
	BytesUp    int64              `json:"bytesUp"`
	BytesDown  int64              `json:"bytesDown"`
	// Goroutines is -1 when the app does not report it.
	Goroutines int `json:"goroutines"`
}

// BridgeStatus is vless.Status as the API sends it.
type BridgeStatus struct {
	Published string `json:"published"`
	HTTP      string `json:"http"`
	User      string `json:"user"`
	Pass      string `json:"pass"`
	Error     string `json:"error"`
	Up        bool   `json:"up"`
}

// SubView is one subscription card.
type SubView struct {
	Servers    int       `json:"servers"`
	Active     string    `json:"active"`
	Reason     string    `json:"reason"`
	SwitchedAt time.Time `json:"switchedAt"`
	Fetching   bool      `json:"fetching"`
	Error      string    `json:"error"`
}

// Event is one connection log row.
type Event struct {
	Time    string `json:"time"`
	Process string `json:"process"`
	PID     uint32 `json:"pid"`
	Proto   string `json:"proto"`
	Dest    string `json:"dest"`
	Via     string `json:"via"`
	Status  string `json:"status"`
	Error   string `json:"error"`
}

// State reads /api/state.
func (a *App) State() (*State, error) {
	s := &State{Goroutines: -1}
	if err := a.Get("/api/state", s); err != nil {
		return nil, err
	}
	return s, nil
}

// MustState reads /api/state or fails the test.
func (a *App) MustState() *State {
	a.t.Helper()
	s, err := a.State()
	if err != nil {
		a.t.Fatalf("state: %v", err)
	}
	return s
}

// UpdateConfig reads the config, lets fn change it and saves it.
func (a *App) UpdateConfig(fn func(c *config.Config)) error {
	s, err := a.State()
	if err != nil {
		return err
	}
	c := s.Config
	fn(c)
	return a.Post("/api/config", map[string]any{"config": c}, nil)
}

// SetAutostart turns the logon task on or off through the API.
func (a *App) SetAutostart(on bool) error {
	s, err := a.State()
	if err != nil {
		return err
	}
	return a.Post("/api/config", map[string]any{"config": s.Config, "autostart": on}, nil)
}

// StartCapture presses Start and waits until capture runs.
func (a *App) StartCapture() error {
	if err := a.Post("/api/start", nil, nil); err != nil {
		return err
	}
	return Eventually(30*time.Second, 300*time.Millisecond, func() error {
		s, err := a.State()
		if err != nil {
			return err
		}
		if !s.Running {
			if s.Error != "" {
				return errors.New(s.Error)
			}
			return errors.New("capture not running yet")
		}
		return nil
	})
}

// StopCapture presses Stop and waits until capture ends.
func (a *App) StopCapture() error {
	if err := a.Post("/api/stop", nil, nil); err != nil {
		return err
	}
	return Eventually(20*time.Second, 300*time.Millisecond, func() error {
		s, err := a.State()
		if err != nil {
			return err
		}
		if s.Running {
			return errors.New("capture still running")
		}
		return nil
	})
}

// Quit closes the window the way «Выход» does (ashgate quit) and waits for
// the process to end. It returns how long the exit took.
func (a *App) Quit() time.Duration {
	start := time.Now()
	cmd := exec.Command(a.Exe, "quit")
	_ = cmd.Run()
	select {
	case <-a.done:
	case <-time.After(25 * time.Second):
		a.t.Errorf("ashgate.exe (pid %d) did not exit within 25 s of `ashgate quit`", a.PID)
		_ = a.cmd.Process.Kill()
		<-a.done
	}
	return time.Since(start)
}

// Kill ends the process the hard way (crash simulation).
func (a *App) Kill() {
	_ = a.cmd.Process.Kill()
	<-a.done
}

// QuitCode runs `ashgate quit` and returns its exit code.
func QuitCode(exe string) int {
	cmd := exec.Command(exe, "quit")
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	if err != nil {
		return -1
	}
	return 0
}
