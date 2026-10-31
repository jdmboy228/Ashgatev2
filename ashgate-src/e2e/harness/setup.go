//go:build windows && e2e

package harness

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ashgate/internal/config"
)

// AppsDir holds the copies of the test client. Rules and kill-switch
// firewall rules point at these paths.
const AppsDir = `C:\ashgate-e2e\apps`

// SharedDir is readable and writable by every account (other-user tests).
const SharedDir = `C:\ashgate-e2e\shared`

// ProgramData is Ashgate's settings folder.
func ProgramData() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "Ashgate")
}

// ConfigPath is the default config file.
func ConfigPath() string { return filepath.Join(ProgramData(), "config.json") }

// Client names. Only the first is matched by the default rule.
const (
	ClientProxied = "ashgate-e2e-client"
	ClientDirect  = "ashgate-e2e-direct"
	ClientSOCKS   = "ashgate-e2e-socks"
	ClientHTTP    = "ashgate-e2e-http"
	ClientTCPOnly = "ashgate-e2e-tcponly"
	ClientPlain   = "ashgate-e2e-plain"
)

// ClientExe copies the client under name and returns its path.
func (e *Env) ClientExe(t testing.TB, name string) string {
	t.Helper()
	dst := filepath.Join(AppsDir, name+".exe")
	if _, err := os.Stat(dst); err == nil {
		return dst
	}
	src := filepath.Join(e.Bin, "ashgate-e2e-client.exe")
	if err := copyFile(src, dst); err != nil {
		t.Fatalf("client copy: %v", err)
	}
	return dst
}

func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// ClientResult is the JSON line the client prints.
type ClientResult struct {
	OK      bool    `json:"ok"`
	Bytes   int64   `json:"bytes"`
	Secs    float64 `json:"secs"`
	MBps    float64 `json:"mbps"`
	SHA     string  `json:"sha"`
	Want    string  `json:"want"`
	Answer  string  `json:"answer"`
	Error   string  `json:"error"`
	Stalls  int     `json:"stalls"`
	Count   int     `json:"count"`
	Failed  int     `json:"failed"`
	MaxGapS float64 `json:"maxGapSecs"`
}

func (r ClientResult) String() string {
	b, _ := json.Marshal(r)
	return string(b)
}

// RunClient runs one client command and parses its output.
func RunClient(exe string, args ...string) ClientResult {
	out, err := exec.Command(exe, args...).Output()
	var r ClientResult
	if jerr := json.Unmarshal(lastLine(out), &r); jerr != nil {
		r.Error = fmt.Sprintf("client output %q: %v / %v", strings.TrimSpace(string(out)), err, jerr)
	}
	return r
}

func lastLine(b []byte) []byte {
	s := strings.TrimSpace(string(b))
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	return []byte(s)
}

// Install runs a Setup.exe silently and waits for it.
func Install(t testing.TB, env *Env, setup string, extra ...string) time.Duration {
	t.Helper()
	if setup == "" {
		t.Fatal("no Setup.exe given (E2E_SETUP)")
	}
	log := env.Path("install", fmt.Sprintf("setup-%d.log", time.Now().UnixNano()))
	args := append([]string{"/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-", "/LOG=" + log}, extra...)
	start := time.Now()
	cmd := exec.Command(setup, args...)
	if err := cmd.Run(); err != nil {
		b, _ := os.ReadFile(log)
		t.Fatalf("Setup.exe %v: %v\n%s", args, err, tail(string(b), 3000))
	}
	return time.Since(start)
}

// Uninstall runs the uninstaller silently and waits for its copy in
// %TEMP% to finish (unins000.exe re-launches itself and exits at once).
func Uninstall(t testing.TB, env *Env) {
	t.Helper()
	unins := filepath.Join(env.InstallDir, "unins000.exe")
	if _, err := os.Stat(unins); err != nil {
		t.Fatalf("no uninstaller: %v", err)
	}
	log := env.Path("install", "uninstall.log")
	if err := exec.Command(unins, "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/LOG="+log).Run(); err != nil {
		t.Fatalf("unins000.exe: %v", err)
	}
	err := Eventually(120*time.Second, time.Second, func() error {
		for _, p := range Procs() {
			n := strings.ToLower(p.Name)
			if strings.HasPrefix(n, "_iu") || n == "unins000.exe" || strings.HasSuffix(n, ".tmp") && strings.HasPrefix(n, "_") {
				return fmt.Errorf("uninstaller still running: %s", p.Name)
			}
		}
		if _, err := os.Stat(unins); err == nil {
			return errors.New("unins000.exe still there")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("uninstall did not finish: %v", err)
	}
}

func tail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

// SubName is the subscription proxy's name in the tests.
const SubName = "e2e-sub"

// AddSubscription imports the fixture's subscription the way the window
// does and waits until it lists both servers.
func AddSubscription(t testing.TB, a *App, f *Fixture) SubView {
	t.Helper()
	if err := a.Post("/api/subscription", map[string]string{"name": SubName, "url": f.SubURL}, nil); err != nil {
		t.Fatalf("add subscription: %v", err)
	}
	var sv SubView
	err := Eventually(30*time.Second, 500*time.Millisecond, func() error {
		s, err := a.State()
		if err != nil {
			return err
		}
		v, ok := s.Subs[SubName]
		if !ok || v.Servers == 0 {
			return fmt.Errorf("subscription not listed yet: %+v", v)
		}
		sv = v
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return sv
}

// RuleOpts tunes a rule.
type RuleOpts struct {
	KillSwitch *bool
	TCPOnly    bool
	Action     string // default proxy
}

// SetRules replaces every rule with one per (exe path → proxy) pair.
func SetRules(t testing.TB, a *App, rules map[string]string, o map[string]RuleOpts) {
	t.Helper()
	err := a.UpdateConfig(func(c *config.Config) {
		c.Rules = nil
		for path, proxy := range rules {
			on := true
			r := config.Rule{Enabled: &on, Process: path, Action: "proxy", Proxy: proxy}
			if opt, ok := o[path]; ok {
				r.KillSwitch, r.TCPOnly = opt.KillSwitch, opt.TCPOnly
				if opt.Action != "" {
					r.Action = opt.Action
				}
			}
			if r.Action != "proxy" {
				r.Proxy = ""
			}
			c.Rules = append(c.Rules, r)
		}
	})
	if err != nil {
		t.Fatalf("set rules: %v", err)
	}
}

// Bool is a pointer helper.
func Bool(v bool) *bool { return &v }

// WaitTunnelHealthy waits until a health check reached the 204 responder
// through the tunnel after since. The first check comes 48–72 s after the
// window opened (60 s ±20 %).
func WaitTunnelHealthy(t testing.TB, f *Fixture, since time.Time, timeout time.Duration) Hit {
	t.Helper()
	var hit Hit
	err := Eventually(timeout, time.Second, func() error {
		for _, h := range f.Health.Since(since) {
			if h.Path == "/generate_204" {
				hit = h
				return nil
			}
		}
		return errors.New("no health check reached the test server yet")
	})
	if err != nil {
		t.Fatalf("%v (within %s)", err, timeout)
	}
	return hit
}

// ActiveServer is the active entry label of the subscription.
func ActiveServer(a *App) string {
	s, err := a.State()
	if err != nil {
		return ""
	}
	return s.Subs[SubName].Active
}

// CollectAppFiles copies Ashgate's settings folder (logs, state; the
// config too, it is masked before upload) into the artifacts.
func (e *Env) CollectAppFiles(label string) {
	dst := e.Path("app", label)
	_ = os.MkdirAll(dst, 0o755)
	_ = filepath.WalkDir(ProgramData(), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(ProgramData(), p)
		_ = copyFile(p, filepath.Join(dst, rel))
		return nil
	})
}

// AppLog returns ashgate.log (and its rotations) as one string.
func AppLog() string {
	var b strings.Builder
	for _, n := range []string{"ashgate.log.2", "ashgate.log.1", "ashgate.log"} {
		if data, err := os.ReadFile(filepath.Join(ProgramData(), n)); err == nil {
			b.Write(data)
		}
	}
	return b.String()
}

// ResetAppState removes Ashgate's settings so the next launch starts
// clean (between independent tests on one runner).
func ResetAppState() {
	_ = os.RemoveAll(ProgramData())
	if la := os.Getenv("LOCALAPPDATA"); la != "" {
		_ = os.RemoveAll(filepath.Join(la, "Ashgate"))
	}
}

// EnsureQuit closes every running Ashgate (end of a test).
func EnsureQuit(exe string) {
	if len(PIDsByName("ashgate.exe")) == 0 {
		return
	}
	_ = QuitCode(exe)
	_ = Eventually(20*time.Second, 300*time.Millisecond, func() error {
		if len(PIDsByName("ashgate.exe")) > 0 {
			return errors.New("still running")
		}
		return nil
	})
	for _, pid := range PIDsByName("ashgate.exe") {
		if p, err := os.FindProcess(int(pid)); err == nil {
			_ = p.Kill()
		}
	}
}
