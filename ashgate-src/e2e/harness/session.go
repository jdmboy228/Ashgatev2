//go:build windows && e2e

package harness

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// Session is a running Ashgate with the fixture, a subscription and a
// kill-switch rule for the proxied client.
type Session struct {
	Env     *Env
	Fx      *Fixture
	App     *App
	Client  string // proxied by the subscription, kill switch on
	Direct  string // no rule
	Started time.Time
}

// SessionOpts tunes NewSession.
type SessionOpts struct {
	NoCapture bool
	// Extra rules (exe path → proxy name) next to the client's.
	Rules map[string]string
	Opts  map[string]RuleOpts
}

// NewSession installs nothing: the workflow installed Setup.exe already.
func NewSession(t *testing.T, o SessionOpts) *Session {
	t.Helper()
	env := LoadEnv(t)
	if err := EnsureFirewallOn(); err != nil {
		t.Logf("firewall: %v", err)
	}
	fx, err := StartFixture(env)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	t.Cleanup(fx.Close)
	s := &Session{Env: env, Fx: fx}
	s.App = Launch(t, env, env.Exe, LaunchOpts{})
	t.Cleanup(func() {
		if ok, _ := s.App.Exited(); !ok {
			s.App.Quit()
		}
		env.CollectAppFiles(t.Name())
	})
	AddSubscription(t, s.App, fx)
	s.Client = env.ClientExe(t, ClientProxied)
	s.Direct = env.ClientExe(t, ClientDirect)
	rules := map[string]string{s.Client: SubName}
	opts := map[string]RuleOpts{s.Client: {KillSwitch: Bool(true)}}
	for k, v := range o.Rules {
		rules[k] = v
	}
	for k, v := range o.Opts {
		opts[k] = v
	}
	SetRules(t, s.App, rules, opts)
	if !o.NoCapture {
		s.Started = time.Now()
		if err := s.App.StartCapture(); err != nil {
			t.Fatalf("start capture: %v", err)
		}
		WaitTunnelHealthy(t, fx, s.App.Started, 150*time.Second)
	}
	return s
}

// URL is the HTTP base URL of a target address.
func URL(addr string) string { return "http://" + addr }

// MiniDump writes a MiniDumpNormal of pid (what WER writes by default).
func MiniDump(pid uint32, path string) error {
	dbghelp := windows.NewLazySystemDLL("dbghelp.dll")
	proc := dbghelp.NewProc("MiniDumpWriteDump")
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	const miniDumpNormal = 0
	r, _, e := proc.Call(uintptr(h), uintptr(pid), f.Fd(), miniDumpNormal, 0, 0, 0)
	if r == 0 {
		return fmt.Errorf("MiniDumpWriteDump: %v", e)
	}
	return nil
}
