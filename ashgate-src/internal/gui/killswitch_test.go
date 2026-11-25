package gui

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ashgate/internal/config"
	"ashgate/internal/killswitch"
	"ashgate/internal/probe"
	rt "ashgate/internal/runtime"
	"ashgate/internal/vless"
)

// When capture fails, the targets saved for the guard are blocked at once,
// before the session's teardown and a new search for the programs.
func TestBlockNowUsesSavedTargets(t *testing.T) {
	dir := t.TempDir()
	var lines []string
	fw := killswitch.NewWithRunner(filepath.Join(dir, "killswitch.json"), func(l string) error {
		lines = append(lines, l)
		return nil
	})
	cfg := config.Default()
	cfg.Proxies = []config.Proxy{{Name: "p", Type: "socks5", Address: "127.0.0.1:1080"}}
	cfg.Rules = []config.Rule{{Process: `C:\Apps\app.exe`, Action: "proxy", Proxy: "p"}}
	c := newController(filepath.Join(dir, "config.json"), cfg, nil, hooks{firewall: fw})
	c.ksMu.Lock()
	err := c.saveTargetsLocked([]string{`C:\Apps\app.exe`, `C:\Apps\child.exe`})
	c.ksMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	c.blockNow()
	if got := fw.Blocked(); len(got) != 0 {
		t.Fatalf("blocked %v without the kill switch", got)
	}
	c.mu.Lock()
	c.cfg.KillSwitch = true
	c.mu.Unlock()
	c.blockNow()
	if got := strings.Join(fw.Blocked(), "|"); got != `C:\Apps\app.exe|C:\Apps\child.exe` {
		t.Fatalf("blocked %s (netsh %v)", got, lines)
	}
}

func TestSyncKillUnblocksOrphanedRulesAndRetriesErrors(t *testing.T) {
	dir := t.TempDir()
	var deleteCalls int
	var deleteErr error
	fw := killswitch.NewWithRunner(filepath.Join(dir, "killswitch.json"), func(l string) error {
		if strings.Contains(l, "delete rule") {
			deleteCalls++
			return deleteErr
		}
		return nil
	})
	if len(fw.Blocked()) != 0 {
		t.Fatalf("expected empty initial state, got %v", fw.Blocked())
	}

	cfg := config.Default()
	c := &controller{
		path:     filepath.Join(dir, "config.json"),
		cfg:      cfg,
		checks:   map[string]probe.Report{},
		bridgeSt: map[string]vless.Status{},
		hooks:    hooks{firewall: fw},
	}

	// First syncKill fails netsh: must record error and NOT mark ksClean.
	deleteErr = errors.New("netsh: exit status 1: access denied")
	c.syncKill()
	if deleteCalls != 1 {
		t.Fatalf("deleteCalls = %d, want 1", deleteCalls)
	}
	if c.ksErr == "" || c.ksClean {
		t.Fatalf("ksErr=%q ksClean=%v after failed unblock", c.ksErr, c.ksClean)
	}

	// Second syncKill retries Unblock even with empty killswitch.json.
	deleteErr = nil
	c.syncKill()
	if deleteCalls != 2 {
		t.Fatalf("deleteCalls = %d, want 2 (retry after error)", deleteCalls)
	}
	if c.ksErr != "" || !c.ksClean {
		t.Fatalf("ksErr=%q ksClean=%v after successful unblock", c.ksErr, c.ksClean)
	}

	// Subsequent syncKill while still clean does not spam netsh.
	c.syncKill()
	if deleteCalls != 2 {
		t.Fatalf("deleteCalls = %d, want 2 while already clean", deleteCalls)
	}
}

func TestSyncKillDoesNotUnblockOnGuardOrSaveFailure(t *testing.T) {
	dir := t.TempDir()
	var unblockCalls int
	fw := killswitch.NewWithRunner(filepath.Join(dir, "killswitch.json"), func(l string) error {
		if strings.Contains(l, "delete rule") && !strings.Contains(l, "program=") {
			unblockCalls++
		}
		return nil
	})
	cfg := config.Default()
	cfg.KillSwitch = true
	cfg.Proxies = []config.Proxy{{Name: "p", Type: "socks5", Address: "127.0.0.1:1080"}}
	cfg.Rules = []config.Rule{{Process: `C:\Apps\app.exe`, Action: "proxy", Proxy: "p"}}

	sessDone := make(chan struct{})
	t.Cleanup(func() { close(sessDone) })
	sess := rt.NewFakeSession(func() {}, sessDone)

	c := &controller{
		path:     filepath.Join(dir, "config.json"),
		cfg:      cfg,
		checks:   map[string]probe.Report{},
		bridgeSt: map[string]vless.Status{},
		hooks:    hooks{firewall: fw},
	}

	// Initially stopped: kill switch blocks app.exe.
	c.syncKill()
	if got := fw.Blocked(); len(got) != 1 || got[0] != `C:\Apps\app.exe` {
		t.Fatalf("initial blocked = %v, want [C:\\Apps\\app.exe]", got)
	}

	// Capture starts running, but guard fails: must NOT call Unblock().
	c.sess = sess
	c.hooks.guard = func(string) (func(), error) {
		return nil, errors.New("guard spawn failed")
	}
	c.syncKill()
	if unblockCalls != 0 {
		t.Fatalf("unblockCalls = %d after guard failure, want 0", unblockCalls)
	}
	if got := fw.Blocked(); len(got) != 1 || got[0] != `C:\Apps\app.exe` {
		t.Fatalf("blocked = %v after guard failure, want rule preserved", got)
	}
	if c.ksClean || !strings.Contains(c.ksErr, "guard spawn failed") {
		t.Fatalf("ksClean=%v ksErr=%q after guard failure", c.ksClean, c.ksErr)
	}

	// saveTargets fails: must NOT call Unblock().
	oldSave := saveTargets
	saveTargets = func(string, []string) error { return errors.New("disk full") }
	t.Cleanup(func() { saveTargets = oldSave })
	c.ksSaved = ""
	c.hooks.guard = func(string) (func(), error) { return func() {}, nil }
	c.syncKill()
	if unblockCalls != 0 {
		t.Fatalf("unblockCalls = %d after saveTargets failure, want 0", unblockCalls)
	}
	if got := fw.Blocked(); len(got) != 1 || got[0] != `C:\Apps\app.exe` {
		t.Fatalf("blocked = %v after saveTargets failure, want rule preserved", got)
	}
	if c.ksClean || !strings.Contains(c.ksErr, "disk full") {
		t.Fatalf("ksClean=%v ksErr=%q after saveTargets failure", c.ksClean, c.ksErr)
	}

	// saveTargets succeeds and guard returns ErrUnsupported: Unblock() IS allowed.
	saveTargets = oldSave
	c.ksSaved = ""
	c.hooks.guard = func(string) (func(), error) { return nil, killswitch.ErrUnsupported }
	c.syncKill()
	if unblockCalls != 1 {
		t.Fatalf("unblockCalls = %d with ErrUnsupported guard, want 1", unblockCalls)
	}
	if got := fw.Blocked(); len(got) != 0 {
		t.Fatalf("blocked = %v after ErrUnsupported guard unblock, want empty", got)
	}
	if !c.ksClean || c.ksErr != "" {
		t.Fatalf("ksClean=%v ksErr=%q after ErrUnsupported guard unblock", c.ksClean, c.ksErr)
	}
}

func TestBlockNowPreservesActiveRulesAndFallsBackWhenTargetsEmpty(t *testing.T) {
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
		hooks:    hooks{firewall: fw},
	}

	// (a) Targets file is missing, but firewall already blocks app.exe: blockNow must NOT wipe it.
	if err := fw.Block([]string{`C:\Apps\app.exe`}); err != nil {
		t.Fatal(err)
	}
	c.blockNow()
	if got := strings.Join(fw.Blocked(), "|"); got != `C:\Apps\app.exe` {
		t.Fatalf("missing targets wiped active block: got %q", got)
	}

	// (b) Targets file has a stale subset while firewall also blocks app.exe: both stay blocked.
	c.ksMu.Lock()
	err := c.saveTargetsLocked([]string{`C:\Apps\old.exe`})
	c.ksMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	c.blockNow()
	if got := strings.Join(fw.Blocked(), "|"); got != `C:\Apps\app.exe|C:\Apps\old.exe` {
		t.Fatalf("stale targets dropped active block: got %q", got)
	}

	// (c) Targets file is missing and firewall is currently empty: falls back to killTargets(cfg).
	if err := fw.Unblock(); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(dir, "killswitch-targets.json"))
	c.blockNow()
	if got := strings.Join(fw.Blocked(), "|"); got != `C:\Apps\app.exe` {
		t.Fatalf("empty targets and empty firewall did not fall back to cfg: got %q", got)
	}
}
