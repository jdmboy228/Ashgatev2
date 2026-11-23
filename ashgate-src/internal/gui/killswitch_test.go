package gui

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"ashgate/internal/config"
	"ashgate/internal/killswitch"
	"ashgate/internal/probe"
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
