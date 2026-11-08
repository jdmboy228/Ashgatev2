package gui

import (
	"path/filepath"
	"strings"
	"testing"

	"ashgate/internal/config"
	"ashgate/internal/killswitch"
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
