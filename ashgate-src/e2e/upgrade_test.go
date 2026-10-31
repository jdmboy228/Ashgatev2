//go:build windows && e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"ashgate/e2e/harness"
	"ashgate/internal/config"
	"ashgate/internal/version"
)

type configT = config.Config
type subscriptionT = config.Subscription

// testUpgrade installs the previous release, gives it settings, proxies,
// rules and a running capture, then installs this build over it.
func testUpgrade(t *testing.T, env *harness.Env) {
	harness.EnsureQuit(env.Exe)
	harness.ResetAppState()
	fx, err := harness.StartFixture(env)
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	client := env.ClientExe(t, harness.ClientProxied)

	harness.Install(t, env, env.SetupPrev)
	prevVer, _ := harness.Run(env.Exe, "version")
	env.Note("info", "upgrade from "+strings.TrimSpace(prevVer))

	// Settings the old version understands, written before its first start.
	seed := map[string]any{
		"version": 1,
		"relay":   map[string]any{"tcp4": "127.0.0.1:34010", "tcp6": "[::1]:34010"},
		"dns": map[string]any{"mode": "proxy", "servers": []string{"1.1.1.1:53", "9.9.9.9:53"},
			"includeSystemResolver": false, "systemResolverProxy": ""},
		"bypassPrivate": true, "udpUnsupported": "direct", "killSwitch": true,
		"log": map[string]any{"level": "debug"},
		"proxies": []any{
			map[string]any{"name": "up-socks", "type": "socks5", "address": fx.SOCKS.Addr, "username": fx.ProxyUser, "password": fx.ProxyPass},
			map[string]any{"name": "up-http", "type": "http", "address": fx.HTTP.Addr, "username": fx.ProxyUser, "password": fx.ProxyPass},
			map[string]any{"name": "up-vless", "type": "vless", "address": fx.XHTTP.Addr, "link": fx.PlainLink},
		},
		"rules": []any{
			map[string]any{"enabled": true, "process": client, "action": "proxy", "proxy": "up-vless"},
			map[string]any{"enabled": false, "process": "curl.exe", "action": "proxy", "proxy": "up-socks", "group": "G1"},
			map[string]any{"enabled": true, "process": "notepad.exe", "action": "direct"},
		},
		"groups": []any{map[string]any{"name": "G1", "enabled": true, "action": "proxy", "proxy": "up-http"}},
	}
	_ = os.MkdirAll(harness.ProgramData(), 0o755)
	b, _ := json.MarshalIndent(seed, "", "  ")
	if err := os.WriteFile(harness.ConfigPath(), b, 0o600); err != nil {
		t.Fatal(err)
	}

	old := harness.Launch(t, env, env.Exe, harness.LaunchOpts{})
	if err := old.SetAutostart(true); err != nil {
		t.Logf("old version: enable autostart: %v", err)
	}
	if err := old.StartCapture(); err != nil {
		t.Fatalf("old version: start capture: %v", err)
	}
	if r := harness.RunClient(client, "get", "-url", harness.URL(harness.TargetTCP), "-n", "1000000"); !r.OK {
		t.Errorf("old version: proxied client failed: %s", r)
	}
	// Close and reopen once so window.json exists, then capture on again.
	old.Quit()
	_ = os.Remove(filepath.Join(harness.ProgramData(), "resume-capture"))
	old = harness.Launch(t, env, env.Exe, harness.LaunchOpts{})
	if err := old.StartCapture(); err != nil {
		t.Fatalf("old version: start capture: %v", err)
	}
	cfgBefore, _ := os.ReadFile(harness.ConfigPath())
	winBefore, _ := os.ReadFile(filepath.Join(harness.ProgramData(), "window.json"))

	// Upgrade while the old window runs with capture on.
	harness.Install(t, env, env.Setup)
	select {
	case <-old.Done():
	case <-time.After(10 * time.Second):
		t.Errorf("the installer did not close the running old version")
		old.Kill()
	}
	out, _ := harness.Run(env.Exe, "version")
	if !strings.Contains(out, version.Version) {
		t.Errorf("after upgrade `ashgate version` = %q, want %s", out, version.Version)
	}
	cfgAfter, _ := os.ReadFile(harness.ConfigPath())
	if !bytes.Equal(cfgBefore, cfgAfter) {
		t.Errorf("the installer changed config.json")
	}
	if winAfter, _ := os.ReadFile(filepath.Join(harness.ProgramData(), "window.json")); !bytes.Equal(winBefore, winAfter) {
		t.Errorf("the installer changed window.json")
	}
	if !exists(filepath.Join(harness.ProgramData(), "resume-capture")) {
		t.Errorf("no resume-capture mark: capture will not come back after the upgrade")
	}

	a := harness.Launch(t, env, env.Exe, harness.LaunchOpts{})
	err = harness.Eventually(30*time.Second, 500*time.Millisecond, func() error {
		if s := a.MustState(); !s.Running {
			return errors.New("capture not resumed")
		}
		return nil
	})
	if err != nil {
		t.Errorf("after upgrade: %v", err)
	}
	if r := harness.RunClient(client, "get", "-url", harness.URL(harness.TargetTCP), "-n", "1000000"); !r.OK {
		t.Errorf("after upgrade: proxied client failed: %s", r)
	}
	// The new version may add fields with defaults; nothing else may change.
	cfgNew, _ := os.ReadFile(harness.ConfigPath())
	var o, n any
	_ = json.Unmarshal(cfgBefore, &o)
	_ = json.Unmarshal(cfgNew, &n)
	if diff := subset(o, n, "config"); diff != "" {
		t.Errorf("upgrade lost or changed settings: %s", diff)
	}
	if x := harness.TaskXML("Ashgate"); x == "" {
		t.Errorf("autostart task lost in the upgrade")
	} else if !strings.Contains(strings.ToLower(x), strings.ToLower(env.Exe)) {
		t.Errorf("autostart task no longer points at %s", env.Exe)
	}
	a.Quit()
	_ = os.Remove(filepath.Join(harness.ProgramData(), "resume-capture"))
	harness.Uninstall(t, env)
	checkNothingLeft(t, env)
}

// subset reports the first value of old that is missing or different in new.
func subset(old, new any, path string) string {
	switch o := old.(type) {
	case map[string]any:
		n, ok := new.(map[string]any)
		if !ok {
			return path + ": not an object any more"
		}
		for k, v := range o {
			nv, ok := n[k]
			if !ok {
				return path + "." + k + ": missing"
			}
			if d := subset(v, nv, path+"."+k); d != "" {
				return d
			}
		}
	case []any:
		n, ok := new.([]any)
		if !ok || len(n) != len(o) {
			return fmt.Sprintf("%s: list changed (%d → %v)", path, len(o), lenOf(new))
		}
		for i := range o {
			if d := subset(o[i], n[i], fmt.Sprintf("%s[%d]", path, i)); d != "" {
				return d
			}
		}
	default:
		if !reflect.DeepEqual(old, new) {
			return fmt.Sprintf("%s: %v → %v", path, old, new)
		}
	}
	return ""
}

func lenOf(v any) any {
	if l, ok := v.([]any); ok {
		return len(l)
	}
	return v
}
