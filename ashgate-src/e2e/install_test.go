//go:build windows && e2e

package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"ashgate/e2e/harness"
	"ashgate/internal/process"
	"ashgate/internal/secret"
	"ashgate/internal/subs"
	"ashgate/internal/version"
)

const uninstallKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{1F695E51-8E7F-4B83-8E84-13113971A2C5}_is1`

// Official WinDivert 2.2.2-A x64 hashes (the same as update.bat).
var winDivertSHA = map[string]string{
	"WinDivert.dll":   "C1E060EE19444A259B2162F8AF0F3FE8C4428A1C6F694DCE20DE194AC8D7D9A2",
	"WinDivert64.sys": "8DA085332782708D8767BCACE5327A6EC7283C17CFB85E40B03CD2323A90DDC2",
}

func sha(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	_, _ = io.Copy(h, f)
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}

func startMenuLink() string {
	return filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows\Start Menu\Programs\Ashgate.lnk`)
}

func desktopLink() string {
	pub := os.Getenv("PUBLIC")
	if pub == "" {
		pub = `C:\Users\Public`
	}
	return filepath.Join(pub, "Desktop", "Ashgate.lnk")
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// TestInstall is the install job: fresh install, files, shortcuts,
// version, WebView2, settings ACL, autostart, reinstall with a
// subscription, uninstall, then an upgrade from the previous release.
func TestInstall(t *testing.T) {
	env := harness.LoadEnv(t)
	harness.EnsureQuit(env.Exe)
	_ = harness.EnsureFirewallOn()

	t.Run("FreshInstall", func(t *testing.T) {
		d := harness.Install(t, env, env.Setup)
		env.Metric("install.seconds", d.Seconds(), "s", "lower")
		if !exists(env.Exe) {
			t.Fatalf("%s missing after install", env.Exe)
		}
	})

	t.Run("Files", func(t *testing.T) {
		for _, f := range []string{"ashgate.exe", "WinDivert.dll", "WinDivert64.sys", "README.md", "LICENSE",
			"THIRD_PARTY_NOTICES.md", "unins000.exe", "unins000.dat"} {
			if !exists(filepath.Join(env.InstallDir, f)) {
				t.Errorf("%s not installed", f)
			}
		}
		if env.Dist != "" {
			for _, f := range []string{"ashgate.exe", "WinDivert.dll", "WinDivert64.sys"} {
				if a, b := sha(filepath.Join(env.Dist, f)), sha(filepath.Join(env.InstallDir, f)); a != b {
					t.Errorf("%s differs from the build: %s vs %s", f, b, a)
				}
			}
		}
		for f, want := range winDivertSHA {
			if got := sha(filepath.Join(env.InstallDir, f)); got != want {
				t.Errorf("%s SHA-256 %s, official %s", f, got, want)
			}
		}
		// Ashgate runs elevated: standard users must not be able to change its files.
		_, aces, err := harness.DACL(env.InstallDir)
		if err != nil {
			t.Fatal(err)
		}
		const writeBits = 0x2 | 0x4 | 0x40000000 | 0x10000000 | 0x40000 | 0x80000 | 0x10000
		for _, a := range aces {
			if a.Allow && a.Mask&writeBits != 0 && harness.IsBroad(a.SID) != "" {
				t.Errorf("%s can write to %s (mask %#x)", a.Account, env.InstallDir, a.Mask)
			}
		}
	})

	t.Run("Shortcuts", func(t *testing.T) {
		b, err := os.ReadFile(startMenuLink())
		if err != nil {
			t.Fatalf("Start menu shortcut: %v", err)
		}
		target, err := process.ParseLNK(b)
		if err != nil || !strings.EqualFold(target, env.Exe) {
			t.Errorf("Start menu shortcut points to %q (%v), want %s", target, err, env.Exe)
		}
		if exists(desktopLink()) {
			t.Errorf("desktop shortcut created although the task is unchecked by default")
		}
	})

	t.Run("Version", func(t *testing.T) {
		want := version.Version
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, uninstallKey, registry.QUERY_VALUE)
		if err != nil {
			t.Fatalf("uninstall entry: %v", err)
		}
		dv, _, _ := k.GetStringValue("DisplayVersion")
		k.Close()
		if dv != want {
			t.Errorf("uninstall DisplayVersion %q, want %q", dv, want)
		}
		m, err := harness.Manifest(env.Exe)
		if err != nil {
			t.Fatalf("manifest: %v", err)
		}
		_ = os.WriteFile(env.Path("install", "manifest.xml"), []byte(m), 0o644)
		if !strings.Contains(m, `level="requireAdministrator"`) {
			t.Errorf("manifest does not require administrator")
		}
		four := want
		for strings.Count(four, ".") < 3 {
			four += ".0"
		}
		if !strings.Contains(m, `version="`+four+`"`) {
			t.Errorf("manifest identity version is not %s (winres.json out of step with version.go)", four)
		}
		out, _ := exec.Command(env.Exe, "version").CombinedOutput()
		if !strings.Contains(string(out), want) {
			t.Errorf("`ashgate version` printed %q, want %s", strings.TrimSpace(string(out)), want)
		}
		if fv := harness.FileVersion(env.Exe); fv == "" {
			env.Note("finding", "ashgate.exe has no VERSIONINFO resource; only the manifest identity carries the version (Explorer → Details shows none)")
		}
		if fv := harness.FileVersion(env.Setup); !strings.HasPrefix(fv, want) {
			t.Errorf("Setup.exe file version %q, want %s", fv, want)
		}
	})

	t.Run("WebView2", func(t *testing.T) {
		pv := ""
		for _, root := range []registry.Key{registry.LOCAL_MACHINE, registry.CURRENT_USER} {
			for _, p := range []string{`SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}`,
				`SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}`} {
				if k, err := registry.OpenKey(root, p, registry.QUERY_VALUE); err == nil {
					if v, _, err := k.GetStringValue("pv"); err == nil && v != "" && v != "0.0.0.0" {
						pv = v
					}
					k.Close()
				}
			}
		}
		if pv == "" {
			t.Fatalf("WebView2 Runtime is not registered on this machine")
		}
		env.Note("info", "WebView2 Runtime "+pv)

		// Hide the runtime: the app must explain, not crash or hang.
		empty := `C:\ashgate-e2e\no-webview2`
		_ = os.MkdirAll(empty, 0o755)
		a := harness.Launch(t, env, env.Exe, harness.LaunchOpts{NoDebug: true,
			Env: []string{"WEBVIEW2_BROWSER_EXECUTABLE_FOLDER=" + empty}})
		var dlg harness.Window
		err := harness.Eventually(40*time.Second, 300*time.Millisecond, func() error {
			if ok, code := a.Exited(); ok {
				return fmt.Errorf("exited with %d before showing a message", code)
			}
			for _, w := range harness.Windows(uint32(a.PID)) {
				if w.Class == "#32770" && w.Visible {
					dlg = w
					return nil
				}
				if w.Visible && w.Title == "Ashgate" && w.Class != "#32770" {
					return errSimulationFailed
				}
			}
			return errors.New("no message yet")
		})
		if errors.Is(err, errSimulationFailed) {
			env.Note("skipped", "WebView2 missing: WEBVIEW2_BROWSER_EXECUTABLE_FOLDER did not hide the runtime; the window opened normally")
			a.Quit()
			t.Skip("cannot hide the WebView2 runtime on this runner")
		}
		if err != nil {
			t.Fatalf("WebView2 missing: %v", err)
		}
		_ = harness.Screenshot(env.Path("screens", "webview2-missing.png"))
		harness.PostMessage(dlg.HWND, 0x0010, 0, 0) // WM_CLOSE
		select {
		case <-a.Done():
		case <-time.After(15 * time.Second):
			a.Kill()
			t.Fatalf("app did not exit after the WebView2 message was closed")
		}
		if _, code := a.Exited(); code == 0 || code == 2 {
			t.Errorf("exit code %d after missing WebView2, want 1 (2 would be a Go panic)", code)
		}
	})

	t.Run("SettingsACL", func(t *testing.T) {
		a := harness.Launch(t, env, env.Exe, harness.LaunchOpts{})
		// Saving once makes sure config.json exists with the app's rights.
		if err := a.UpdateConfig(func(c *configT) {}); err != nil {
			t.Fatal(err)
		}
		a.Quit()
		checkSettingsACL(t, env)
	})

	t.Run("Autostart", func(t *testing.T) {
		a := harness.Launch(t, env, env.Exe, harness.LaunchOpts{})
		if err := a.SetAutostart(true); err != nil {
			t.Fatalf("enable autostart: %v", err)
		}
		a.Quit()
		x := harness.TaskXML("Ashgate")
		_ = os.WriteFile(env.Path("install", "task.xml"), []byte(x), 0o644)
		if x == "" {
			t.Fatalf("no scheduled task \\Ashgate after turning autostart on")
		}
		checkTask(t, env, x)

		// Run it the way a logon would and check the window and capture.
		_ = os.Remove(filepath.Join(harness.ProgramData(), "resume-capture"))
		if out, err := harness.Run("schtasks", "/Run", "/TN", "Ashgate"); err != nil {
			t.Fatalf("schtasks /Run: %v: %s", err, out)
		}
		var pid uint32
		var win harness.Window
		err := harness.Eventually(45*time.Second, 300*time.Millisecond, func() error {
			pids := harness.PIDsByName("ashgate.exe")
			for _, p := range pids {
				if w, ok := harness.MainWindow(p); ok {
					pid, win = p, w
					return nil
				}
			}
			return fmt.Errorf("no visible Ashgate window yet (processes %v)", pids)
		})
		if err != nil {
			t.Fatal(err)
		}
		_ = harness.Screenshot(env.Path("screens", "autostart-window.png"))
		if win.Iconic {
			t.Errorf("autostart opened the window minimized")
		}
		if w := win.Rect[2] - win.Rect[0]; w < 600 {
			t.Errorf("autostart window is only %d px wide", w)
		}
		err = harness.Eventually(30*time.Second, 500*time.Millisecond, func() error {
			if harness.ServiceState("WinDivert") != "RUNNING" {
				return errors.New("WinDivert not running")
			}
			for _, s := range harness.SocketsOf(pid) {
				if s.Proto == "tcp" && s.State == harness.TCPListen && s.LPort == 34010 {
					return nil
				}
			}
			return errors.New("relay 34010 not listening")
		})
		if err != nil {
			t.Errorf("--autostart did not turn capture on: %v", err)
		}
		if code := harness.QuitCode(env.Exe); code != 0 {
			t.Errorf("ashgate quit returned %d", code)
		}
		harness.EnsureQuit(env.Exe)
		_ = os.Remove(filepath.Join(harness.ProgramData(), "resume-capture"))
	})

	t.Run("ReinstallKeepsSubscription", func(t *testing.T) {
		fx, err := harness.StartFixture(env)
		if err != nil {
			t.Fatal(err)
		}
		defer fx.Close()
		a := harness.Launch(t, env, env.Exe, harness.LaunchOpts{})
		harness.AddSubscription(t, a, fx)
		client := env.ClientExe(t, harness.ClientProxied)
		// A kill-switch rule, so the uninstall below has firewall rules to remove.
		harness.SetRules(t, a, map[string]string{client: harness.SubName},
			map[string]harness.RuleOpts{client: {KillSwitch: harness.Bool(true)}})
		before := readConfig(t)
		a.Quit()

		// Same version again, now with the desktop icon task.
		harness.Install(t, env, env.Setup, "/TASKS=desktopicon")
		if !exists(desktopLink()) {
			t.Errorf("desktop shortcut missing after /TASKS=desktopicon")
		}
		after := readConfig(t)
		if !reflect.DeepEqual(subOf(before), subOf(after)) {
			t.Errorf("subscription changed by the reinstall:\nbefore %+v\nafter  %+v", subOf(before), subOf(after))
		}
		a = harness.Launch(t, env, env.Exe, harness.LaunchOpts{})
		s := a.MustState()
		if v := s.Subs[harness.SubName]; v.Servers != 2 {
			t.Errorf("after reinstall the subscription lists %d servers, want 2 (%+v)", v.Servers, v)
		}
		a.Quit()
		plain, err := secret.Open(subOf(after).Sealed)
		if err != nil {
			t.Fatalf("sealed subscription does not open after reinstall: %v", err)
		}
		var sec subs.Secret
		if err := json.Unmarshal(plain, &sec); err != nil || sec.URL != fx.SubURL || len(sec.Links) != 2 {
			t.Errorf("sealed subscription content changed (url ok: %v, links %d, err %v)", sec.URL == fx.SubURL, len(sec.Links), err)
		}
	})

	t.Run("Uninstall", func(t *testing.T) {
		harness.EnsureQuit(env.Exe)
		// Preconditions, so the uninstall really has something to clean.
		err := harness.Eventually(40*time.Second, time.Second, func() error {
			r, err := harness.FirewallRules("Ashgate kill switch")
			if err != nil || len(r) == 0 {
				return fmt.Errorf("no kill-switch firewall rules yet (%v)", err)
			}
			return nil
		})
		if err != nil {
			t.Logf("precondition: %v", err)
		}
		if harness.TaskXML("Ashgate") == "" {
			t.Logf("precondition: no autostart task before uninstall")
		}
		harness.Uninstall(t, env)
		checkNothingLeft(t, env)
	})

	t.Run("UpgradeFromPrevious", func(t *testing.T) {
		if env.SetupPrev == "" {
			env.Note("skipped", "upgrade: no previous Setup.exe (no published release and no previous version to build)")
			t.Skip("no previous release")
		}
		testUpgrade(t, env)
	})
}

var errSimulationFailed = errors.New("the runtime was not hidden")

func checkSettingsACL(t *testing.T, env *harness.Env) {
	t.Helper()
	allowed := harness.AllowedReaders()
	for _, p := range []string{harness.ProgramData(), harness.ConfigPath()} {
		owner, aces, err := harness.DACL(p)
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		env.WriteJSON(filepath.Join("install", "acl-"+filepath.Base(p)+".json"), map[string]any{"owner": owner, "aces": aces})
		for _, a := range harness.ReadersBeyond(aces, allowed) {
			t.Errorf("%s is readable by %s (%s, mask %#x); only SYSTEM, Administrators and the installing user may read it",
				p, a.Account, a.SID, a.Mask)
		}
	}
	u, err := harness.NewOtherUser(env)
	if err != nil {
		t.Logf("other user: %v", err)
		return
	}
	defer u.Delete()
	client := env.ClientExe(t, harness.ClientProxied)
	r, err := u.RunAs(client, "read", "-path", harness.ConfigPath())
	if err != nil {
		env.Note("skipped", "settings ACL as another user: "+err.Error())
		t.Logf("run as other user: %v", err)
		return
	}
	if r.OK {
		t.Errorf("a standard user read config.json (%d bytes)", r.Bytes)
	}
}

type taskXML struct {
	Triggers struct {
		Logon struct {
			Enabled string `xml:"Enabled"`
			UserID  string `xml:"UserId"`
		} `xml:"LogonTrigger"`
	} `xml:"Triggers"`
	Principals struct {
		P struct {
			UserID    string `xml:"UserId"`
			LogonType string `xml:"LogonType"`
			RunLevel  string `xml:"RunLevel"`
		} `xml:"Principal"`
	} `xml:"Principals"`
	Settings struct {
		Limit       string `xml:"ExecutionTimeLimit"`
		NoBattery   string `xml:"DisallowStartIfOnBatteries"`
		StopBattery string `xml:"StopIfGoingOnBatteries"`
		Hidden      string `xml:"Hidden"`
		Enabled     string `xml:"Enabled"`
	} `xml:"Settings"`
	Actions struct {
		Exec struct {
			Command   string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Exec"`
	} `xml:"Actions"`
}

func checkTask(t *testing.T, env *harness.Env, x string) {
	t.Helper()
	if i := strings.Index(x, "?>"); strings.HasPrefix(strings.TrimSpace(x), "<?xml") && i > 0 {
		x = x[i+2:]
	}
	var task taskXML
	if err := xml.Unmarshal([]byte(x), &task); err != nil {
		t.Fatalf("task xml: %v", err)
	}
	u, _ := windows.GetCurrentProcessToken().GetTokenUser()
	sid := u.User.Sid.String()
	acct, _, _, _ := u.User.Sid.LookupAccount("")
	me := func(id string) bool {
		return strings.EqualFold(id, sid) || strings.HasSuffix(strings.ToLower(id), strings.ToLower(acct))
	}
	p := task.Principals.P
	checks := []struct {
		ok   bool
		what string
	}{
		{me(task.Triggers.Logon.UserID), "logon trigger for the current user, got " + task.Triggers.Logon.UserID},
		{task.Triggers.Logon.Enabled != "false", "logon trigger enabled"},
		{me(p.UserID), "principal is the current user, got " + p.UserID},
		{p.LogonType == "InteractiveToken", "LogonType InteractiveToken, got " + p.LogonType},
		{p.RunLevel == "HighestAvailable", "RunLevel HighestAvailable (administrator), got " + p.RunLevel},
		{task.Settings.Limit == "PT0S", "no execution time limit, got " + task.Settings.Limit},
		{task.Settings.NoBattery == "false", "allowed on battery"},
		{task.Settings.StopBattery == "false", "not stopped on battery"},
		{task.Settings.Hidden != "true", "task not hidden"},
		{task.Settings.Enabled != "false", "task enabled"},
		{strings.EqualFold(strings.Trim(task.Actions.Exec.Command, `"`), env.Exe), "runs " + env.Exe + ", got " + task.Actions.Exec.Command},
		{strings.Contains(task.Actions.Exec.Arguments, "--autostart"), "passes --autostart, got " + task.Actions.Exec.Arguments},
	}
	for _, c := range checks {
		if !c.ok {
			t.Errorf("autostart task: want %s", c.what)
		}
	}
}

func checkNothingLeft(t *testing.T, env *harness.Env) {
	t.Helper()
	left := func(what string) { t.Errorf("left after uninstall: %s", what) }
	if exists(env.InstallDir) {
		var names []string
		_ = filepath.Walk(env.InstallDir, func(p string, _ os.FileInfo, _ error) error {
			names = append(names, p)
			return nil
		})
		left(env.InstallDir + " " + strings.Join(names, ", "))
	}
	if exists(startMenuLink()) {
		left(startMenuLink())
	}
	if exists(desktopLink()) {
		left(desktopLink())
	}
	if harness.TaskXML("Ashgate") != "" {
		left(`scheduled task \Ashgate`)
	}
	for _, svc := range []string{"Ashgate", "WinDivert"} {
		if st := harness.ServiceState(svc); st != "" {
			left("service " + svc + " (" + st + ")")
		}
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\WinDivert`, registry.QUERY_VALUE); err == nil {
		k.Close()
		left(`HKLM\SYSTEM\CurrentControlSet\Services\WinDivert`)
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, uninstallKey, registry.QUERY_VALUE); err == nil {
		k.Close()
		left("uninstall registry entry")
	}
	if r, _ := harness.FirewallRules("Ashgate kill switch"); len(r) > 0 {
		left(fmt.Sprintf("%d firewall rules \"Ashgate kill switch\"", len(r)))
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager`, registry.QUERY_VALUE); err == nil {
		if v, _, err := k.GetStringsValue("PendingFileRenameOperations"); err == nil {
			for _, s := range v {
				if strings.Contains(strings.ToLower(s), `\ashgate\`) {
					left("pending delete at reboot: " + s)
				}
			}
		}
		k.Close()
	}
	if pids := harness.PIDsByName("ashgate.exe"); len(pids) > 0 {
		left(fmt.Sprintf("ashgate.exe processes %v", pids))
	}
	if la := os.Getenv("LOCALAPPDATA"); la != "" && exists(filepath.Join(la, "Ashgate")) {
		left(filepath.Join(la, "Ashgate") + " (WebView2 profile)")
	}
	// Settings are kept on purpose (README, installer.iss).
	if exists(harness.ProgramData()) {
		env.Note("info", "uninstall kept "+harness.ProgramData()+" (settings, by design)")
	}
}

func readConfig(t *testing.T) *configT {
	t.Helper()
	b, err := os.ReadFile(harness.ConfigPath())
	if err != nil {
		t.Fatalf("config.json: %v", err)
	}
	var c configT
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("config.json: %v", err)
	}
	return &c
}

func subOf(c *configT) subscriptionT {
	for _, p := range c.Proxies {
		if p.Name == harness.SubName && p.Sub != nil {
			return *p.Sub
		}
	}
	return subscriptionT{}
}
