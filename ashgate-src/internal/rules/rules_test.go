package rules

import (
	"testing"

	"ashgate/internal/config"
)

func TestMatchOrderAndShape(t *testing.T) {
	off := false
	on := true
	set := Compile([]config.Rule{
		{Enabled: &off, Process: "curl.exe", Action: "direct"},
		{Enabled: &on, Process: "curl.exe", Action: "proxy", Proxy: "second"},
		{Enabled: &on, Process: `C:/Program Files/Mozilla Firefox/firefox.exe`, Action: "direct"},
	})
	curl := Process{PID: 10, Name: "curl.exe", Path: `C:\Windows\System32\curl.exe`}
	if d := set.Match(curl); d.Action != "proxy" || d.Proxy != "second" {
		t.Fatalf("disabled first rule should be skipped, got %+v", d)
	}
	full := Process{PID: 11, Name: "firefox.exe", Path: `C:\Program Files\Mozilla Firefox\firefox.exe`}
	if d := set.Match(full); d.Action != "direct" || d.RuleIndex != 2 {
		t.Fatalf("full path: %+v", d)
	}
	other := Process{PID: 12, Name: "firefox.exe", Path: `D:\firefox.exe`}
	if d := set.Match(other); d.Action != "" {
		t.Fatalf("different path must not match a full-path rule, got %+v", d)
	}
	notCurl := Process{Name: "notcurl.exe", Path: `C:\notcurl.exe`}
	if d := set.Match(notCurl); d.Action != "" {
		t.Fatalf("prefix name matched: %+v", d)
	}
	upper := Process{Name: "CURL.EXE", Path: `\\?\C:\Windows\System32\CURL.EXE`}
	if d := set.Match(upper); d.Action != "proxy" || d.Proxy != "second" {
		t.Fatalf("case/prefix: %+v", d)
	}
	if d := set.Match(Process{Path: `C:\Windows\System32\curl.exe`}); d.Proxy != "second" {
		t.Fatalf("name from path: %+v", d)
	}
}

func TestBase(t *testing.T) {
	if got := Base(`\\?\C:\Windows\System32\curl.exe`); got != "curl.exe" {
		t.Fatal(got)
	}
	if IsPath("curl.exe") {
		t.Fatal("bare name detected as path")
	}
	if !IsPath(`C:\curl.exe`) || !IsPath("bin/curl.exe") {
		t.Fatal("path not detected")
	}
	if !IsSystemDNS("svchost.exe") || IsSystemDNS("curl.exe") {
		t.Fatal("svchost")
	}
}

func TestBareNameMatchesExe(t *testing.T) {
	s := Compile([]config.Rule{{Process: "Chrome", Action: "direct"}})
	if d := s.Match(Process{Name: "chrome.exe"}); d.Action != "direct" {
		t.Fatalf("bare name did not match: %+v", d)
	}
	if d := s.Match(Process{Name: "chrome2.exe"}); d.Action != "" {
		t.Fatalf("matched another program: %+v", d)
	}
}

func TestChildInheritsParentRule(t *testing.T) {
	off := false
	s := Compile([]config.Rule{
		{Process: "code.exe", Action: "proxy", Proxy: "v"},
		{Process: "git.exe", Action: "direct"},
		{Process: "steam.exe", Action: "proxy", Proxy: "v", Children: &off},
		{Process: "explorer.exe", Action: "proxy", Proxy: "v"},
	})
	code := Process{PID: 10, Name: "code.exe"}
	explorer := Process{PID: 2, Name: "explorer.exe"}
	node := Process{PID: 11, Name: "node.exe", Parents: []Process{{PID: 12, Name: "electron-helper.exe"}, code, explorer}}
	if d := s.Match(node); d.Action != "proxy" || d.Parent != "code.exe" {
		t.Fatalf("grandchild did not inherit: %+v", d)
	}
	git := Process{Name: "git.exe", Parents: []Process{code}}
	if d := s.Match(git); d.Action != "direct" || d.Parent != "" {
		t.Fatalf("own rule must win: %+v", d)
	}
	game := Process{Name: "game.exe", Parents: []Process{{Name: "steam.exe"}}}
	if d := s.Match(game); d.Action != "" {
		t.Fatalf("children switched off: %+v", d)
	}
	desktop := Process{Name: "notepad.exe", Parents: []Process{explorer}}
	if d := s.Match(desktop); d.Action != "" {
		t.Fatalf("rule spread through explorer: %+v", d)
	}
}

func TestWildcardMask(t *testing.T) {
	s := Compile([]config.Rule{{Process: `*\Discord\app-*\Discord.exe`, Action: "direct"}})
	if d := s.Match(Process{Name: "Discord.exe", Path: `C:\Users\u\AppData\Local\Discord\app-1.0.9187\Discord.exe`}); d.Action != "direct" {
		t.Fatalf("mask did not match: %+v", d)
	}
	if d := s.Match(Process{Name: "Discord.exe", Path: `C:\Other\Discord.exe`}); d.Action != "" {
		t.Fatalf("mask matched another folder: %+v", d)
	}
	for _, c := range []struct {
		p, s string
		ok   bool
	}{{"a*b", "ab", true}, {"a*b", "axxb", true}, {"a*b", "axxbc", false}, {"*", "", true}, {"a?c", "abc", true}, {"*\\x.exe", "c:\\x.exe", true}} {
		if Glob(c.p, c.s) != c.ok {
			t.Fatalf("Glob(%q, %q) != %v", c.p, c.s, c.ok)
		}
	}
}

func TestGroupAndKillSwitchSettings(t *testing.T) {
	off, on := false, true
	cfg := &config.Config{
		KillSwitch: true,
		Groups:     []config.Group{{Name: "Мессенджеры", Enabled: &on, Action: "proxy", Proxy: "v"}, {Name: "Off", Enabled: &off, Action: "direct"}},
		Rules: []config.Rule{
			{Process: "telegram.exe", Action: "direct", Group: "Мессенджеры", TCPOnly: true},
			{Process: "steam.exe", Action: "proxy", Proxy: "v", Group: "Off"},
			{Process: "curl.exe", Action: "proxy", Proxy: "v", KillSwitch: &off},
		},
	}
	s := Compile(cfg.EffectiveRules())
	if d := s.Match(Process{Name: "telegram.exe"}); d.Action != "proxy" || d.Proxy != "v" || !d.KillSwitch || !d.TCPOnly {
		t.Fatalf("group route or settings lost: %+v", d)
	}
	if d := s.Match(Process{Name: "steam.exe"}); d.Action != "" {
		t.Fatalf("disabled group still matched: %+v", d)
	}
	if d := s.Match(Process{Name: "curl.exe"}); d.KillSwitch {
		t.Fatalf("rule override ignored: %+v", d)
	}
}

func TestMaskSkipsServiceHost(t *testing.T) {
	s := Compile([]config.Rule{
		{Process: "svc*", Action: "proxy", Proxy: "v"},
		{Process: "svchost.exe", Action: "proxy", Proxy: "v"},
	})
	if d := s.Match(Process{Name: "svchost.exe", Path: `C:\Windows\System32\svchost.exe`}); d.Action != "" {
		t.Fatalf("rule caught svchost: %+v", d)
	}
}

func TestGlobUTF8QuestionMark(t *testing.T) {
	if !Glob("п?ивет", "привет") {
		t.Fatal("? did not match 2-byte UTF-8 rune")
	}
	if Glob("п?вет", "привет") {
		t.Fatal("? matched two runes")
	}
}

func TestShellOrSystemDoesNotInheritParentRule(t *testing.T) {
	s := Compile([]config.Rule{{Process: "code.exe", Action: "proxy", Proxy: "v"}})
	p := Process{Name: "explorer.exe", Parents: []Process{{Name: "code.exe"}}}
	if d := s.Match(p); d.Action != "" {
		t.Fatalf("shell process inherited parent rule: %+v", d)
	}
}

func TestVersionMask(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{`C:\Users\u\AppData\Local\Discord\app-1.0.9187\Discord.exe`, `C:\Users\u\AppData\Local\Discord\app-*\Discord.exe`, true},
		{`D:/Games/Slack/app-4.36.140/slack.exe`, `D:/Games/Slack/app-*/slack.exe`, true},
		{`C:\Program Files\App\app-1.0\bin\app.exe`, `C:\Program Files\App\app-*\bin\app.exe`, true},
		{`C:\Apps\Thing\app-1.0\app-2.0\thing.exe`, `C:\Apps\Thing\app-*\app-*\thing.exe`, true},
		{`C:\Program Files\App\App.exe`, "", false},
		{`C:\Apps\appdata-1\App.exe`, "", false},
		{`*\Discord\app-*\Discord.exe`, "", false},
		{`discord`, "", false},
		{`C:\Apps\app-\App.exe`, "", false},
	}
	for _, c := range cases {
		got, ok := VersionMask(c.in)
		if got != c.want || ok != c.ok {
			t.Fatalf("VersionMask(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestCompanionByFolder(t *testing.T) {
	s := Compile([]config.Rule{{Process: `C:\LDPlayer\LDPlayer9\dnplayer.exe`, Action: "proxy", Proxy: "v"}})
	// A service started the network process: no ancestor in the app's tree.
	head := Process{Name: "Ld9BoxHeadless.exe", Path: `C:\LDPlayer\LDPlayer9\Ld9BoxHeadless.exe`}
	if d := s.Match(head); d.Action != "proxy" || d.Parent != "dnplayer.exe" {
		t.Fatalf("companion in the install folder: %+v", d)
	}
	sub := Process{Name: "engine.exe", Path: `C:\LDPlayer\LDPlayer9\bin\engine.exe`}
	if d := s.Match(sub); d.Action != "proxy" {
		t.Fatalf("companion in a subfolder: %+v", d)
	}
	if d := s.Match(Process{Name: "other.exe", Path: `C:\LDPlayer\LDPlayer9x\other.exe`}); d.Action != "" {
		t.Fatalf("prefix of a folder name matched: %+v", d)
	}
	if d := s.Match(Process{Name: "other.exe", Path: `C:\Other\other.exe`}); d.Action != "" {
		t.Fatalf("unrelated folder matched: %+v", d)
	}
}

func TestCompanionRespectsChildrenSwitch(t *testing.T) {
	off := false
	s := Compile([]config.Rule{{Process: `C:\LDPlayer\LDPlayer9\dnplayer.exe`, Action: "proxy", Proxy: "v", Children: &off}})
	if d := s.Match(Process{Name: "Ld9BoxHeadless.exe", Path: `C:\LDPlayer\LDPlayer9\Ld9BoxHeadless.exe`}); d.Action != "" {
		t.Fatalf("children off still covered a companion: %+v", d)
	}
}

func TestCompanionByFamily(t *testing.T) {
	s := Compile([]config.Rule{{Process: "dnplayer", Action: "proxy", Proxy: "v"}})
	head := Process{Name: "Ld9BoxHeadless.exe", Path: `D:\Somewhere\Ld9BoxHeadless.exe`}
	if d := s.Match(head); d.Action != "proxy" || d.Parent != "dnplayer.exe" {
		t.Fatalf("family companion: %+v", d)
	}
	if d := s.Match(Process{Name: "chrome.exe", Path: `D:\Somewhere\chrome.exe`}); d.Action != "" {
		t.Fatalf("family caught another program: %+v", d)
	}
	if got := Family("Ld9BoxHeadless.exe"); got != "ldplayer" {
		t.Fatalf("Family = %q", got)
	}
	if got := Family(`C:\Program Files\BlueStacks_nxt\HD-Player.exe`); got != "bluestacks" {
		t.Fatalf("Family = %q", got)
	}
	if got := Family("curl.exe"); got != "" {
		t.Fatalf("Family of curl = %q", got)
	}
}

func TestCompanionSharedRoots(t *testing.T) {
	// A rule naming an exe straight in Program Files names no folder of its own.
	s := Compile([]config.Rule{{Process: `C:\Program Files\tool.exe`, Action: "proxy", Proxy: "v"}})
	if d := s.Match(Process{Name: "neighbour.exe", Path: `C:\Program Files\neighbour.exe`}); d.Action != "" {
		t.Fatalf("shared root covered a neighbour: %+v", d)
	}
	// Nor does a portable exe in Downloads or on the Desktop.
	for _, dir := range []string{`C:\Users\me\Downloads`, `C:\Users\me\Desktop`, `C:\Users\me\Documents`} {
		s := Compile([]config.Rule{{Process: dir + `\portable.exe`, Action: "proxy", Proxy: "v"}})
		if d := s.Match(Process{Name: "other.exe", Path: dir + `\other.exe`}); d.Action != "" {
			t.Fatalf("%s covered a neighbour: %+v", dir, d)
		}
	}
}

func TestCompanionSkipsSystem(t *testing.T) {
	s := Compile([]config.Rule{{Process: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, Action: "proxy", Proxy: "v"}})
	// services.exe is not matched itself, and the folder rule must not catch it.
	if d := s.Match(Process{Name: "services.exe", Path: `C:\Windows\System32\services.exe`}); d.Action != "" {
		t.Fatalf("system process caught by folder: %+v", d)
	}
	// A sibling in the same System32 subfolder is a real companion.
	if d := s.Match(Process{Name: "helper.exe", Path: `C:\Windows\System32\WindowsPowerShell\v1.0\helper.exe`}); d.Action != "proxy" {
		t.Fatalf("folder companion in System32 subfolder: %+v", d)
	}
}

func TestAncestorWinsOverFolder(t *testing.T) {
	s := Compile([]config.Rule{
		{Process: `C:\Games\Launcher\launcher.exe`, Action: "proxy", Proxy: "ancestor"},
		{Process: `C:\Games\Launcher\other.exe`, Action: "direct"},
	})
	// other.exe's rule names the same folder; the process is started by
	// launcher.exe, so the ancestor's rule decides first.
	game := Process{Name: "game.exe", Path: `C:\Games\Launcher\game.exe`, Parents: []Process{{Name: "launcher.exe", Path: `C:\Games\Launcher\launcher.exe`}}}
	if d := s.Match(game); d.Action != "proxy" || d.Proxy != "ancestor" || d.Parent != "launcher.exe" {
		t.Fatalf("ancestor did not win: %+v", d)
	}
}

func TestCompanionDirOfMask(t *testing.T) {
	// A mask names the folder before its first wildcard: …\Discord.
	s := Compile([]config.Rule{{Process: `C:\Users\u\AppData\Local\Discord\app-*\Discord.exe`, Action: "proxy", Proxy: "v"}})
	helper := Process{Name: "DiscordHelper.exe", Path: `C:\Users\u\AppData\Local\Discord\DiscordHelper.exe`}
	if d := s.Match(helper); d.Action != "proxy" {
		t.Fatalf("mask folder companion: %+v", d)
	}
	if d := s.Match(Process{Name: "x.exe", Path: `C:\Users\u\AppData\Local\Other\x.exe`}); d.Action != "" {
		t.Fatalf("mask folder too wide: %+v", d)
	}
}
