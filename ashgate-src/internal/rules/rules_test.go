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
