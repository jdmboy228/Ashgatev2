package process

import (
	"bytes"
	"image/png"
	"os"
	"runtime"
	"testing"
)

func TestIsLocalExePath(t *testing.T) {
	valid := []string{
		`C:\Windows\notepad.exe`,
		`d:\Games\App.EXE`,
		`  C:\a.exe  `,
	}
	for _, p := range valid {
		if !IsLocalExePath(p) {
			t.Errorf("IsLocalExePath(%q) = false, want true", p)
		}
	}

	invalid := []string{
		"",
		"   ",
		`\\attacker\share\app.exe`,
		`//attacker/share/app.exe`,
		`\\?\C:\Windows\notepad.exe`,
		`\\?\UNC\attacker\share\app.exe`,
		`notepad.exe`,
		`..\notepad.exe`,
		`C:notepad.exe`,
		`C:/Windows/notepad.exe`,
		`C:\.exe`,
		`C:\dir\.exe`,
		`C:\dir/.exe`,
		`C:\Windows\notepad.dll`,
		`C:\Windows\notepad.exe:stream`,
		"C:\\Windows\\note\x00pad.exe",
	}
	for _, p := range invalid {
		if IsLocalExePath(p) {
			t.Errorf("IsLocalExePath(%q) = true, want false", p)
		}
	}
}

func TestExeIconPNGRejectsNonLocalPaths(t *testing.T) {
	bad := []string{
		"",
		`\\192.0.2.1\share\app.exe`,
		`//192.0.2.1/share/app.exe`,
		`\\?\C:\Windows\notepad.exe`,
		`notepad.exe`,
		`C:notepad.exe`,
		`C:\dir\.exe`,
		`C:\Windows\notepad.dll`,
	}
	for _, p := range bad {
		if _, err := ExeIconPNG(p); err == nil {
			t.Errorf("ExeIconPNG(%q) succeeded, want error", p)
		}
	}
}

func TestExeIconPNGLiveWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only live icon test")
	}
	for _, p := range []string{
		`C:\Windows\System32\notepad.exe`,
		`C:\Windows\System32\curl.exe`,
	} {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("%s not present: %v", p, err)
		}
		data, err := ExeIconPNG(p)
		if err != nil {
			t.Fatalf("ExeIconPNG(%q): %v", p, err)
		}
		cfg, err := png.DecodeConfig(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("ExeIconPNG(%q) returned invalid PNG: %v", p, err)
		}
		if cfg.Width != 32 || cfg.Height != 32 {
			t.Fatalf("ExeIconPNG(%q) size = %dx%d, want 32x32", p, cfg.Width, cfg.Height)
		}
	}
}

func TestExeIconUnavailableOffWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has exe icons")
	}
	if _, err := ExeIconPNG(`C:\Windows\notepad.exe`); err == nil {
		t.Fatal("expected an error off Windows")
	}
}
