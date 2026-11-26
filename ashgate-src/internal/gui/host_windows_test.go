//go:build windows

package gui

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"
)

func TestOpenRelRootAndMkdirAllUnderRoot(t *testing.T) {
	base := t.TempDir()
	rel := filepath.Join("Ashgate", "WebView2")
	if err := mkdirAllUnderRoot(base, rel); err != nil {
		t.Fatalf("mkdirAllUnderRoot normal: %v", err)
	}
	full := filepath.Join(base, rel)
	if st, err := os.Stat(full); err != nil || !st.IsDir() {
		t.Fatalf("created dir missing: st=%v err=%v", st, err)
	}
	// Idempotent on existing directories.
	if err := mkdirAllUnderRoot(base, rel); err != nil {
		t.Fatalf("mkdirAllUnderRoot second call: %v", err)
	}
	root, err := openRelRoot(full)
	if err != nil {
		t.Fatalf("openRelRoot normal: %v", err)
	}
	_ = root.Close()

	// Reject UNC paths.
	if _, err := openRelRoot(`\\127.0.0.1\share\Ashgate`); err == nil {
		t.Fatal("openRelRoot accepted UNC path")
	}

	// Real NTFS junction tests: neither openRelRoot, mkdirAllUnderRoot, nor
	// removeWebViewInBase may traverse or delete a junction target.
	victim := t.TempDir()
	victimFile := filepath.Join(victim, "keep.txt")
	if err := os.WriteFile(victimFile, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("junction on Ashgate", func(t *testing.T) {
		jBase := t.TempDir()
		jAsh := filepath.Join(jBase, "Ashgate")
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", jAsh, victim).CombinedOutput(); err != nil {
			t.Skipf("mklink /J unavailable: %v (%s)", err, strings.TrimSpace(string(out)))
		}
		if _, err := openRelRoot(jAsh); err == nil {
			t.Fatal("openRelRoot traversed junction on Ashgate")
		}
		if err := mkdirAllUnderRoot(jBase, filepath.Join("Ashgate", "WebView2")); err == nil {
			t.Fatal("mkdirAllUnderRoot traversed junction on Ashgate")
		}
		removeWebViewInBase(jBase)
		if _, err := os.Stat(victimFile); err != nil {
			t.Fatalf("victim file deleted via Ashgate junction: %v", err)
		}
	})

	t.Run("junction on WebView2", func(t *testing.T) {
		jBase := t.TempDir()
		jAsh := filepath.Join(jBase, "Ashgate")
		if err := os.MkdirAll(jAsh, 0o700); err != nil {
			t.Fatal(err)
		}
		jWV := filepath.Join(jAsh, "WebView2")
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", jWV, victim).CombinedOutput(); err != nil {
			t.Skipf("mklink /J unavailable: %v (%s)", err, strings.TrimSpace(string(out)))
		}
		if err := mkdirAllUnderRoot(jBase, filepath.Join("Ashgate", "WebView2")); err == nil {
			t.Fatal("mkdirAllUnderRoot traversed junction on WebView2")
		}
		removeWebViewInBase(jBase)
		if _, err := os.Stat(victimFile); err != nil {
			t.Fatalf("victim file deleted via WebView2 junction: %v", err)
		}
	})

	t.Run("junction on ancestor base", func(t *testing.T) {
		parent := t.TempDir()
		targetBase := filepath.Join(parent, "target")
		if err := os.MkdirAll(filepath.Join(targetBase, "Ashgate", "WebView2"), 0o700); err != nil {
			t.Fatal(err)
		}
		keep := filepath.Join(targetBase, "Ashgate", "WebView2", "keep.txt")
		if err := os.WriteFile(keep, []byte("stay"), 0o600); err != nil {
			t.Fatal(err)
		}
		jBase := filepath.Join(parent, "linkbase")
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", jBase, targetBase).CombinedOutput(); err != nil {
			t.Skipf("mklink /J unavailable: %v (%s)", err, strings.TrimSpace(string(out)))
		}
		removeWebViewInBase(jBase)
		if _, err := os.Stat(keep); err != nil {
			t.Fatalf("target deleted through ancestor junction: %v", err)
		}
	})

	t.Run("normal removeWebViewInBase deletes WebView2 and empty Ashgate", func(t *testing.T) {
		nBase := t.TempDir()
		wv := filepath.Join(nBase, "Ashgate", "WebView2")
		if err := os.MkdirAll(filepath.Join(wv, "EBWebView"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(wv, "EBWebView", "cache.dat"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		removeWebViewInBase(nBase)
		if _, err := os.Stat(filepath.Join(nBase, "Ashgate")); !os.IsNotExist(err) {
			t.Fatalf("expected Ashgate dir removed, stat err = %v", err)
		}
	})
}

func TestIsUnderProgramFiles(t *testing.T) {
	for _, bad := range []string{
		"",
		`relative\path`,
		`\\127.0.0.1\Program Files\Microsoft`,
		`C:\Users\alice\AppData\Local\Microsoft\EdgeWebView\Application\1.0`,
		`C:\Program Files`,
		`C:\Program Files Evil\Microsoft`,
		`C:\Program Files (x86)Evil\Microsoft`,
		`C:\Temp\WebView2`,
	} {
		if isUnderProgramFiles(bad) {
			t.Errorf("isUnderProgramFiles(%q) = true, want false", bad)
		}
	}
	if !isUnderProgramFiles(`C:\Program Files (x86)\Microsoft\EdgeWebView\Application\1.0`) &&
		!isUnderProgramFiles(`C:\Program Files\Microsoft\EdgeWebView\Application\1.0`) {
		t.Error("expected Program Files path to be accepted")
	}
}

func TestSystemWebView2DirFindsInstalledRuntime(t *testing.T) {
	dir, err := systemWebView2Dir()
	if err != nil {
		t.Skipf("no machine-wide WebView2 Runtime in HKLM on this host: %v", err)
	}
	if !isUnderProgramFiles(dir) {
		t.Fatalf("systemWebView2Dir returned non-ProgramFiles path: %q", dir)
	}
	if !noAncestorReparse(dir) {
		t.Fatalf("systemWebView2Dir returned path with reparse point: %q", dir)
	}
	dll := filepath.Join(dir, "EBWebView", webViewArch(), "EmbeddedBrowserWebView.dll")
	if _, err := os.Stat(dll); err != nil {
		t.Fatalf("EmbeddedBrowserWebView.dll missing at %q: %v", dll, err)
	}
}

func TestPolicyMatchesAppAndMissingKey(t *testing.T) {
	for _, tc := range []struct {
		val, exe string
		want     bool
	}{
		{"*", "ashgate.exe", true},
		{"ashgate.exe", "ashgate.exe", true},
		{"Ashgate.EXE", "other.exe", true},
		{"custom.exe", "custom.exe", true},
		{"notepad.exe", "ashgate.exe", false},
		{"", "ashgate.exe", false},
	} {
		if got := policyMatchesApp(tc.val, tc.exe); got != tc.want {
			t.Errorf("policyMatchesApp(%q, %q) = %v, want %v", tc.val, tc.exe, got, tc.want)
		}
	}
	// Missing policy key must succeed cleanly.
	if err := checkWebViewPolicyKey(registry.CURRENT_USER, `Software\AshgateTestNonExistentPolicyKey_9f8a7b`, "ashgate.exe"); err != nil {
		t.Fatalf("missing key returned error: %v", err)
	}
}
