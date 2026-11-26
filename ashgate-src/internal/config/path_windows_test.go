//go:build windows

package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// config.json keeps proxy passwords and VLESS keys in plain text: the
// shared folder must not let Users, Everyone or Authenticated Users read it.
func TestSharedDirIsNotReadableByEveryone(t *testing.T) {
	sddl := sharedDirSDDL + ownerReadACE()
	for _, group := range []string{";;;BU)", ";;;WD)", ";;;AU)", ";;;IU)"} {
		if strings.Contains(sddl, group) {
			t.Errorf("shared folder SDDL grants %s: %s", strings.Trim(group, ";)"), sddl)
		}
	}
	if ownerReadACE() == "" {
		t.Fatal("no entry for the current user")
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatalf("SDDL %s: %v", sddl, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		t.Fatalf("sharedDirSDDL missing owner: owner=%v err=%v", owner, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("sharedDirSDDL missing DACL: dacl=%v err=%v", dacl, err)
	}
}

func TestSharedPathUsesKnownFolder(t *testing.T) {
	t.Setenv("ProgramData", "")
	got := sharedPath()
	if !filepath.IsAbs(got) {
		t.Fatalf("sharedPath = %q, want absolute path", got)
	}
	wantSuffix := filepath.Join("Ashgate", "config.json")
	if !strings.HasSuffix(strings.ToLower(got), strings.ToLower(wantSuffix)) {
		t.Fatalf("sharedPath = %q, want suffix %q", got, wantSuffix)
	}
}

func TestCheckNotReparsePoint(t *testing.T) {
	base := t.TempDir()
	realDir := filepath.Join(base, "real")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Run("normal", func(t *testing.T) {
		if err := checkNotReparsePoint(realDir); err != nil {
			t.Fatalf("normal directory rejected: %v", err)
		}
	})
	t.Run("missing", func(t *testing.T) {
		missing := filepath.Join(base, "does-not-exist")
		if err := checkNotReparsePoint(missing); err == nil {
			t.Fatal("missing path accepted by checkNotReparsePoint")
		}
	})
	t.Run("junction", func(t *testing.T) {
		junction := filepath.Join(base, "junction")
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, realDir).CombinedOutput(); err != nil {
			t.Skipf("mklink /J unavailable: %v (%s)", err, strings.TrimSpace(string(out)))
		}
		if err := checkNotReparsePoint(junction); err == nil {
			t.Fatal("NTFS junction accepted by checkNotReparsePoint")
		}
	})
}

func TestSecureDirNonSharedIsNoOp(t *testing.T) {
	if err := secureDir(t.TempDir()); err != nil {
		t.Fatalf("secureDir on non-shared dir returned error: %v", err)
	}
}

func TestSecureHandleRefusesNilDACLAndJunction(t *testing.T) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sddl := "O:" + u.User.Sid.String() + "D:PAI(A;OICI;FA;;;" + u.User.Sid.String() + ")"
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		t.Fatalf("owner: %v %v", owner, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("dacl: %v %v", dacl, err)
	}

	base := t.TempDir()
	realDir := filepath.Join(base, "real")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	filePath := filepath.Join(realDir, "config.json")
	if err := os.WriteFile(filePath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Must never allow a nil DACL (which grants Everyone Full Control on Windows).
	if err := secureHandle(filePath, owner, nil, false); err == nil {
		t.Fatal("secureHandle accepted nil DACL")
	}
	if err := secureHandle(filePath, nil, dacl, false); err == nil {
		t.Fatal("secureHandle accepted nil owner")
	}

	// Normal directory + file tree (including a deep leftover WebView2 cache
	// tree that exceeds normal nesting) succeeds without recursing into WebView2.
	deepWV := filepath.Join(realDir, "WebView2", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j")
	if err := os.MkdirAll(deepWV, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deepWV, "cache.dat"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := secureTree(realDir, owner, dacl, 0); err != nil {
		t.Fatalf("secureTree on normal dir failed: %v", err)
	}

	// NTFS junction must be refused by both secureHandle and secureTree.
	junction := filepath.Join(base, "junction")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, realDir).CombinedOutput(); err != nil {
		t.Skipf("mklink /J unavailable: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	if err := secureHandle(junction, owner, dacl, true); err == nil {
		t.Fatal("secureHandle accepted NTFS junction")
	}
	childJunction := filepath.Join(realDir, "evil")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", childJunction, base).CombinedOutput(); err != nil {
		t.Skipf("mklink /J unavailable: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	if err := secureTree(realDir, owner, dacl, 0); err == nil {
		t.Fatal("secureTree accepted child NTFS junction")
	}
}
