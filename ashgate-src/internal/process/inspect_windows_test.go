//go:build windows

package process

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectorSystemBinaryAndSelfCommandLine(t *testing.T) {
	ins := NewInspector()

	// CommandLine of the current test process must be readable with
	// PROCESS_QUERY_LIMITED_INFORMATION and contain our binary name.
	pid := uint32(os.Getpid())
	if raw, err := queryCommandLineErr(pid); err != nil || raw == "" {
		t.Fatalf("queryCommandLineErr(self=%d) = (%q, %v)", pid, raw, err)
	}
	cmd := ins.CommandLine(pid, 1)
	if cmd == "" {
		t.Fatal("CommandLine(self) returned empty string")
	}
	exe, err := os.Executable()
	if err == nil {
		base := strings.ToLower(strings.TrimSuffix(filepath.Base(exe), ".exe"))
		if !strings.Contains(strings.ToLower(cmd), base) {
			t.Errorf("CommandLine(self) = %q, expected to contain %q", cmd, base)
		}
	}
	// Cached repeat call must match.
	if again := ins.CommandLine(pid, 1); again != cmd {
		t.Errorf("cached CommandLine = %q, want %q", again, cmd)
	}

	// Standard Windows binary must have Microsoft PE metadata (and usually an
	// embedded or catalog signature — PE CompanyName is always present).
	cmdExe := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	if _, err := os.Stat(cmdExe); err == nil {
		meta := ins.FileMetadata(cmdExe)
		if !strings.Contains(strings.ToLower(meta.Company), "microsoft") {
			t.Errorf("FileMetadata(cmd.exe).Company = %q, want Microsoft", meta.Company)
		}
		if meta.Product == "" {
			t.Errorf("FileMetadata(cmd.exe).Product is empty")
		}
		// Cache hit check.
		if again := ins.FileMetadata(cmdExe); again != meta {
			t.Errorf("cached FileMetadata mismatch: %+v != %+v", again, meta)
		}
	}

	// Non-existent path must return zero value without panicking.
	if got := ins.FileMetadata(`C:\does-not-exist-ashgate\missing.exe`); got != (FileMeta{}) {
		t.Errorf("missing file FileMetadata = %+v, want zero", got)
	}
}
