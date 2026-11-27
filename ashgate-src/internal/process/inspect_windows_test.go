//go:build windows

package process

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func selfCreationTime(t *testing.T) int64 {
	t.Helper()
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("OpenProcess(self): %v", err)
	}
	defer windows.CloseHandle(h)
	var create, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &create, &exit, &kernel, &user); err != nil {
		t.Fatalf("GetProcessTimes(self): %v", err)
	}
	return create.Nanoseconds()
}

func TestInspectorSystemBinaryAndSelfCommandLine(t *testing.T) {
	ins := NewInspector()

	// CommandLine of the current test process must be readable with
	// PROCESS_QUERY_LIMITED_INFORMATION and contain our binary name.
	pid := uint32(os.Getpid())
	started := selfCreationTime(t)
	if raw, err := queryCommandLineErr(pid, 0); err != nil || raw == "" {
		t.Fatalf("queryCommandLineErr(self=%d, 0) = (%q, %v)", pid, raw, err)
	}
	if raw, err := queryCommandLineErr(pid, started); err != nil || raw == "" {
		t.Fatalf("queryCommandLineErr(self=%d, started) = (%q, %v)", pid, raw, err)
	}
	// Mismatched creation time (PID reuse guard) must reject the query.
	if raw, err := queryCommandLineErr(pid, started+int64(time.Minute)); err == nil || raw != "" {
		t.Fatalf("mismatched started should fail, got (%q, %v)", raw, err)
	}
	if _, err := queryCommandLineErr(4, 0); err == nil {
		t.Fatal("pid 4 should be rejected")
	}
	if _, err := queryCommandLineErr(0xFFFFFFFC, 0); err == nil {
		t.Fatal("nonexistent pid should fail")
	}

	cmd := ins.CommandLine(pid, started)
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
	if again := ins.CommandLine(pid, started); again != cmd {
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

	// Non-existent path and directory must return zero value without panicking.
	if got := ins.FileMetadata(`C:\does-not-exist-ashgate\missing.exe`); got != (FileMeta{}) {
		t.Errorf("missing file FileMetadata = %+v, want zero", got)
	}
	if got := ins.FileMetadata(t.TempDir()); got != (FileMeta{}) {
		t.Errorf("dir FileMetadata = %+v, want zero", got)
	}
}

func TestInspectorZeroValueAndConcurrency(t *testing.T) {
	// Zero-value Inspector must lazily initialize caches without panicking.
	var ins Inspector
	pid := uint32(os.Getpid())
	started := selfCreationTime(t)
	cmdExe := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")

	if got := ins.CommandLine(pid, started); got == "" {
		t.Fatal("zero-value Inspector.CommandLine returned empty")
	}

	// Verify concurrent reads/writes are race-free under -race.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_ = ins.CommandLine(pid, started)
				_ = ins.FileMetadata(cmdExe)
			}
		}()
	}
	wg.Wait()
}

func TestInspectorNoHandleLeaks(t *testing.T) {
	procGetHandleCount := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProcessHandleCount")
	getHandles := func() (uint32, bool) {
		var count uint32
		r1, _, _ := procGetHandleCount.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&count)))
		return count, r1 != 0
	}
	before, ok := getHandles()
	if !ok {
		t.Skip("GetProcessHandleCount unavailable")
	}
	pid := uint32(os.Getpid())
	cmdExe := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	// Call underlying uncached functions repeatedly to ensure every handle/store/msg is closed.
	for i := 0; i < 100; i++ {
		_, _ = queryCommandLineErr(pid, 0)
		_ = readAuthenticodeSigner(cmdExe)
		_, _, _ = readVersionStrings(cmdExe)
	}
	after, ok := getHandles()
	if !ok {
		t.Fatal("GetProcessHandleCount failed after loop")
	}
	// Allow small runtime noise, but 100 iterations would leak >=100 handles if broken.
	if after > before+25 {
		t.Fatalf("handle count grew from %d to %d after 100 inspections", before, after)
	}
}
