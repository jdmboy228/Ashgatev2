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
	dirs := []string{`C:\Windows`}

	if got := ins.CommandLine(pid, started); got == "" {
		t.Fatal("zero-value Inspector.CommandLine returned empty")
	}
	_ = ins.HasModuleInDirs(pid, started, dirs)

	// Verify concurrent reads/writes are race-free under -race.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_ = ins.CommandLine(pid, started)
				_ = ins.FileMetadata(cmdExe)
				_ = ins.HasModuleInDirs(pid, started, dirs)
			}
		}()
	}
	wg.Wait()
}

// findEmbeddedSignedSystemBinary returns a system binary that carries an
// embedded Authenticode signature. Many Windows binaries are only
// catalog-signed, so known candidates are tried first and a bounded scan of
// System32 .exe files follows.
func findEmbeddedSignedSystemBinary(t *testing.T) (string, FileMeta) {
	t.Helper()
	ins := NewInspector()
	sys32 := filepath.Join(os.Getenv("SystemRoot"), "System32")
	candidates := []string{
		filepath.Join(sys32, "ApplicationFrameHost.exe"),
		filepath.Join(sys32, "ApplyTrustOffline.exe"),
		filepath.Join(sys32, "AuthHost.exe"),
		filepath.Join(sys32, "notepad.exe"),
		filepath.Join(sys32, "cmd.exe"),
		filepath.Join(sys32, "WindowsPowerShell", "v1.0", "powershell.exe"),
	}
	tryPath := func(path string) (string, FileMeta, bool) {
		if _, err := os.Stat(path); err != nil {
			return "", FileMeta{}, false
		}
		if meta := ins.FileMetadata(path); meta.Signer != "" {
			return path, meta, true
		}
		return "", FileMeta{}, false
	}
	for _, path := range candidates {
		if p, meta, ok := tryPath(path); ok {
			return p, meta
		}
	}
	entries, err := os.ReadDir(sys32)
	if err != nil {
		return "", FileMeta{}
	}
	for i, e := range entries {
		if i >= 250 {
			break
		}
		if e.IsDir() || filepath.Ext(e.Name()) != ".exe" {
			continue
		}
		if p, meta, ok := tryPath(filepath.Join(sys32, e.Name())); ok {
			return p, meta
		}
	}
	return "", FileMeta{}
}

func TestFileMetadataCertThumbprint(t *testing.T) {
	ins := NewInspector()
	path, meta := findEmbeddedSignedSystemBinary(t)
	if path == "" {
		t.Skip("no system binary with an embedded Authenticode signature found")
	}
	if meta.CertThumbprint == "" {
		t.Fatalf("FileMetadata(%s).CertThumbprint is empty for signer %q", path, meta.Signer)
	}
	if len(meta.CertThumbprint) != 64 {
		t.Fatalf("CertThumbprint length = %d, want 64 (%q)", len(meta.CertThumbprint), meta.CertThumbprint)
	}
	for _, c := range meta.CertThumbprint {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Fatalf("CertThumbprint %q is not lowercase hex", meta.CertThumbprint)
		}
	}
	// The cached repeat call must return the identical thumbprint.
	if again := ins.FileMetadata(path); again.CertThumbprint != meta.CertThumbprint {
		t.Errorf("cached CertThumbprint = %q, want %q", again.CertThumbprint, meta.CertThumbprint)
	}
}

func TestHasModuleInDirsSelf(t *testing.T) {
	ins := NewInspector()
	pid := uint32(os.Getpid())
	started := selfCreationTime(t)

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	selfDir := filepath.Dir(exe)
	parentDir := filepath.Dir(selfDir)

	if dirs, err := queryModuleDirsErr(pid, started); err != nil || len(dirs) == 0 {
		t.Fatalf("queryModuleDirsErr(self) = (%v, %v), want a non-empty list", dirs, err)
	}
	// A wrong creation time (PID reuse guard) must reject the query.
	if dirs, err := queryModuleDirsErr(pid, started+int64(time.Minute)); err == nil || len(dirs) != 0 {
		t.Fatalf("mismatched started should fail, got (%v, %v)", dirs, err)
	}

	if !ins.HasModuleInDirs(pid, started, []string{selfDir}) {
		t.Errorf("HasModuleInDirs(self, %q) = false, want true", selfDir)
	}
	// Cached path must still answer the same way.
	if !ins.HasModuleInDirs(pid, started, []string{selfDir}) {
		t.Errorf("cached HasModuleInDirs(self, %q) = false, want true", selfDir)
	}
	if !ins.HasModuleInDirs(pid, started, []string{parentDir}) {
		t.Errorf("HasModuleInDirs(self, %q) = false, want true", parentDir)
	}
	if ins.HasModuleInDirs(pid, started, []string{`C:\does-not-exist-ashgate-dir`}) {
		t.Error("HasModuleInDirs with a nonexistent dir = true, want false")
	}
	if ins.HasModuleInDirs(4, started, []string{`C:\Windows`}) {
		t.Error("HasModuleInDirs(pid=4) = true, want false")
	}
	if ins.HasModuleInDirs(pid, started, nil) {
		t.Error("HasModuleInDirs with no dirs = true, want false")
	}
}

func TestExpandShortPathAndNormDir(t *testing.T) {
	// Nonexistent path with '~' must fall back cleanly without error.
	missing := `C:\no-such~1\folder`
	if got := normDir(missing); got != `c:\no-such~1\folder` {
		t.Fatalf("normDir(%q) = %q, want fallback", missing, got)
	}

	// Create a long directory name and ask Windows for its 8.3 short path.
	longDir := filepath.Join(t.TempDir(), "ashgate_long_directory_name_test")
	if err := os.MkdirAll(longDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	src, err := windows.UTF16PtrFromString(longDir)
	if err != nil {
		t.Fatalf("UTF16PtrFromString: %v", err)
	}
	buf := make([]uint16, 512)
	n, err := windows.GetShortPathName(src, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || n >= uint32(len(buf)) {
		t.Skipf("GetShortPathName unavailable: n=%d err=%v", n, err)
	}
	shortDir := windows.UTF16ToString(buf[:n])
	if !strings.ContainsRune(shortDir, '~') {
		t.Skipf("volume has 8.3 short names disabled (short=%q)", shortDir)
	}
	want := normDir(longDir)
	if got := normDir(shortDir); got != want {
		t.Fatalf("normDir(%q) = %q, want %q", shortDir, got, want)
	}
	if !matchModuleDirs([]string{normDir(shortDir)}, []string{longDir}) {
		t.Errorf("matchModuleDirs(short=%q, long=%q) = false, want true", shortDir, longDir)
	}
	if !matchModuleDirs([]string{want}, []string{shortDir}) {
		t.Errorf("matchModuleDirs(long=%q, short=%q) = false, want true", want, shortDir)
	}
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
		_, _ = queryModuleDirsErr(pid, 0)
		_, _ = readAuthenticodeSigner(cmdExe)
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
