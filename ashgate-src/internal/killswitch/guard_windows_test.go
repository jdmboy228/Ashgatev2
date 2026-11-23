//go:build windows

package killswitch

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestGuardTestHelperProcess(t *testing.T) {
	if os.Getenv("ASHGATE_GUARD_TEST_HELPER") != "1" {
		return
	}
	switch os.Getenv("ASHGATE_GUARD_TEST_MODE") {
	case "exit":
		os.Exit(0)
	case "sleep":
		time.Sleep(10 * time.Second)
		os.Exit(0)
	case "wait-event":
		hVal, err := strconv.ParseUint(os.Getenv("ASHGATE_GUARD_TEST_HANDLE"), 10, 64)
		if err != nil {
			os.Exit(2)
		}
		ev := windows.Handle(hVal)
		defer windows.CloseHandle(ev)
		got, err := windows.WaitForSingleObject(ev, 5000)
		if err != nil || got != windows.WAIT_OBJECT_0 {
			os.Exit(3)
		}
		os.Exit(0)
	default:
		os.Exit(1)
	}
}

func spawnGuardTestHelper(t *testing.T, mode string, extraEnv []string, inherit ...windows.Handle) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestGuardTestHelperProcess$")
	env := append(os.Environ(), "ASHGATE_GUARD_TEST_HELPER=1", "ASHGATE_GUARD_TEST_MODE="+mode)
	env = append(env, extraEnv...)
	cmd.Env = env
	if len(inherit) > 0 {
		hs := make([]syscall.Handle, len(inherit))
		for i, h := range inherit {
			hs[i] = syscall.Handle(h)
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{
			HideWindow:                 true,
			CreationFlags:              windows.CREATE_NO_WINDOW,
			AdditionalInheritedHandles: hs,
		}
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return cmd
}

func hookGuardAction(t *testing.T) *int {
	t.Helper()
	var calls int
	old := guardAction
	guardAction = func(string) error {
		calls++
		return nil
	}
	t.Cleanup(func() { guardAction = old })
	return &calls
}

func TestRunGuardInheritedHandleParentCrashTriggersBlock(t *testing.T) {
	state := filepath.Join(t.TempDir(), "killswitch.json")

	// Case 1: parent exited before RunGuard opens its PID, event unsignaled.
	calls := hookGuardAction(t)
	cmd1 := spawnGuardTestHelper(t, "sleep", nil)
	pid1 := cmd1.Process.Pid
	_ = cmd1.Process.Kill()
	_ = cmd1.Wait()
	ev1, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = RunGuard([]string{
		"-pid", strconv.Itoa(pid1),
		"-handle", strconv.FormatUint(uint64(ev1), 10),
		"-state", state,
	})
	if err != nil {
		t.Fatalf("RunGuard after dead parent: %v", err)
	}
	if *calls != 1 {
		t.Fatalf("guardAction calls = %d, want 1", *calls)
	}

	// Case 2: parent dies while RunGuard is waiting.
	*calls = 0
	cmd2 := spawnGuardTestHelper(t, "sleep", nil)
	pid2 := cmd2.Process.Pid
	ev2, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		_ = cmd2.Process.Kill()
		_ = cmd2.Wait()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- RunGuard([]string{
			"-pid", strconv.Itoa(pid2),
			"-handle", strconv.FormatUint(uint64(ev2), 10),
			"-state", state,
		})
	}()
	time.Sleep(30 * time.Millisecond)
	_ = cmd2.Process.Kill()
	_ = cmd2.Wait()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunGuard while waiting: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RunGuard did not return after parent exited")
	}
	if *calls != 1 {
		t.Fatalf("guardAction calls = %d, want 1", *calls)
	}
}

func TestRunGuardInheritedHandleCleanStopDoesNotBlock(t *testing.T) {
	state := filepath.Join(t.TempDir(), "killswitch.json")
	calls := hookGuardAction(t)

	// Clean stop signaled even if parent has already exited.
	cmd1 := spawnGuardTestHelper(t, "exit", nil)
	pid1 := cmd1.Process.Pid
	_ = cmd1.Wait()
	ev1, err := windows.CreateEvent(nil, 1, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := RunGuard([]string{
		"-pid", strconv.Itoa(pid1),
		"-handle", strconv.FormatUint(uint64(ev1), 10),
		"-state", state,
	}); err != nil {
		t.Fatalf("RunGuard clean stop (exited parent): %v", err)
	}
	if *calls != 0 {
		t.Fatalf("guardAction calls = %d, want 0", *calls)
	}

	// Clean stop signaled while parent is still alive.
	cmd2 := spawnGuardTestHelper(t, "sleep", nil)
	defer func() {
		_ = cmd2.Process.Kill()
		_ = cmd2.Wait()
	}()
	ev2, err := windows.CreateEvent(nil, 1, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := RunGuard([]string{
		"-pid", strconv.Itoa(cmd2.Process.Pid),
		"-handle", strconv.FormatUint(uint64(ev2), 10),
		"-state", state,
	}); err != nil {
		t.Fatalf("RunGuard clean stop (live parent): %v", err)
	}
	if *calls != 0 {
		t.Fatalf("guardAction calls = %d, want 0", *calls)
	}
}

func TestRunGuardMissingNamedEventWithExitedParentTriggersBlock(t *testing.T) {
	state := filepath.Join(t.TempDir(), "killswitch.json")
	calls := hookGuardAction(t)

	// Keep cmd.Process open so OpenProcess succeeds on the exited process while
	// OpenEvent fails because the named event does not exist.
	cmd := spawnGuardTestHelper(t, "exit", nil)
	defer func() { _ = cmd.Wait() }()
	// Poll until the child has actually exited (still tracked by cmd.Process).
	ph, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(cmd.Process.Pid))
	if err == nil {
		_, _ = windows.WaitForSingleObject(ph, 3000)
		_ = windows.CloseHandle(ph)
	}

	missing := fmt.Sprintf(`Local\AshgateMissingGuard-%d-%d`, os.Getpid(), time.Now().UnixNano())
	if err := RunGuard([]string{
		"-pid", strconv.Itoa(cmd.Process.Pid),
		"-event", missing,
		"-state", state,
	}); err != nil {
		t.Fatalf("RunGuard legacy missing event after parent exit: %v", err)
	}
	if *calls != 1 {
		t.Fatalf("guardAction calls = %d, want 1", *calls)
	}
}

func TestStartGuardHandleInheritanceWorks(t *testing.T) {
	sa := windows.SecurityAttributes{
		Length:        uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		InheritHandle: 1,
	}
	ev, err := windows.CreateEvent(&sa, 1, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	cmd := spawnGuardTestHelper(
		t,
		"wait-event",
		[]string{"ASHGATE_GUARD_TEST_HANDLE=" + strconv.FormatUint(uint64(ev), 10)},
		ev,
	)
	_ = windows.SetHandleInformation(ev, windows.HANDLE_FLAG_INHERIT, 0)
	_ = windows.SetEvent(ev)
	_ = windows.CloseHandle(ev)
	if err := cmd.Wait(); err != nil {
		t.Fatalf("child failed waiting on inherited guard event: %v", err)
	}
}
