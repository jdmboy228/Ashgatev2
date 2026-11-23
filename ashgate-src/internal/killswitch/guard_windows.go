//go:build windows

package killswitch

import (
	"errors"
	"flag"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"ashgate/internal/windivert"
)

// guardAction blocks the saved targets and stops the driver when the parent dies.
// Tests override it to avoid calling netsh or WinDivert.
var guardAction = func(state string) error {
	err := New(state).Block(LoadTargets(state))
	_ = windivert.StopDriver()
	return err
}

// StartGuard starts a helper process that blocks the saved targets if this
// process exits without calling the returned stop. While capture runs the
// firewall rules are absent, so without the guard a crash of Ashgate would
// let proxied applications connect directly.
func StartGuard(state string) (stop func(), err error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	sa := windows.SecurityAttributes{
		Length:        uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		InheritHandle: 1,
	}
	ev, err := windows.CreateEvent(&sa, 1, 0, nil)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(exe, GuardCommand, "-pid", strconv.Itoa(os.Getpid()), "-handle", strconv.FormatUint(uint64(ev), 10), "-state", state)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:                 true,
		CreationFlags:              windows.CREATE_NO_WINDOW,
		AdditionalInheritedHandles: []syscall.Handle{syscall.Handle(ev)},
	}
	if err := cmd.Start(); err != nil {
		windows.CloseHandle(ev)
		return nil, err
	}
	// Clear inheritance on the parent's copy so unrelated child processes do not
	// accidentally inherit the guard event.
	_ = windows.SetHandleInformation(ev, windows.HANDLE_FLAG_INHERIT, 0)
	go func() { _ = cmd.Wait() }()
	var once sync.Once
	return func() {
		once.Do(func() {
			_ = windows.SetEvent(ev)
			windows.CloseHandle(ev)
		})
	}, nil
}

// RunGuard is the helper's main. It waits for the parent to exit or to
// signal a clean stop. When the parent exits first it blocks the targets.
func RunGuard(args []string) error {
	fs := flag.NewFlagSet(GuardCommand, flag.ContinueOnError)
	pid := fs.Uint("pid", 0, "")
	handle := fs.Uint64("handle", 0, "")
	event := fs.String("event", "", "")
	state := fs.String("state", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pid == 0 || (*handle == 0 && *event == "") || *state == "" {
		return errors.New("killswitch-guard: missing arguments")
	}
	if *handle != 0 {
		ev := windows.Handle(*handle)
		defer windows.CloseHandle(ev)
		if got, err := windows.WaitForSingleObject(ev, 0); err == nil && got == windows.WAIT_OBJECT_0 {
			return nil
		}
		ph, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(*pid))
		if err != nil {
			// Re-check ev in case the parent signalled a clean stop and exited
			// right before OpenProcess ran.
			if got, werr := windows.WaitForSingleObject(ev, 0); werr == nil && got == windows.WAIT_OBJECT_0 {
				return nil
			}
			return guardAction(*state)
		}
		defer windows.CloseHandle(ph)
		return waitGuard(ev, ph, *state)
	}

	ph, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(*pid))
	if err != nil {
		// The parent is already gone: block now.
		return guardAction(*state)
	}
	defer windows.CloseHandle(ph)
	pname, _ := windows.UTF16PtrFromString(*event)
	ev, err := windows.OpenEvent(windows.SYNCHRONIZE, false, pname)
	if err != nil {
		// If the parent crashed before OpenEvent, Windows closes its handle table
		// shortly before signalling the process object.
		if got, werr := windows.WaitForSingleObject(ph, 100); werr == nil && got == windows.WAIT_OBJECT_0 {
			return guardAction(*state)
		}
		return err
	}
	defer windows.CloseHandle(ev)
	return waitGuard(ev, ph, *state)
}

func waitGuard(ev, ph windows.Handle, state string) error {
	got, err := windows.WaitForMultipleObjects([]windows.Handle{ev, ph}, false, windows.INFINITE)
	if err != nil {
		return err
	}
	if got == windows.WAIT_OBJECT_0 {
		return nil // clean stop: Ashgate manages the rules itself
	}
	// Ashgate died: Windows closed its WinDivert handles, the driver stays.
	return guardAction(state)
}
