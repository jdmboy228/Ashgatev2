//go:build windows

package killswitch

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/windows"

	"ashgate/internal/windivert"
)

// StartGuard starts a helper process that blocks the saved targets if this
// process exits without calling the returned stop. While capture runs the
// firewall rules are absent, so without the guard a crash of Ashgate would
// let proxied applications connect directly.
func StartGuard(state string) (stop func(), err error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	name := fmt.Sprintf(`Local\AshgateKillGuard-%d-%d`, os.Getpid(), time.Now().UnixNano())
	pname, _ := windows.UTF16PtrFromString(name)
	ev, err := windows.CreateEvent(nil, 1, 0, pname)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(exe, GuardCommand, "-pid", strconv.Itoa(os.Getpid()), "-event", name, "-state", state)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	if err := cmd.Start(); err != nil {
		windows.CloseHandle(ev)
		return nil, err
	}
	go func() { _ = cmd.Wait() }()
	return func() {
		_ = windows.SetEvent(ev)
		windows.CloseHandle(ev)
	}, nil
}

// RunGuard is the helper's main. It waits for the parent to exit or to
// signal a clean stop. When the parent exits first it blocks the targets.
func RunGuard(args []string) error {
	fs := flag.NewFlagSet(GuardCommand, flag.ContinueOnError)
	pid := fs.Uint("pid", 0, "")
	event := fs.String("event", "", "")
	state := fs.String("state", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pid == 0 || *event == "" || *state == "" {
		return errors.New("killswitch-guard: missing arguments")
	}
	ph, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(*pid))
	if err != nil {
		// The parent is already gone: block now.
		err := New(*state).Block(loadTargets(*state))
		_ = windivert.StopDriver()
		return err
	}
	defer windows.CloseHandle(ph)
	pname, _ := windows.UTF16PtrFromString(*event)
	ev, err := windows.OpenEvent(windows.SYNCHRONIZE, false, pname)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(ev)
	got, err := windows.WaitForMultipleObjects([]windows.Handle{ev, ph}, false, windows.INFINITE)
	if err != nil {
		return err
	}
	if got == windows.WAIT_OBJECT_0 {
		return nil // clean stop: Ashgate manages the rules itself
	}
	// Ashgate died: Windows closed its WinDivert handles, the driver stays.
	err = New(*state).Block(loadTargets(*state))
	_ = windivert.StopDriver()
	return err
}
