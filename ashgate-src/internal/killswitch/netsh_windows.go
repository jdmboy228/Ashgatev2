//go:build windows

package killswitch

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32                = windows.NewLazySystemDLL("kernel32.dll")
	procMultiByteToWideChar = kernel32.NewProc("MultiByteToWideChar")
)

// runNetsh runs netsh with a literal command line. netsh expects
// program="C:\path with spaces\app.exe" exactly, which Go's own argument
// quoting would not produce.
func runNetsh(cmdline string) error {
	exe := filepath.Join(os.Getenv("SystemRoot"), "System32", "netsh.exe")
	cmd := exec.Command(exe)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW,
		CmdLine:       `"` + exe + `" ` + cmdline,
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("netsh: %w: %s", err, strings.TrimSpace(decodeConsole(out)))
	}
	return nil
}

// decodeConsole converts OEM codepage output (e.g. Russian CP866) to UTF-8.
func decodeConsole(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if utf8.Valid(b) {
		return string(b)
	}
	const cpOEM = 1
	n, _, _ := procMultiByteToWideChar.Call(
		cpOEM, 0,
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)),
		0, 0,
	)
	if n == 0 {
		runtime.KeepAlive(b)
		return string(b)
	}
	w := make([]uint16, n)
	m, _, _ := procMultiByteToWideChar.Call(
		cpOEM, 0,
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)),
		uintptr(unsafe.Pointer(&w[0])), n,
	)
	runtime.KeepAlive(b)
	if m == 0 {
		return string(b)
	}
	s := windows.UTF16ToString(w[:m])
	runtime.KeepAlive(w)
	return s
}
