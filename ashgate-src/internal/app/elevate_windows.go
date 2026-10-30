//go:build windows

package app

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func prepareConsole() {
	kernel := windows.NewLazySystemDLL("kernel32.dll")
	r, _, _ := kernel.NewProc("AttachConsole").Call(^uintptr(0))
	if r == 0 {
		kernel.NewProc("AllocConsole").Call()
	}
	reopen()
}

func reopen() {
	out, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err == nil {
		os.Stdout = os.NewFile(uintptr(out), "stdout")
	}
	errh, err := windows.GetStdHandle(windows.STD_ERROR_HANDLE)
	if err == nil {
		os.Stderr = os.NewFile(uintptr(errh), "stderr")
	}
	in, err := windows.GetStdHandle(windows.STD_INPUT_HANDLE)
	if err == nil {
		os.Stdin = os.NewFile(uintptr(in), "stdin")
	}
}

// ensureElevated relaunches the process with UAC when the token is not elevated.
// The bool is true when the caller should exit with the returned code.
func ensureElevated(args []string) (bool, int) {
	if elevated() {
		return false, 0
	}
	exe, err := os.Executable()
	if err != nil {
		return true, 1
	}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = quoteArg(a)
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(strings.Join(quoted, " "))
	dir, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
	err = windows.ShellExecute(0, verb, file, params, dir, 1)
	if err != nil {
		text, _ := windows.UTF16PtrFromString("Не удалось запросить права администратора: " + err.Error())
		caption, _ := windows.UTF16PtrFromString("Ashgate")
		_, _ = windows.MessageBox(0, text, caption, windows.MB_OK|windows.MB_ICONERROR)
		return true, 1
	}
	return true, 0
}

func elevated() bool {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}
