//go:build windows

package gui

import "golang.org/x/sys/windows"

// windowsDir is the Windows directory from the API, not the environment
// this process was started with.
func windowsDir() string {
	if d, err := windows.GetWindowsDirectory(); err == nil && d != "" {
		return d
	}
	return `C:\Windows`
}
