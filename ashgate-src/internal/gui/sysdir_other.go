//go:build !windows

package gui

import "os"

func windowsDir() string {
	if root := os.Getenv("SystemRoot"); root != "" {
		return root
	}
	return `C:\Windows`
}
