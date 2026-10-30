//go:build !windows

package gui

import (
	"errors"
	"time"
)

// Run reports that the window is only available on Windows.
func Run(string, bool) error {
	return errors.New("графический интерфейс Ashgate доступен только в Windows")
}

// Quit result codes for the ashgate quit command; see instance_windows.go.
const (
	QuitDone       = 0
	QuitTimeout    = 1
	QuitNotRunning = 2
	QuitTooOld     = 3
	QuitDenied     = 4
)

// Quit has no window to stop outside Windows.
func Quit(time.Duration) int { return QuitNotRunning }
