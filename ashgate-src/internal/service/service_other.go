//go:build !windows

package service

import "errors"

// Name is the Windows service name.
const Name = "Ashgate"

// RunningAsService is always false outside Windows.
func RunningAsService() bool { return false }

// Install is only available on Windows.
func Install(string, string) error { return windowsOnly() }

// Uninstall is only available on Windows.
func Uninstall() error { return windowsOnly() }

// Start is only available on Windows.
func Start() error { return windowsOnly() }

// Stop is only available on Windows.
func Stop() error { return windowsOnly() }

// Serve is only available on Windows.
func Serve() error { return windowsOnly() }

// RemoveLegacy is a no-op outside Windows.
func RemoveLegacy() (bool, bool, error) { return false, false, nil }

func windowsOnly() error {
	return errors.New("служба Windows доступна только в Windows")
}
