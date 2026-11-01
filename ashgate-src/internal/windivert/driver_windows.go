//go:build windows

package windivert

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// StopDriver unloads the WinDivert driver after the last handle is closed.
// WinDivert.dll starts the driver and marks its service for deletion, but
// the driver itself stays loaded, and WinDivert64.sys locked, until someone
// stops the service or Windows restarts: uninstalling Ashgate then left its
// folder and the service behind, and a reinstall asked for a restart.
// Only a driver loaded from this exe's folder is stopped, so another
// program's WinDivert is left alone. If a handle is still open somewhere,
// Windows unloads the driver once it closes.
func StopDriver() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService("WinDivert")
	if err != nil {
		return nil // not loaded
	}
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		return err
	}
	if !strings.Contains(strings.ToLower(cfg.BinaryPathName), strings.ToLower(filepath.Dir(exe))) {
		return nil
	}
	if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return err
	}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		st, err := s.Query()
		if err != nil || st.State == svc.Stopped {
			return nil
		}
	}
	return errors.New("драйвер WinDivert не выгрузился за 5 секунд")
}
