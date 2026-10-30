//go:build windows

package service

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"ashgate/internal/config"
	"ashgate/internal/logbuf"
	"ashgate/internal/runtime"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Name is the service name.
const Name = "Ashgate"

// RunningAsService reports whether this process was started by the Service Control Manager.
func RunningAsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

// Install registers an automatic service that runs `ashgate run -config <path>`.
func Install(exe, configPath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err == nil {
		s.Close()
		return fmt.Errorf("служба %s уже установлена", Name)
	}
	s, err = m.CreateService(Name, exe, mgr.Config{
		DisplayName:  "Ashgate Transparent Proxy",
		Description:  "Прозрачное перенаправление трафика выбранных приложений через SOCKS5 или HTTP-прокси.",
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
	}, "run", "-config", configPath)
	if err != nil {
		return err
	}
	s.Close()
	return nil
}

// Uninstall stops and deletes the service.
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return fmt.Errorf("служба %s не установлена: %w", Name, err)
	}
	defer s.Close()
	_, err = s.Control(svc.Stop)
	if err == nil {
		_ = waitState(s, svc.Stopped, 20*time.Second)
	}
	return s.Delete()
}

// RemoveLegacy stops and deletes the Ashgate service left by older builds.
// wasAuto is true when that service started by itself at boot.
func RemoveLegacy() (existed bool, wasAuto bool, err error) {
	m, err := mgr.Connect()
	if err != nil {
		return false, false, err
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return false, false, nil
	}
	defer s.Close()
	if cfg, cerr := s.Config(); cerr == nil {
		wasAuto = cfg.StartType == mgr.StartAutomatic || cfg.DelayedAutoStart
	}
	if _, serr := s.Control(svc.Stop); serr == nil {
		_ = waitState(s, svc.Stopped, 20*time.Second)
	}
	if derr := s.Delete(); derr != nil {
		return true, wasAuto, derr
	}
	return true, wasAuto, nil
}

// Start starts the installed service.
func Start() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.Start(); err != nil {
		return err
	}
	return waitState(s, svc.Running, 20*time.Second)
}

// Stop stops the installed service.
func Stop() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return err
	}
	defer s.Close()
	if _, err := s.Control(svc.Stop); err != nil {
		return err
	}
	return waitState(s, svc.Stopped, 20*time.Second)
}

// Serve runs the service handler. It returns when the service stops.
func Serve() error {
	return svc.Run(Name, &handler{})
}

type handler struct{}

func (handler) Execute(args []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	var tail []string
	if len(args) > 1 {
		tail = args[1:]
	}
	path := config.PathFromArgs(append(append([]string{}, tail...), os.Args[1:]...))
	cfg, err := config.LoadOrInit(path)
	if err != nil {
		return false, 1
	}
	if cfg.Log.File == "" {
		cfg.Log.File = defaultLog(path)
	}
	logs, err := logbuf.New(2000, cfg.Log.File)
	if err != nil {
		return false, 1
	}
	defer logs.Close()
	sess, err := runtime.Start(nil, cfg, logs)
	if err != nil {
		logs.Add(logbuf.Event{Process: "ashgate", Status: "error", Error: err.Error()})
		return false, 1
	}
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case <-sess.Done():
			return false, 1
		case c := <-requests:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				sess.Stop()
				select {
				case <-sess.Done():
				case <-time.After(15 * time.Second):
				}
				return false, 0
			case svc.Interrogate:
				changes <- c.CurrentStatus
			}
		}
	}
}

func defaultLog(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "ashgate.log")
}

func waitState(s *mgr.Service, want svc.State, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == want {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("служба не перешла в состояние %d", want)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
