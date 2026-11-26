//go:build windows

package gui

import (
	"errors"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	instanceMutex = `Global\Ashgate`
	instanceEvent = `Global\AshgateShow`
	// The creator (elevated admin / SYSTEM) gets full access. Everyone else
	// only gets SYNCHRONIZE, so a non-elevated CreateMutex fails closed
	// instead of opening a second window. The event also allows SetEvent.
	mutexSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00100000;;;WD)(A;;0x00100000;;;AU)"
	eventSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00100002;;;WD)(A;;0x00100002;;;AU)"
	// The quit event (ashgate quit, used by update.bat) is for SYSTEM and
	// elevated administrators only: anyone else could switch protection off.
	instanceQuitEvent = `Global\AshgateQuit`
	quitSDDL          = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
)

const alreadyRunning = "Ashgate уже запущен. Если окна не видно, откройте диспетчер задач и завершите лишний ashgate.exe, затем запустите снова."

// claimInstance makes this process the only window. A second process, elevated
// or not, asks the first to come forward and leaves. release closes the mutex
// so the next launch can open a window after Выход.
func claimInstance() (release func(), already bool) {
	sa := sdSA(mutexSDDL)
	if sa == nil {
		alert("Не удалось подготовить единственный экземпляр Ashgate.")
		return func() {}, true
	}
	mutex, exists, err := createNamed(func(name *uint16) (windows.Handle, error) {
		return windows.CreateMutex(sa, false, name)
	}, instanceMutex)
	if exists || accessDenied(err) {
		if mutex != 0 {
			windows.CloseHandle(mutex)
		}
		if accessDenied(err) && !exists && !instancePresent() {
			alert("Не удалось занять единственный экземпляр Ashgate: " + err.Error())
			return func() {}, true
		}
		signalExisting()
		return func() {}, true
	}
	if err != nil || mutex == 0 {
		if err != nil {
			alert("Не удалось занять единственный экземпляр Ashgate: " + err.Error())
		}
		return func() {}, true
	}
	inst := &singleInstance{
		mutex: mutex,
		ev:    createEvent(eventSDDL, instanceEvent),
		quit:  createStrictEvent(quitSDDL, instanceQuitEvent),
		stop:  make(chan struct{}),
	}
	inst.watch(inst.ev, requestShow)
	inst.watch(inst.quit, requestQuit)
	return inst.release, false
}

type singleInstance struct {
	mutex windows.Handle
	ev    windows.Handle
	quit  windows.Handle
	stop  chan struct{}
	wg    sync.WaitGroup
	once  sync.Once
}

func (s *singleInstance) watch(ev windows.Handle, fire func()) {
	if ev == 0 {
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		watchEvent(ev, s.stop, fire)
	}()
}

func (s *singleInstance) release() {
	s.once.Do(func() {
		close(s.stop)
		s.wg.Wait()
		if s.ev != 0 {
			windows.CloseHandle(s.ev)
		}
		if s.quit != 0 {
			windows.CloseHandle(s.quit)
		}
		if s.mutex != 0 {
			windows.CloseHandle(s.mutex)
		}
	})
}

func createNamed(open func(*uint16) (windows.Handle, error), name string) (windows.Handle, bool, error) {
	ptr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, false, err
	}
	h, err := open(ptr)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) || accessDenied(err) {
		return h, errors.Is(err, windows.ERROR_ALREADY_EXISTS), err
	}
	return h, false, err
}

func createEvent(sddl, name string) windows.Handle {
	sa := sdSA(sddl)
	if sa == nil {
		return 0
	}
	ev, _, err := createNamed(func(name *uint16) (windows.Handle, error) {
		return windows.CreateEvent(sa, 0, 0, name)
	}, name)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		if ev != 0 {
			windows.CloseHandle(ev)
		}
		return 0
	}
	return ev
}

// createStrictEvent creates a named event and refuses to adopt an existing
// one. A non-elevated process can pre-create events in Global\, which would
// cause CreateEvent to ignore sa and return ERROR_ALREADY_EXISTS with the
// squatted handle.
func createStrictEvent(sddl, name string) windows.Handle {
	sa := sdSA(sddl)
	if sa == nil {
		return 0
	}
	ev, exists, err := createNamed(func(n *uint16) (windows.Handle, error) {
		return windows.CreateEvent(sa, 0, 0, n)
	}, name)
	if err != nil || exists {
		if ev != 0 {
			windows.CloseHandle(ev)
		}
		return 0
	}
	return ev
}

func instancePresent() bool {
	ptr, err := windows.UTF16PtrFromString(instanceMutex)
	if err != nil {
		return false
	}
	h, err := windows.OpenMutex(windows.SYNCHRONIZE, false, ptr)
	if err == nil {
		windows.CloseHandle(h)
		return true
	}
	return accessDenied(err)
}

func accessDenied(err error) bool {
	return err != nil && errors.Is(err, windows.ERROR_ACCESS_DENIED)
}

func watchEvent(ev windows.Handle, stop <-chan struct{}, fire func()) {
	for {
		select {
		case <-stop:
			return
		default:
		}
		r, err := windows.WaitForSingleObject(ev, 200)
		if err != nil && !errors.Is(err, windows.ERROR_SUCCESS) {
			return
		}
		select {
		case <-stop:
			return
		default:
		}
		if r == windows.WAIT_OBJECT_0 {
			fire()
		}
	}
}

// requestQuit asks the window thread to exit as «Выход» does.
func requestQuit() {
	h := appHost.Load()
	if h == nil {
		return
	}
	if hwnd := h.hwnd.Load(); hwnd != 0 {
		pPostMessage.Call(hwnd, wmQuitReq, 0, 0)
	}
}

// Quit result codes for the ashgate quit command.
const (
	QuitDone       = 0 // the running window exited
	QuitTimeout    = 1 // signalled, but it did not exit in time
	QuitNotRunning = 2 // no Ashgate window is running
	QuitTooOld     = 3 // a window runs, but its version has no quit signal
	QuitDenied     = 4 // not elevated: only administrators may stop Ashgate
)

// Quit asks the running window to exit the way «Выход» does (stop capture,
// restore the kill switch, stop the bridges) and waits for it to go.
func Quit(timeout time.Duration) int {
	if !instancePresent() {
		return QuitNotRunning
	}
	ptr, err := windows.UTF16PtrFromString(instanceQuitEvent)
	if err != nil {
		return QuitTooOld
	}
	h, err := windows.OpenEvent(windows.EVENT_MODIFY_STATE, false, ptr)
	if accessDenied(err) {
		return QuitDenied
	}
	if err != nil || h == 0 {
		return QuitTooOld
	}
	err = windows.SetEvent(h)
	windows.CloseHandle(h)
	if err != nil {
		return QuitTimeout
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !instancePresent() {
			return QuitDone
		}
		time.Sleep(200 * time.Millisecond)
	}
	return QuitTimeout
}

func requestShow() {
	h := appHost.Load()
	if h == nil {
		return
	}
	if hwnd := h.hwnd.Load(); hwnd != 0 {
		pPostMessage.Call(hwnd, wmShow, 0, 0)
	}
}

// signalExisting lets the process that already owns the window restore itself.
// This process does not call SetForegroundWindow: UIPI blocks that across
// integrity levels. AllowSetForegroundWindow runs here, while this process is
// still in the foreground, so the owner is allowed to take the window back.
func signalExisting() {
	allowForeground()
	ptr, err := windows.UTF16PtrFromString(instanceEvent)
	if err != nil {
		alert(alreadyRunning)
		return
	}
	var h windows.Handle
	deadline := time.Now().Add(time.Second)
	for {
		h, err = windows.OpenEvent(windows.EVENT_MODIFY_STATE|windows.SYNCHRONIZE, false, ptr)
		if err == nil && h != 0 {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil || h == 0 {
		alert(alreadyRunning)
		return
	}
	err = windows.SetEvent(h)
	windows.CloseHandle(h)
	if err != nil {
		alert(alreadyRunning)
		return
	}
	time.Sleep(400 * time.Millisecond)
}

func allowForeground() {
	user32.NewProc("AllowSetForegroundWindow").Call(^uintptr(0))
}

func sdSA(sddl string) *windows.SecurityAttributes {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil || sd == nil {
		return nil
	}
	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
		InheritHandle:      0,
	}
}
