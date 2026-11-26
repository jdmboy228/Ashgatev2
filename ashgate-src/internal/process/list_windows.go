//go:build windows

package process

import (
	"sort"
	"strings"
	"sync"
	"unsafe"

	"ashgate/internal/rules"
	"golang.org/x/sys/windows"
)

// App is one running application. Several PIDs of the same image collapse
// into one row. Window marks programs with a visible top-level window.
type App struct {
	PID    uint32 `json:"pid"`
	Name   string `json:"name"`
	Path   string `json:"path"`
	Window bool   `json:"window"`
	Title  string `json:"title,omitempty"` // main window caption
}

var (
	user32              = windows.NewLazySystemDLL("user32.dll")
	procGetWindow       = user32.NewProc("GetWindow")
	procGetWindowLong   = user32.NewProc("GetWindowLongPtrW")
	procInternalGetText = user32.NewProc("InternalGetWindowText")
)

const (
	gwOwner         = 4
	gwlExStyle      = ^uintptr(19) // -20
	wsExToolWindow  = 0x00000080
	maxWindowTitle  = 256
	backgroundWords = "crashpad crashhandler crashreport update helper webview service svc broker elevation agent daemon tray watchdog launcherhelper"
)

// List returns the applications a person would pick: processes in the
// caller's desktop session, excluding services (session 0), Windows'
// own background processes and helper processes without a window.
// Programs with a window come first.
func List() ([]App, error) {
	windowed := windowPIDs()
	var mySession uint32
	_ = windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &mySession)
	sysDir := strings.ToLower(windowsDir()) + `\`

	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snap, &entry); err != nil {
		return nil, err
	}
	byPath := map[string]int{}
	var out []App
	self := windows.GetCurrentProcessId()
	for ; err == nil; err = windows.Process32Next(snap, &entry) {
		pid := entry.ProcessID
		if pid <= 4 || pid == self {
			continue
		}
		var sess uint32
		if windows.ProcessIdToSessionId(pid, &sess) != nil || sess != mySession {
			continue
		}
		img := queryImage(pid)
		if img.Path == "" || strings.EqualFold(img.Name, "ashgate.exe") {
			continue
		}
		title, win := windowed[pid]
		low := strings.ToLower(img.Path)
		if !win && (strings.HasPrefix(low, sysDir) || looksBackground(img.Name)) {
			continue
		}
		if i, ok := byPath[low]; ok {
			if win && !out[i].Window {
				out[i].Window, out[i].PID, out[i].Title = true, pid, title
			}
			continue
		}
		byPath[low] = len(out)
		out = append(out, App{PID: pid, Name: img.Name, Path: img.Path, Window: win, Title: title})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Window != out[j].Window {
			return out[i].Window
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, nil
}

func looksBackground(name string) bool {
	low := strings.ToLower(strings.TrimSuffix(strings.ToLower(name), ".exe"))
	for _, w := range strings.Fields(backgroundWords) {
		if strings.Contains(low, w) {
			return true
		}
	}
	return false
}

var (
	enumOnce sync.Once
	enumCB   uintptr
	enumMu   sync.Mutex
	enumOut  map[uint32]string
)

// windowPIDs returns the PIDs that own a visible, titled, unowned top-level
// window that is not a tool window (what the taskbar shows), with the
// caption of the first such window.
func windowPIDs() map[uint32]string {
	enumOnce.Do(func() {
		enumCB = windows.NewCallback(func(hwnd windows.HWND, _ uintptr) uintptr {
			if !windows.IsWindowVisible(hwnd) {
				return 1
			}
			if owner, _, _ := procGetWindow.Call(uintptr(hwnd), gwOwner); owner != 0 {
				return 1
			}
			if ex, _, _ := procGetWindowLong.Call(uintptr(hwnd), gwlExStyle); ex&wsExToolWindow != 0 {
				return 1
			}
			var buf [maxWindowTitle]uint16
			n, _, _ := procInternalGetText.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
			if int32(n) <= 0 {
				return 1
			}
			var pid uint32
			if _, err := windows.GetWindowThreadProcessId(hwnd, &pid); err == nil && pid != 0 {
				if _, seen := enumOut[pid]; !seen {
					enumOut[pid] = windows.UTF16ToString(buf[:min(int(n), len(buf))])
				}
			}
			return 1
		})
	})
	enumMu.Lock()
	defer enumMu.Unlock()
	enumOut = map[uint32]string{}
	_ = windows.EnumWindows(enumCB, nil)
	out := enumOut
	enumOut = nil
	return out
}

// Snapshot returns every process with its image path, parent and start
// time, for the kill switch. Processes that cannot be opened are skipped.
func Snapshot() []rules.Process {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	var out []rules.Process
	for err = windows.Process32First(snap, &entry); err == nil; err = windows.Process32Next(snap, &entry) {
		if entry.ProcessID <= 4 {
			continue
		}
		p := queryImage(entry.ProcessID)
		if p.Path == "" {
			continue
		}
		if p.PPID == 0 {
			p.PPID = entry.ParentProcessID
		}
		out = append(out, p)
	}
	return WithParents(out)
}
