//go:build windows

package process

import (
	"errors"
	"sync"
	"syscall"
	"unsafe"

	"ashgate/internal/rules"
	"golang.org/x/sys/windows"
)

var (
	iphlp   = windows.NewLazySystemDLL("iphlpapi.dll")
	procTCP = iphlp.NewProc("GetExtendedTcpTable")
	procUDP = iphlp.NewProc("GetExtendedUdpTable")
)

func configure(r *Resolver) {
	t := &handleTable{m: map[uint32]heldProc{}}
	r.image = t.query
	r.exited = t.exited
	r.release = t.closeAll
	r.loadHelper = loadTables
	r.present = processPresent
}

// processPresent reports that pid runs. A protected process may refuse to
// be opened; the refusal still says it exists.
func processPresent(pid uint32) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return err == windows.ERROR_ACCESS_DENIED
	}
	defer windows.CloseHandle(h)
	var code uint32
	if windows.GetExitCodeProcess(h, &code) != nil {
		return true
	}
	const stillActive = 259
	return code == stillActive
}

type heldProc struct {
	h       windows.Handle
	started int64
}

// handleTable keeps one open handle per PID a resolver has cached. While a
// handle is open Windows cannot hand that PID to a new process, and
// WaitForSingleObject on it tells when the cached process has exited.
// Each resolver owns its table and closes it when capture stops.
type handleTable struct {
	mu sync.Mutex
	m  map[uint32]heldProc
}

func (t *handleTable) query(pid uint32) rules.Process {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return queryImage(pid)
	}
	p := readImage(h, pid)
	if p.Path == "" {
		windows.CloseHandle(h)
		return p
	}
	t.mu.Lock()
	if old, ok := t.m[pid]; ok {
		windows.CloseHandle(old.h)
	}
	t.m[pid] = heldProc{h: h, started: p.Started}
	t.mu.Unlock()
	return p
}

// exited reports whether the process cached for pid is gone. For protected
// processes where SYNCHRONIZE was denied (no held handle), it falls back to a
// PROCESS_QUERY_LIMITED_INFORMATION liveness check so live sockets are not
// wiped on prune.
func (t *handleTable) exited(pid uint32, started int64) bool {
	t.mu.Lock()
	hp, ok := t.m[pid]
	if ok {
		if started != 0 && hp.started != started {
			t.mu.Unlock()
			return true
		}
		ev, err := windows.WaitForSingleObject(hp.h, 0)
		if err == nil && ev == uint32(windows.WAIT_TIMEOUT) {
			t.mu.Unlock()
			return false
		}
		windows.CloseHandle(hp.h)
		delete(t.m, pid)
		t.mu.Unlock()
		return true
	}
	t.mu.Unlock()

	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		// ACCESS_DENIED means the PID is still alive (protected process).
		return !errors.Is(err, windows.ERROR_ACCESS_DENIED)
	}
	defer windows.CloseHandle(h)
	const stillActive = 259
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err == nil && code != stillActive {
		return true
	}
	if started != 0 {
		var create, exit, kernel, user windows.Filetime
		if err := windows.GetProcessTimes(h, &create, &exit, &kernel, &user); err == nil {
			if ct := create.Nanoseconds(); ct != 0 && ct != started {
				return true
			}
		}
	}
	return false
}

func (t *handleTable) closeAll() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for pid, hp := range t.m {
		windows.CloseHandle(hp.h)
		delete(t.m, pid)
	}
}

// queryImage reads a process without keeping a handle. List and TCPOwner
// use it; only resolvers hold handles.
func queryImage(pid uint32) rules.Process {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return rules.Process{PID: pid}
	}
	defer windows.CloseHandle(h)
	return readImage(h, pid)
}

// readImage returns the image path, parent PID and creation time.
func readImage(h windows.Handle, pid uint32) rules.Process {
	path, ok := imageName(h)
	if !ok {
		return rules.Process{PID: pid}
	}
	p := rules.Process{PID: pid, Name: rules.Base(path), Path: path}
	var pbi windows.PROCESS_BASIC_INFORMATION
	if windows.NtQueryInformationProcess(h, windows.ProcessBasicInformation, unsafe.Pointer(&pbi), uint32(unsafe.Sizeof(pbi)), nil) == nil {
		p.PPID = uint32(pbi.InheritedFromUniqueProcessId)
	}
	var created, exit, kernel, user windows.Filetime
	if windows.GetProcessTimes(h, &created, &exit, &kernel, &user) == nil {
		p.Started = created.Nanoseconds()
	}
	return p
}

// imageName reads the full image path. Snapshot calls it for every process
// every few seconds, so it starts with a buffer that fits nearly every path
// and only retries with the 32K-character maximum when that is too small.
func imageName(h windows.Handle) (string, bool) {
	for _, size := range []int{520, 32768} {
		buf := make([]uint16, size)
		n := uint32(len(buf))
		err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n)
		if err == nil {
			return windows.UTF16ToString(buf[:n]), true
		}
		if err != windows.ERROR_INSUFFICIENT_BUFFER {
			return "", false
		}
	}
	return "", false
}

func loadTables() ([]Endpoint, error) {
	var out []Endpoint
	specs := []struct {
		proc  *windows.LazyProc
		af    uintptr
		class uintptr
		kind  TableKind
	}{
		{procTCP, 2, 5, TableTCP4},
		{procTCP, 23, 5, TableTCP6},
		{procUDP, 2, 1, TableUDP4},
		{procUDP, 23, 1, TableUDP6},
	}
	var first error
	for _, spec := range specs {
		buf, err := readTable(spec.proc, spec.af, spec.class)
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		eps, err := ParseOwnerTable(buf, spec.kind)
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		out = append(out, eps...)
	}
	if len(out) == 0 && first != nil {
		return nil, first
	}
	return out, nil
}

func readTable(proc *windows.LazyProc, af, class uintptr) ([]byte, error) {
	size := uint32(64 * 1024)
	for size <= 4<<20 {
		buf := make([]byte, size)
		sz := size
		r, _, _ := proc.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&sz)),
			0,
			af,
			class,
			0,
		)
		if r == 0 {
			if sz > size {
				sz = size
			}
			return buf[:sz], nil
		}
		if r != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			return nil, syscall.Errno(r)
		}
		if sz > size {
			size = sz
		} else {
			size *= 2
		}
	}
	return nil, windows.ERROR_INSUFFICIENT_BUFFER
}
