//go:build windows

package windivert

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Handle is a WinDivert handle. The zero value is closed.
type Handle uintptr

const invalidHandle = ^uintptr(0)

var (
	loadOnce sync.Once
	dll      *windows.LazyDLL
	loadErr  error

	procOpen     *windows.LazyProc
	procRecv     *windows.LazyProc
	procSend     *windows.LazyProc
	procRecvEx   *windows.LazyProc
	procSendEx   *windows.LazyProc
	procShutdown *windows.LazyProc
	procClose    *windows.LazyProc
	procSetParam *windows.LazyProc
)

func load() error {
	loadOnce.Do(func() {
		exe, err := os.Executable()
		if err != nil {
			loadErr = err
			return
		}
		dir := filepath.Dir(exe)
		dllPath := filepath.Join(dir, "WinDivert.dll")
		sysPath := filepath.Join(dir, "WinDivert64.sys")
		if _, err := os.Stat(dllPath); err != nil {
			loadErr = fmt.Errorf("не найден %s — положите WinDivert.dll и WinDivert64.sys рядом с ashgate.exe", dllPath)
			return
		}
		if _, err := os.Stat(sysPath); err != nil {
			loadErr = fmt.Errorf("не найден %s — драйвер должен лежать в той же папке, что и WinDivert.dll", sysPath)
			return
		}
		dll = windows.NewLazyDLL(dllPath)
		procOpen = dll.NewProc("WinDivertOpen")
		procRecv = dll.NewProc("WinDivertRecv")
		procSend = dll.NewProc("WinDivertSend")
		procRecvEx = dll.NewProc("WinDivertRecvEx")
		procSendEx = dll.NewProc("WinDivertSendEx")
		procShutdown = dll.NewProc("WinDivertShutdown")
		procClose = dll.NewProc("WinDivertClose")
		procSetParam = dll.NewProc("WinDivertSetParam")
	})
	return loadErr
}

// Open opens a WinDivert handle. priority is passed to the driver as INT16.
func Open(filter string, layer uint8, priority int16, flags uint64) (Handle, error) {
	if err := load(); err != nil {
		return 0, err
	}
	filterPtr, err := windows.BytePtrFromString(filter)
	if err != nil {
		return 0, err
	}
	r, _, callErr := procOpen.Call(
		uintptr(unsafe.Pointer(filterPtr)),
		uintptr(layer),
		uintptr(priority),
		uintptr(flags),
	)
	runtime.KeepAlive(filterPtr)
	if r == 0 || r == invalidHandle {
		if callErr == nil || callErr == windows.ERROR_SUCCESS {
			callErr = windows.ERROR_INVALID_HANDLE
		}
		return 0, fmt.Errorf("WinDivertOpen(%q): %s", filter, FormatError(callErr))
	}
	return Handle(r), nil
}

// Recv reads one event. buf may be nil for SOCKET and FLOW handles.
func (h Handle) Recv(buf []byte, addr *Address) (int, error) {
	if h == 0 {
		return 0, windows.ERROR_INVALID_HANDLE
	}
	var n uint32
	var pbuf uintptr
	if len(buf) > 0 {
		pbuf = uintptr(unsafe.Pointer(&buf[0]))
	}
	r, _, err := procRecv.Call(uintptr(h), pbuf, uintptr(len(buf)), uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(addr)))
	if r == 0 {
		if err == nil || err == windows.ERROR_SUCCESS {
			err = windows.ERROR_INVALID_HANDLE
		}
		return 0, err
	}
	return int(n), nil
}

// Send injects one packet.
func (h Handle) Send(buf []byte, addr *Address) error {
	if h == 0 {
		return windows.ERROR_INVALID_HANDLE
	}
	if len(buf) == 0 {
		return windows.ERROR_INVALID_PARAMETER
	}
	var n uint32
	r, _, err := procSend.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&n)),
		uintptr(unsafe.Pointer(addr)),
	)
	if r == 0 {
		if err == nil || err == windows.ERROR_SUCCESS {
			err = windows.ERROR_INVALID_HANDLE
		}
		return err
	}
	return nil
}

// RecvBatch reads up to len(addrs) packets (at most BatchMax) into buf with
// WinDivertRecvEx. The packets lie back to back in buf[:n] (see SplitBatch)
// and addrs[:count] are their addresses. It waits for one packet only: the
// driver adds the packets already queued that fit in buf.
func (h Handle) RecvBatch(buf []byte, addrs []Address) (n, count int, err error) {
	if h == 0 {
		return 0, 0, windows.ERROR_INVALID_HANDLE
	}
	if len(buf) == 0 || len(addrs) == 0 {
		return 0, 0, windows.ERROR_INVALID_PARAMETER
	}
	if len(addrs) > BatchMax {
		addrs = addrs[:BatchMax]
	}
	var recvLen uint32
	addrLen := uint32(len(addrs) * AddressSize)
	// The UINT64 flags argument fits one register: Ashgate is x64 only.
	r, _, err := procRecvEx.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&recvLen)),
		0,
		uintptr(unsafe.Pointer(&addrs[0])),
		uintptr(unsafe.Pointer(&addrLen)),
		0,
	)
	if r == 0 {
		if err == nil || err == windows.ERROR_SUCCESS {
			err = windows.ERROR_INVALID_HANDLE
		}
		return 0, 0, err
	}
	return int(recvLen), int(addrLen) / AddressSize, nil
}

// SendBatch injects the packets packed back to back in buf, one per
// address, with one WinDivertSendEx. The driver splits buf by the IP
// length fields; Batch.Add only takes packets whose length is right.
func (h Handle) SendBatch(buf []byte, addrs []Address) error {
	if h == 0 {
		return windows.ERROR_INVALID_HANDLE
	}
	if len(buf) == 0 || len(addrs) == 0 || len(addrs) > BatchMax {
		return windows.ERROR_INVALID_PARAMETER
	}
	var n uint32
	r, _, err := procSendEx.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&n)),
		0,
		uintptr(unsafe.Pointer(&addrs[0])),
		uintptr(len(addrs)*AddressSize),
		0,
	)
	if r == 0 {
		if err == nil || err == windows.ERROR_SUCCESS {
			err = windows.ERROR_INVALID_HANDLE
		}
		return err
	}
	return nil
}

// SetParam sets a WinDivert queue parameter.
func (h Handle) SetParam(param uint32, value uint64) error {
	r, _, err := procSetParam.Call(uintptr(h), uintptr(param), uintptr(value))
	if r == 0 {
		return err
	}
	return nil
}

// Shutdown unblocks Recv and Send.
func (h Handle) Shutdown(how uint32) error {
	if h == 0 {
		return nil
	}
	r, _, err := procShutdown.Call(uintptr(h), uintptr(how))
	if r == 0 {
		return err
	}
	return nil
}

// Close closes the handle.
func (h Handle) Close() error {
	if h == 0 {
		return nil
	}
	r, _, err := procClose.Call(uintptr(h))
	if r == 0 {
		return err
	}
	return nil
}

// ConfigureQueue raises the driver queue of the handle to its limits, so a
// burst of packets or socket events waits instead of being dropped. Each
// parameter is set even if another fails. Failures are ignored by the caller.
func (h Handle) ConfigureQueue() error {
	return errors.Join(
		h.SetParam(ParamQueueLength, QueueLengthMax),
		h.SetParam(ParamQueueTime, 8000),
		h.SetParam(ParamQueueSize, QueueSizeMax),
	)
}
