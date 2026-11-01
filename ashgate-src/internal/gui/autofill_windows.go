//go:build windows

package gui

import (
	"errors"
	"fmt"
	"reflect"
	"syscall"
	"unsafe"

	"github.com/jchv/go-webview2"
	"github.com/jchv/go-webview2/pkg/edge"
	"golang.org/x/sys/windows"
)

// WebView2 keeps what is typed into text fields as form history in its
// profile ("Web Data" under %LOCALAPPDATA%\Ashgate\WebView2), a folder any
// program of the user can read without elevation. The proxy dialog takes
// VLESS links, UUIDs, keys, logins and subscription URLs, and WebView2
// saves them even with autocomplete="off". So general autofill and password
// saving are switched off in the WebView2 settings (ICoreWebView2Settings4).
// go-webview2 has the vtable slots but no methods, and keeps its browser
// object in an unexported field, hence the reflection.

// IID_ICoreWebView2Settings4
var iidSettings4 = windows.GUID{Data1: 0xfdb5ab74, Data2: 0xaf33, Data3: 0x4854,
	Data4: [8]byte{0x84, 0xf0, 0x0a, 0x63, 0x1d, 0xeb, 0x5e, 0xba}}

// comObject is any COM interface pointer: its first word is the vtable.
type comObject struct{ vtbl *[29]uintptr }

// Vtable slots of ICoreWebView2Settings4: IUnknown (3), Settings (18),
// Settings2 (2), Settings3 (2), then get/put IsPasswordAutosaveEnabled and
// get/put IsGeneralAutofillEnabled.
const (
	slotQueryInterface      = 0
	slotRelease             = 2
	slotPutPasswordAutosave = 26
	slotPutGeneralAutofill  = 28
)

func disableAutofill(w webview2.WebView) error {
	v := reflect.ValueOf(w)
	if v.Kind() != reflect.Pointer || v.Elem().Kind() != reflect.Struct {
		return errors.New("go-webview2: unexpected WebView type")
	}
	f := v.Elem().FieldByName("browser")
	if !f.IsValid() || !f.CanAddr() {
		return errors.New("go-webview2: no browser field")
	}
	f = reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem()
	ch, ok := f.Interface().(*edge.Chromium)
	if !ok || ch == nil {
		return errors.New("go-webview2: the browser is not Chromium")
	}
	s, err := ch.GetSettings()
	if err != nil || s == nil {
		return fmt.Errorf("WebView2 settings: %v", err)
	}
	unk := (*comObject)(unsafe.Pointer(s))
	var s4 *comObject
	hr, _, _ := syscall.SyscallN(unk.vtbl[slotQueryInterface], uintptr(unsafe.Pointer(unk)),
		uintptr(unsafe.Pointer(&iidSettings4)), uintptr(unsafe.Pointer(&s4)))
	if hr != 0 || s4 == nil {
		return fmt.Errorf("ICoreWebView2Settings4 not available (0x%x)", hr)
	}
	defer syscall.SyscallN(s4.vtbl[slotRelease], uintptr(unsafe.Pointer(s4)))
	for _, slot := range []int{slotPutGeneralAutofill, slotPutPasswordAutosave} {
		if hr, _, _ := syscall.SyscallN(s4.vtbl[slot], uintptr(unsafe.Pointer(s4)), 0); hr != 0 {
			return fmt.Errorf("WebView2 settings slot %d: 0x%x", slot, hr)
		}
	}
	return nil
}
