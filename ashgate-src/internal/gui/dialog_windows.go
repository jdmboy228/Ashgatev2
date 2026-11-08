//go:build windows

package gui

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	comdlg32         = windows.NewLazySystemDLL("comdlg32.dll")
	pGetOpenFileName = comdlg32.NewProc("GetOpenFileNameW")
	pCommDlgError    = comdlg32.NewProc("CommDlgExtendedError")
)

// openExe asks for an application file. An empty path means the user cancelled.
func openExe(owner uintptr) (string, error) {
	buf := make([]uint16, 32768)
	filter := utf16Multi("Программы (*.exe)", "*.exe", "Все файлы", "*.*")
	title, err := windows.UTF16PtrFromString("Выбор приложения")
	if err != nil {
		return "", err
	}
	ofn := OpenFileName{
		StructSize: uint32(unsafe.Sizeof(OpenFileName{})),
		Owner:      owner,
		Filter:     &filter[0],
		File:       &buf[0],
		MaxFile:    uint32(len(buf)),
		Flags:      0x00080000 | 0x00001000 | 0x00000800 | 0x00000008,
		Title:      title,
	}
	r, _, _ := pGetOpenFileName.Call(uintptr(unsafe.Pointer(&ofn)))
	if r == 0 {
		// Zero means the user closed the dialog. The thread's last error is
		// stale here and said nothing about the dialog.
		if code, _, _ := pCommDlgError.Call(); code != 0 {
			return "", fmt.Errorf("окно выбора файла не открылось (код %#x)", code)
		}
		return "", nil
	}
	return windows.UTF16ToString(buf), nil
}

func utf16Multi(parts ...string) []uint16 {
	var out []uint16
	for _, p := range parts {
		u, err := windows.UTF16FromString(p)
		if err != nil {
			continue
		}
		out = append(out, u...)
	}
	return append(out, 0)
}
