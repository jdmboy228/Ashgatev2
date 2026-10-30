//go:build windows

package process

import (
	"bytes"
	"errors"
	"image"
	"image/png"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modShell32           = windows.NewLazySystemDLL("shell32.dll")
	modUser32            = windows.NewLazySystemDLL("user32.dll")
	modGdi32             = windows.NewLazySystemDLL("gdi32.dll")
	procExtractIconExW   = modShell32.NewProc("ExtractIconExW")
	procSHGetFileInfoW   = modShell32.NewProc("SHGetFileInfoW")
	procDestroyIcon      = modUser32.NewProc("DestroyIcon")
	procGetDC            = modUser32.NewProc("GetDC")
	procReleaseDC        = modUser32.NewProc("ReleaseDC")
	procDrawIconEx       = modUser32.NewProc("DrawIconEx")
	procCreateCompatDC   = modGdi32.NewProc("CreateCompatibleDC")
	procCreateDIBSection = modGdi32.NewProc("CreateDIBSection")
	procSelectObject     = modGdi32.NewProc("SelectObject")
	procDeleteDC         = modGdi32.NewProc("DeleteDC")
	procDeleteObject     = modGdi32.NewProc("DeleteObject")
)

const (
	diNormal       = 3
	shgfiIcon      = 0x000000100
	shgfiLargeIcon = 0x000000000
)

// shFileInfo is SHFILEINFOW.
type shFileInfo struct {
	Icon        uintptr
	IconIndex   int32
	Attributes  uint32
	DisplayName [260]uint16
	TypeName    [80]uint16
}

type bitmapInfoHeader struct {
	Size          uint32
	Width         int32
	Height        int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
}

// ExeIconPNG extracts the first icon of a Windows executable as a 32×32 PNG.
func ExeIconPNG(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("пустой путь")
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var large, small uintptr
	r, _, callErr := procExtractIconExW.Call(
		uintptr(unsafe.Pointer(p)),
		0,
		uintptr(unsafe.Pointer(&large)),
		uintptr(unsafe.Pointer(&small)),
		1,
	)
	if small != 0 {
		defer procDestroyIcon.Call(small)
	}
	if r == 0 || large == 0 {
		// No icon of its own (curl.exe, helpers): take the one Explorer
		// shows, which for such an exe is the generic program icon.
		if png, err := shellIconPNG(p); err == nil {
			return png, nil
		}
		if callErr != nil && callErr != windows.ERROR_SUCCESS {
			return nil, callErr
		}
		return nil, errors.New("у файла нет иконки")
	}
	defer procDestroyIcon.Call(large)
	return hiconPNG(large, 32)
}

func shellIconPNG(path *uint16) ([]byte, error) {
	var info shFileInfo
	r, _, _ := procSHGetFileInfoW.Call(
		uintptr(unsafe.Pointer(path)),
		0,
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
		shgfiIcon|shgfiLargeIcon,
	)
	if r == 0 || info.Icon == 0 {
		return nil, errors.New("у файла нет иконки")
	}
	defer procDestroyIcon.Call(info.Icon)
	return hiconPNG(info.Icon, 32)
}

func hiconPNG(icon uintptr, size int) ([]byte, error) {
	hdc, _, _ := procGetDC.Call(0)
	if hdc == 0 {
		return nil, errors.New("нет контекста экрана")
	}
	defer procReleaseDC.Call(0, hdc)
	mem, _, _ := procCreateCompatDC.Call(hdc)
	if mem == 0 {
		return nil, errors.New("не удалось создать контекст")
	}
	defer procDeleteDC.Call(mem)

	bi := bitmapInfoHeader{
		Size: 40, Width: int32(size), Height: -int32(size),
		Planes: 1, BitCount: 32,
	}
	var bits uintptr
	bmp, _, _ := procCreateDIBSection.Call(mem, uintptr(unsafe.Pointer(&bi)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if bmp == 0 || bits == 0 {
		return nil, errors.New("не удалось создать изображение")
	}
	defer procDeleteObject.Call(bmp)
	prev, _, _ := procSelectObject.Call(mem, bmp)
	defer procSelectObject.Call(mem, prev)
	ok, _, _ := procDrawIconEx.Call(mem, 0, 0, icon, uintptr(size), uintptr(size), 0, 0, diNormal)
	if ok == 0 {
		return nil, errors.New("не удалось нарисовать иконку")
	}
	n := size * size * 4
	raw := unsafe.Slice((*byte)(unsafe.Pointer(bits)), n)
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	for i := 0; i < size*size; i++ {
		b := raw[i*4]
		g := raw[i*4+1]
		r := raw[i*4+2]
		a := raw[i*4+3]
		img.Pix[i*4] = r
		img.Pix[i*4+1] = g
		img.Pix[i*4+2] = b
		img.Pix[i*4+3] = a
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
