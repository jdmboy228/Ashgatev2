//go:build windows

package gui

import (
	"errors"
	"image"
	"image/color"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	gdi32         = windows.NewLazySystemDLL("gdi32.dll")
	pGetDC        = user32.NewProc("GetDC")
	pReleaseDC    = user32.NewProc("ReleaseDC")
	pCreateDIB    = gdi32.NewProc("CreateDIBSection")
	pCreateBitmap = gdi32.NewProc("CreateBitmap")
	pDeleteObject = gdi32.NewProc("DeleteObject")
	pCreateIcon   = user32.NewProc("CreateIconIndirect")
	pDestroyIcon  = user32.NewProc("DestroyIcon")
)

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

func iconFromImage(img *image.NRGBA) (uintptr, error) {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	hdc, _, _ := pGetDC.Call(0)
	if hdc != 0 {
		defer pReleaseDC.Call(0, hdc)
	}
	bi := bitmapInfoHeader{Size: 40, Width: int32(w), Height: -int32(h), Planes: 1, BitCount: 32}
	var bits unsafe.Pointer
	colorBmp, _, _ := pCreateDIB.Call(hdc, uintptr(unsafe.Pointer(&bi)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	runtime.KeepAlive(&bi)
	if colorBmp == 0 || bits == nil {
		if colorBmp != 0 {
			pDeleteObject.Call(colorBmp)
		}
		return 0, errors.New("не удалось собрать значок")
	}
	pix := unsafe.Slice((*byte)(bits), w*h*4)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			p := img.NRGBAAt(b.Min.X+x, b.Min.Y+y)
			i := (y*w + x) * 4
			pix[i] = p.B
			pix[i+1] = p.G
			pix[i+2] = p.R
			pix[i+3] = p.A
		}
	}
	mask, _, _ := pCreateBitmap.Call(uintptr(w), uintptr(h), 1, 1, 0)
	ii := IconInfo{Icon: 1, Mask: mask, Color: colorBmp}
	hicon, _, _ := pCreateIcon.Call(uintptr(unsafe.Pointer(&ii)))
	runtime.KeepAlive(&ii)
	pDeleteObject.Call(colorBmp)
	if mask != 0 {
		pDeleteObject.Call(mask)
	}
	if hicon == 0 {
		return 0, errors.New("не удалось собрать значок")
	}
	return hicon, nil
}

func withDot(src *image.NRGBA, c color.NRGBA) *image.NRGBA {
	dst := image.NewNRGBA(src.Bounds())
	copy(dst.Pix, src.Pix)
	w, h := dst.Bounds().Dx(), dst.Bounds().Dy()
	r := w / 7
	if r < 2 {
		r = 2
	}
	cx, cy := w-r-2, h-r-2
	for y := cy - r - 1; y <= cy+r+1; y++ {
		for x := cx - r - 1; x <= cx+r+1; x++ {
			if x < 0 || y < 0 || x >= w || y >= h {
				continue
			}
			dx, dy := x-cx, y-cy
			if dx*dx+dy*dy <= (r+1)*(r+1) {
				dst.SetNRGBA(x, y, color.NRGBA{R: 14, G: 15, B: 19, A: 255})
			}
			if dx*dx+dy*dy <= r*r {
				dst.SetNRGBA(x, y, c)
			}
		}
	}
	return dst
}
