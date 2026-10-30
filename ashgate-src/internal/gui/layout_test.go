package gui

import (
	"testing"
	"unsafe"
)

func TestWin32LayoutAMD64(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Fatal("layout is specified for 64-bit pointers")
	}
	if unsafe.Sizeof(WndClassEx{}) != 80 || unsafe.Offsetof(WndClassEx{}.LpszClassName) != 64 {
		t.Fatalf("WNDCLASSEX size %d class %d", unsafe.Sizeof(WndClassEx{}), unsafe.Offsetof(WndClassEx{}.LpszClassName))
	}
	if unsafe.Offsetof(MinMaxInfo{}.MinTrack) != 24 {
		t.Fatal(unsafe.Offsetof(MinMaxInfo{}.MinTrack))
	}
	if unsafe.Sizeof(MonitorInfo{}) != 40 || unsafe.Offsetof(MonitorInfo{}.RcWork) != 20 {
		t.Fatalf("MONITORINFO size %d work %d", unsafe.Sizeof(MonitorInfo{}), unsafe.Offsetof(MonitorInfo{}.RcWork))
	}
	if unsafe.Sizeof(WindowPlacement{}) != 44 || unsafe.Offsetof(WindowPlacement{}.NormalPosition) != 28 {
		t.Fatalf("WINDOWPLACEMENT size %d normal %d", unsafe.Sizeof(WindowPlacement{}), unsafe.Offsetof(WindowPlacement{}.NormalPosition))
	}
	if unsafe.Sizeof(IconInfo{}) != 32 || unsafe.Offsetof(IconInfo{}.Mask) != 16 {
		t.Fatalf("ICONINFO size %d mask %d", unsafe.Sizeof(IconInfo{}), unsafe.Offsetof(IconInfo{}.Mask))
	}
	if unsafe.Sizeof(OpenFileName{}) != 152 || unsafe.Offsetof(OpenFileName{}.File) != 48 || unsafe.Offsetof(OpenFileName{}.FlagsEx) != 148 {
		t.Fatalf("OPENFILENAME size %d file %d flagsEx %d", unsafe.Sizeof(OpenFileName{}), unsafe.Offsetof(OpenFileName{}.File), unsafe.Offsetof(OpenFileName{}.FlagsEx))
	}
	n := NotifyIconData{}
	if unsafe.Sizeof(n) != 976 || unsafe.Offsetof(n.SzTip) != 40 || unsafe.Offsetof(n.HBalloonIcon) != 968 {
		t.Fatalf("NOTIFYICON size %d tip %d balloon %d", unsafe.Sizeof(n), unsafe.Offsetof(n.SzTip), unsafe.Offsetof(n.HBalloonIcon))
	}
}

func TestFitWindow(t *testing.T) {
	cases := []struct {
		name                           string
		w, h, minW, minH, workW, workH int32
		wantW, wantH                   int32
	}{
		{"default on a large desktop", 1100, 720, 760, 520, 1920, 1080, 1100, 720},
		{"raise a tiny saved size", 400, 300, 760, 520, 1920, 1080, 760, 520},
		{"cap to the work area minus 32", 2000, 2000, 760, 520, 1366, 768, 1334, 736},
		{"minimum wins when the desktop is smaller", 1100, 720, 760, 520, 700, 500, 760, 520},
		{"unknown work area only enforces the minimum", 100, 800, 760, 520, 0, 0, 760, 800},
	}
	for _, tc := range cases {
		gotW, gotH := fitWindow(tc.w, tc.h, tc.minW, tc.minH, tc.workW, tc.workH)
		if gotW != tc.wantW || gotH != tc.wantH {
			t.Errorf("%s: got %d×%d want %d×%d", tc.name, gotW, gotH, tc.wantW, tc.wantH)
		}
	}
}

func TestDIPScale(t *testing.T) {
	for _, dpi := range []int32{96, 120, 144, 192} {
		for _, dip := range []int32{minWindowDIPW, minWindowDIPH, defWindowDIPW, defWindowDIPH} {
			if pxToDip(dipToPx(dip, dpi), dpi) != dip {
				t.Errorf("dpi %d dip %d -> %d -> %d", dpi, dip, dipToPx(dip, dpi), pxToDip(dipToPx(dip, dpi), dpi))
			}
		}
	}
	if dipToPx(760, 144) != 1140 || dipToPx(520, 120) != 650 {
		t.Fatalf("144%% %d 125%% %d", dipToPx(760, 144), dipToPx(520, 120))
	}
}

func TestClampOrigin(t *testing.T) {
	x, y := clampOrigin(100, 80, 1100, 720, 0, 0, 1920, 1040)
	if x != 100 || y != 80 {
		t.Fatalf("inside: %d,%d", x, y)
	}
	x, y = clampOrigin(-40, -10, 800, 600, 0, 40, 1920, 1040)
	if x != 0 || y != 40 {
		t.Fatalf("pulled in: %d,%d", x, y)
	}
	x, y = clampOrigin(1500, 900, 800, 600, 0, 0, 1920, 1040)
	if x != 1120 || y != 440 {
		t.Fatalf("pulled back: %d,%d", x, y)
	}
	x, y = clampOrigin(50, 50, 800, 600, 0, 0, 700, 500)
	if x != 0 || y != 0 {
		t.Fatalf("larger than work: %d,%d", x, y)
	}
}

func TestApplyMinTrackLeavesMaximums(t *testing.T) {
	mmi := MinMaxInfo{
		MaxSize:     Point{X: 1920, Y: 1080},
		MaxPosition: Point{X: 0, Y: 40},
		MaxTrack:    Point{X: 8000, Y: 4000},
	}
	applyMinTrack(&mmi, 144, 16, 8)
	if mmi.MinTrack.X != 1140+16 || mmi.MinTrack.Y != 780+8 {
		t.Fatalf("min track %v", mmi.MinTrack)
	}
	if mmi.MaxSize.X != 1920 || mmi.MaxSize.Y != 1080 || mmi.MaxPosition.Y != 40 || mmi.MaxTrack.X != 8000 || mmi.MaxTrack.Y != 4000 {
		t.Fatalf("maximums changed: %+v", mmi)
	}
	applyMinTrack(nil, 96, 0, 0)
}
