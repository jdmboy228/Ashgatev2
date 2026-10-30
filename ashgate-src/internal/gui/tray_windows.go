//go:build windows

package gui

import (
	"fmt"
	"image/color"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

type trayRow struct {
	id     int
	y, h   int32
	label  string
	accent bool
	fill   bool
}

type trayState struct {
	added    bool
	hwnd     uintptr
	menu     uintptr
	iconRun  uintptr
	iconStop uintptr
	iconErr  uintptr
	logo     uintptr
	logoPx   int
	fontDPI  int32
	font13   uintptr
	font11   uintptr
	fontMed  uintptr
	dpi      int32
	tip      string
	cur      uintptr
	running  bool
	flows    int64
	errText  string
	hover    int
	class    *uint16
	cb       uintptr
	ready    bool
}

var tray trayState

func trayAdd(owner uintptr) error {
	tray.hwnd = owner
	// A retry (wmClose re-adds the icon when it is missing) must not leak
	// the handles of the previous attempt.
	freeStateIcons()
	px := 32
	if n, _, _ := pGetSystemMet.Call(49); n >= 16 { // SM_CXSMICON
		px = int(n)
	}
	base := LogoImage(px)
	var err error
	tray.iconStop, err = iconFromImage(base)
	if err != nil {
		return err
	}
	tray.iconRun, err = iconFromImage(withDot(base, color.NRGBA{R: 0x3D, G: 0xD6, B: 0x8C, A: 255}))
	if err != nil {
		return err
	}
	tray.iconErr, err = iconFromImage(withDot(base, color.NRGBA{R: 0xFF, G: 0x63, B: 0x63, A: 255}))
	if err != nil {
		return err
	}
	if !trayNotify(nimAdd, tray.iconStop, "Ashgate — Остановлен") {
		return fmt.Errorf("не удалось добавить значок в трей")
	}
	tray.added = true
	tray.cur = tray.iconStop
	tray.tip = "Ashgate — Остановлен"
	return nil
}

func trayRemove() {
	if tray.added {
		trayNotify(nimDelete, 0, "")
		tray.added = false
	}
	trayHideMenu()
	freeStateIcons()
	if tray.logo != 0 {
		pDestroyIcon.Call(tray.logo)
		tray.logo = 0
	}
	freeFonts()
}

// freeStateIcons destroys the running, stopped and error icons.
func freeStateIcons() {
	for _, ic := range []uintptr{tray.iconRun, tray.iconStop, tray.iconErr} {
		if ic != 0 {
			pDestroyIcon.Call(ic)
		}
	}
	tray.iconRun, tray.iconStop, tray.iconErr = 0, 0, 0
	tray.cur = 0
}

func trayUpdate(running bool, flows int64, errText string) {
	if !tray.added {
		return
	}
	icon := tray.iconStop
	tip := "Ashgate — Остановлен"
	switch {
	case running:
		icon = tray.iconRun
		tip = fmt.Sprintf("Ashgate — Работает · потоков: %d", flows)
	case errText != "":
		icon = tray.iconErr
		msg := errText
		if len([]rune(msg)) > 80 {
			msg = string([]rune(msg)[:80])
		}
		tip = "Ashgate — " + msg
	}
	changed := icon != tray.cur || tip != tray.tip || running != tray.running || flows != tray.flows || errText != tray.errText
	tray.running = running
	tray.flows = flows
	tray.errText = errText
	tray.cur = icon
	tray.tip = tip
	if changed {
		trayNotify(nimModify, icon, tip)
		if tray.menu != 0 {
			pInvalidate.Call(tray.menu, 0, 1)
		}
	}
}

func trayNotify(msg uint32, icon uintptr, tip string) bool {
	nid := NotifyIconData{
		CbSize:           uint32(unsafe.Sizeof(NotifyIconData{})),
		HWnd:             tray.hwnd,
		UID:              1,
		UFlags:           nifMessage | nifIcon | nifTip,
		UCallbackMessage: trayMsg,
		HIcon:            icon,
	}
	if msg == nimDelete {
		nid.UFlags = 0
	}
	u, err := windows.UTF16FromString(tip)
	if err == nil {
		if len(u) > len(nid.SzTip) {
			u = append(u[:len(nid.SzTip)-1], 0)
		}
		copy(nid.SzTip[:], u)
	}
	r, _, _ := pNotifyIcon.Call(uintptr(msg), uintptr(unsafe.Pointer(&nid)))
	return r != 0
}

func trayShowMenu() {
	if appHost == nil {
		return
	}
	ensureTrayClass()
	dpi := windowDPI(appHost.hwnd)
	w, h := menuSize(dpi)
	var pt Point
	pGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	vx, _, _ := pGetSystemMet.Call(76)
	vy, _, _ := pGetSystemMet.Call(77)
	vw, _, _ := pGetSystemMet.Call(78)
	vh, _, _ := pGetSystemMet.Call(79)
	x := pt.X
	y := pt.Y - h - 8
	if x+w > int32(vx)+int32(vw) {
		x = int32(vx) + int32(vw) - w - 8
	}
	if x < int32(vx) {
		x = int32(vx)
	}
	if y < int32(vy) {
		y = pt.Y + 8
	}
	if y+h > int32(vy)+int32(vh) {
		y = int32(vy) + int32(vh) - h - 8
	}
	if tray.menu == 0 {
		title, _ := windows.UTF16PtrFromString("Ashgate")
		var inst windows.Handle
		_ = windows.GetModuleHandleEx(0, nil, &inst)
		hwnd, _, _ := pCreateWindowEx.Call(
			wsExTopmost|wsExTool,
			uintptr(unsafe.Pointer(tray.class)),
			uintptr(unsafe.Pointer(title)),
			wsPopup,
			uintptr(x), uintptr(y), uintptr(w), uintptr(h),
			appHost.hwnd, 0, uintptr(inst), 0,
		)
		runtime.KeepAlive(title)
		if hwnd == 0 {
			return
		}
		tray.menu = hwnd
	}
	tray.dpi = dpi
	tray.hover = 2
	ensureFonts(dpi)
	ensureLogo(dpi)
	pSetWindowPos.Call(tray.menu, ^uintptr(0), uintptr(x), uintptr(y), uintptr(w), uintptr(h), swpShowWindow)
	rgn, _, _ := pCreateRgn.Call(0, 0, uintptr(w+1), uintptr(h+1), uintptr(dp(16, dpi)), uintptr(dp(16, dpi)))
	if rgn != 0 {
		pSetWindowRgn.Call(tray.menu, rgn, 1)
	}
	pSetForeground.Call(tray.menu)
}

func trayHideMenu() {
	if tray.menu != 0 {
		pShowWindow.Call(tray.menu, swHide)
	}
}

func ensureTrayClass() {
	if tray.ready {
		return
	}
	tray.cb = windows.NewCallback(trayProc)
	name, _ := windows.UTF16PtrFromString("AshgateTrayMenu")
	tray.class = name
	bg, _, _ := pCreateBrush.Call(bgr(0x2B, 0x2B, 0x32))
	cur, _, _ := pLoadCursor.Call(0, 32512)
	var inst windows.Handle
	_ = windows.GetModuleHandleEx(0, nil, &inst)
	wc := WndClassEx{
		CbSize:        uint32(unsafe.Sizeof(WndClassEx{})),
		LpfnWndProc:   tray.cb,
		HInstance:     uintptr(inst),
		HCursor:       cur,
		HbrBackground: bg,
		LpszClassName: name,
	}
	pRegisterClass.Call(uintptr(unsafe.Pointer(&wc)))
	tray.ready = true
}

func trayProc(hwnd, msg, wp, lp uintptr) uintptr {
	switch msg {
	case wmPaint:
		var ps [80]byte
		hdc, _, _ := pBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps[0])))
		paintMenu(hdc)
		pEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps[0])))
		return 0
	case wmMouseMove:
		x, y := loHi(lp)
		id := hitRow(x, y)
		if id != tray.hover {
			tray.hover = id
			pInvalidate.Call(hwnd, 0, 0)
		}
		var tme struct {
			Size      uint32
			Flags     uint32
			HwndTrack uintptr
			HoverTime uint32
		}
		tme.Size = uint32(unsafe.Sizeof(tme))
		tme.Flags = 2
		tme.HwndTrack = hwnd
		pTrackMouse.Call(uintptr(unsafe.Pointer(&tme)))
		return 0
	case wmMouseLeave:
		tray.hover = 0
		pInvalidate.Call(hwnd, 0, 0)
		return 0
	case wmLButtonDown:
		return 0
	case wmLButtonUp:
		x, y := loHi(lp)
		id := hitRow(x, y)
		if id != 0 {
			trayAct(id)
		}
		return 0
	case wmKeyDown:
		if wp == 0x1B {
			trayHideMenu()
		}
		if wp == 0x0D {
			id := tray.hover
			if id == 0 {
				id = 2
			}
			trayAct(id)
		}
		return 0
	case wmActivate:
		if wp == 0 {
			trayHideMenu()
		}
		return 0
	case wmClose:
		trayHideMenu()
		return 0
	}
	r, _, _ := pDefWindowProc.Call(hwnd, msg, wp, lp)
	return r
}

func trayAct(id int) {
	trayHideMenu()
	switch id {
	case 1:
		showMain()
	case 2:
		go toggleEngine()
	case 3:
		hostQuit()
	}
}

func paintMenu(hdc uintptr) {
	dpi := tray.dpi
	if dpi < 96 {
		dpi = 96
	}
	w, h := menuSize(dpi)
	pSetBkMode.Call(hdc, 1)
	bg, _, _ := pCreateBrush.Call(bgr(0x2B, 0x2B, 0x32))
	fill(hdc, bg, 0, 0, w, h)
	pDeleteObject.Call(bg)

	logo := dp(24, dpi)
	if tray.logo != 0 {
		pDrawIconEx.Call(hdc, uintptr(dp(14, dpi)), uintptr(dp(16, dpi)), tray.logo, uintptr(logo), uintptr(logo), 0, 0, 3)
	}
	drawText(hdc, "Ashgate", rect(dp(48, dpi), dp(10, dpi), w-dp(12, dpi), dp(28, dpi)), bgr(0xEE, 0xEE, 0xF2), tray.fontMed, 0x824)
	status, dot := menuStatus()
	drawText(hdc, status, rect(dp(60, dpi), dp(28, dpi), w-dp(12, dpi), dp(48, dpi)), bgr(0x6E, 0x6E, 0x7A), tray.font11, 0x824)
	dotBrush, _, _ := pCreateBrush.Call(dot)
	dotPen, _, _ := pCreatePen.Call(0, 1, dot)
	oldB, _, _ := pSelectObject.Call(hdc, dotBrush)
	oldP, _, _ := pSelectObject.Call(hdc, dotPen)
	dx, dy, ds := dp(48, dpi), dp(36, dpi), dp(6, dpi)
	pEllipse.Call(hdc, uintptr(dx), uintptr(dy), uintptr(dx+ds), uintptr(dy+ds))
	pSelectObject.Call(hdc, oldB)
	pSelectObject.Call(hdc, oldP)
	pDeleteObject.Call(dotBrush)
	pDeleteObject.Call(dotPen)

	sep(hdc, w, dp(56, dpi))
	for _, row := range menuRows(dpi) {
		if row.fill || tray.hover == row.id {
			col := bgr(0x38, 0x38, 0x3E)
			if tray.hover == row.id {
				col = bgr(0x49, 0x49, 0x50)
			}
			br, _, _ := pCreateBrush.Call(col)
			pen, _, _ := pCreatePen.Call(0, 1, col)
			ob, _, _ := pSelectObject.Call(hdc, br)
			op, _, _ := pSelectObject.Call(hdc, pen)
			rad := dp(8, dpi)
			x1, y1 := dp(4, dpi), row.y
			pRoundRect.Call(hdc, uintptr(x1), uintptr(y1), uintptr(w-dp(4, dpi)), uintptr(y1+row.h), uintptr(rad), uintptr(rad))
			pSelectObject.Call(hdc, ob)
			pSelectObject.Call(hdc, op)
			pDeleteObject.Call(br)
			pDeleteObject.Call(pen)
		}
		col := bgr(0xEE, 0xEE, 0xF2)
		font := tray.font13
		if row.accent {
			col = bgr(0xFF, 0x7A, 0x45)
			font = tray.fontMed
		}
		drawText(hdc, row.label, rect(dp(40, dpi), row.y, w-dp(12, dpi), row.y+row.h), col, font, 0x824)
	}
	sep(hdc, w, dp(135, dpi))
}

func sep(hdc uintptr, w, y int32) {
	br, _, _ := pCreateBrush.Call(bgr(0x3A, 0x3A, 0x42))
	fill(hdc, br, 0, y, w, y+1)
	pDeleteObject.Call(br)
}

func fill(hdc, brush uintptr, l, t, r, b int32) {
	rc := Rect{Left: l, Top: t, Right: r, Bottom: b}
	pFillRect.Call(hdc, uintptr(unsafe.Pointer(&rc)), brush)
}

func drawText(hdc uintptr, s string, r Rect, color, font, flags uintptr) {
	if font != 0 {
		pSelectObject.Call(hdc, font)
	}
	pSetTextColor.Call(hdc, color)
	u, err := windows.UTF16PtrFromString(s)
	if err != nil {
		return
	}
	pDrawText.Call(hdc, uintptr(unsafe.Pointer(u)), ^uintptr(0), uintptr(unsafe.Pointer(&r)), flags)
	runtime.KeepAlive(u)
}

func rect(l, t, r, b int32) Rect { return Rect{Left: l, Top: t, Right: r, Bottom: b} }

func menuStatus() (string, uintptr) {
	if tray.running {
		return fmt.Sprintf("Работает · потоков: %d", tray.flows), bgr(0x3D, 0xD6, 0x8C)
	}
	if tray.errText != "" {
		return "Ошибка", bgr(0xFF, 0x63, 0x63)
	}
	return "Остановлен", bgr(0x6E, 0x6E, 0x7A)
}

func menuRows(dpi int32) []trayRow {
	power := "Стоп"
	accent := false
	if !tray.running {
		power = "Старт"
		accent = true
	}
	return []trayRow{
		{id: 1, y: dp(61, dpi), h: dp(34, dpi), label: "Открыть"},
		{id: 2, y: dp(97, dpi), h: dp(34, dpi), label: power, accent: accent, fill: true},
		{id: 3, y: dp(140, dpi), h: dp(34, dpi), label: "Выход"},
	}
}

func hitRow(x, y int32) int {
	dpi := tray.dpi
	if dpi < 96 {
		dpi = 96
	}
	w, _ := menuSize(dpi)
	if x < dp(4, dpi) || x > w-dp(4, dpi) {
		return 0
	}
	for _, row := range menuRows(dpi) {
		if y >= row.y && y < row.y+row.h {
			return row.id
		}
	}
	return 0
}

func menuSize(dpi int32) (int32, int32) {
	return dp(232, dpi), dp(178, dpi)
}

func dp(v, dpi int32) int32 {
	if dpi < 96 {
		dpi = 96
	}
	return v * dpi / 96
}

func bgr(r, g, b byte) uintptr {
	return uintptr(r) | uintptr(g)<<8 | uintptr(b)<<16
}

func loHi(lp uintptr) (int32, int32) {
	return int32(int16(lp & 0xFFFF)), int32(int16((lp >> 16) & 0xFFFF))
}

func ensureFonts(dpi int32) {
	if tray.font13 != 0 && tray.fontDPI == dpi {
		return
	}
	freeFonts()
	tray.font13 = makeFont(13, dpi, 400)
	tray.font11 = makeFont(11, dpi, 400)
	tray.fontMed = makeFont(13, dpi, 600)
	tray.fontDPI = dpi
}

func freeFonts() {
	for _, f := range []uintptr{tray.font13, tray.font11, tray.fontMed} {
		if f != 0 {
			pDeleteObject.Call(f)
		}
	}
	tray.font13, tray.font11, tray.fontMed = 0, 0, 0
	tray.fontDPI = 0
}

func makeFont(px, dpi int32, weight uintptr) uintptr {
	name, _ := windows.UTF16PtrFromString("Segoe UI")
	h := -px * dpi / 96
	f, _, _ := pCreateFont.Call(uintptr(h), 0, 0, 0, weight, 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(name)))
	runtime.KeepAlive(name)
	return f
}

func ensureLogo(dpi int32) {
	px := int(dp(24, dpi))
	if px < 16 {
		px = 16
	}
	if tray.logo != 0 && tray.logoPx == px {
		return
	}
	if tray.logo != 0 {
		pDestroyIcon.Call(tray.logo)
		tray.logo = 0
	}
	if ic, err := iconFromImage(LogoImage(px)); err == nil {
		tray.logo = ic
		tray.logoPx = px
	}
}
