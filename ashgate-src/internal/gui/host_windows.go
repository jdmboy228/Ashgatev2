//go:build windows

package gui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"ashgate/internal/atomicfile"
	"ashgate/internal/autostart"
	"ashgate/internal/bootstrap"
	"ashgate/internal/config"
	"ashgate/internal/killswitch"
	"ashgate/internal/logbuf"
	"ashgate/internal/service"
	"github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
)

const webviewMissing = "Не найден WebView2 Runtime. Установите Microsoft Edge WebView2:\nhttps://developer.microsoft.com/microsoft-edge/webview2/"

// host is the single GUI process: local page, WebView2 window, tray.
type host struct {
	path      string
	logs      *logbuf.Buffer
	ctrl      *controller
	w         webview2.WebView
	hwnd      uintptr
	orig      uintptr
	quitting  bool
	iconBig   uintptr
	iconSmall uintptr
	cb        uintptr
	// Last restored (not maximized, not minimized) outer rectangle, physical pixels.
	normalX, normalY int32
	normalW, normalH int32
	normalDPI        int32
	maximized        bool
	// shown is whether the page was last told the window is on screen; the
	// page stops polling while hidden. UI thread only.
	shown bool
}

// windowState is window.json beside the config. W/H are DIP; X/Y are screen pixels.
// It is not part of config.json, so the config version stays 1.
type windowState struct {
	X   int32 `json:"x"`
	Y   int32 `json:"y"`
	W   int32 `json:"w"`
	H   int32 `json:"h"`
	Max bool  `json:"max,omitempty"`
}

var appHost *host

// Run opens the window and blocks until the user exits from the tray menu.
func Run(configPath string, startCapture bool) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	release, already := claimInstance()
	if already {
		return nil
	}
	defer release()
	if configPath == "" {
		configPath = config.DefaultPath()
	}
	cfg, err := config.LoadOrInit(configPath)
	if err != nil {
		alert(err.Error())
		return err
	}
	bootstrap.Default.SetFile(bootstrap.CacheFile(configPath))
	// After an update (ashgate quit) capture comes back as it was. Read
	// after LoadOrInit, which locks down the shared folder first.
	if consumeResume(configPath) {
		startCapture = true
	}
	logs, logErr := openLog(cfg, configPath)
	h := &host{path: configPath, logs: logs}
	appHost = h
	notice := retireService(configPath, logs)
	h.ctrl = newController(configPath, cfg, logs, hooks{
		admin:        isAdmin(),
		window:       h.window,
		browse:       h.browse,
		autostart:    autostart.Enabled,
		setAutostart: h.setAutostart,
		firewall:     killswitch.New(killswitch.StatePath(configPath)),
		guard:        killswitch.StartGuard,
		visible:      h.onScreen,
	})
	// Registered before anything below can fail, so an early return still
	// stops capture and the VLESS bridges and closes the log.
	defer func() {
		_ = h.ctrl.stop()
		h.ctrl.shutdown()
		if h.logs != nil {
			_ = h.logs.Close()
		}
	}()
	h.ctrl.setNotice(notice)
	if logErr != nil {
		h.ctrl.mu.Lock()
		h.ctrl.errText = logErr.Error()
		h.ctrl.mu.Unlock()
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		alert(err.Error())
		return err
	}
	srv := &http.Server{
		Handler:           h.ctrl.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      60 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	data := webViewDataDir()
	_ = os.MkdirAll(data, 0o700)

	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		DataPath:  data,
		WindowOptions: webview2.WindowOptions{
			Title:  "Ashgate",
			Width:  defWindowDIPW,
			Height: defWindowDIPH,
			Center: true,
		},
	})
	if w == nil {
		dismissBlankWebView()
		// Destroying the blank window posted WM_QUIT (go-webview2 quits on
		// WM_DESTROY); a message box opened with it queued closes at once,
		// and the user never sees why Ashgate did not start.
		dropQuitMessage()
		alert(webviewMissing)
		return errors.New(webviewMissing)
	}
	h.w = w
	if err := disableAutofill(w); err != nil && h.logs != nil {
		h.logs.Add(logbuf.Event{Process: "ashgate", Status: "error", Error: "WebView2: не удалось выключить автозаполнение: " + err.Error()})
	}
	h.hwnd = uintptr(w.Window())
	pShowWindow.Call(h.hwnd, swHide)
	// Subclass before the first resize so WM_NCCALCSIZE drops the caption
	// frame and WM_GETMINMAXINFO already enforces the DIP minimum.
	h.subclass()
	styleWindow(h.hwnd)
	h.installIcons()
	_ = w.Bind("ashgateDrag", func() { pPostMessage.Call(h.hwnd, wmDrag, 0, 0) })
	_ = w.Bind("ashgateMin", func() { pPostMessage.Call(h.hwnd, wmMin, 0, 0) })
	_ = w.Bind("ashgateMax", func() { pPostMessage.Call(h.hwnd, wmMax, 0, 0) })
	_ = w.Bind("ashgateClose", func() { pPostMessage.Call(h.hwnd, wmClose, 0, 0) })
	// The window has no top frame, so the page's title bar resizes from the top edge.
	_ = w.Bind("ashgateResize", func(edge string) {
		if ht := topEdgeHit(edge); ht != 0 {
			pPostMessage.Call(h.hwnd, wmResize, ht, 0)
		}
	})
	// Hand the API token to the page before it loads, and only to it: the
	// script runs in every document the WebView opens, and a dropped file or
	// link would be another one. json.Marshal yields safe string literals.
	tok, _ := json.Marshal(h.ctrl.token)
	origin, _ := json.Marshal("http://" + ln.Addr().String())
	w.Init("if(location.origin===" + string(origin) + ")window.__ashgateToken=" + string(tok) + ";")
	if err := trayAdd(h.hwnd); err != nil {
		h.ctrl.mu.Lock()
		if h.ctrl.errText == "" {
			h.ctrl.errText = err.Error()
		}
		h.ctrl.mu.Unlock()
	}
	pSetTimer.Call(h.hwnd, 1, 1000, 0)
	if startCapture {
		go func() { _ = h.ctrl.start() }()
	}
	w.Navigate("http://" + ln.Addr().String() + "/")
	cmd := uintptr(swShow)
	if startCapture {
		cmd = swRestore
	}
	pShowWindow.Call(h.hwnd, cmd)
	w.Run()
	trayRemove()
	if h.iconBig != 0 {
		pDestroyIcon.Call(h.iconBig)
	}
	if h.iconSmall != 0 {
		pDestroyIcon.Call(h.iconSmall)
	}
	return nil
}

func openLog(cfg *config.Config, path string) (*logbuf.Buffer, error) {
	file := cfg.Log.File
	if file == "" {
		file = filepath.Join(filepath.Dir(path), "ashgate.log")
	}
	logs, err := logbuf.New(2000, file)
	if err != nil {
		logs, _ = logbuf.New(2000, "")
		return logs, err
	}
	return logs, nil
}

func (h *host) window(op string) {
	var msg uintptr
	switch strings.ToLower(op) {
	case "drag":
		msg = wmDrag
	case "min":
		msg = wmMin
	case "max":
		msg = wmMax
	case "close":
		msg = wmClose
	default:
		return
	}
	if h.hwnd != 0 {
		pPostMessage.Call(h.hwnd, msg, 0, 0)
	}
}

func (h *host) browse() (string, error) {
	if h.w == nil {
		return "", errors.New("выбор файла доступен в окне Windows")
	}
	type result struct {
		path string
		err  error
	}
	ch := make(chan result, 1)
	h.w.Dispatch(func() {
		p, err := openExe(h.hwnd)
		ch <- result{p, err}
	})
	res := <-ch
	return res.path, res.err
}

func (h *host) setAutostart(on bool) error {
	if on {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		return autostart.Enable(exe, h.path)
	}
	return autostart.Disable()
}

func retireService(configPath string, logs *logbuf.Buffer) string {
	existed, wasAuto, err := service.RemoveLegacy()
	if err != nil && !existed {
		if logs != nil {
			logs.Add(logbuf.Event{Process: "ashgate", Status: "error", Error: "не удалось проверить службу Ashgate: " + err.Error()})
		}
		return ""
	}
	if !existed {
		return ""
	}
	if wasAuto {
		if exe, exErr := os.Executable(); exErr == nil {
			if enErr := autostart.Enable(exe, configPath); enErr != nil && logs != nil {
				logs.Add(logbuf.Event{Process: "ashgate", Status: "error", Error: "не удалось включить автозапуск окна: " + enErr.Error()})
			}
		}
	}
	if err != nil {
		if logs != nil {
			logs.Add(logbuf.Event{Process: "ashgate", Status: "error", Error: "не удалось удалить службу Ashgate: " + err.Error()})
		}
		return ""
	}
	const msg = "Старая служба Ashgate удалена, теперь автозапуск открывает окно"
	if logs != nil {
		logs.Add(logbuf.Event{Process: "ashgate", Status: "info", Error: msg})
	}
	return msg
}

func (h *host) subclass() {
	prev, _, _ := pGetWindowLong.Call(h.hwnd, gwlpWndProc)
	h.orig = prev
	h.cb = windows.NewCallback(hostProc)
	pSetWindowLong.Call(h.hwnd, gwlpWndProc, h.cb)
}

func (h *host) installIcons() {
	if big, err := iconFromImage(LogoImage(32)); err == nil {
		pSendMessage.Call(h.hwnd, wmSetIcon, 1, big)
		h.iconBig = big
	}
	if small, err := iconFromImage(LogoImage(16)); err == nil {
		pSendMessage.Call(h.hwnd, wmSetIcon, 0, small)
		h.iconSmall = small
	}
}

func hostProc(hwnd, msg, wp, lp uintptr) uintptr {
	h := appHost
	if h == nil || h.orig == 0 {
		r, _, _ := pDefWindowProc.Call(hwnd, msg, wp, lp)
		return r
	}
	switch msg {
	case wmShow:
		if !h.quitting {
			showMain()
		}
		return 0
	case wmQuitReq:
		// An update is replacing this exe. If capture is on, leave a mark so
		// the new version turns it back on at start.
		if h.ctrl != nil {
			if on, _, _ := h.ctrl.running(); on {
				_ = markResume(h.path)
			}
		}
		hostQuit()
		return 0
	case wmClose:
		if !h.quitting {
			if !tray.added {
				if err := trayAdd(hwnd); err != nil {
					hostQuit()
					return 0
				}
			}
			h.noteNormal()
			h.saveWindow()
			pShowWindow.Call(hwnd, swHide)
			// Hidden now: a quick re-show must wake the page again.
			h.shown = false
			return 0
		}
	case wmNcCalcSize:
		// Without a caption Windows still draws the top resize border as a
		// white strip. Keep the side and bottom borders (resizing, shadow) and
		// give the top to the page. A maximized window keeps the default
		// inset: its frame lies outside the screen.
		if wp == 0 || lp == 0 || windowMaximized(hwnd) {
			break
		}
		r := lparam[Rect](lp)
		top := r.Top
		ret, _, _ := pCallWindowProc.Call(h.orig, hwnd, msg, wp, lp)
		r.Top = top
		return ret
	case wmResize:
		if windowMaximized(hwnd) {
			return 0
		}
		pReleaseCapture.Call()
		pSendMessage.Call(hwnd, wmNCLeftDown, wp, 0)
		return 0
	case wmGetMinMaxInfo:
		applyMinMax(hwnd, lp)
		return 0
	case wmDpiChanged:
		// Let WebView2 resize its child, then pin the window to the rect
		// Windows suggested for the new monitor.
		pCallWindowProc.Call(h.orig, hwnd, msg, wp, lp)
		if lp != 0 {
			r := lparam[Rect](lp)
			pSetWindowPos.Call(hwnd, 0, uintptr(r.Left), uintptr(r.Top), uintptr(r.Right-r.Left), uintptr(r.Bottom-r.Top), swpNoZOrder|swpNoActivate)
		}
		h.noteNormal()
		return 0
	case wmSize, wmExitSizeMove:
		h.noteNormal()
		h.wakePage()
	case trayMsg:
		switch lp {
		case wmLButtonUp, wmLButtonDblClk:
			showMain()
		case wmRButtonUp, 0x007B:
			trayShowMenu()
		}
		return 0
	case wmDrag:
		pReleaseCapture.Call()
		pSendMessage.Call(hwnd, wmNCLeftDown, htCaption, 0)
		return 0
	case wmMin:
		pShowWindow.Call(hwnd, swMinimize)
		return 0
	case wmMax:
		zoomed, _, _ := pIsZoomed.Call(hwnd)
		if zoomed != 0 {
			pShowWindow.Call(hwnd, swRestore)
		} else {
			pShowWindow.Call(hwnd, swMaximize)
		}
		return 0
	case wmTimer:
		if h.ctrl != nil {
			on, n, errText := h.ctrl.running()
			trayUpdate(on, n, errText)
		}
		h.wakePage()
		return 0
	}
	r, _, _ := pCallWindowProc.Call(h.orig, hwnd, msg, wp, lp)
	return r
}

// topEdgeHit maps the page's top-edge grip to a hit-test code.
func topEdgeHit(edge string) uintptr {
	switch edge {
	case "top":
		return htTop
	case "topleft":
		return htTopLeft
	case "topright":
		return htTopRight
	}
	return 0
}

func showMain() {
	h := appHost
	if h == nil || h.hwnd == 0 {
		return
	}
	iconic, _, _ := pIsIconic.Call(h.hwnd)
	if iconic != 0 {
		pShowWindow.Call(h.hwnd, swRestore)
	} else {
		pShowWindow.Call(h.hwnd, swShow)
	}
	pSetForeground.Call(h.hwnd)
	h.wakePage()
}

// onScreen tells whether the window is visible and not minimized.
func (h *host) onScreen() bool {
	if h.hwnd == 0 {
		return true
	}
	on, _, _ := pIsWindowVisible.Call(h.hwnd)
	iconic, _, _ := pIsIconic.Call(h.hwnd)
	return on != 0 && iconic == 0
}

// wakePage tells the page the window is back on screen. The page stops
// polling while it is hidden or minimized and refreshes at once on this.
func (h *host) wakePage() {
	vis := h.onScreen()
	if vis && !h.shown && h.w != nil && !h.quitting {
		h.w.Eval("window.ashgateShown && window.ashgateShown()")
	}
	h.shown = vis
}

func hostQuit() {
	h := appHost
	if h == nil || h.quitting {
		return
	}
	h.noteNormal()
	h.saveWindow()
	h.quitting = true
	// Stopping capture can take up to 8 seconds. Do it off the UI thread so
	// the window does not freeze; it exits only after capture stopped and
	// the kill switch blocked proxied apps.
	trayRemove()
	if h.hwnd != 0 {
		pShowWindow.Call(h.hwnd, swHide)
	}
	exit := func() {
		if h.w != nil {
			h.w.Terminate()
		}
		if h.hwnd != 0 {
			pPostMessage.Call(h.hwnd, wmClose, 0, 0)
		}
	}
	if h.w == nil {
		if h.ctrl != nil {
			_ = h.ctrl.stop()
			h.ctrl.shutdown()
		}
		exit()
		return
	}
	go func() {
		if h.ctrl != nil {
			_ = h.ctrl.stop()
			h.ctrl.shutdown()
		}
		h.w.Dispatch(exit)
	}()
}

func styleWindow(hwnd uintptr) {
	// Keep the thick frame as a real non-client border. Swallowing
	// WM_NCCALCSIZE makes the client fill the window, WebView2 then covers
	// every edge, and the parent never receives the hit-test that 0.3.1 used
	// to resize. A client-area hit-test cannot see those pixels either.
	// Only the top border is dropped (WM_NCCALCSIZE in hostProc); the page
	// resizes from there through ashgateResize.
	style, _, _ := pGetWindowLong.Call(hwnd, gwlStyle)
	style &^= wsCaption
	style |= wsThickFrame | wsMinimizeBox | wsMaximizeBox | wsSysMenu | wsClipChildren
	pSetWindowLong.Call(hwnd, gwlStyle, style)
	pSetWindowPos.Call(hwnd, 0, 0, 0, 0, 0, swpFrameChanged|swpNoMove|swpNoSize|swpNoZOrder|swpNoActivate)

	dpi := windowDPI(hwnd)
	w, h := int32(defWindowDIPW), int32(defWindowDIPH)
	var saved *windowState
	var hasPos bool
	var maxed bool
	if appHost != nil {
		saved = loadWindowState(appHost.windowFile())
	}
	if saved != nil {
		w, h = saved.W, saved.H
		hasPos = true
		maxed = saved.Max
	}
	var work Rect
	if hasPos {
		_, work = monitorFromRect(Rect{Left: saved.X, Top: saved.Y, Right: saved.X + 1, Bottom: saved.Y + 1})
	} else {
		_, work = monitorAreas(hwnd)
	}
	workW := pxToDip(work.Right-work.Left, dpi)
	workH := pxToDip(work.Bottom-work.Top, dpi)
	w, h = fitWindow(w, h, minWindowDIPW, minWindowDIPH, workW, workH)
	fx, fy := frameSize(hwnd)
	ow := dipToPx(w, dpi) + fx
	oh := dipToPx(h, dpi) + fy
	var x, y int32
	if hasPos {
		x, y = clampOrigin(saved.X, saved.Y, ow, oh, work.Left, work.Top, work.Right, work.Bottom)
	} else {
		x = work.Left + ((work.Right-work.Left)-ow)/2
		y = work.Top + ((work.Bottom-work.Top)-oh)/2
		if x < work.Left {
			x = work.Left
		}
		if y < work.Top {
			y = work.Top
		}
	}
	pSetWindowPos.Call(hwnd, 0, uintptr(x), uintptr(y), uintptr(ow), uintptr(oh), swpNoZOrder|swpFrameChanged)
	if appHost != nil {
		appHost.noteNormal()
		if maxed {
			pShowWindow.Call(hwnd, swMaximize)
			appHost.maximized = true
		}
		logWindowMetrics(hwnd, dpi, w, h)
	}
	pref := uint32(2) // DWMWCP_ROUND
	pDwmAttribute.Call(hwnd, 33, uintptr(unsafe.Pointer(&pref)), 4)
}

func (h *host) windowFile() string {
	return filepath.Join(filepath.Dir(h.path), "window.json")
}

func loadWindowState(path string) *windowState {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var st windowState
	if json.Unmarshal(raw, &st) != nil || st.W < 1 || st.H < 1 {
		return nil
	}
	return &st
}

func (h *host) noteNormal() {
	if h == nil || h.hwnd == 0 {
		return
	}
	h.maximized = windowMaximized(h.hwnd)
	iconic, _, _ := pIsIconic.Call(h.hwnd)
	if h.maximized || iconic != 0 {
		return
	}
	var wr Rect
	pGetWindowRect.Call(h.hwnd, uintptr(unsafe.Pointer(&wr)))
	runtime.KeepAlive(&wr)
	w, ht := wr.Right-wr.Left, wr.Bottom-wr.Top
	if w < 1 || ht < 1 {
		return
	}
	h.normalX, h.normalY = wr.Left, wr.Top
	h.normalW, h.normalH = w, ht
	h.normalDPI = windowDPI(h.hwnd)
}

func (h *host) saveWindow() {
	if h == nil || h.normalW < 1 || h.normalH < 1 {
		return
	}
	dpi := h.normalDPI
	if dpi < 96 {
		dpi = 96
	}
	fx, fy := frameSize(h.hwnd)
	cw, ch := h.normalW-fx, h.normalH-fy
	if cw < 1 {
		cw = h.normalW
	}
	if ch < 1 {
		ch = h.normalH
	}
	st := windowState{
		X:   h.normalX,
		Y:   h.normalY,
		W:   pxToDip(cw, dpi),
		H:   pxToDip(ch, dpi),
		Max: h.maximized,
	}
	buf, err := json.MarshalIndent(&st, "", "  ")
	if err != nil {
		return
	}
	buf = append(buf, '\n')
	_ = atomicfile.Write(h.windowFile(), buf)
}

func frameSize(hwnd uintptr) (int32, int32) {
	var wr, cr Rect
	pGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&wr)))
	pGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&cr)))
	runtime.KeepAlive(&wr)
	runtime.KeepAlive(&cr)
	fx := (wr.Right - wr.Left) - cr.Right
	fy := (wr.Bottom - wr.Top) - cr.Bottom
	if fx < 0 {
		fx = 0
	}
	if fy < 0 {
		fy = 0
	}
	return fx, fy
}

// lparam reads a message's lParam as the address of the structure Windows
// passed with it. The memory is Windows', not the Go heap; reading the
// pointer through the variable keeps go vet's unsafeptr check meaningful
// for the rest of the code.
func lparam[T any](lp uintptr) *T { return *(**T)(unsafe.Pointer(&lp)) }

func applyMinMax(hwnd, lp uintptr) {
	if lp == 0 {
		return
	}
	dpi := windowDPI(hwnd)
	fx, fy := frameSize(hwnd)
	mmi := lparam[MinMaxInfo](lp)
	// Drag minimum only. ptMaxTrackSize is left at the value Windows already
	// filled in, so there is no upper limit while dragging. ptMaxSize is the
	// maximized size and is set to the work area so a caption-less window does
	// not cover the taskbar; it does not limit tracking.
	applyMinTrack(mmi, dpi, fx, fy)
	mon, work := monitorAreas(hwnd)
	if work.Right > work.Left && work.Bottom > work.Top {
		mmi.MaxPosition.X = work.Left - mon.Left
		mmi.MaxPosition.Y = work.Top - mon.Top
		mmi.MaxSize.X = work.Right - work.Left
		mmi.MaxSize.Y = work.Bottom - work.Top
	}
}

func logWindowMetrics(hwnd uintptr, dpi, dipW, dipH int32) {
	if appHost == nil || appHost.logs == nil {
		return
	}
	fx, fy := frameSize(hwnd)
	minW := dipToPx(minWindowDIPW, dpi) + fx
	minH := dipToPx(minWindowDIPH, dpi) + fy
	_, work := monitorAreas(hwnd)
	appHost.logs.Add(logbuf.Event{
		Process: "ashgate",
		Proto:   "UI",
		Dest: fmt.Sprintf("dpi=%d min=%dx%dDIP (%dx%dpx) maxTrack=none maximize=%dx%dpx size=%dx%dDIP",
			dpi, minWindowDIPW, minWindowDIPH, minW, minH,
			work.Right-work.Left, work.Bottom-work.Top, dipW, dipH),
		Status: "open",
	})
}

func windowMaximized(hwnd uintptr) bool {
	zoomed, _, _ := pIsZoomed.Call(hwnd)
	if zoomed != 0 {
		return true
	}
	var place WindowPlacement
	place.Length = uint32(unsafe.Sizeof(place))
	ok, _, _ := pGetPlacement.Call(hwnd, uintptr(unsafe.Pointer(&place)))
	runtime.KeepAlive(&place)
	return ok != 0 && place.ShowCmd == swMaximize
}

const monitorDefaultToNearest = 2

func monitorAreas(hwnd uintptr) (monitor, work Rect) {
	mon, _, _ := pMonitorFromWnd.Call(hwnd, monitorDefaultToNearest)
	if m, w, ok := readMonitor(mon); ok {
		return m, w
	}
	return primaryWork()
}

func monitorFromRect(r Rect) (monitor, work Rect) {
	mon, _, _ := pMonitorFromRect.Call(uintptr(unsafe.Pointer(&r)), monitorDefaultToNearest)
	runtime.KeepAlive(&r)
	if m, w, ok := readMonitor(mon); ok {
		return m, w
	}
	return primaryWork()
}

func readMonitor(mon uintptr) (monitor, work Rect, ok bool) {
	if mon == 0 {
		return Rect{}, Rect{}, false
	}
	var info MonitorInfo
	info.CbSize = uint32(unsafe.Sizeof(info))
	ret, _, _ := pGetMonitorInfo.Call(mon, uintptr(unsafe.Pointer(&info)))
	runtime.KeepAlive(&info)
	if ret == 0 || info.RcWork.Right <= info.RcWork.Left || info.RcWork.Bottom <= info.RcWork.Top {
		return Rect{}, Rect{}, false
	}
	return info.RcMonitor, info.RcWork, true
}

func primaryWork() (monitor, work Rect) {
	var workRect Rect
	pSystemParams.Call(0x0030, 0, uintptr(unsafe.Pointer(&workRect)), 0) // SPI_GETWORKAREA
	runtime.KeepAlive(&workRect)
	sw, _, _ := pGetSystemMet.Call(0)
	sh, _, _ := pGetSystemMet.Call(1)
	screen := Rect{Left: 0, Top: 0, Right: int32(sw), Bottom: int32(sh)}
	if workRect.Right > workRect.Left && workRect.Bottom > workRect.Top {
		return screen, workRect
	}
	return screen, screen
}

func windowDPI(hwnd uintptr) int32 {
	dpi, _, _ := pGetDpiWindow.Call(hwnd)
	if dpi < 96 {
		dpi, _, _ = pGetDpiSystem.Call()
	}
	if dpi < 96 {
		return 96
	}
	return int32(dpi)
}

func isAdmin() bool {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok); err != nil {
		return false
	}
	defer tok.Close()
	return tok.IsElevated()
}

func alert(text string) {
	body, _ := windows.UTF16PtrFromString(text)
	title, _ := windows.UTF16PtrFromString("Ashgate")
	pMessageBox.Call(0, uintptr(unsafe.Pointer(body)), uintptr(unsafe.Pointer(title)), 0x10)
	runtime.KeepAlive(body)
	runtime.KeepAlive(title)
}

// webViewDataDir is the WebView2 profile of the window.
func webViewDataDir() string {
	if os.Getenv("LOCALAPPDATA") == "" {
		return filepath.Join(os.TempDir(), "Ashgate", "WebView2")
	}
	return filepath.Join(os.Getenv("LOCALAPPDATA"), "Ashgate", "WebView2")
}

// RemoveWebViewData deletes the WebView2 profile (ashgate cleanup, run by
// the uninstaller). Its processes can hold files for a moment after the
// window closed, so it retries for up to 10 seconds.
func RemoveWebViewData() {
	dir := webViewDataDir()
	for i := 0; i < 20; i++ {
		if err := os.RemoveAll(dir); err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	_ = os.Remove(filepath.Dir(dir)) // the Ashgate folder, if now empty
}

// dropQuitMessage removes a pending WM_QUIT from this thread's queue.
func dropQuitMessage() {
	const wmQuit, pmRemove = 0x0012, 0x0001
	var msg [48]byte // MSG
	for i := 0; i < 4; i++ {
		r, _, _ := pPeekMessage.Call(uintptr(unsafe.Pointer(&msg[0])), 0, wmQuit, wmQuit, pmRemove)
		if r == 0 {
			return
		}
	}
}

func dismissBlankWebView() {
	class, _ := windows.UTF16PtrFromString("webview")
	for i := 0; i < 4; i++ {
		hwnd, _, _ := pFindWindow.Call(uintptr(unsafe.Pointer(class)), 0)
		if hwnd == 0 {
			break
		}
		pDestroyWindow.Call(hwnd)
	}
	runtime.KeepAlive(class)
}

func toggleEngine() {
	h := appHost
	if h == nil || h.ctrl == nil {
		return
	}
	on, _, _ := h.ctrl.running()
	var err error
	if on {
		err = h.ctrl.stop()
	} else {
		err = h.ctrl.start()
	}
	if err != nil {
		h.ctrl.mu.Lock()
		h.ctrl.errText = err.Error()
		h.ctrl.mu.Unlock()
	}
	if h.hwnd != 0 {
		pPostMessage.Call(h.hwnd, wmTimer, 0, 0)
	}
}
