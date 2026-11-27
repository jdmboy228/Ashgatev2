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
	"sync/atomic"
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
	"golang.org/x/sys/windows/registry"
)

const webviewMissing = "Не найден системный WebView2 Runtime. Установите Microsoft Edge WebView2 (для всех пользователей):\nhttps://developer.microsoft.com/microsoft-edge/webview2/"

// host is the single GUI process: local page, WebView2 window, tray.
type host struct {
	path      string
	logs      *logbuf.Buffer
	ctrl      *controller
	w         webview2.WebView
	hwnd      atomic.Uintptr
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

var appHost atomic.Pointer[host]

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
	appHost.Store(h)
	defer func() {
		appHost.Store(nil)
		quitPending.Store(false)
	}()
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

	base, err := webViewBaseDir()
	if err != nil {
		alert(err.Error())
		return err
	}
	if err := mkdirAllUnderRoot(base, filepath.Join("Ashgate", "WebView2")); err != nil {
		alert(err.Error())
		return err
	}
	data := filepath.Join(base, "Ashgate", "WebView2")
	clearWebViewEnv()
	var browserFolder string
	if isAdmin() {
		if err := checkHKCUWebViewPolicy(); err != nil {
			alert(err.Error())
			return err
		}
		runtimeDir, err := systemWebView2Dir()
		if err != nil {
			alert(err.Error())
			return err
		}
		browserFolder = runtimeDir
	}

	// Exit right away if `ashgate quit` already arrived before WebView2 starts.
	if quitPending.Load() {
		return nil
	}

	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:                   false,
		AutoFocus:               true,
		DataPath:                data,
		BrowserExecutableFolder: browserFolder,
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
	hwnd := uintptr(w.Window())
	h.hwnd.Store(hwnd)
	pShowWindow.Call(hwnd, swHide)
	// Subclass before the first resize so WM_NCCALCSIZE drops the caption
	// frame and WM_GETMINMAXINFO already enforces the DIP minimum.
	h.subclass()
	// Deliver any `ashgate quit` that arrived while WebView2 was starting now
	// that the subclassed window procedure can handle wmQuitReq.
	deliverPendingQuit()
	styleWindow(hwnd)
	h.installIcons()
	_ = w.Bind("ashgateDrag", func() { pPostMessage.Call(hwnd, wmDrag, 0, 0) })
	_ = w.Bind("ashgateMin", func() { pPostMessage.Call(hwnd, wmMin, 0, 0) })
	_ = w.Bind("ashgateMax", func() { pPostMessage.Call(hwnd, wmMax, 0, 0) })
	_ = w.Bind("ashgateClose", func() { pPostMessage.Call(hwnd, wmClose, 0, 0) })
	// The window has no top frame, so the page's title bar resizes from the top edge.
	_ = w.Bind("ashgateResize", func(edge string) {
		if ht := topEdgeHit(edge); ht != 0 {
			pPostMessage.Call(hwnd, wmResize, ht, 0)
		}
	})
	// Hand the API token to the page before it loads, and only to it: the
	// script runs in every document the WebView opens, and a dropped file or
	// link would be another one. json.Marshal yields safe string literals.
	tok, _ := json.Marshal(h.ctrl.token)
	origin, _ := json.Marshal("http://" + ln.Addr().String())
	w.Init("if(location.origin===" + string(origin) + ")window.__ashgateToken=" + string(tok) + ";")
	if err := trayAdd(hwnd); err != nil {
		h.ctrl.mu.Lock()
		if h.ctrl.errText == "" {
			h.ctrl.errText = err.Error()
		}
		h.ctrl.mu.Unlock()
	}
	pSetTimer.Call(hwnd, 1, 1000, 0)
	if startCapture {
		go func() { _ = h.ctrl.start() }()
	}
	w.Navigate("http://" + ln.Addr().String() + "/")
	cmd := uintptr(swShow)
	if startCapture {
		cmd = swRestore
	}
	pShowWindow.Call(hwnd, cmd)
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
	if hwnd := h.hwnd.Load(); hwnd != 0 {
		pPostMessage.Call(hwnd, msg, 0, 0)
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
		p, err := openExe(h.hwnd.Load())
		ch <- result{p, err}
	})
	var done <-chan struct{}
	if h.ctrl != nil {
		done = h.ctrl.done
	}
	select {
	case res := <-ch:
		return res.path, res.err
	case <-done:
		return "", errors.New("окно закрывается")
	}
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
	hwnd := h.hwnd.Load()
	prev, _, _ := pGetWindowLong.Call(hwnd, gwlpWndProc)
	h.orig = prev
	h.cb = windows.NewCallback(hostProc)
	pSetWindowLong.Call(hwnd, gwlpWndProc, h.cb)
}

func (h *host) installIcons() {
	hwnd := h.hwnd.Load()
	if big, err := iconFromImage(LogoImage(32)); err == nil {
		pSendMessage.Call(hwnd, wmSetIcon, 1, big)
		h.iconBig = big
	}
	if small, err := iconFromImage(LogoImage(16)); err == nil {
		pSendMessage.Call(hwnd, wmSetIcon, 0, small)
		h.iconSmall = small
	}
}

func hostProc(hwnd, msg, wp, lp uintptr) uintptr {
	h := appHost.Load()
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
	case wmQuitDone:
		if h.w != nil {
			h.w.Terminate()
		}
		pPostMessage.Call(hwnd, wmClose, 0, 0)
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
	h := appHost.Load()
	if h == nil {
		return
	}
	hwnd := h.hwnd.Load()
	if hwnd == 0 {
		return
	}
	iconic, _, _ := pIsIconic.Call(hwnd)
	if iconic != 0 {
		pShowWindow.Call(hwnd, swRestore)
	} else {
		pShowWindow.Call(hwnd, swShow)
	}
	pSetForeground.Call(hwnd)
	h.wakePage()
}

// onScreen tells whether the window is visible and not minimized.
func (h *host) onScreen() bool {
	hwnd := h.hwnd.Load()
	if hwnd == 0 {
		return true
	}
	on, _, _ := pIsWindowVisible.Call(hwnd)
	iconic, _, _ := pIsIconic.Call(hwnd)
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
	h := appHost.Load()
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
	hwnd := h.hwnd.Load()
	if hwnd != 0 {
		pShowWindow.Call(hwnd, swHide)
	}
	if h.w == nil {
		if h.ctrl != nil {
			h.ctrl.shutdown()
		}
		if hwnd != 0 {
			pPostMessage.Call(hwnd, wmClose, 0, 0)
		}
		return
	}
	go func() {
		if h.ctrl != nil {
			h.ctrl.shutdown()
		}
		// PostMessageW to the window itself survives modal loops (such as
		// GetOpenFileNameW), unlike thread-posted w.Dispatch callbacks.
		if hwnd != 0 {
			pPostMessage.Call(hwnd, wmQuitDone, 0, 0)
		} else {
			h.w.Dispatch(func() { h.w.Terminate() })
		}
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
	if cur := appHost.Load(); cur != nil {
		saved = loadWindowState(cur.windowFile())
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
	if cur := appHost.Load(); cur != nil {
		cur.noteNormal()
		if maxed {
			pShowWindow.Call(hwnd, swMaximize)
			cur.maximized = true
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
	if h == nil {
		return
	}
	hwnd := h.hwnd.Load()
	if hwnd == 0 {
		return
	}
	h.maximized = windowMaximized(hwnd)
	iconic, _, _ := pIsIconic.Call(hwnd)
	if h.maximized || iconic != 0 {
		return
	}
	var wr Rect
	pGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&wr)))
	runtime.KeepAlive(&wr)
	w, ht := wr.Right-wr.Left, wr.Bottom-wr.Top
	if w < 1 || ht < 1 {
		return
	}
	h.normalX, h.normalY = wr.Left, wr.Top
	h.normalW, h.normalH = w, ht
	h.normalDPI = windowDPI(hwnd)
}

func (h *host) saveWindow() {
	if h == nil || h.normalW < 1 || h.normalH < 1 {
		return
	}
	dpi := h.normalDPI
	if dpi < 96 {
		dpi = 96
	}
	fx, fy := frameSize(h.hwnd.Load())
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
	cur := appHost.Load()
	if cur == nil || cur.logs == nil {
		return
	}
	fx, fy := frameSize(hwnd)
	minW := dipToPx(minWindowDIPW, dpi) + fx
	minH := dipToPx(minWindowDIPH, dpi) + fy
	_, work := monitorAreas(hwnd)
	cur.logs.Add(logbuf.Event{
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

// clearWebViewEnv unsets WEBVIEW2_* environment variables before creating the
// WebView2 environment so a non-elevated process (via HKCU\Environment) cannot
// override the browser executable folder or inject Chromium flags into the
// elevated window. Admin-only HKLM WebView2 policies remain honored.
func clearWebViewEnv() {
	for _, kv := range os.Environ() {
		if k, _, ok := strings.Cut(kv, "="); ok && strings.HasPrefix(strings.ToUpper(k), "WEBVIEW2_") {
			_ = os.Unsetenv(k)
		}
	}
}

// webViewBaseDir returns the user's LocalAppData directory resolved via
// KnownFolderPath (ignoring HKCU env overrides). Microsoft Edge WebView2
// de-elevates its browser and AppContainer processes even when hosted by an
// elevated window, so the profile must live in a user-writable folder rather
// than admin-only %ProgramData%\Ashgate.
func webViewBaseDir() (string, error) {
	if base, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0); err == nil && base != "" {
		return base, nil
	}
	if base := os.Getenv("LOCALAPPDATA"); base != "" {
		return base, nil
	}
	if base, err := os.UserCacheDir(); err == nil && base != "" {
		return base, nil
	}
	return os.TempDir(), nil
}

// webViewDataDir is the WebView2 profile of the window, under webViewBaseDir.
func webViewDataDir() (string, error) {
	base, err := webViewBaseDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "Ashgate", "WebView2"), nil
}

// openRelRoot opens absPath anchored at its admin-owned volume root (e.g. C:\)
// via volRoot.OpenRoot(rel) so Go opens every user-owned component with
// OBJ_DONT_REPARSE and refuses NTFS junctions and escaping symlinks.
func openRelRoot(absPath string) (*os.Root, error) {
	clean := filepath.Clean(absPath)
	vol := filepath.VolumeName(clean)
	if len(vol) != 2 || vol[1] != ':' ||
		!((vol[0] >= 'a' && vol[0] <= 'z') || (vol[0] >= 'A' && vol[0] <= 'Z')) {
		return nil, fmt.Errorf("некорректный локальный путь %q", absPath)
	}
	if !noAncestorReparse(clean) {
		return nil, fmt.Errorf("каталог данных WebView2 является точкой повторного анализа: %s", clean)
	}
	volRoot, err := os.OpenRoot(vol + `\`)
	if err != nil {
		return nil, err
	}
	rel := strings.TrimPrefix(clean, vol)
	rel = strings.TrimPrefix(rel, `\`)
	if rel == "" || rel == "." {
		return volRoot, nil
	}
	sub, err := volRoot.OpenRoot(rel)
	_ = volRoot.Close()
	if err != nil {
		return nil, err
	}
	return sub, nil
}

// mkdirAllUnderRoot safely creates rel under base using a volume-anchored
// os.Root so no ancestor or created component can traverse an NTFS junction or
// symlink.
func mkdirAllUnderRoot(base, rel string) error {
	cur, err := openRelRoot(base)
	if err != nil {
		return err
	}
	defer func() {
		if cur != nil {
			_ = cur.Close()
		}
	}()
	cleanRel := filepath.Clean(rel)
	if cleanRel == "" || cleanRel == "." {
		return nil
	}
	for _, part := range strings.Split(cleanRel, `\`) {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			return fmt.Errorf("некорректный относительный путь %q", rel)
		}
		if err := cur.Mkdir(part, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		fi, err := cur.Lstat(part)
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			return fmt.Errorf("каталог данных WebView2 является точкой повторного анализа: %s", part)
		}
		next, err := cur.OpenRoot(part)
		if err != nil {
			return err
		}
		_ = cur.Close()
		cur = next
	}
	return nil
}

// isReparsePoint reports whether path is an NTFS reparse point (junction or
// symlink). Missing paths return false; unexpected attribute errors fail closed.
func isReparsePoint(path string) bool {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return true
	}
	attrs, err := windows.GetFileAttributes(p)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return false
		}
		return true
	}
	return attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

// noAncestorReparse reports whether path and every ancestor up to its volume
// root exist without any NTFS reparse points.
func noAncestorReparse(path string) bool {
	clean := filepath.Clean(path)
	vol := filepath.VolumeName(clean)
	if len(vol) != 2 || vol[1] != ':' {
		return false
	}
	root := vol + `\`
	for cur := clean; ; cur = filepath.Dir(cur) {
		if isReparsePoint(cur) {
			return false
		}
		if strings.EqualFold(cur, root) {
			return true
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return false
		}
	}
}

// isUnderProgramFiles reports whether dir resides strictly under the system
// Program Files or Program Files (x86) directory resolved via KnownFolderPath.
func isUnderProgramFiles(dir string) bool {
	clean := filepath.Clean(dir)
	if !filepath.IsAbs(clean) {
		return false
	}
	for _, id := range []*windows.KNOWNFOLDERID{windows.FOLDERID_ProgramFiles, windows.FOLDERID_ProgramFilesX86} {
		pf, err := windows.KnownFolderPath(id, 0)
		if err != nil || pf == "" {
			continue
		}
		pf = filepath.Clean(pf)
		prefix := pf + `\`
		if len(clean) > len(prefix) && strings.EqualFold(clean[:len(prefix)], prefix) {
			return true
		}
	}
	return false
}

func webViewArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x64"
	case "arm64":
		return "arm64"
	case "386":
		return "x86"
	default:
		return ""
	}
}

func validSystemWebView2Dir(dir string) bool {
	if dir == "" || !isUnderProgramFiles(dir) {
		return false
	}
	arch := webViewArch()
	if arch == "" {
		return false
	}
	dll := filepath.Join(dir, "EBWebView", arch, "EmbeddedBrowserWebView.dll")
	if !noAncestorReparse(dll) {
		return false
	}
	st, err := os.Lstat(dll)
	if err != nil || st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return false
	}
	root, err := openRelRoot(dir)
	if err != nil {
		return false
	}
	_ = root.Close()
	return true
}

// webView2ChannelGUIDs lists all four Microsoft Edge WebView2 Runtime/Edge
// channel GUIDs supported by WebView2Loader.dll.
var webView2ChannelGUIDs = []string{
	"{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}", // Evergreen WebView2 Runtime
	"{2CD8A007-E189-409D-A2C8-9AF4EF3C72AA}", // Beta
	"{0D50BFEC-CD6A-4F9A-964C-C7416E3ACB10}", // Dev
	"{65C35B14-6C1D-4122-AC46-7148CC9D6497}", // Canary
}

// systemWebView2Dir resolves a machine-wide WebView2 Runtime strictly from
// HKLM under Program Files / Program Files (x86) so an elevated host never
// falls back to user-writable HKCU registry entries.
func systemWebView2Dir() (string, error) {
	views := []uint32{
		registry.QUERY_VALUE | registry.WOW64_32KEY,
		registry.QUERY_VALUE | registry.WOW64_64KEY,
	}
	for _, guid := range webView2ChannelGUIDs {
		stateKey := `SOFTWARE\Microsoft\EdgeUpdate\ClientState\` + guid
		for _, access := range views {
			k, err := registry.OpenKey(registry.LOCAL_MACHINE, stateKey, access)
			if err != nil {
				continue
			}
			dir, _, err := k.GetStringValue("EBWebView")
			_ = k.Close()
			if err == nil && validSystemWebView2Dir(dir) {
				return filepath.Clean(dir), nil
			}
		}
		clientKey := `SOFTWARE\Microsoft\EdgeUpdate\Clients\` + guid
		for _, access := range views {
			k, err := registry.OpenKey(registry.LOCAL_MACHINE, clientKey, access)
			if err != nil {
				continue
			}
			loc, _, lerr := k.GetStringValue("location")
			pv, _, perr := k.GetStringValue("pv")
			_ = k.Close()
			if lerr == nil && perr == nil && loc != "" && pv != "" {
				dir := filepath.Join(loc, pv)
				if validSystemWebView2Dir(dir) {
					return filepath.Clean(dir), nil
				}
			}
		}
	}
	return "", errors.New(webviewMissing)
}

// checkHKCUWebViewPolicy refuses launch when user-writable HKCU WebView2
// policies try to override BrowserExecutableFolder or
// AdditionalBrowserArguments (which WebView2Loader.dll applies even when
// BrowserExecutableFolder is passed explicitly).
func checkHKCUWebViewPolicy() error {
	exeBase := "ashgate.exe"
	if exe, err := os.Executable(); err == nil && exe != "" {
		exeBase = filepath.Base(exe)
	}
	return checkWebViewPolicyKey(registry.CURRENT_USER, `Software\Policies\Microsoft\Edge\WebView2`, exeBase)
}

func checkWebViewPolicyKey(root registry.Key, baseSubkey, exeBase string) error {
	policies := []string{"BrowserExecutableFolder", "AdditionalBrowserArguments"}
	views := []uint32{
		registry.QUERY_VALUE | registry.WOW64_64KEY,
		registry.QUERY_VALUE | registry.WOW64_32KEY,
	}
	for _, access := range views {
		if k, err := registry.OpenKey(root, baseSubkey, access); err == nil {
			for _, name := range policies {
				if val, _, verr := k.GetStringValue(name); verr == nil && strings.TrimSpace(val) != "" {
					_ = k.Close()
					return fmt.Errorf("обнаружена пользовательская политика WebView2 (HKCU %s); запуск от администратора запрещён", name)
				}
			}
			_ = k.Close()
		}
		for _, pol := range policies {
			sub, err := registry.OpenKey(root, baseSubkey+`\`+pol, access)
			if err != nil {
				continue
			}
			names, nerr := sub.ReadValueNames(0)
			if nerr == nil {
				for _, vn := range names {
					if !policyMatchesApp(vn, exeBase) {
						continue
					}
					if val, _, verr := sub.GetStringValue(vn); verr == nil && strings.TrimSpace(val) != "" {
						_ = sub.Close()
						return fmt.Errorf("обнаружена пользовательская политика WebView2 (HKCU %s\\%s); запуск от администратора запрещён", pol, vn)
					}
				}
			}
			_ = sub.Close()
		}
	}
	return nil
}

func policyMatchesApp(valueName, exeBase string) bool {
	v := strings.TrimSpace(valueName)
	return v == "*" || strings.EqualFold(v, "ashgate.exe") || (exeBase != "" && strings.EqualFold(v, exeBase))
}

func removeWebViewInBase(base string) {
	if base == "" {
		return
	}
	baseRoot, err := openRelRoot(base)
	if err != nil {
		return
	}
	defer baseRoot.Close()
	ashRoot, err := baseRoot.OpenRoot("Ashgate")
	if err != nil {
		return
	}
	removeWebViewChild(ashRoot)
	_ = ashRoot.Close()
	_ = baseRoot.Remove("Ashgate") // if now empty
}

func removeWebViewSubdirInRoot(parentDir string) {
	if parentDir == "" {
		return
	}
	root, err := openRelRoot(parentDir)
	if err != nil {
		return
	}
	defer root.Close()
	removeWebViewChild(root)
}

func removeWebViewChild(parentRoot *os.Root) {
	fi, err := parentRoot.Lstat("WebView2")
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return
	}
	for i := 0; i < 20; i++ {
		fi2, lerr := parentRoot.Lstat("WebView2")
		if lerr != nil || fi2.Mode()&os.ModeSymlink != 0 || !fi2.IsDir() {
			return
		}
		if err := parentRoot.RemoveAll("WebView2"); err == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// RemoveWebViewData deletes the WebView2 profile (ashgate cleanup, run by
// the uninstaller). Its processes can hold files for a moment after the
// window closed, so it retries for up to 10 seconds. It uses a volume-anchored
// os.Root so NTFS junctions on user-owned paths cannot redirect elevated
// deletion.
func RemoveWebViewData() {
	if base, err := webViewBaseDir(); err == nil && base != "" {
		removeWebViewInBase(base)
	}
	// Clean up any leftover ProgramData\Ashgate\WebView2 created by 0.9.5.
	if windows.GetCurrentProcessToken().IsElevated() {
		if dir, err := config.ProtectedDir(); err == nil && dir != "" {
			removeWebViewSubdirInRoot(dir)
		}
	}
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
	h := appHost.Load()
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
	if hwnd := h.hwnd.Load(); hwnd != 0 {
		pPostMessage.Call(hwnd, wmTimer, 0, 0)
	}
}
