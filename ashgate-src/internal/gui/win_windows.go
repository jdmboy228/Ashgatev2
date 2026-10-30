//go:build windows

package gui

import "golang.org/x/sys/windows"

var (
	user32  = windows.NewLazySystemDLL("user32.dll")
	shell32 = windows.NewLazySystemDLL("shell32.dll")

	pGetWindowLong   = user32.NewProc("GetWindowLongPtrW")
	pSetWindowLong   = user32.NewProc("SetWindowLongPtrW")
	pCallWindowProc  = user32.NewProc("CallWindowProcW")
	pDefWindowProc   = user32.NewProc("DefWindowProcW")
	pShowWindow      = user32.NewProc("ShowWindow")
	pSetWindowPos    = user32.NewProc("SetWindowPos")
	pGetWindowRect   = user32.NewProc("GetWindowRect")
	pGetClientRect   = user32.NewProc("GetClientRect")
	pReleaseCapture  = user32.NewProc("ReleaseCapture")
	pSendMessage     = user32.NewProc("SendMessageW")
	pPostMessage     = user32.NewProc("PostMessageW")
	pSetForeground   = user32.NewProc("SetForegroundWindow")
	pIsZoomed        = user32.NewProc("IsZoomed")
	pIsIconic        = user32.NewProc("IsIconic")
	pIsWindowVisible = user32.NewProc("IsWindowVisible")
	pSetTimer        = user32.NewProc("SetTimer")
	pMessageBox      = user32.NewProc("MessageBoxW")
	pFindWindow      = user32.NewProc("FindWindowW")
	pDestroyWindow   = user32.NewProc("DestroyWindow")
	pGetDpiWindow    = user32.NewProc("GetDpiForWindow")
	pGetDpiSystem    = user32.NewProc("GetDpiForSystem")
	pGetSystemMet    = user32.NewProc("GetSystemMetrics")
	pMonitorFromWnd  = user32.NewProc("MonitorFromWindow")
	pMonitorFromRect = user32.NewProc("MonitorFromRect")
	pGetMonitorInfo  = user32.NewProc("GetMonitorInfoW")
	pGetPlacement    = user32.NewProc("GetWindowPlacement")
	pSystemParams    = user32.NewProc("SystemParametersInfoW")
	pGetCursorPos    = user32.NewProc("GetCursorPos")
	pCreateWindowEx  = user32.NewProc("CreateWindowExW")
	pRegisterClass   = user32.NewProc("RegisterClassExW")
	pLoadCursor      = user32.NewProc("LoadCursorW")
	pBeginPaint      = user32.NewProc("BeginPaint")
	pEndPaint        = user32.NewProc("EndPaint")
	pDrawText        = user32.NewProc("DrawTextW")
	pInvalidate      = user32.NewProc("InvalidateRect")
	pSetWindowRgn    = user32.NewProc("SetWindowRgn")
	pTrackMouse      = user32.NewProc("TrackMouseEvent")
	pDrawIconEx      = user32.NewProc("DrawIconEx")
	pNotifyIcon      = shell32.NewProc("Shell_NotifyIconW")
	pDwmAttribute    = windows.NewLazySystemDLL("dwmapi.dll").NewProc("DwmSetWindowAttribute")

	pCreateFont   = gdi32.NewProc("CreateFontW")
	pCreateBrush  = gdi32.NewProc("CreateSolidBrush")
	pCreatePen    = gdi32.NewProc("CreatePen")
	pSelectObject = gdi32.NewProc("SelectObject")
	pSetBkMode    = gdi32.NewProc("SetBkMode")
	pSetTextColor = gdi32.NewProc("SetTextColor")
	pEllipse      = gdi32.NewProc("Ellipse")
	pRoundRect    = gdi32.NewProc("RoundRect")
	pCreateRgn    = gdi32.NewProc("CreateRoundRectRgn")
	pFillRect     = user32.NewProc("FillRect")
)

const (
	wmSetIcon = 0x0080
	wmDrag    = 0x8002
	wmMin     = 0x8003
	wmMax     = 0x8004
	wmShow    = 0x8005
	wmQuitReq = 0x8006 // ashgate quit (update.bat): exit like «Выход»
	wmResize  = 0x8007 // resize from the page's top edge
	trayMsg   = 0x8001

	swMinimize = 6
	swMaximize = 3

	gwlpWndProc = ^uintptr(3)  // -4
	gwlStyle    = ^uintptr(15) // -16

	wsThickFrame  = 0x00040000
	wsMinimizeBox = 0x00020000
	wsMaximizeBox = 0x00010000
	wsExTopmost   = 0x00000008
	wsExTool      = 0x00000080

	wmNCLeftDown  = 0x00A1
	htCaption     = 2
	wmKeyDown     = 0x0100
	wmMouseMove   = 0x0200
	wmMouseLeave  = 0x02A3
	wmActivate    = 0x0006
	wmPaint       = 0x000F
	wmLButtonDown = 0x0201

	swpFrameChanged = 0x0020
	swpNoMove       = 0x0002
	swpNoSize       = 0x0001
	swpNoZOrder     = 0x0004
	swpNoActivate   = 0x0010
	swpShowWindow   = 0x0040

	nimModify = 1
)
