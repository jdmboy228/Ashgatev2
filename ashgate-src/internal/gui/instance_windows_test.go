//go:build windows

package gui

import (
	"sync/atomic"
	"testing"
)

// TestRequestQuitPendingDelivered verifies that an `ashgate quit` signal
// received while the window is still starting (appHost == nil or hwnd == 0)
// is latched and delivered once the window handle is ready, instead of being
// silently dropped.
func TestRequestQuitPendingDelivered(t *testing.T) {
	prevHost := appHost.Swap(nil)
	prevPost := postQuitMessage
	quitPending.Store(false)
	t.Cleanup(func() {
		appHost.Store(prevHost)
		postQuitMessage = prevPost
		quitPending.Store(false)
	})

	var posted atomic.Uintptr
	var calls atomic.Int32
	postQuitMessage = func(hwnd uintptr) {
		posted.Store(hwnd)
		calls.Add(1)
	}

	// 1. Signal arrives before appHost exists.
	requestQuit()
	if !quitPending.Load() {
		t.Fatal("quitPending = false after early requestQuit, want true")
	}
	if calls.Load() != 0 {
		t.Fatalf("posted %d times with nil host, want 0", calls.Load())
	}

	// 2. Host exists, but hwnd is still 0 (WebView2 creating the window).
	h := &host{}
	appHost.Store(h)
	deliverPendingQuit()
	if !quitPending.Load() || calls.Load() != 0 {
		t.Fatalf("delivered with hwnd=0: pending=%v calls=%d", quitPending.Load(), calls.Load())
	}

	// 3. Window handle is ready and subclassed: latched quit must be delivered once.
	const wantHWND uintptr = 0x12345
	h.hwnd.Store(wantHWND)
	deliverPendingQuit()
	if quitPending.Load() {
		t.Fatal("quitPending still true after delivery")
	}
	if calls.Load() != 1 || posted.Load() != wantHWND {
		t.Fatalf("posted=(%d, %#x), want (1, %#x)", calls.Load(), posted.Load(), wantHWND)
	}
	// A duplicate deliverPendingQuit must be a no-op.
	deliverPendingQuit()
	if calls.Load() != 1 {
		t.Fatalf("duplicate delivery: calls=%d, want 1", calls.Load())
	}

	// 4. Subsequent requestQuit with an existing hwnd posts immediately.
	requestQuit()
	if calls.Load() != 2 || quitPending.Load() {
		t.Fatalf("immediate quit: calls=%d pending=%v, want 2, false", calls.Load(), quitPending.Load())
	}
}
