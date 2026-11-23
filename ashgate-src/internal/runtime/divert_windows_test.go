//go:build windows

package runtime

import (
	"errors"
	"testing"

	"ashgate/internal/windivert"
	"golang.org/x/sys/windows"
)

func TestDivertClosedHandleReturnsInvalidHandle(t *testing.T) {
	var d divert
	if err := d.close(); err != nil {
		t.Fatalf("close on zero divert: %v", err)
	}
	var addr windivert.Address
	if err := d.send([]byte{1}, &addr); !errors.Is(err, windows.ERROR_INVALID_HANDLE) {
		t.Fatalf("send on closed divert: %v", err)
	}
	var b windivert.Batch
	if _, err := d.sendBatch(&b); !errors.Is(err, windows.ERROR_INVALID_HANDLE) {
		t.Fatalf("sendBatch on closed divert: %v", err)
	}
	if err := d.InjectInbound([]byte{0x45}, 1, 0); !errors.Is(err, windows.ERROR_INVALID_HANDLE) {
		t.Fatalf("InjectInbound on closed divert: %v", err)
	}
}
