package runtime

import (
	"errors"
	"testing"
)

// Failed fires with the first failure, not with a clean stop.
func TestFailedClosesOnFirstError(t *testing.T) {
	s := &Session{}
	ch := s.Failed()
	select {
	case <-ch:
		t.Fatal("closed before any failure")
	default:
	}
	s.setErr(errors.New("WinDivertRecv: broken"))
	s.setErr(errors.New("second"))
	select {
	case <-ch:
	default:
		t.Fatal("not closed after the failure")
	}
	if s.Err().Error() != "WinDivertRecv: broken" {
		t.Fatalf("err %v", s.Err())
	}
	late := &Session{}
	late.setErr(errors.New("x"))
	select {
	case <-late.Failed():
	default:
		t.Fatal("Failed after the failure is not closed")
	}
	var none *Session
	if none.Failed() != nil {
		t.Fatal("nil session")
	}
}
