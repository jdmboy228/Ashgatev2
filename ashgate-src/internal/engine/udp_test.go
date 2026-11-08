package engine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"

	"ashgate/internal/config"
	"ashgate/internal/packet"
)

// scriptSession returns its replies in order, then io.EOF.
type scriptSession struct {
	mu      sync.Mutex
	replies [][]byte
}

func (s *scriptSession) Send(context.Context, *net.UDPAddr, []byte) error { return nil }

func (s *scriptSession) Recv(context.Context) (*net.UDPAddr, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.replies) == 0 {
		return nil, nil, io.EOF
	}
	p := s.replies[0]
	s.replies = s.replies[1:]
	return nil, p, nil
}

func (s *scriptSession) Close() error { return nil }

// flakyInj fails its first injection.
type flakyInj struct {
	memInj
	calls int
}

func (f *flakyInj) InjectInbound(pkt []byte, a, b uint32) error {
	f.calls++
	if f.calls == 1 {
		return errors.New("host unreachable")
	}
	return f.memInj.InjectInbound(pkt, a, b)
}

func TestReadUDPSurvivesInjectErrors(t *testing.T) {
	inj := &flakyInj{}
	e, _ := newEngine(t, testConfig(), fixedRes{}, &fakeDial{}, inj)
	flow := &udpFlow{
		app:   packet.V4(10, 0, 0, 2, 5000),
		orig:  packet.V4(9, 9, 9, 9, 3478),
		proxy: config.Proxy{Name: "socks"},
	}
	big := make([]byte, 65001) // BuildUDP refuses it
	sess := &scriptSession{replies: [][]byte{big, []byte("lost"), []byte("ok")}}
	e.readUDP(flow, sess)
	if inj.calls != 2 || inj.count() != 1 {
		t.Fatalf("%d injections, %d delivered", inj.calls, inj.count())
	}
	var h packet.Header
	got := inj.packet(0)
	if err := packet.Parse(got, &h); err != nil || !bytes.Equal(got[h.PayloadOff:h.PayloadOff+h.PayloadLen], []byte("ok")) {
		t.Fatalf("delivered %x, %v", got, err)
	}
	if want := int64(len(big) + len("lost") + len("ok")); flow.down.Load() != want || e.bytesDown.Load() != want {
		t.Fatalf("down %d, engine %d, want %d", flow.down.Load(), e.bytesDown.Load(), want)
	}
	if !flow.closed {
		t.Fatal("flow not retired after the session ended")
	}
}
