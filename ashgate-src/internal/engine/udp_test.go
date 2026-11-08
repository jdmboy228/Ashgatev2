package engine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"ashgate/internal/config"
	"ashgate/internal/dialer"
	"ashgate/internal/packet"
	"ashgate/internal/rules"
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

// slowDial hands out a session whose Send blocks until release closes, and
// can block the dial itself.
type slowDial struct {
	fakeDial
	blockDial bool
	release   chan struct{}
	sending   chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
}

func (d *slowDial) DialUDP(context.Context, config.Proxy) (dialer.Session, error) {
	if d.blockDial {
		d.sending <- struct{}{}
		<-d.release
	}
	return &slowSession{d: d}, nil
}

type slowSession struct{ d *slowDial }

func (s *slowSession) Send(context.Context, *net.UDPAddr, []byte) error {
	s.d.sending <- struct{}{}
	<-s.d.release
	return nil
}

func (s *slowSession) Recv(context.Context) (*net.UDPAddr, []byte, error) {
	<-s.d.closed
	return nil, nil, io.EOF
}

func (s *slowSession) Close() error {
	s.d.closeOnce.Do(func() { close(s.d.closed) })
	return nil
}

// A session or dial stuck in I/O must not make the Janitor or Stop wait.
func TestUDPSweepAndCloseAllDoNotWaitForIO(t *testing.T) {
	for _, blockDial := range []bool{false, true} {
		d := &slowDial{blockDial: blockDial, release: make(chan struct{}), sending: make(chan struct{}, 2), closed: make(chan struct{})}
		cfg := testConfig()
		cfg.DNS.Mode = "original"
		e, _ := newEngine(t, cfg, fixedRes{p: rules.Process{Name: "curl.exe", PID: 5}, ok: true}, d, nil)
		pkt, _ := packet.BuildUDP(packet.V4(10, 9, 8, 7, 1900), packet.V4(9, 9, 9, 9, 3478), []byte{1})
		res := e.HandlePacket(pkt, Meta{}, true)
		if res.Action != ActionUDP {
			t.Fatal(res.Action)
		}
		fwd := make(chan struct{})
		go func() {
			defer close(fwd)
			_ = e.ForwardUDP(context.Background(), *res.UDP)
		}()
		<-d.sending // the dial or the send is now stuck
		for name, fn := range map[string]func(){
			"sweep":    func() { e.sweep(e.now().Add(time.Hour)) },
			"closeAll": e.closeAll,
		} {
			done := make(chan struct{})
			go func() { fn(); close(done) }()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatalf("blockDial=%v: %s waits for a stuck send", blockDial, name)
			}
		}
		close(d.release)
		<-fwd
		if blockDial {
			// The session that came after the flow was retired is closed.
			select {
			case <-d.closed:
			case <-time.After(3 * time.Second):
				t.Fatal("session dialed for a retired flow stays open")
			}
		}
	}
}
