package probe

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"ashgate/internal/config"
	"ashgate/internal/testkit"
)

func TestSOCKSCheck(t *testing.T) {
	px, err := testkit.ListenSOCKS("u", "p")
	if err != nil {
		t.Fatal(err)
	}
	defer px.Close()
	ln := localEcho(t)
	host, port := split(t, ln.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rep := CheckTarget(ctx, config.Proxy{Name: "s", Type: "socks5", Address: px.Addr, Username: "u", Password: "p"}, host, port)
	if !rep.OK || !rep.UDP || rep.Millis < 1 {
		t.Fatalf("%+v", rep)
	}
	bad := CheckTarget(ctx, config.Proxy{Name: "s", Type: "socks5", Address: px.Addr, Username: "u", Password: "no"}, host, port)
	if bad.OK || bad.Label != "нет ответа" {
		t.Fatalf("%+v", bad)
	}
}

func TestHTTPCheck(t *testing.T) {
	px, err := testkit.ListenHTTP("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer px.Close()
	ln := localEcho(t)
	host, port := split(t, ln.Addr().String())
	rep := CheckTarget(context.Background(), config.Proxy{Name: "h", Type: "http", Address: px.Addr}, host, port)
	if !rep.OK || rep.UDP || rep.Detail != "только TCP" {
		t.Fatalf("%+v", rep)
	}
}

func localEcho(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return ln
}

func split(t *testing.T, addr string) (string, uint16) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return host, uint16(n)
}

// fakeUDP answers with the replies it is given, in order, then waits for ctx.
type fakeUDP struct {
	sent    []byte
	dst     *net.UDPAddr
	sendErr error
	replies [][]byte
}

func (f *fakeUDP) Send(_ context.Context, dst *net.UDPAddr, p []byte) error {
	f.sent, f.dst = p, dst
	return f.sendErr
}

func (f *fakeUDP) Recv(ctx context.Context) (*net.UDPAddr, []byte, error) {
	if len(f.replies) == 0 {
		<-ctx.Done()
		return nil, nil, ctx.Err()
	}
	r := f.replies[0]
	f.replies = f.replies[1:]
	return nil, r, nil
}

func TestUDPProbeNeedsAnAnswer(t *testing.T) {
	answer := func(id uint16) []byte {
		q := dnsProbe(id)
		q[2] |= 0x80
		return q
	}
	ctx := context.Background()
	f := &fakeUDP{replies: [][]byte{{1, 2}, answer(1), answer(0xA5E7)}}
	if !udpAnswers(ctx, f) {
		t.Fatal("no UDP with an answer")
	}
	if f.dst.String() != "1.1.1.1:53" || len(f.sent) < 12 || f.sent[2]&0x80 != 0 || f.sent[5] != 1 {
		t.Fatalf("query %x to %v", f.sent, f.dst)
	}
	if udpAnswers(ctx, &fakeUDP{sendErr: errors.New("closed")}) {
		t.Fatal("UDP with a failed send")
	}
	// Silence: the probe ends with its context, not before and not never.
	tctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if udpAnswers(tctx, &fakeUDP{}) {
		t.Fatal("UDP without an answer")
	}
	if tctx.Err() == nil {
		t.Fatal("returned before the context ended")
	}
}
