//go:build !race

// The in-process dials against live Xray instances; see e2e_test.go for
// why these do not run under -race.
package vless_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"ashgate/internal/vless"
)

// plainBridge runs a VLESS server without TLS on loopback and a bridge to
// it with routing rt.
func plainBridge(t *testing.T, ctx context.Context, rt vless.Routing) *vless.Bridge {
	t.Helper()
	const uuid = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	port := mustFree(t)
	stop, err := vless.StartRaw(mustServer(t, map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": port, "protocol": "vless",
			"settings": map[string]any{
				"decryption": "none",
				"clients":    []any{map[string]any{"id": uuid}},
			},
		}},
		"outbounds": []any{testFreedom},
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	br, err := vless.ListenWith(ctx, net.JoinHostPort("127.0.0.1", itoa(port)),
		vless.Params{UUID: uuid, Network: "tcp", Security: "none"}, vless.Inbound{}, rt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(br.Close)
	return br
}

// slowEcho answers each read after a pause, so the client can half-close
// before the answer leaves.
func slowEcho(t *testing.T) string {
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
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				b := make([]byte, 64)
				n, err := c.Read(b)
				if err != nil {
					return
				}
				time.Sleep(300 * time.Millisecond)
				_, _ = c.Write(b[:n])
			}()
		}
	}()
	return ln.Addr().String()
}

// DialTCP keeps net.Conn's contract: half-close keeps the download,
// deadlines fail reads without breaking the connection (also a read that
// is already waiting), and Close ends a waiting read.
func TestInProcessTCP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	br := plainBridge(t, ctx, vless.Routing{})

	host, port := splitHostPort(t, slowEcho(t))
	conn, err := vless.DialTCP(br.Addr, host, port)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "half"); err != nil {
		t.Fatal(err)
	}
	cw, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("no CloseWrite")
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("x")); err == nil {
		t.Fatal("write after CloseWrite")
	}
	_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	got, err := io.ReadAll(conn)
	if string(got) != "half" {
		t.Fatalf("after CloseWrite read %q, %v\n%s", got, err, vless.RecentLog(time.Now().Add(-20*time.Second)))
	}
	_ = conn.Close()

	_, echoAddr := tcpEcho(t)
	host, port = splitHostPort(t, echoAddr)
	conn, err = vless.DialTCP(br.Addr, host, port)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	isTimeout := func(err error) bool {
		var ne net.Error
		return errors.Is(err, os.ErrDeadlineExceeded) && errors.As(err, &ne) && ne.Timeout()
	}
	buf := make([]byte, 4)
	start := time.Now()
	_ = conn.SetReadDeadline(start.Add(300 * time.Millisecond))
	if _, err := conn.Read(buf); !isTimeout(err) || time.Since(start) > 3*time.Second {
		t.Fatalf("read with a deadline and nothing to read: %v after %v", err, time.Since(start))
	}
	_ = conn.SetReadDeadline(time.Time{})
	waiting := make(chan error, 1)
	go func() {
		_, err := conn.Read(buf)
		waiting <- err
	}()
	time.Sleep(200 * time.Millisecond)
	_ = conn.SetReadDeadline(time.Now())
	select {
	case err := <-waiting:
		if !isTimeout(err) {
			t.Fatalf("waiting read: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a new deadline did not wake a waiting read")
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(conn, "ping"); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("after timeouts: %q %v", buf, err)
	}
	_ = conn.SetDeadline(time.Time{})
	go func() {
		_, err := conn.Read(buf)
		waiting <- err
	}()
	time.Sleep(100 * time.Millisecond)
	_ = conn.Close()
	select {
	case err := <-waiting:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("read after Close: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not end a waiting read")
	}

	// A server that cannot be reached: the dial succeeds (like the SOCKS
	// inbound did), the read fails with nothing read and says why.
	dead, err := vless.ListenWith(ctx, deadServer(t), vless.Params{UUID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", Network: "tcp", Security: "none"}, vless.Inbound{}, vless.Routing{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dead.Close)
	conn, err = vless.DialTCP(dead.Addr, host, port)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	_, _ = io.WriteString(conn, "ping")
	n, err := conn.Read(buf)
	if n != 0 || err == nil || isTimeout(err) {
		t.Fatalf("through a dead server: %d %v", n, err)
	}
	if got := vless.Explain(err); got.Error() != "VLESS: сервер отклонил соединение" {
		t.Logf("explained as %v (raw %v)", got, err)
	}
	if _, err := vless.DialTCP("127.0.0.1:1", host, port); err == nil {
		t.Fatal("dial through a bridge that does not run")
	}
}

// One request answered with a burst of datagrams while nobody reads yet:
// every one arrives. core.DialUDP kept 16 and dropped the rest.
func TestUDPBurstIsNotDropped(t *testing.T) {
	const burst = 400 // more than the session queue: the rest waits in Xray
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	br := plainBridge(t, ctx, vless.Routing{})

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		b := make([]byte, 2048)
		for {
			_, addr, err := pc.ReadFromUDP(b)
			if err != nil {
				return
			}
			for i := 0; i < burst; i++ {
				_, _ = pc.WriteToUDP([]byte(fmt.Sprintf("seq %03d", i)), addr)
				if i%8 == 7 {
					// Keep the server's socket buffer from overflowing:
					// this test is about Ashgate's side.
					time.Sleep(time.Millisecond)
				}
			}
		}
	}()
	us, err := vless.DialUDP(br.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer us.Close()
	dst := pc.LocalAddr().(*net.UDPAddr)
	if err := us.Send(ctx, dst, []byte("burst")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond) // the reader starts late
	seen := map[string]bool{}
	for len(seen) < burst {
		rctx, rcancel := context.WithTimeout(ctx, 5*time.Second)
		from, b, err := us.Recv(rctx)
		rcancel()
		if err != nil {
			t.Fatalf("got %d of %d datagrams: %v\n%s", len(seen), burst, err, vless.RecentLog(time.Now().Add(-20*time.Second)))
		}
		if from == nil || !from.IP.Equal(dst.IP) || from.Port != dst.Port {
			t.Fatalf("reply from %v, want %v", from, dst)
		}
		seen[string(b)] = true
	}
	// Close with replies still queued must not hang.
	if err := us.Send(ctx, dst, []byte("burst")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	closed := make(chan struct{})
	go func() {
		_ = us.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Close hung with replies queued")
	}
	if _, _, err := us.Recv(ctx); err == nil {
		t.Fatal("Recv after Close")
	}
}
