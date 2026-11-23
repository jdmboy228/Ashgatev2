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

// TestVerifyAndCheckXHTTPReality verifies that vless.Run + vless.Verify only
// succeeds when a VLESS+XHTTP+REALITY tunnel connects and passes two
// consecutive probes stably, and returns specific Russian error messages for
// connection refused, wrong REALITY publicKey, wrong XHTTP path, wrong UUID,
// unstable connections that drop after the first probe, and mid-session
// server shutdown (Check).
func TestVerifyAndCheckXHTTPReality(t *testing.T) {
	const (
		uuid = "22222222-2222-4222-8222-222222222222"
		priv = realityPrivate
		pub  = realityPublic
		sid  = realityShort
		sni  = realitySNI
	)
	dest := tlsDest(t)
	port := mustFree(t)
	stopServer, err := vless.StartRaw(mustServer(t, map[string]any{
		"log": map[string]any{"loglevel": "info"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": port, "protocol": "vless",
			"settings": map[string]any{
				"decryption": "none",
				"clients":    []any{map[string]any{"id": uuid}},
			},
			"streamSettings": map[string]any{
				"network": "xhttp", "security": "reality",
				"xhttpSettings": map[string]any{"path": "/xh", "mode": "auto"},
				"realitySettings": map[string]any{
					"dest": dest, "serverNames": []string{sni},
					"privateKey": priv, "shortIds": []string{sid},
				},
			},
		}},
		"outbounds": []any{testFreedom},
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stopServer)

	// Local HTTP 204 target that can also simulate instability (fail after 1st 204).
	probeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = probeLn.Close() })
	var dropAfterFirst bool
	var probeHits int
	go func() {
		for {
			c, err := probeLn.Accept()
			if err != nil {
				return
			}
			probeHits++
			hit := probeHits
			if dropAfterFirst && hit > 1 {
				_ = c.Close()
				continue
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				b := make([]byte, 512)
				_, _ = conn.Read(b)
				_, _ = io.WriteString(conn, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
			}(c)
		}
	}()

	pHost, pPort := splitHostPort(t, probeLn.Addr().String())
	oldHost, oldPort, oldPause, oldWait := vless.ProbeHost, vless.ProbePort, vless.ProbePause, vless.ProbeWait
	vless.ProbeHost, vless.ProbePort = pHost, pPort
	vless.ProbePause, vless.ProbeWait = 20*time.Millisecond, 8*time.Second
	t.Cleanup(func() {
		vless.ProbeHost, vless.ProbePort = oldHost, oldPort
		vless.ProbePause, vless.ProbeWait = oldPause, oldWait
	})

	clientDoc := func(srvAddr string, p vless.Params) []byte {
		out, err := vless.Outbound(srvAddr, port, p)
		if err != nil {
			t.Fatal(err)
		}
		if h, pStr, err := net.SplitHostPort(srvAddr); err == nil {
			pNum, _ := net.LookupPort("tcp", pStr)
			out, err = vless.Outbound(h, pNum, p)
			if err != nil {
				t.Fatal(err)
			}
		}
		return mustServer(t, map[string]any{
			"log":       map[string]any{"access": "none", "error": "none", "loglevel": "none"},
			"outbounds": []any{out},
		})
	}

	goodParams := vless.Params{
		UUID: uuid, Network: "xhttp", Security: "reality",
		SNI: sni, PublicKey: pub, ShortID: sid, Path: "/xh", Mode: "auto",
	}

	// 1. Healthy & stable server passes Verify (at least 2 probes) and Check.
	probeHits = 0
	inst, err := vless.Run(clientDoc(net.JoinHostPort("127.0.0.1", itoa(port)), goodParams))
	if err != nil {
		t.Fatal(err)
	}
	if err := vless.Verify(inst); err != nil {
		_ = inst.Close()
		t.Fatalf("Verify healthy: %v (hits=%d)\nlog:\n%s", err, probeHits, vless.RecentLog(time.Now().Add(-10*time.Second)))
	}
	if probeHits < 2 {
		_ = inst.Close()
		t.Fatalf("Verify made %d probes, want at least 2 for stability", probeHits)
	}
	if err := vless.Check(inst); err != nil {
		_ = inst.Close()
		t.Fatalf("Check healthy: %v", err)
	}
	_ = inst.Close()

	// 2. Unstable server (succeeds on first probe, drops subsequent probes) fails Verify.
	dropAfterFirst = true
	probeHits = 0
	inst, err = vless.Run(clientDoc(net.JoinHostPort("127.0.0.1", itoa(port)), goodParams))
	if err != nil {
		t.Fatal(err)
	}
	err = vless.Verify(inst)
	_ = inst.Close()
	dropAfterFirst = false
	if err == nil || err.Error() != "VLESS: соединение нестабильно (оборвалось после подключения)" {
		t.Fatalf("Verify unstable: got %v", err)
	}

	// 3. Wrong XHTTP path -> HTTP 404 from server -> specific XHTTP error.
	badPath := goodParams
	badPath.Path = "/wrong-path"
	inst, err = vless.Run(clientDoc(net.JoinHostPort("127.0.0.1", itoa(port)), badPath))
	if err != nil {
		t.Fatal(err)
	}
	err = vless.Verify(inst)
	_ = inst.Close()
	if err == nil || err.Error() != "VLESS: сервер отклонил запрос XHTTP. Проверьте path и host" {
		t.Fatalf("Verify bad path: got %v", err)
	}

	// 4. Wrong REALITY public key -> specific REALITY/auth error.
	badKey := goodParams
	badKey.PublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	inst, err = vless.Run(clientDoc(net.JoinHostPort("127.0.0.1", itoa(port)), badKey))
	if err != nil {
		t.Fatal(err)
	}
	err = vless.Verify(inst)
	_ = inst.Close()
	if err == nil || !wrongKeyExplained(err) {
		t.Fatalf("Verify bad REALITY key: got %v", err)
	}

	// 5. Wrong VLESS UUID -> server closes stream without answering.
	badUUID := goodParams
	badUUID.UUID = "99999999-9999-4999-8999-999999999999"
	inst, err = vless.Run(clientDoc(net.JoinHostPort("127.0.0.1", itoa(port)), badUUID))
	if err != nil {
		t.Fatal(err)
	}
	err = vless.Verify(inst)
	_ = inst.Close()
	if err == nil || err.Error() != "VLESS: сервер не ответил. Проверьте адрес и порт сервера, UUID и ключи" {
		t.Fatalf("Verify bad UUID: got %v", err)
	}

	// 6. Unreachable port (connection refused) -> specific refusal error.
	inst, err = vless.Run(clientDoc(deadServer(t), goodParams))
	if err != nil {
		t.Fatal(err)
	}
	err = vless.Verify(inst)
	_ = inst.Close()
	if err == nil || err.Error() != "VLESS: сервер отклонил соединение" {
		t.Fatalf("Verify dead server: got %v", err)
	}

	// 7. Connected tunnel whose VLESS server stops later -> Check detects failure.
	inst, err = vless.Run(clientDoc(net.JoinHostPort("127.0.0.1", itoa(port)), goodParams))
	if err != nil {
		t.Fatal(err)
	}
	defer inst.Close()
	if err := vless.Verify(inst); err != nil {
		t.Fatalf("Verify before stop: %v", err)
	}
	stopServer()
	if err := vless.Check(inst); err == nil {
		t.Fatal("Check succeeded after VLESS server stopped")
	}
}
