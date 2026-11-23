package httpproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"ashgate/internal/config"
	"ashgate/internal/testkit"
)

func TestConnectAuthAndEcho(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	target := ln.Addr().(*net.TCPAddr)

	px, err := testkit.ListenHTTP("user", "pass")
	if err != nil {
		t.Fatal(err)
	}
	defer px.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := Dial(ctx, config.Proxy{Type: "http", Address: px.Addr}, "127.0.0.1", uint16(target.Port)); err == nil {
		t.Fatal("expected 407")
	}
	conn, err := Dial(ctx, config.Proxy{Type: "http", Address: px.Addr, Username: "user", Password: "pass"}, "127.0.0.1", uint16(target.Port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("xyz")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 3)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "xyz" {
		t.Fatalf("got %q", buf)
	}
}

func TestDNSQueryOverConnect(t *testing.T) {
	px, err := testkit.ListenHTTP("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer px.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	query := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	got, err := DNSQuery(ctx, config.Proxy{Type: "http", Address: px.Addr}, "1.1.1.1:53", query)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) < 3 || got[0] != 0x12 || got[2]&0x80 == 0 {
		t.Fatalf("response %x", got)
	}
}

func TestDNSExchangeCancelsWithContext(t *testing.T) {
	near, far := net.Pipe()
	defer near.Close()
	defer far.Close()
	go func() {
		buf := make([]byte, 256)
		_, _ = far.Read(buf)
		_, _ = far.Read(buf)
	}()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := dnsExchange(ctx, near, []byte{0x12, 0x34, 0x01, 0x00})
		done <- err
	}()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dnsExchange did not unblock on context cancellation")
	}
}
