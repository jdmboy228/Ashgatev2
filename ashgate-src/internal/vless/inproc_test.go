package vless

import (
	"context"
	"net"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

// pipeDialer hands out in-memory connections; the far ends are kept so
// the test can make the "server" answer.
type pipeDialer struct{ far chan net.Conn }

func (d pipeDialer) Dial(context.Context, xnet.Address, xnet.Destination, *internet.SocketConfig) (net.Conn, error) {
	near, far := net.Pipe()
	d.far <- far
	return near, nil
}

func (pipeDialer) DestIpAddress() net.IP { return nil }

// At most two new connections to one VLESS server handshake at a time; a
// slot frees when the server's first bytes arrive. Other destinations are
// not limited.
func TestHandshakeGate(t *testing.T) {
	const server = "203.0.113.10:443"
	gateAdd(server)
	t.Cleanup(func() { gateRemove(server) })
	far := make(chan net.Conn, 8)
	d := gateDialer{base: pipeDialer{far: far}}
	dest := xnet.TCPDestination(xnet.ParseAddress("203.0.113.10"), 443)

	dialed := make(chan net.Conn, 3)
	for i := 0; i < 3; i++ {
		go func() {
			c, err := d.Dial(context.Background(), nil, dest, nil)
			if err != nil {
				t.Error(err)
				return
			}
			dialed <- c
		}()
	}
	first, second := <-dialed, <-dialed
	select {
	case <-dialed:
		t.Fatal("a third handshake started while two were in flight")
	case <-time.After(200 * time.Millisecond):
	}
	if n := gateInUse(server); n != 2 {
		t.Fatalf("slots in use = %d, want 2", n)
	}
	// The server answers the first connection: its slot frees.
	srv := <-far
	go func() { _, _ = srv.Write([]byte{0x16}) }()
	if _, err := first.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	select {
	case third := <-dialed:
		_ = third.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("the third handshake did not start after a slot freed")
	}
	_ = first.Close()
	_ = second.Close()

	// Another destination is not gated.
	other := xnet.TCPDestination(xnet.ParseAddress("198.51.100.1"), 443)
	for i := 0; i < 4; i++ {
		c, err := d.Dial(context.Background(), nil, other, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}
}

func TestDNSServers(t *testing.T) {
	got := DNSServers([]string{"1.1.1.1:53", "8.8.8.8:53", "192.0.2.53:53", "dns.example:53", "1.1.1.1:5353"})
	want := []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query", "tcp://192.0.2.53:53", "tcp://1.1.1.1:5353"}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%v, want %v", got, want)
		}
	}
}
