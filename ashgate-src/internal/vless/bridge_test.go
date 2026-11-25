package vless

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestFixedPortBusy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	_, err = Listen(context.Background(), "203.0.113.10:443", Params{
		UUID: sampleUUID, Network: "tcp", Security: "none",
	}, Inbound{Port: port})
	if err == nil || !strings.Contains(err.Error(), "занят") || !strings.Contains(err.Error(), "SOCKS5") {
		t.Fatalf("%v", err)
	}
}

func TestWaitPortRespectsCancel(t *testing.T) {
	port, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(40 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	err = waitPort(ctx, fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
	elapsed := time.Since(start)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if elapsed > time.Second {
		t.Fatalf("waitPort took %v after cancel", elapsed)
	}
}

func freePortPair(t *testing.T, skip ...int) int {
	t.Helper()
	// Pick from below the Windows dynamic ephemeral range (49152-65535) so a
	// bridge's private :0 listener cannot grab p or p+1 mid-Sync.
	used := func(p int) bool {
		for _, s := range skip {
			if p == s || p == s+1 || p+1 == s {
				return true
			}
		}
		return false
	}
	for p := 24100; p < 32000; p += 2 {
		if used(p) {
			continue
		}
		ln1, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			continue
		}
		ln2, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p+1))
		_ = ln1.Close()
		if err != nil {
			continue
		}
		_ = ln2.Close()
		return p
	}
	t.Fatal("could not find a free consecutive port pair")
	return 0
}

func TestManagerSyncRenameSwapAndDedup(t *testing.T) {
	p1 := freePortPair(t)
	p2 := freePortPair(t, p1)
	ep := func(name string, port int) Endpoint {
		return Endpoint{
			Name:    name,
			Address: "127.0.0.1:443",
			Params:  Params{UUID: sampleUUID, Network: "tcp", Security: "none"},
			Inbound: Inbound{Port: port},
		}
	}
	m := NewManager()
	defer m.Close()

	st, err := m.Sync(context.Background(), []Endpoint{ep("a", p1), ep("b", p2)})
	if err != nil {
		t.Fatalf("initial sync: %v", err)
	}
	if !st["a"].Up || st["a"].Published != fmt.Sprintf("127.0.0.1:%d", p1) {
		t.Fatalf("initial a: %+v", st["a"])
	}
	if !st["b"].Up || st["b"].Published != fmt.Sprintf("127.0.0.1:%d", p2) {
		t.Fatalf("initial b: %+v", st["b"])
	}

	// Rename "a" -> "a2" on the same fixed port p1.
	st, err = m.Sync(context.Background(), []Endpoint{ep("a2", p1), ep("b", p2)})
	if err != nil {
		t.Fatalf("rename sync: %v", err)
	}
	if !st["a2"].Up || st["a2"].Published != fmt.Sprintf("127.0.0.1:%d", p1) {
		t.Fatalf("renamed a2: %+v", st["a2"])
	}

	// Swap fixed ports between "a2" and "b".
	st, err = m.Sync(context.Background(), []Endpoint{ep("a2", p2), ep("b", p1)})
	if err != nil {
		t.Fatalf("swap sync: %v", err)
	}
	if !st["a2"].Up || st["a2"].Published != fmt.Sprintf("127.0.0.1:%d", p2) {
		t.Fatalf("swapped a2: %+v", st["a2"])
	}
	if !st["b"].Up || st["b"].Published != fmt.Sprintf("127.0.0.1:%d", p1) {
		t.Fatalf("swapped b: %+v", st["b"])
	}

	// Duplicate Name entries must not leak a second started bridge.
	st, err = m.Sync(context.Background(), []Endpoint{ep("a2", p1), ep("a2", p2)})
	if err != nil {
		t.Fatalf("dedup sync: %v", err)
	}
	if !st["a2"].Up || st["a2"].Published != fmt.Sprintf("127.0.0.1:%d", p1) {
		t.Fatalf("dedup a2: %+v", st["a2"])
	}
	if err := portFree(p2, false); err != nil {
		t.Fatalf("duplicate entry leaked bridge on port %d: %v", p2, err)
	}
}

func TestManagerCloseCancelsInFlightSync(t *testing.T) {
	oldResolve := ResolveServer
	started := make(chan struct{})
	ResolveServer = func(ctx context.Context, host string) ([]net.IP, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	t.Cleanup(func() { ResolveServer = oldResolve })

	m := NewManager()
	syncDone := make(chan error, 1)
	go func() {
		_, err := m.Sync(context.Background(), []Endpoint{{
			Name:    "slow",
			Address: "slow.example.invalid:443",
			Params:  Params{UUID: sampleUUID, Network: "tcp", Security: "none"},
		}})
		syncDone <- err
	}()
	<-started
	closeDone := make(chan struct{})
	go func() {
		m.Close()
		close(closeDone)
	}()
	select {
	case err := <-syncDone:
		if err == nil {
			t.Fatal("Sync succeeded after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("Sync did not abort promptly when Manager.Close was called")
	}
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("Manager.Close hung")
	}
}
