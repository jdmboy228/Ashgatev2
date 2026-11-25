package runtime

import (
	"errors"
	"sync"
	"testing"

	"ashgate/internal/config"
	"ashgate/internal/engine"
	"ashgate/internal/packet"
	"ashgate/internal/rules"
)

type stubRes struct{ p rules.Process }

func (r stubRes) Lookup(uint8, packet.Addr) (rules.Process, bool) { return r.p, true }

type stubAlloc struct {
	mu   sync.Mutex
	next uint16
}

func (a *stubAlloc) Reserve(int) (uint16, func(), error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.next == 0 {
		a.next = 25000
	}
	a.next++
	return a.next, func() {}, nil
}

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

// Session.Apply pins the relay addresses bound at Start so changing cfg.Relay
// cannot desync the live capture filter/listeners from the engine snapshot, and
// serializes concurrent Apply calls.
func TestSessionApplyPinsRelayAndSerializes(t *testing.T) {
	base := &config.Config{
		Relay: config.Relay{TCP4: "127.0.0.1:34010", TCP6: "[::1]:34011"},
		Proxies: []config.Proxy{
			{Name: "socks", Type: "socks5", Address: "127.0.0.1:1080"},
		},
		Rules: []config.Rule{
			{Process: "curl.exe", Action: "proxy", Proxy: "socks"},
		},
	}
	eng, err := engine.New(base, engine.Options{
		Resolver: stubRes{p: rules.Process{PID: 10, Name: "curl.exe"}},
		Alloc:    &stubAlloc{},
		SkipSelf: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	s := &Session{eng: eng, relay: base.Relay}

	updated := &config.Config{
		Relay: config.Relay{TCP4: "127.0.0.1:39999", TCP6: "[::1]:39998"},
		Proxies: []config.Proxy{
			{Name: "socks", Type: "socks5", Address: "127.0.0.1:1081"},
		},
		Rules: []config.Rule{
			{Process: "curl.exe", Action: "proxy", Proxy: "socks"},
		},
	}
	if err := s.Apply(updated); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	pkt, err := packet.BuildTCP(packet.V4(10, 0, 0, 8, 41000), packet.V4(9, 9, 9, 9, 443), 0x02)
	if err != nil {
		t.Fatal(err)
	}
	res := eng.HandlePacket(pkt, engine.Meta{IfIdx: 1}, true)
	if res.Action != engine.ActionModified {
		t.Fatalf("action %v, want ActionModified", res.Action)
	}
	var h packet.Header
	if err := packet.Parse(pkt, &h); err != nil {
		t.Fatal(err)
	}
	if h.Dst.Port != 34010 {
		t.Fatalf("rewritten relay port = %d, want pinned 34010", h.Dst.Port)
	}

	// Concurrent Apply calls must serialize cleanly without races.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cfg := *updated
			if i%2 == 0 {
				cfg.Relay = config.Relay{TCP4: "127.0.0.1:41000", TCP6: "[::1]:41001"}
			}
			if err := s.Apply(&cfg); err != nil {
				t.Errorf("concurrent Apply %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
}
