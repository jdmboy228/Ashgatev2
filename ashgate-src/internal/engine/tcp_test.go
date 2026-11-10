package engine

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ashgate/internal/config"
	"ashgate/internal/dialer"
)

// pipeDial hands out the near ends of in-memory connections; each test
// relay plays the server on the far end.
type pipeDial struct {
	next chan net.Conn
	fail error
}

func (d *pipeDial) DialTCP(context.Context, config.Proxy, string, uint16) (net.Conn, error) {
	if d.fail != nil {
		return nil, d.fail
	}
	return <-d.next, nil
}

func (d *pipeDial) DialUDP(context.Context, config.Proxy) (dialer.Session, error) {
	return nil, dialer.ErrUDPUnsupported
}

// directConn is an upstream that left a VLESS bridge through its direct
// outbound.
type directConn struct{ net.Conn }

func (directConn) Direct() bool { return true }

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// Relays that upload and get nothing back are dead; one that gets an
// answer clears them. Idle relays and Direct domains say nothing.
func TestRelayHealth(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	pd := &pipeDial{next: make(chan net.Conn, 1)}
	e, _ := newEngine(t, testConfig(), fixedRes{}, pd, nil)
	e.now = clk.now

	// relay runs one connection: app writes send (if any) and reads
	// until EOF; the server reads, answers with reply (if any) and closes.
	relay := func(send, reply string, wrap func(net.Conn) net.Conn) {
		t.Helper()
		near, far := net.Pipe()
		if wrap != nil {
			near = wrap(near)
		}
		pd.next <- near
		go func() {
			defer far.Close()
			if send != "" {
				b := make([]byte, len(send))
				if _, err := io.ReadFull(far, b); err != nil {
					return
				}
			}
			if reply != "" {
				_, _ = far.Write([]byte(reply))
			}
		}()
		appSide, relaySide := net.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			e.serveFlow(relaySide, &tcpFlow{proxy: config.Proxy{Name: "p"}, created: clk.now()})
		}()
		if send != "" {
			_, _ = appSide.Write([]byte(send))
		}
		_, _ = io.Copy(io.Discard, appSide)
		_ = appSide.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("relay did not finish")
		}
	}
	start := clk.now()
	var none time.Time
	for i := 1; i <= 3; i++ {
		relay("GET /", "", nil)
		if h := e.RelayHealth("p", none); h.Dead != i || !h.LastDead.Equal(clk.now()) || !h.LastAsk.Equal(clk.now()) || h.Waiting != 0 {
			t.Fatalf("after %d dead relays: %+v", i, h)
		}
		clk.add(time.Second)
	}
	// Relays that started before the cutoff are another server's.
	if h := e.RelayHealth("p", start.Add(time.Second)); h.Dead != 2 {
		t.Fatalf("dead relays from the cutoff on: %+v", h)
	}
	if h := e.RelayHealth("p", clk.now()); h.Dead != 0 || !h.LastDead.IsZero() {
		t.Fatalf("dead relays before the cutoff counted: %+v", h)
	}
	relay("", "", nil) // opened and closed: nothing to judge
	if h := e.RelayHealth("p", none); h.Dead != 3 {
		t.Fatalf("an idle relay counted: %+v", h)
	}
	relay("GET /", "200 OK", directConn{}.wrap)
	if h := e.RelayHealth("p", none); h.Dead != 3 || !h.LastGood.IsZero() {
		t.Fatalf("a Direct domain's answer counted for the server: %+v", h)
	}
	relay("GET /", "200 OK", nil)
	if h := e.RelayHealth("p", none); h.Dead != 0 || !h.LastGood.Equal(clk.now()) || h.Waiting != 0 {
		t.Fatalf("an answer did not clear the dead relays: %+v", h)
	}
	if h := e.RelayHealth("other", none); h != (RelayHealth{}) {
		t.Fatalf("another proxy: %+v", h)
	}

	// A failed dial is a dead relay; the window forgets it.
	pd.fail = errors.New("refused")
	appSide, relaySide := net.Pipe()
	defer appSide.Close()
	e.serveFlow(relaySide, &tcpFlow{proxy: config.Proxy{Name: "p"}, created: clk.now()})
	if h := e.RelayHealth("p", none); h.Dead != 1 {
		t.Fatalf("dial error: %+v", h)
	}
	clk.add(relayWindow + time.Second)
	if h := e.RelayHealth("p", none); h.Dead != 0 {
		t.Fatalf("outside the window: %+v", h)
	}
}

// An open relay whose app sent something and got nothing yet is waiting,
// from its first bytes until the first ones back. A relay that asked
// before the last answer waits for its own destination, and one where the
// server speaks first never waits.
func TestRelayWaiting(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	pd := &pipeDial{next: make(chan net.Conn, 1)}
	e, _ := newEngine(t, testConfig(), fixedRes{}, pd, nil)
	e.now = clk.now
	var none time.Time

	// open starts a relay and returns the app's and the server's ends.
	open := func() (app, server net.Conn, done chan struct{}) {
		t.Helper()
		near, far := net.Pipe()
		pd.next <- near
		appSide, relaySide := net.Pipe()
		done = make(chan struct{})
		go func() {
			defer close(done)
			e.serveFlow(relaySide, &tcpFlow{proxy: config.Proxy{Name: "p"}, created: clk.now()})
		}()
		return appSide, far, done
	}
	// health polls until ok accepts it: the relay's goroutines count the
	// bytes a moment after the test wrote them.
	health := func(since time.Time, what string, ok func(RelayHealth) bool) RelayHealth {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			h := e.RelayHealth("p", since)
			if ok(h) {
				return h
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: %+v", what, h)
			}
			time.Sleep(2 * time.Millisecond)
		}
	}
	send := func(c net.Conn, peer net.Conn, msg string) {
		t.Helper()
		go func() { _, _ = c.Write([]byte(msg)) }()
		if _, err := io.ReadFull(peer, make([]byte, len(msg))); err != nil {
			t.Fatal(err)
		}
	}
	finish := func(app, server net.Conn, done chan struct{}) {
		t.Helper()
		_ = server.Close()
		_ = app.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("relay did not finish")
		}
	}

	// Opened, nothing sent: not waiting.
	a1, s1, d1 := open()
	if h := e.RelayHealth("p", none); h.Waiting != 0 {
		t.Fatalf("a relay that sent nothing waits: %+v", h)
	}
	asked := clk.now()
	send(a1, s1, "hello")
	health(none, "a relay that sent does not wait", func(h RelayHealth) bool {
		return h.Waiting == 1 && h.WaitingSince.Equal(asked) && h.LastAsk.Equal(asked)
	})
	// A second one asks two seconds later: the first is still the oldest.
	clk.add(2 * time.Second)
	a2, s2, d2 := open()
	send(a2, s2, "hello")
	health(none, "two waiting relays", func(h RelayHealth) bool { return h.Waiting == 2 && h.WaitingSince.Equal(asked) })
	// The cutoff leaves out the relay that started before it.
	health(clk.now(), "relays from the cutoff on", func(h RelayHealth) bool {
		return h.Waiting == 1 && h.WaitingSince.Equal(clk.now())
	})
	// The second gets its answer: the server works, and the first, which
	// asked before that, waits for its own destination.
	clk.add(time.Second)
	send(s2, a2, "world")
	health(none, "an answered relay still waits", func(h RelayHealth) bool {
		return h.Waiting == 0 && h.LastGood.Equal(clk.now())
	})
	// A third asks after the answer and waits.
	clk.add(time.Second)
	a3, s3, d3 := open()
	send(a3, s3, "hello")
	health(none, "a relay that asked after the last answer", func(h RelayHealth) bool {
		return h.Waiting == 1 && h.WaitingSince.Equal(clk.now())
	})
	// It ends unanswered: no longer waiting, dead instead.
	finish(a3, s3, d3)
	if h := e.RelayHealth("p", none); h.Waiting != 0 || h.Dead != 1 {
		t.Fatalf("an ended relay: %+v", h)
	}
	finish(a1, s1, d1)
	finish(a2, s2, d2)

	// The server speaks first (SSH, SMTP): what the app sends after that
	// is not a question left unanswered.
	a4, s4, d4 := open()
	send(s4, a4, "220 ready")
	health(none, "the banner is not an answer", func(h RelayHealth) bool { return h.LastGood.Equal(clk.now()) })
	clk.add(time.Second)
	send(a4, s4, "EHLO")
	health(none, "the app's bytes were not seen", func(h RelayHealth) bool { return h.LastAsk.Equal(clk.now()) })
	if h := e.RelayHealth("p", none); h.Waiting != 0 {
		t.Fatalf("a relay whose server spoke first waits: %+v", h)
	}
	finish(a4, s4, d4)
}

func (directConn) wrap(c net.Conn) net.Conn { return directConn{c} }

func TestRelayBookKeepsTheNewest(t *testing.T) {
	var b relayBook
	at := time.Unix(1_700_000_000, 0)
	for i := 0; i < relayKeep+10; i++ {
		b.dead("p", at.Add(time.Duration(i)*time.Millisecond), at.Add(time.Duration(i)*time.Millisecond))
	}
	// The ten oldest were dropped: a cutoff at the eleventh's start still
	// counts all that are kept.
	h := b.health("p", at.Add(10*time.Millisecond), at.Add(time.Second))
	if h.Dead != relayKeep || !h.LastDead.Equal(at.Add(time.Duration(relayKeep+9)*time.Millisecond)) {
		t.Fatalf("%+v", h)
	}
	if h := b.health("p", time.Time{}, at.Add(time.Second)); h.Dead != relayKeep {
		t.Fatalf("%+v", h)
	}
}

// bigReader fills every read and offers WriteTo, which would copy with a
// buffer of its own.
type bigReader struct {
	net.Conn
	left int
}

func (r *bigReader) Read(p []byte) (int, error) {
	if r.left == 0 {
		return 0, io.EOF
	}
	n := min(len(p), r.left)
	r.left -= n
	return n, nil
}

func (r *bigReader) WriteTo(io.Writer) (int64, error) { panic("WriteTo bypassed the relay buffer") }
func (r *bigReader) Write(p []byte) (int, error)      { return len(p), nil }
func (r *bigReader) CloseWrite() error                { return nil }

// sizeWriter records the largest write and EOFs on reads.
type sizeWriter struct {
	net.Conn
	max, total int
}

func (w *sizeWriter) Write(p []byte) (int, error) {
	w.max = max(w.max, len(p))
	w.total += len(p)
	return len(p), nil
}

func (w *sizeWriter) Read([]byte) (int, error) { return 0, io.EOF }
func (w *sizeWriter) CloseWrite() error        { return nil }

// The relay copies with its own 64 KiB buffers, and counts every byte.
func TestSpliceUsesLargeBuffers(t *testing.T) {
	app := &sizeWriter{}
	up := &bigReader{left: 1 << 20}
	var a, b, c, d atomic.Int64
	if err := splice(app, up, counter{flow: &a, total: &b}, counter{flow: &c, total: &d}); err != nil {
		t.Fatal(err)
	}
	if app.max != relayBuf || app.total != 1<<20 || c.Load() != 1<<20 || d.Load() != 1<<20 {
		t.Fatalf("largest write %d, total %d, counted %d", app.max, app.total, c.Load())
	}
}

// silentUpstream never answers: reads block until Close, and CloseWrite
// only records the half-close like a VLESS session does.
type silentUpstream struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (u *silentUpstream) Read([]byte) (int, error) {
	<-u.closed
	return 0, net.ErrClosed
}
func (u *silentUpstream) Write(p []byte) (int, error) { return len(p), nil }
func (u *silentUpstream) CloseWrite() error           { return nil }
func (u *silentUpstream) Close() error {
	u.once.Do(func() { close(u.closed) })
	return nil
}

// After the app ended its side, an upstream that has sent nothing is
// closed after noReplyGrace; one that answered keeps its half-close.
func TestSpliceClosesSilentUpstreamAfterAppEOF(t *testing.T) {
	old := noReplyGrace
	noReplyGrace = 200 * time.Millisecond
	defer func() { noReplyGrace = old }()

	run := func(answer bool) (took time.Duration, closedEarly bool) {
		near, far := net.Pipe()
		up := &silentUpstream{closed: make(chan struct{})}
		var a, b, c, d atomic.Int64
		if answer {
			c.Store(1) // the upstream's first bytes were counted
		}
		finished := make(chan error, 1)
		start := time.Now()
		go func() {
			finished <- splice(near, up, counter{flow: &a, total: &b}, counter{flow: &c, total: &d})
		}()
		_, _ = far.Write([]byte("GET /"))
		_ = far.Close() // the app gives up
		select {
		case err := <-finished:
			if err != nil {
				t.Errorf("splice: %v", err)
			}
			return time.Since(start), true
		case <-time.After(1500 * time.Millisecond):
			up.Close() // let the half-closed relay end
			<-finished
			return 0, false
		}
	}

	took, ok := run(false)
	if !ok || took < noReplyGrace {
		t.Fatalf("silent upstream: closed=%v after %v, want close after ~%v", ok, took, noReplyGrace)
	}
	if _, ok := run(true); ok {
		t.Fatal("an upstream that answered was closed after the app's EOF")
	}
}
