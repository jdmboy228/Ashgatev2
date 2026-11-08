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
	for i := 1; i <= 3; i++ {
		relay("GET /", "", nil)
		clk.add(time.Second)
		if h := e.RelayHealth("p"); h.Dead != i || !h.Since.Equal(start) {
			t.Fatalf("after %d dead relays: %+v", i, h)
		}
	}
	relay("", "", nil) // opened and closed: nothing to judge
	if h := e.RelayHealth("p"); h.Dead != 3 {
		t.Fatalf("an idle relay counted: %+v", h)
	}
	relay("GET /", "200 OK", directConn{}.wrap)
	if h := e.RelayHealth("p"); h.Dead != 3 || !h.LastGood.IsZero() {
		t.Fatalf("a Direct domain's answer counted for the server: %+v", h)
	}
	relay("GET /", "200 OK", nil)
	if h := e.RelayHealth("p"); h.Dead != 0 || !h.LastGood.Equal(clk.now()) {
		t.Fatalf("an answer did not clear the dead relays: %+v", h)
	}
	if h := e.RelayHealth("other"); h != (RelayHealth{}) {
		t.Fatalf("another proxy: %+v", h)
	}

	// A failed dial is a dead relay; the window forgets it.
	pd.fail = errors.New("refused")
	appSide, relaySide := net.Pipe()
	defer appSide.Close()
	e.serveFlow(relaySide, &tcpFlow{proxy: config.Proxy{Name: "p"}, created: clk.now()})
	if h := e.RelayHealth("p"); h.Dead != 1 {
		t.Fatalf("dial error: %+v", h)
	}
	clk.add(relayWindow + time.Second)
	if h := e.RelayHealth("p"); h.Dead != 0 {
		t.Fatalf("outside the window: %+v", h)
	}
}

func (directConn) wrap(c net.Conn) net.Conn { return directConn{c} }

func TestRelayBookKeepsTheNewest(t *testing.T) {
	var b relayBook
	at := time.Unix(1_700_000_000, 0)
	for i := 0; i < relayKeep+10; i++ {
		b.dead("p", at.Add(time.Duration(i)*time.Millisecond), at.Add(time.Duration(i)*time.Millisecond))
	}
	h := b.health("p", at.Add(time.Second))
	if h.Dead != relayKeep || !h.Since.Equal(at.Add(10*time.Millisecond)) {
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
