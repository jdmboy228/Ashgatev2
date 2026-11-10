package engine

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"ashgate/internal/config"
	"ashgate/internal/logbuf"
	"ashgate/internal/packet"
	"ashgate/internal/rules"
)

type tcpFlow struct {
	ver  int
	app  packet.Addr
	orig packet.Addr
	// dial, when set, is where the proxy connects instead of orig (DNS
	// over TCP goes to the configured servers).
	dial     packet.Addr
	alloc    uint16
	release  func()
	proxy    config.Proxy
	proc     rules.Process
	ifIdx    uint32
	subIfIdx uint32
	created  time.Time
	// closedAt is set when the relay ended; the mapping lives on for
	// tcpCloseGrace (see closeFlowLocked).
	closedAt time.Time
	conn     net.Conn
	live     bool
	parent   string
	stat     *ruleStat
	mu       sync.Mutex
	// settled is set when the relay got its first bytes back or ended; a
	// relay asks at most once before that. Guarded by relayBook.mu.
	settled bool
}

// ServeConn looks up the NAT entry for an accepted local connection and relays it.
func (e *Engine) ServeConn(conn net.Conn) {
	ta, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		conn.Close()
		return
	}
	ver := 4
	if ta.IP.To4() == nil {
		ver = 6
	}
	e.mu.Lock()
	flow := e.byAlloc[allocKey{ver: ver, port: uint16(ta.Port)}]
	if flow != nil && !flow.closedAt.IsZero() {
		flow = nil // ended: only its last packets may still pass
	}
	if flow != nil {
		flow.mu.Lock()
		flow.conn = conn
		flow.mu.Unlock()
	}
	e.mu.Unlock()
	if flow == nil {
		conn.Close()
		return
	}
	e.serveFlow(conn, flow)
}

func (e *Engine) serveFlow(conn net.Conn, flow *tcpFlow) {
	defer conn.Close()
	defer e.finishTCP(flow)

	target := flow.orig
	if !flow.dial.IsZero() {
		target = flow.dial
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	upstream, err := e.dial.DialTCP(ctx, flow.proxy, target.NetIP().String(), target.Port)
	cancel()
	if err != nil {
		e.relays.dead(flow.proxy.Name, flow.created, e.now())
		flow.stat.fail(err.Error(), e.now())
		e.log(logbuf.Event{
			Process: display(flow.proc),
			PID:     flow.proc.PID,
			Proto:   "TCP",
			Dest:    flow.orig.String(),
			Via:     flow.proxy.Name,
			Status:  "error",
			Error:   err.Error(),
			Parent:  flow.parent,
		})
		return
	}
	defer upstream.Close()
	e.log(logbuf.Event{
		Process: display(flow.proc),
		PID:     flow.proc.PID,
		Proto:   "TCP",
		Dest:    flow.orig.String(),
		Via:     flow.proxy.Name,
		Status:  "open",
		Parent:  flow.parent,
	})
	var up, down atomic.Int64
	// From the app's first bytes until the first ones back, the relay
	// waits for an answer; see RelayHealth.
	asked := func() { e.relays.asked(flow.proxy.Name, flow, e.now()) }
	defer e.relays.settled(flow.proxy.Name, flow)
	good := func() {
		e.relays.settled(flow.proxy.Name, flow)
		// A VLESS bridge sends Direct domains past its server; their
		// answers say nothing about it.
		if d, ok := upstream.(interface{ Direct() bool }); ok && d.Direct() {
			return
		}
		e.relays.good(flow.proxy.Name, e.now())
	}
	upErr := splice(conn, upstream,
		counter{flow: &up, total: &e.bytesUp, rule: flow.stat.upCounter(), first: asked},
		counter{flow: &down, total: &e.bytesDown, rule: flow.stat.downCounter(), first: good})
	if down.Load() == 0 && (up.Load() > 0 || upErr != nil) {
		// The app spoke, or the upstream broke, and nothing came back.
		e.relays.dead(flow.proxy.Name, flow.created, e.now())
	}
	e.log(logbuf.Event{
		Process:   display(flow.proc),
		PID:       flow.proc.PID,
		Proto:     "TCP",
		Dest:      flow.orig.String(),
		Via:       flow.proxy.Name,
		Status:    "closed",
		BytesUp:   up.Load(),
		BytesDown: down.Load(),
		Parent:    flow.parent,
	})
}

func (e *Engine) finishTCP(flow *tcpFlow) {
	e.mu.Lock()
	e.closeFlowLocked(flow)
	e.mu.Unlock()
}

// tcpCloseGrace keeps the mapping of an ended flow. Its last FIN and ACKs
// can still sit in the capture queue when the relay closes; dropped
// untranslated, they left the app's socket half-closed, and it went on
// sending toward the server later (a crash of Ashgate then put it on the
// wire). The janitor drops the mapping afterwards; closedTCP then drops
// whatever is still late.
const tcpCloseGrace = 10 * time.Second

// closeFlowLocked ends a relayed flow and keeps its mapping for
// tcpCloseGrace, so both ends can finish closing through it.
func (e *Engine) closeFlowLocked(flow *tcpFlow) {
	if flow == nil || !flow.closedAt.IsZero() {
		return
	}
	flow.closedAt = e.now()
	if flow.live {
		flow.live = false
		e.active.Add(-1)
		if flow.stat != nil {
			flow.stat.flows.Add(-1)
		}
	}
	flow.mu.Lock()
	c := flow.conn
	flow.conn = nil
	flow.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}

func (e *Engine) dropFlowLocked(flow *tcpFlow) {
	if flow == nil {
		return
	}
	if cur, ok := e.byClient[flow.app]; ok && cur == flow {
		delete(e.byClient, flow.app)
		e.closedTCP.add(flow.app)
	}
	if cur, ok := e.byAlloc[allocKey{ver: flow.ver, port: flow.alloc}]; ok && cur == flow {
		delete(e.byAlloc, allocKey{ver: flow.ver, port: flow.alloc})
	}
	if flow.release != nil {
		flow.release()
		flow.release = nil
	}
	if flow.live {
		flow.live = false
		e.active.Add(-1)
		if flow.stat != nil {
			flow.stat.flows.Add(-1)
		}
	}
	flow.mu.Lock()
	c := flow.conn
	flow.conn = nil
	flow.mu.Unlock()
	if c != nil {
		// Unblock splice without waiting for it. Close is safe if serveFlow
		// already returned and closed the same connection.
		_ = c.Close()
	}
}

// counter adds relayed bytes to a per-flow and an engine-wide total as they
// move, so the window's traffic figure grows during long transfers instead
// of jumping when the connection closes.
type counter struct {
	flow, total *atomic.Int64
	rule        *atomic.Int64 // may be nil
	first       func()        // runs on the flow's first bytes; may be nil
}

func (c counter) add(n int) {
	if c.flow.Add(int64(n)) == int64(n) && n > 0 && c.first != nil {
		c.first()
	}
	c.total.Add(int64(n))
	if c.rule != nil {
		c.rule.Add(int64(n))
	}
}

func (s *ruleStat) upCounter() *atomic.Int64 {
	if s == nil {
		return nil
	}
	return &s.up
}

func (s *ruleStat) downCounter() *atomic.Int64 {
	if s == nil {
		return nil
	}
	return &s.down
}

type countWriter struct {
	w io.Writer
	c counter
}

func (cw countWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	cw.c.add(n)
	return n, err
}

// relayBuf is one direction's copy buffer: twice what io.Copy uses, so
// fast transfers need half the reads and writes.
const relayBuf = 64 << 10

var relayBufs = sync.Pool{New: func() any {
	b := make([]byte, relayBuf)
	return &b
}}

// source hides its reader's WriteTo, so that io.CopyBuffer uses the pooled
// buffer (TCPConn.WriteTo would copy with 32 KiB of its own), and keeps
// the last read error.
type source struct {
	r   io.Reader
	err error
}

func (s *source) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if err != nil {
		s.err = err
	}
	return n, err
}

func relay(dst countWriter, src *source) {
	bp := relayBufs.Get().(*[]byte)
	_, _ = io.CopyBuffer(dst, src, *bp)
	relayBufs.Put(bp)
}

// noReplyGrace is how long an upstream that has sent nothing at all may
// stay open after the app ended its side. A half-closed connection that
// was answered goes on as long as the server likes; one that never was
// is a session nobody waits for, and closing it also cancels what Xray
// still does for it (the dial retries of a black-holed destination ran
// for over a minute after the app was gone).
var noReplyGrace = 5 * time.Second

// splice copies both ways until both ends are done. Each side gets EOF
// as a half-close when the other stops sending. It returns the error the
// upstream's reads ended with: nil for EOF or a close of our own.
func splice(app, upstream net.Conn, up, down counter) error {
	var wg sync.WaitGroup
	wg.Add(1)
	var grace atomic.Pointer[time.Timer]
	go func() {
		defer wg.Done()
		relay(countWriter{upstream, up}, &source{r: app})
		closeWrite(upstream)
		// The app is gone or finished sending. If the upstream has not
		// said a single byte, give it noReplyGrace, then close it fully.
		grace.Store(time.AfterFunc(noReplyGrace, func() {
			if down.flow.Load() == 0 {
				_ = upstream.Close()
			}
		}))
	}()
	from := &source{r: upstream}
	relay(countWriter{app, down}, from)
	closeWrite(app)
	wg.Wait()
	if t := grace.Load(); t != nil {
		t.Stop()
	}
	if err := from.err; err != nil && err != io.EOF && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
		return err
	}
	return nil
}

// relayWindow: relays that ended longer ago than this leave RelayHealth.
const relayWindow = 20 * time.Second

// relayKeep caps the dead relays remembered per proxy.
const relayKeep = 32

// RelayHealth is how the TCP relays through one proxy go right now. The
// subscription failover reads it several times a second: unanswered
// relays are its sign that the server stopped answering, an answered one
// its proof that the server works. Relays that started before the cutoff
// given to Engine.RelayHealth are left out of Dead and Waiting.
type RelayHealth struct {
	// Dead counts relays that ended within relayWindow with nothing
	// downloaded although the app sent something (or the dial or the
	// upstream failed), after the last relay that got an answer.
	Dead int
	// LastDead is when the newest of those relays ended.
	LastDead time.Time
	// Waiting counts open relays whose app sent something, after the last
	// relay that got an answer, and that have received nothing yet.
	Waiting int
	// WaitingSince is when the first of those relays sent its first bytes.
	WaitingSince time.Time
	// LastGood is when a relay last got its first bytes back through the
	// proxy's server.
	LastGood time.Time
	// LastAsk is when a relay last sent its first bytes: programs use the
	// proxy.
	LastAsk time.Time
}

// relayBook keeps RelayHealth per proxy name. It has its own lock: relays
// must not wait on e.mu for it.
type relayBook struct {
	mu sync.Mutex
	m  map[string]*relayLog
}

type relayLog struct {
	dead     []deadRelay // by end time
	lastGood time.Time
	lastAsk  time.Time
	// waiting holds the open relays that sent and got nothing yet, with
	// the time of their first bytes.
	waiting map[*tcpFlow]waitingRelay
}

type deadRelay struct{ start, end time.Time }

type waitingRelay struct{ start, asked time.Time }

func (b *relayBook) logLocked(proxy string) *relayLog {
	if b.m == nil {
		b.m = map[string]*relayLog{}
	}
	l := b.m[proxy]
	if l == nil {
		l = &relayLog{}
		b.m[proxy] = l
	}
	return l
}

func (l *relayLog) prune(now time.Time) {
	cut := now.Add(-relayWindow)
	i := 0
	for i < len(l.dead) && l.dead[i].end.Before(cut) {
		i++
	}
	l.dead = append(l.dead[:0], l.dead[i:]...)
}

// asked notes the first bytes flow's app sent.
func (b *relayBook) asked(proxy string, flow *tcpFlow, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	l := b.logLocked(proxy)
	l.lastAsk = now
	if flow.settled {
		return // the server spoke first
	}
	if l.waiting == nil {
		l.waiting = map[*tcpFlow]waitingRelay{}
	}
	l.waiting[flow] = waitingRelay{start: flow.created, asked: now}
}

// settled ends flow's wait: its first bytes came back, or it ended.
func (b *relayBook) settled(proxy string, flow *tcpFlow) {
	b.mu.Lock()
	flow.settled = true
	if l := b.m[proxy]; l != nil {
		delete(l.waiting, flow)
	}
	b.mu.Unlock()
}

func (b *relayBook) good(proxy string, now time.Time) {
	b.mu.Lock()
	l := b.logLocked(proxy)
	l.lastGood = now
	l.dead = l.dead[:0]
	b.mu.Unlock()
}

func (b *relayBook) dead(proxy string, start, now time.Time) {
	b.mu.Lock()
	l := b.logLocked(proxy)
	l.prune(now)
	if len(l.dead) >= relayKeep {
		l.dead = append(l.dead[:0], l.dead[1:]...)
	}
	l.dead = append(l.dead, deadRelay{start: start, end: now})
	b.mu.Unlock()
}

func (b *relayBook) health(proxy string, since, now time.Time) RelayHealth {
	b.mu.Lock()
	defer b.mu.Unlock()
	l := b.m[proxy]
	if l == nil {
		return RelayHealth{}
	}
	l.prune(now)
	h := RelayHealth{LastGood: l.lastGood, LastAsk: l.lastAsk}
	for _, d := range l.dead {
		if d.start.Before(since) {
			continue
		}
		h.Dead++
		if d.end.After(h.LastDead) {
			h.LastDead = d.end
		}
	}
	for _, w := range l.waiting {
		// One that asked before the last answer is waiting for its own
		// destination, not for the server.
		if w.start.Before(since) || !w.asked.After(l.lastGood) {
			continue
		}
		h.Waiting++
		if h.WaitingSince.IsZero() || w.asked.Before(h.WaitingSince) {
			h.WaitingSince = w.asked
		}
	}
	return h
}

// RelayHealth reports how the TCP relays through the proxy named proxy
// go; see RelayHealth. Relays that started before since are not counted
// as dead or waiting: the caller knows they say nothing (they used the
// server it has since replaced, or it has judged them already).
func (e *Engine) RelayHealth(proxy string, since time.Time) RelayHealth {
	return e.relays.health(proxy, since, e.now())
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

// OSAllocator reserves a localhost port by binding it for the life of the flow.
type OSAllocator struct{}

// Reserve binds 127.0.0.1 or ::1 on an ephemeral port and returns that port.
func (OSAllocator) Reserve(ver int) (uint16, func(), error) {
	network := "tcp4"
	host := "127.0.0.1"
	if ver == 6 {
		network = "tcp6"
		host = "::1"
	}
	ln, err := net.Listen(network, net.JoinHostPort(host, "0"))
	if err != nil {
		return 0, nil, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	return uint16(port), func() { _ = ln.Close() }, nil
}
