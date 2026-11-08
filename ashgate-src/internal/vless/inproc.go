package vless

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xctx "github.com/xtls/xray-core/common/ctx"
	xnet "github.com/xtls/xray-core/common/net"
	pudp "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet"
	iudp "github.com/xtls/xray-core/transport/internet/udp"
	"github.com/xtls/xray-core/transport/pipe"
)

// Running bridges by their private SOCKS5 address, for DialTCP and DialUDP.
var (
	bridgesMu sync.Mutex
	bridges   = map[string]*Bridge{}
)

func register(b *Bridge) {
	bridgesMu.Lock()
	bridges[b.Addr] = b
	bridgesMu.Unlock()
	gateAdd(b.server)
}

func unregister(b *Bridge) {
	bridgesMu.Lock()
	if bridges[b.Addr] == b {
		delete(bridges, b.Addr)
	}
	bridgesMu.Unlock()
	gateRemove(b.server)
}

// dispatcherAt is the Xray dispatcher of the bridge whose private SOCKS5
// inbound is addr.
func dispatcherAt(addr string) (*Bridge, routing.Dispatcher, error) {
	bridgesMu.Lock()
	b := bridges[addr]
	bridgesMu.Unlock()
	if b == nil || b.inst == nil {
		return nil, nil, errors.New("VLESS: локальный мост не запущен")
	}
	d, ok := b.inst.GetFeature(routing.DispatcherType()).(routing.Dispatcher)
	if !ok {
		return nil, nil, errors.New("VLESS: локальный мост не запущен")
	}
	return b, d, nil
}

// inboundContext is what Xray's SOCKS inbound gives a connection: the
// instance, a session id, Ashgate's inbound tag (the routing rules match
// it), its buffer policy, and sniffing for sniff when the bridge has Direct
// domains: route by the name the program asked for, keep the IP it chose.
func (b *Bridge) inboundContext(ctx context.Context, sniff ...string) context.Context {
	// core.Dial does the same: sniffing and the DNS outbound's dialerProxy
	// look the instance up in the context.
	ctx = context.WithValue(ctx, core.XrayKey(1), b.inst)
	ctx = xctx.ContextWithID(ctx, session.NewID())
	// CanSpliceCopy 3: there is no socket on this side to splice into.
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: tagAshgate, Name: "socks", CanSpliceCopy: 3})
	if len(b.routing.Direct) > 0 {
		ctx = session.ContextWithContent(ctx, &session.Content{SniffingRequest: session.SniffingRequest{
			Enabled: true, OverrideDestinationForProtocol: sniff, RouteOnly: true,
		}})
	}
	if pm, ok := b.inst.GetFeature(policy.ManagerType()).(policy.Manager); ok {
		ctx = policy.ContextWithBufferPolicy(ctx, pm.ForLevel(0).Buffer)
	}
	return ctx
}

// DialTCP connects to host:port through the bridge whose private SOCKS5
// inbound is addr, inside this process: no second loopback connection for
// capture to see and no SOCKS5 handshake. It is routed like that inbound.
// Like the inbound, it succeeds before Xray reaches the server: a server
// that cannot be reached shows as a read error with nothing read.
func DialTCP(addr, host string, port uint16) (net.Conn, error) {
	b, d, err := dispatcherAt(addr)
	if err != nil {
		return nil, err
	}
	if host == "" || port == 0 {
		return nil, errors.New("VLESS: неверный адрес назначения")
	}
	// The connection's context lives until Close: Xray runs the whole
	// session in the dispatch context.
	ctx, cancel := context.WithCancel(context.Background())
	c := &tcpConn{cancel: cancel, ob: &session.Outbound{}}
	ctx = b.inboundContext(ctx, "http", "tls", "quic")
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{c.ob})
	ctx = session.TrackedConnectionError(ctx, c)
	link, err := d.Dispatch(ctx, xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(port)))
	if err != nil {
		cancel()
		return nil, err
	}
	r, ok := link.Reader.(*pipe.Reader)
	if !ok {
		cancel()
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		return nil, errors.New("VLESS: неожиданный канал Xray")
	}
	c.r, c.w = r, link.Writer
	c.remote = &net.TCPAddr{IP: net.ParseIP(host), Port: int(port)}
	return c, nil
}

// errWake makes a Read blocked in the pipe look at its deadline again.
var errWake = errors.New("vless: wake")

// tcpConn is one TCP connection dispatched into Xray. Reads drain the
// downlink pipe, writes fill the uplink pipe.
type tcpConn struct {
	r      *pipe.Reader
	w      buf.Writer
	ob     *session.Outbound
	cancel context.CancelFunc
	remote net.Addr

	// Read's own goroutine only.
	left   buf.MultiBuffer
	routed bool
	direct atomic.Bool

	mu       sync.Mutex
	closed   bool
	reading  bool
	rdl, wdl time.Time
	rtimer   *time.Timer
	failed   error
	once     sync.Once
}

// SubmitError takes the outbound's failure (session.TrackedConnectionError)
// so that Read returns it instead of a bare closed pipe.
func (c *tcpConn) SubmitError(err error) {
	c.mu.Lock()
	if c.failed == nil {
		c.failed = err
	}
	c.mu.Unlock()
}

func (c *tcpConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for c.left.IsEmpty() {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return 0, net.ErrClosed
		}
		if passed(c.rdl) {
			c.mu.Unlock()
			return 0, timeout("read")
		}
		c.reading = true
		c.mu.Unlock()
		mb, err := c.r.ReadMultiBuffer()
		c.mu.Lock()
		c.reading = false
		closed, failed := c.closed, c.failed
		c.mu.Unlock()
		if err == errWake {
			continue
		}
		if err != nil {
			buf.ReleaseMulti(mb)
			switch {
			case closed:
				return 0, net.ErrClosed
			case failed != nil && !errors.Is(err, io.EOF):
				return 0, failed
			}
			return 0, err
		}
		if !c.routed {
			// Xray set the outbound tag before the first bytes went into
			// the pipe, whose lock orders it before this read.
			c.routed = true
			c.direct.Store(c.ob.Tag == tagDirect)
		}
		c.left = mb
	}
	var n int
	c.left, n = buf.SplitBytes(c.left, p)
	return n, nil
}

// Direct reports that the connection left through the direct outbound (a
// Direct domain), so its answers say nothing about the VLESS server. It is
// known once something was read.
func (c *tcpConn) Direct() bool { return c.direct.Load() }

func (c *tcpConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	closed, wdl := c.closed, c.wdl
	c.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	if len(p) == 0 {
		return 0, nil
	}
	if passed(wdl) {
		return 0, timeout("write")
	}
	var late atomic.Bool
	if !wdl.IsZero() {
		// The pipe blocks a write only while Xray has a full buffer
		// queued. Nobody can tell how much of p went, so a deadline then
		// breaks the upload.
		t := time.AfterFunc(time.Until(wdl), func() {
			late.Store(true)
			common.Interrupt(c.w)
		})
		defer t.Stop()
	}
	if err := c.w.WriteMultiBuffer(buf.MergeBytes(nil, p)); err != nil {
		c.mu.Lock()
		closed := c.closed
		c.mu.Unlock()
		switch {
		case closed:
			return 0, net.ErrClosed
		case late.Load():
			return 0, timeout("write")
		}
		return 0, err
	}
	return len(p), nil
}

// CloseWrite ends the upload: the server gets EOF, the download goes on
// (engine/tcp.go relies on it for half-closed connections).
func (c *tcpConn) CloseWrite() error {
	return common.Close(c.w)
}

// Close ends the session in Xray.
func (c *tcpConn) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		if c.rtimer != nil {
			c.rtimer.Stop()
		}
		c.mu.Unlock()
		c.cancel()
		common.Interrupt(c.r)
		common.Interrupt(c.w)
	})
	return nil
}

func (c *tcpConn) LocalAddr() net.Addr  { return &net.TCPAddr{IP: net.IPv4zero} }
func (c *tcpConn) RemoteAddr() net.Addr { return c.remote }

func (c *tcpConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *tcpConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.rdl = t
	if c.rtimer != nil {
		c.rtimer.Stop()
		c.rtimer = nil
	}
	switch {
	case t.IsZero():
	case passed(t):
		c.wakeLocked()
	default:
		c.rtimer = time.AfterFunc(time.Until(t), func() {
			c.mu.Lock()
			c.wakeLocked()
			c.mu.Unlock()
		})
	}
	return nil
}

func (c *tcpConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.wdl = t
	return nil
}

// wakeLocked makes a Read blocked in the pipe return errWake. Only this
// connection sends on the pipe's one-slot error channel, and it empties
// the slot first, so the send never blocks.
func (c *tcpConn) wakeLocked() {
	if c.reading {
		_ = c.r.Recover()
		c.r.ReturnAnError(errWake)
	}
}

func passed(t time.Time) bool { return !t.IsZero() && !time.Now().Before(t) }

func timeout(op string) error {
	return &net.OpError{Op: op, Net: "vless", Err: os.ErrDeadlineExceeded}
}

// udpQueue is how many replies may wait for Recv. When it is full, Xray's
// reader waits as well, and the pipe behind it holds the server back,
// instead of dropping datagrams like core.DialUDP's 16-slot cache did.
const udpQueue = 256

// udpSendQueue is how many datagrams may wait for the writer. Dispatch
// blocks in Xray's size-limited pipe while the server is slow or gone, so
// Send queues instead and drops when the queue is full, as a UDP socket
// with a full send buffer would.
const udpSendQueue = 256

// UDPSession carries one capture flow's UDP through a bridge inside this
// process. The bridge's SOCKS5 inbound has no UDP ASSOCIATE, so no local
// UDP port exists that another program could send to.
type UDPSession struct {
	d      *iudp.Dispatcher
	ctx    context.Context
	cancel context.CancelFunc
	in     chan *pudp.Packet
	out    chan *buf.Buffer
	done   chan struct{}
	once   sync.Once
	// dropped counts datagrams that Send dropped on a full queue.
	dropped atomic.Uint64
}

// DialUDP opens a UDP session through the bridge whose private SOCKS5
// inbound is addr. It is routed like that inbound: port 53 to Xray's DNS,
// Direct domains (QUIC) to the direct outbound.
func DialUDP(addr string) (*UDPSession, error) {
	b, d, err := dispatcherAt(addr)
	if err != nil {
		return nil, err
	}
	// The session lives until Close, not as long as one request.
	ctx, cancel := context.WithCancel(context.Background())
	return newUDPSession(b.inboundContext(ctx, "quic"), cancel, d), nil
}

// newUDPSession starts a session on d; cancel ends ctx.
func newUDPSession(ctx context.Context, cancel context.CancelFunc, d routing.Dispatcher) *UDPSession {
	s := &UDPSession{
		ctx:    ctx,
		cancel: cancel,
		in:     make(chan *pudp.Packet, udpQueue),
		out:    make(chan *buf.Buffer, udpSendQueue),
		done:   make(chan struct{}),
	}
	// The dispatcher keeps one link for every destination. A session is
	// one capture flow, so routing by its first destination is right.
	s.d = iudp.NewDispatcher(d, s.deliver)
	go s.writeLoop()
	return s
}

// writeLoop is the only caller of Dispatch, which may block on Xray's pipe.
// Close interrupts that write.
func (s *UDPSession) writeLoop() {
	for {
		select {
		case <-s.done:
			return
		case b := <-s.out:
			select {
			case <-s.done:
				b.Release()
				return
			default:
			}
			s.d.Dispatch(s.ctx, *b.UDP, b)
		}
	}
}

// drainOut releases the datagrams nobody will write.
func (s *UDPSession) drainOut() {
	for {
		select {
		case b := <-s.out:
			b.Release()
		default:
			return
		}
	}
}

// Dropped is how many datagrams Send dropped because the server did not
// take the earlier ones.
func (s *UDPSession) Dropped() uint64 { return s.dropped.Load() }

// deliver queues one reply. It runs in Xray's reader and waits while the
// queue is full.
func (s *UDPSession) deliver(_ context.Context, p *pudp.Packet) {
	select {
	case <-s.done:
		p.Payload.Release()
		return
	default:
	}
	select {
	case s.in <- p:
	case <-s.done:
		p.Payload.Release()
	}
}

// Send queues one datagram for dst and never waits for Xray. When the queue
// is full the datagram is dropped and counted; that is not an error, as for
// any UDP send.
func (s *UDPSession) Send(_ context.Context, dst *net.UDPAddr, payload []byte) error {
	select {
	case <-s.done:
		return net.ErrClosed
	default:
	}
	b := buf.New()
	n := copy(b.Extend(buf.Size), payload)
	b.Resize(0, int32(n))
	dest := xnet.DestinationFromAddr(dst)
	b.UDP = &dest
	select {
	case s.out <- b:
		select {
		case <-s.done:
			// Close drained the queue before this datagram joined it.
			s.drainOut()
		default:
		}
	default:
		b.Release()
		s.dropped.Add(1)
	}
	return nil
}

// Recv returns the next reply.
func (s *UDPSession) Recv(ctx context.Context) (*net.UDPAddr, []byte, error) {
	var p *pudp.Packet
	select {
	case <-s.done:
		return nil, nil, io.EOF
	default:
	}
	select {
	case p = <-s.in:
	case <-s.done:
		return nil, nil, io.EOF
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
	data := append([]byte(nil), p.Payload.Bytes()...)
	p.Payload.Release()
	from := &net.UDPAddr{Port: int(p.Source.Port)}
	if a := p.Source.Address; a != nil && a.Family().IsIP() {
		from.IP = a.IP()
	}
	return from, data, nil
}

// Close ends the session and drops the replies nobody read.
func (s *UDPSession) Close() error {
	s.once.Do(func() {
		close(s.done)
		s.cancel()
		s.d.RemoveRay()
		s.drainOut()
		for {
			select {
			case p := <-s.in:
				p.Payload.Release()
			default:
				return
			}
		}
	})
	return nil
}

// The handshake gate keeps reconnect storms off the VLESS servers: only a
// few new connections to one server handshake at a time. A slot is held
// from the dial until the server's first bytes arrive (the end of the
// TLS/REALITY handshake), the connection closes, or gateHold passes.
// While the server answers, gateHigh may handshake at once: with
// RAW+Vision every app connection is a handshake of its own, and a page
// load opens dozens. After a failed dial, or a slot freed by gateHold with
// nothing read, only gateLow may, until a handshake completes again.
// Retries go through Xray unchanged, so fingerprint and SNI never vary.
const (
	gateHigh = 8
	gateLow  = 2
)

// gateHold is a variable for tests.
var gateHold = 10 * time.Second

var (
	gateMu sync.Mutex
	gates  = map[string]*gate{}
)

type gate struct {
	refs int // under gateMu

	mu    sync.Mutex
	busy  int
	limit int
	free  chan struct{} // closed and replaced when a slot frees or the limit rises
}

func init() {
	internet.UseAlternativeSystemDialer(gateDialer{base: &internet.DefaultSystemDialer{}})
}

func gateAdd(server string) {
	gateMu.Lock()
	defer gateMu.Unlock()
	g := gates[server]
	if g == nil {
		g = &gate{limit: gateHigh, free: make(chan struct{})}
		gates[server] = g
	}
	g.refs++
}

func gateRemove(server string) {
	gateMu.Lock()
	defer gateMu.Unlock()
	if g := gates[server]; g != nil {
		if g.refs--; g.refs <= 0 {
			delete(gates, server)
		}
	}
}

func gateFor(dest xnet.Destination) *gate {
	if dest.Network != xnet.Network_TCP {
		return nil
	}
	gateMu.Lock()
	defer gateMu.Unlock()
	return gates[dest.NetAddr()]
}

func (g *gate) acquire(ctx context.Context) error {
	for {
		g.mu.Lock()
		if g.busy < g.limit {
			g.busy++
			g.mu.Unlock()
			return nil
		}
		free := g.free
		g.mu.Unlock()
		select {
		case <-free:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (g *gate) wakeLocked() {
	close(g.free)
	g.free = make(chan struct{})
}

// release frees a slot; failed lowers the limit to gateLow.
func (g *gate) release(failed bool) {
	g.mu.Lock()
	g.busy--
	if failed {
		g.limit = gateLow
	}
	g.wakeLocked()
	g.mu.Unlock()
}

// answered records the server's first bytes on c: the limit goes back to
// gateHigh. c.got is set under g.mu, so a gateHold release racing with
// the read never lowers the limit after it.
func (g *gate) answered(c *gatedConn) {
	g.mu.Lock()
	if !c.got.Load() {
		c.got.Store(true)
		if g.limit != gateHigh {
			g.limit = gateHigh
			g.wakeLocked()
		}
	}
	g.mu.Unlock()
}

// expired frees c's slot when gateHold passed; nothing read yet means the
// handshake never completed.
func (g *gate) expired(c *gatedConn) {
	g.mu.Lock()
	g.busy--
	if !c.got.Load() {
		g.limit = gateLow
	}
	g.wakeLocked()
	g.mu.Unlock()
}

type gateDialer struct{ base internet.SystemDialer }

func (d gateDialer) Dial(ctx context.Context, src xnet.Address, dest xnet.Destination, sockopt *internet.SocketConfig) (net.Conn, error) {
	g := gateFor(dest)
	if g == nil {
		return d.base.Dial(ctx, src, dest, sockopt)
	}
	if err := g.acquire(ctx); err != nil {
		return nil, err
	}
	conn, err := d.base.Dial(ctx, src, dest, sockopt)
	if err != nil {
		g.release(ctx.Err() == nil)
		return nil, err
	}
	gc := &gatedConn{Conn: conn, g: g}
	gc.timer = time.AfterFunc(gateHold, func() { gc.once.Do(func() { g.expired(gc) }) })
	return gc, nil
}

func (d gateDialer) DestIpAddress() net.IP { return d.base.DestIpAddress() }

// gatedConn frees its gate slot on the first read or on Close.
type gatedConn struct {
	net.Conn
	g     *gate
	timer *time.Timer
	once  sync.Once
	got   atomic.Bool // the server's first bytes came; set under g.mu
}

func (c *gatedConn) release() {
	c.once.Do(func() {
		c.timer.Stop()
		c.g.release(false)
	})
}

func (c *gatedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && !c.got.Load() {
		c.g.answered(c)
	}
	c.release()
	return n, err
}

func (c *gatedConn) Close() error {
	c.release()
	return c.Conn.Close()
}

// gateInUse reports the busy slots for server; tests use it.
func gateInUse(server string) int {
	gateMu.Lock()
	g := gates[server]
	gateMu.Unlock()
	if g == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.busy
}

// gateLimit reports how many handshakes server may run at once; tests use it.
func gateLimit(server string) int {
	gateMu.Lock()
	g := gates[server]
	gateMu.Unlock()
	if g == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.limit
}
