package engine

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"ashgate/internal/config"
	"ashgate/internal/dialer"
	"ashgate/internal/logbuf"
	"ashgate/internal/packet"
	"ashgate/internal/rules"
)

type udpFlow struct {
	key    udpKey
	app    packet.Addr
	orig   packet.Addr
	relay  packet.Addr
	proxy  config.Proxy
	proc   rules.Process
	ifIdx  uint32
	sub    uint32
	last   atomic.Int64
	up     atomic.Int64
	down   atomic.Int64
	live   bool
	closed bool
	parent string
	stat   *ruleStat
	// sys marks system DNS (see dns.go): split by name per packet, and
	// DNS over TCP through SOCKS5.
	sys  bool
	sess dialer.Session
	// failedAt is the last failed DialUDP. While the proxy is down, packets
	// within udpRetry of it are dropped instead of each starting a new
	// association and logging another error.
	failedAt time.Time
	// mu guards closed, sess and failedAt and is never held across I/O.
	// dialMu serializes the dial and is.
	mu     sync.Mutex
	dialMu sync.Mutex
}

const (
	udpRetry = 3 * time.Second
	// udpIdle retires a UDP flow; dnsIdle a DNS one sooner. A DNS flow is
	// one query and its answer (Xray's DNS gives up within ~10 s), and with
	// every Windows lookup going through the tunnel there are many.
	udpIdle = 30 * time.Second
	dnsIdle = 15 * time.Second
	// httpDNSParallel bounds concurrent DNS-over-CONNECT queries. Each one
	// is a full TCP round trip, so running them inline would let four slow
	// lookups stall every proxied UDP flow.
	httpDNSParallel = 32
)

func (f *udpFlow) touch(t time.Time) {
	f.last.Store(t.UnixNano())
}

// ForwardUDP sends one datagram through the proxy and injects replies.
func (e *Engine) ForwardUDP(ctx context.Context, d UDPDatagram) error {
	e.mu.Lock()
	flow := e.udp[d.Key]
	e.mu.Unlock()
	if flow == nil {
		return nil
	}
	flow.touch(e.now())
	if flow.proxy.Type == "http" || (flow.sys && flow.proxy.Type == "socks5") {
		select {
		case e.dnsSem <- struct{}{}:
			go func() {
				defer func() { <-e.dnsSem }()
				_ = e.forwardDNSTCP(ctx, flow, d.Payload)
			}()
			return nil
		default:
			return e.forwardDNSTCP(ctx, flow, d.Payload)
		}
	}
	return e.forwardSOCKS(ctx, flow, d)
}

func (e *Engine) forwardSOCKS(ctx context.Context, flow *udpFlow, d UDPDatagram) error {
	sess, err := e.udpSession(ctx, flow, d.Payload)
	if sess == nil {
		return err
	}
	// Sent outside flow.mu: the Janitor and Stop take it, and must not wait
	// for I/O.
	dst := &net.UDPAddr{IP: flow.relay.NetIP(), Port: int(flow.relay.Port)}
	if err := sess.Send(ctx, dst, d.Payload); err != nil {
		e.log(logbuf.Event{Process: display(flow.proc), PID: flow.proc.PID, Proto: "UDP", Dest: flow.orig.String(), Via: flow.proxy.Name, Status: "error", Error: err.Error()})
		e.failDNS(flow, d.Payload)
		return err
	}
	return nil
}

// udpSession returns the flow's session and opens it when there is none. It
// returns nil when the datagram is not to be sent: the flow is closed, or
// the proxy is down and err says so (nil for a retry-window drop). flow.mu
// only guards the fields; dialMu keeps two dials of one flow apart, so the
// dial itself, which does I/O, never holds flow.mu.
func (e *Engine) udpSession(ctx context.Context, flow *udpFlow, payload []byte) (dialer.Session, error) {
	flow.dialMu.Lock()
	defer flow.dialMu.Unlock()
	flow.mu.Lock()
	closed, sess, failedAt := flow.closed, flow.sess, flow.failedAt
	flow.mu.Unlock()
	if closed {
		return nil, nil
	}
	if sess != nil {
		return sess, nil
	}
	if !failedAt.IsZero() && e.now().Sub(failedAt) < udpRetry {
		e.failDNS(flow, payload)
		return nil, nil
	}
	sess, err := e.dial.DialUDP(ctx, flow.proxy)
	if err != nil {
		flow.mu.Lock()
		flow.failedAt = e.now()
		flow.mu.Unlock()
		flow.stat.fail(err.Error(), e.now())
		e.log(logbuf.Event{Process: display(flow.proc), PID: flow.proc.PID, Proto: "UDP", Dest: flow.orig.String(), Via: flow.proxy.Name, Status: "error", Error: err.Error()})
		e.failDNS(flow, payload)
		return nil, err
	}
	flow.mu.Lock()
	if flow.closed {
		// Retired while dialing.
		flow.mu.Unlock()
		_ = sess.Close()
		return nil, nil
	}
	flow.sess = sess
	flow.mu.Unlock()
	go e.readUDP(flow, sess)
	return sess, nil
}

func (e *Engine) readUDP(flow *udpFlow, sess dialer.Session) {
	defer e.retireUDP(flow)
	for {
		_, payload, err := sess.Recv(context.Background())
		if err != nil {
			return
		}
		n := int64(len(payload))
		flow.down.Add(n)
		e.bytesDown.Add(n)
		if flow.stat != nil {
			flow.stat.down.Add(n)
		}
		flow.touch(e.now())
		// A reply that cannot be built (too big for one packet) or
		// injected is lost like any UDP datagram; the flow goes on.
		_ = e.injectUDP(flow, payload)
	}
}

func (e *Engine) injectUDP(flow *udpFlow, payload []byte) error {
	inj := e.injector()
	if inj == nil {
		return nil
	}
	pkt, err := packet.BuildUDP(flow.orig, flow.app, payload)
	if err != nil {
		return err
	}
	return inj.InjectInbound(pkt, flow.ifIdx, flow.sub)
}

func (e *Engine) retireUDP(flow *udpFlow) {
	flow.mu.Lock()
	if flow.closed {
		flow.mu.Unlock()
		return
	}
	flow.closed = true
	sess := flow.sess
	flow.sess = nil
	flow.mu.Unlock()
	if sess != nil {
		_ = sess.Close()
	}
	e.mu.Lock()
	if cur, ok := e.udp[flow.key]; ok && cur == flow {
		delete(e.udp, flow.key)
	}
	dec := flow.live
	flow.live = false
	if dec && flow.stat != nil {
		flow.stat.flows.Add(-1)
	}
	e.mu.Unlock()
	if dec {
		e.active.Add(-1)
	}
	e.log(logbuf.Event{
		Process:   display(flow.proc),
		PID:       flow.proc.PID,
		Proto:     "UDP",
		Dest:      flow.orig.String(),
		Via:       flow.proxy.Name,
		Status:    "closed",
		BytesUp:   flow.up.Load(),
		BytesDown: flow.down.Load(),
		Parent:    flow.parent,
	})
}

// Janitor closes idle UDP flows and TCP handshakes that never completed.
func (e *Engine) Janitor(ctx context.Context) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			e.closeAll()
			return
		case <-tick.C:
			e.sweep(e.now())
		}
	}
}

// cacheAge is how often the direct/block caches age. A flow idle for one to
// two intervals is classified again on its next packet, which gives the same
// answer; the caches no longer grow with every connection the machine makes.
const cacheAge = 2 * time.Minute

func (e *Engine) sweep(now time.Time) {
	e.mu.Lock()
	if e.rotatedAt.IsZero() {
		e.rotatedAt = now
	} else if now.Sub(e.rotatedAt) >= cacheAge {
		e.rotatedAt = now
		e.directTCP.rotate()
		e.directUDP.rotate()
		e.reindexDirectUDP()
		e.blockTCP.rotate()
		e.blockUDP.rotate()
		e.closedTCP.rotate()
		e.fragDrop.rotate()
	}
	var staleTCP []*tcpFlow
	for _, f := range e.byClient {
		f.mu.Lock()
		accepted := f.conn != nil
		f.mu.Unlock()
		switch {
		case !f.closedAt.IsZero():
			if now.Sub(f.closedAt) >= tcpCloseGrace {
				staleTCP = append(staleTCP, f)
			}
		case !accepted && now.Sub(f.created) > 30*time.Second:
			staleTCP = append(staleTCP, f)
		}
	}
	var staleUDP []*udpFlow
	for _, f := range e.udp {
		last := time.Unix(0, f.last.Load())
		idle := udpIdle
		if f.orig.Port == 53 {
			idle = dnsIdle
		}
		if now.Sub(last) > idle {
			staleUDP = append(staleUDP, f)
		}
	}
	for _, f := range staleTCP {
		e.dropFlowLocked(f)
	}
	e.mu.Unlock()
	for _, f := range staleUDP {
		f.mu.Lock()
		sess := f.sess
		f.mu.Unlock()
		if sess != nil {
			_ = sess.Close()
		} else {
			e.retireUDP(f)
		}
	}
}

func (e *Engine) closeAll() {
	e.mu.Lock()
	var udps []*udpFlow
	for _, f := range e.udp {
		udps = append(udps, f)
	}
	var tcps []*tcpFlow
	for _, f := range e.byClient {
		tcps = append(tcps, f)
	}
	for _, f := range tcps {
		e.dropFlowLocked(f)
	}
	e.mu.Unlock()
	for _, f := range udps {
		f.mu.Lock()
		sess := f.sess
		f.mu.Unlock()
		if sess != nil {
			_ = sess.Close()
		} else {
			e.retireUDP(f)
		}
	}
}
