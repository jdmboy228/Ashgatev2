package engine

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"ashgate/internal/config"
	"ashgate/internal/dialer"
	"ashgate/internal/httpproxy"
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
	sess   dialer.Session
	// failedAt is the last failed DialUDP. While the proxy is down, packets
	// within udpRetry of it are dropped instead of each starting a new
	// association and logging another error.
	failedAt time.Time
	mu       sync.Mutex
}

const (
	udpRetry = 3 * time.Second
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
	if flow.proxy.Type == "http" {
		select {
		case e.dnsSem <- struct{}{}:
			go func() {
				defer func() { <-e.dnsSem }()
				_ = e.forwardHTTPDns(ctx, flow, d.Payload)
			}()
			return nil
		default:
			return e.forwardHTTPDns(ctx, flow, d.Payload)
		}
	}
	return e.forwardSOCKS(ctx, flow, d)
}

func (e *Engine) forwardHTTPDns(ctx context.Context, flow *udpFlow, payload []byte) error {
	server := flow.relay.String()
	resp, err := httpproxy.DNSQuery(ctx, flow.proxy, server, payload)
	if err != nil {
		flow.stat.fail(err.Error(), e.now())
		e.log(logbuf.Event{Process: display(flow.proc), PID: flow.proc.PID, Proto: "UDP", Dest: flow.orig.String(), Via: flow.proxy.Name, Status: "error", Error: err.Error()})
		return err
	}
	n := int64(len(resp))
	flow.down.Add(n)
	e.bytesDown.Add(n)
	if flow.stat != nil {
		flow.stat.down.Add(n)
	}
	return e.injectUDP(flow, resp)
}

func (e *Engine) forwardSOCKS(ctx context.Context, flow *udpFlow, d UDPDatagram) error {
	flow.mu.Lock()
	defer flow.mu.Unlock()
	if flow.closed {
		return nil
	}
	if flow.sess == nil {
		if !flow.failedAt.IsZero() && e.now().Sub(flow.failedAt) < udpRetry {
			return nil
		}
		sess, err := e.dial.DialUDP(ctx, flow.proxy)
		if err != nil {
			flow.stat.fail(err.Error(), e.now())
			flow.failedAt = e.now()
			e.log(logbuf.Event{Process: display(flow.proc), PID: flow.proc.PID, Proto: "UDP", Dest: flow.orig.String(), Via: flow.proxy.Name, Status: "error", Error: err.Error()})
			return err
		}
		flow.sess = sess
		go e.readUDP(flow, sess)
	}
	dst := &net.UDPAddr{IP: flow.relay.NetIP(), Port: int(flow.relay.Port)}
	if err := flow.sess.Send(ctx, dst, d.Payload); err != nil {
		e.log(logbuf.Event{Process: display(flow.proc), PID: flow.proc.PID, Proto: "UDP", Dest: flow.orig.String(), Via: flow.proxy.Name, Status: "error", Error: err.Error()})
		return err
	}
	return nil
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
		if err := e.injectUDP(flow, payload); err != nil {
			return
		}
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
		if !accepted && now.Sub(f.created) > 30*time.Second {
			staleTCP = append(staleTCP, f)
		}
	}
	var staleUDP []*udpFlow
	for _, f := range e.udp {
		last := time.Unix(0, f.last.Load())
		if now.Sub(last) > 30*time.Second {
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
