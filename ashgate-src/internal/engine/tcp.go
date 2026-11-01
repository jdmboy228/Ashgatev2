package engine

import (
	"context"
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
	ver      int
	app      packet.Addr
	orig     packet.Addr
	alloc    uint16
	release  func()
	proxy    config.Proxy
	proc     rules.Process
	ifIdx    uint32
	subIfIdx uint32
	created  time.Time
	conn     net.Conn
	live     bool
	parent   string
	stat     *ruleStat
	mu       sync.Mutex
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

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	upstream, err := e.dial.DialTCP(ctx, flow.proxy, flow.orig.NetIP().String(), flow.orig.Port)
	cancel()
	if err != nil {
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
	splice(conn, upstream, counter{&up, &e.bytesUp, flow.stat.upCounter()}, counter{&down, &e.bytesDown, flow.stat.downCounter()})
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
	e.dropFlowLocked(flow)
	e.mu.Unlock()
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
}

func (c counter) add(n int) {
	c.flow.Add(int64(n))
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

func splice(app, upstream net.Conn, up, down counter) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(countWriter{upstream, up}, app)
		closeWrite(upstream)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(countWriter{app, down}, upstream)
		closeWrite(app)
	}()
	wg.Wait()
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
