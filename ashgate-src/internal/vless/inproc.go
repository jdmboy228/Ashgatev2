package vless

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport/internet"
)

// Running bridges by their private SOCKS5 address, for DialUDP.
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

// UDPSession carries one capture flow's UDP through a bridge inside this
// process. The bridge's SOCKS5 inbound has no UDP ASSOCIATE, so no local
// UDP port exists that another program could send to.
type UDPSession struct {
	pc     net.PacketConn
	cancel context.CancelFunc
	buf    []byte
}

// DialUDP opens a UDP session through the bridge whose private SOCKS5
// inbound is addr. It is routed like that inbound: port 53 to Xray's DNS,
// Direct domains (QUIC) to the direct outbound.
func DialUDP(addr string) (*UDPSession, error) {
	bridgesMu.Lock()
	b := bridges[addr]
	bridgesMu.Unlock()
	if b == nil {
		return nil, errors.New("VLESS: локальный мост не запущен")
	}
	// The session lives until Close, not as long as one request.
	ctx, cancel := context.WithCancel(context.Background())
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: tagAshgate, Name: "socks"})
	if len(b.routing.Direct) > 0 {
		ctx = session.ContextWithContent(ctx, &session.Content{SniffingRequest: session.SniffingRequest{
			Enabled: true, OverrideDestinationForProtocol: []string{"quic"}, RouteOnly: true,
		}})
	}
	pc, err := core.DialUDP(ctx, b.inst)
	if err != nil {
		cancel()
		return nil, err
	}
	return &UDPSession{pc: pc, cancel: cancel}, nil
}

// Send writes one datagram for dst.
func (s *UDPSession) Send(_ context.Context, dst *net.UDPAddr, payload []byte) error {
	_, err := s.pc.WriteTo(payload, dst)
	return err
}

// Recv returns the next reply. Only one goroutine may call it at a time.
func (s *UDPSession) Recv(_ context.Context) (*net.UDPAddr, []byte, error) {
	if s.buf == nil {
		s.buf = make([]byte, 65535)
	}
	n, from, err := s.pc.ReadFrom(s.buf)
	if err != nil {
		return nil, nil, err
	}
	addr, _ := from.(*net.UDPAddr)
	return addr, append([]byte(nil), s.buf[:n]...), nil
}

// Close ends the session.
func (s *UDPSession) Close() error {
	s.cancel()
	return s.pc.Close()
}

// The handshake gate keeps reconnect storms off the VLESS servers: at most
// gateSlots new connections to one server are handshaking at a time. A
// slot is held from the dial until the server's first bytes arrive (the end
// of the TLS/REALITY handshake), the connection closes, or gateHold passes.
// Retries go through Xray unchanged, so fingerprint and SNI never vary.
const (
	gateSlots = 2
	gateHold  = 10 * time.Second
)

var (
	gateMu sync.Mutex
	gates  = map[string]*gate{}
)

type gate struct {
	slots chan struct{}
	refs  int
}

func init() {
	internet.UseAlternativeSystemDialer(gateDialer{base: &internet.DefaultSystemDialer{}})
}

func gateAdd(server string) {
	gateMu.Lock()
	defer gateMu.Unlock()
	g := gates[server]
	if g == nil {
		g = &gate{slots: make(chan struct{}, gateSlots)}
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

type gateDialer struct{ base internet.SystemDialer }

func (d gateDialer) Dial(ctx context.Context, src xnet.Address, dest xnet.Destination, sockopt *internet.SocketConfig) (net.Conn, error) {
	g := gateFor(dest)
	if g == nil {
		return d.base.Dial(ctx, src, dest, sockopt)
	}
	select {
	case g.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	conn, err := d.base.Dial(ctx, src, dest, sockopt)
	if err != nil {
		<-g.slots
		return nil, err
	}
	gc := &gatedConn{Conn: conn}
	release := func() { <-g.slots }
	gc.timer = time.AfterFunc(gateHold, func() { gc.once.Do(release) })
	gc.release = func() {
		gc.once.Do(func() {
			gc.timer.Stop()
			release()
		})
	}
	return gc, nil
}

func (d gateDialer) DestIpAddress() net.IP { return d.base.DestIpAddress() }

// gatedConn frees its gate slot on the first read or on Close.
type gatedConn struct {
	net.Conn
	once    sync.Once
	timer   *time.Timer
	release func()
}

func (c *gatedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
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
	defer gateMu.Unlock()
	if g := gates[server]; g != nil {
		return len(g.slots)
	}
	return 0
}

// dohByIP lists resolvers that answer DoH on their own IP address, so no
// name has to be resolved to reach them.
var dohByIP = map[string]string{
	"1.1.1.1": "https://1.1.1.1/dns-query", "1.0.0.1": "https://1.0.0.1/dns-query",
	"8.8.8.8": "https://8.8.8.8/dns-query", "8.8.4.4": "https://8.8.4.4/dns-query",
	"9.9.9.9": "https://9.9.9.9/dns-query", "149.112.112.112": "https://149.112.112.112/dns-query",
	"77.88.8.8": "https://77.88.8.8/dns-query", "77.88.8.1": "https://77.88.8.1/dns-query",
	"94.140.14.14": "https://94.140.14.14/dns-query", "94.140.15.15": "https://94.140.15.15/dns-query",
}

// DNSServers turns the configured DNS servers ("1.1.1.1:53") into Xray DNS
// addresses: DoH where the resolver offers it on its IP, DNS over TCP
// otherwise. Xray sends both through the tunnel.
func DNSServers(servers []string) []string {
	var out []string
	for _, s := range servers {
		host, port, err := net.SplitHostPort(s)
		if err != nil || net.ParseIP(host) == nil {
			continue
		}
		if doh, ok := dohByIP[host]; ok && port == "53" {
			out = append(out, doh)
			continue
		}
		out = append(out, "tcp://"+net.JoinHostPort(host, port))
	}
	return out
}
