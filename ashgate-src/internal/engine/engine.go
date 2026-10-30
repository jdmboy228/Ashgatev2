// Package engine decides which packets to redirect and relays the accepted
// TCP connections and UDP payloads through the configured proxy.
package engine

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ashgate/internal/config"
	"ashgate/internal/dialer"
	"ashgate/internal/logbuf"
	"ashgate/internal/packet"
	"ashgate/internal/rules"
)

// Action is what the capture loop should do with a packet.
type Action int

const (
	// ActionPass reinjects the packet unchanged.
	ActionPass Action = iota
	// ActionModified reinjects the rewritten packet.
	ActionModified
	// ActionDrop discards the packet.
	ActionDrop
	// ActionUDP forwards the payload through the proxy and does not reinject.
	ActionUDP
	// ActionUnknown asks the capture loop to hold the packet briefly and retry.
	ActionUnknown
)

// Meta is capture metadata needed to inject a reply later.
type Meta struct {
	IfIdx    uint32
	SubIfIdx uint32
}

// Result is the classification of one packet.
type Result struct {
	Action   Action
	Inbound  bool
	IfIdx    uint32
	SubIfIdx uint32
	UDP      *UDPDatagram
}

// UDPDatagram is a proxied UDP payload. The capture loop passes it to ForwardUDP.
type UDPDatagram struct {
	Key       udpKey
	App       packet.Addr
	OrigDst   packet.Addr
	RelayDst  packet.Addr
	Payload   []byte
	IfIdx     uint32
	SubIfIdx  uint32
	ProxyName string
	Process   string
	PID       uint32
}

type udpKey struct {
	Src packet.Addr
	Dst packet.Addr
}

// Resolver maps a local endpoint to the owning process.
type Resolver interface {
	Lookup(proto uint8, src packet.Addr) (rules.Process, bool)
}

// Allocator reserves a local port used as the source of a redirected TCP handshake.
type Allocator interface {
	Reserve(ver int) (port uint16, release func(), err error)
}

// Injector delivers a locally generated reply to the operating system.
type Injector interface {
	InjectInbound(pkt []byte, ifIdx, subIfIdx uint32) error
}

// Options overrides production dependencies. Zero values use the defaults.
type Options struct {
	Resolver Resolver
	Alloc    Allocator
	Dialer   dialer.Dialer
	Logs     *logbuf.Buffer
	Injector Injector
	SelfPID  uint32
	Now      func() time.Time
	SkipSelf bool
}

// Engine is safe for one packet goroutine plus the accept and UDP goroutines.
type Engine struct {
	logs     *logbuf.Buffer
	alloc    Allocator
	dial     dialer.Dialer
	resolver Resolver
	now      func() time.Time
	selfPID  uint32
	verbose  bool

	snap atomic.Pointer[snapshot]
	// bypass holds the proxies' own IPs (ports zero); see RefreshBypass.
	bypass atomic.Pointer[map[packet.Addr]struct{}]
	inj    atomic.Pointer[Injector]

	mu        sync.Mutex
	byClient  map[packet.Addr]*tcpFlow
	byAlloc   map[allocKey]*tcpFlow
	directTCP ageSet[packet.Addr]
	directUDP ageSet[udpKey]
	blockTCP  ageSet[packet.Addr]
	blockUDP  ageSet[udpKey]
	// fragDrop remembers datagrams whose first fragment was dropped, so
	// their later fragments (which carry no ports) are dropped too instead
	// of reaching the destination directly.
	fragDrop ageSet[fragKey]
	udp      map[udpKey]*udpFlow
	// stats are per-rule counters keyed by RuleKey.
	stats map[string]*ruleStat
	// rotatedAt is when the direct/block caches last aged; see sweep.
	rotatedAt time.Time

	dnsSem chan struct{}

	active    atomic.Int64
	bytesUp   atomic.Int64
	bytesDown atomic.Int64
	dnsRR     atomic.Uint64
}

type fragKey struct {
	src, dst packet.Addr // ports zero
	id       uint32
}

func fragOf(h *packet.Header) fragKey {
	k := fragKey{src: h.Src, dst: h.Dst, id: h.FragID}
	k.src.Port, k.dst.Port = 0, 0
	return k
}

// dropFragment records h's datagram when h is a first fragment.
func (e *Engine) dropFragment(h *packet.Header) {
	if h.Frag {
		e.fragDrop.add(fragOf(h))
	}
}

type allocKey struct {
	ver  int
	port uint16
}

type snapshot struct {
	rules          *rules.Set
	proxies        map[string]config.Proxy
	dns            config.DNS
	udpUnsupported string
	bypassPrivate  bool
	relay4         packet.Addr
	relay6         packet.Addr
	// ruleKeys maps a rule index to its RuleKey.
	ruleKeys []string
}

// New compiles cfg and returns an engine. The relay addresses come from cfg.
func New(cfg *config.Config, opt Options) (*Engine, error) {
	if cfg == nil {
		return nil, errors.New("nil config")
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	e := &Engine{
		logs:      opt.Logs,
		alloc:     opt.Alloc,
		dial:      opt.Dialer,
		resolver:  opt.Resolver,
		now:       opt.Now,
		byClient:  map[packet.Addr]*tcpFlow{},
		byAlloc:   map[allocKey]*tcpFlow{},
		directTCP: newAgeSet[packet.Addr](),
		directUDP: newAgeSet[udpKey](),
		blockTCP:  newAgeSet[packet.Addr](),
		blockUDP:  newAgeSet[udpKey](),
		fragDrop:  newAgeSet[fragKey](),
		udp:       map[udpKey]*udpFlow{},
		dnsSem:    make(chan struct{}, httpDNSParallel),
		stats:     map[string]*ruleStat{},
	}
	if e.alloc == nil {
		e.alloc = OSAllocator{}
	}
	if e.dial == nil {
		e.dial = dialer.Net{}
	}
	if e.now == nil {
		e.now = time.Now
	}
	if opt.SelfPID != 0 {
		e.selfPID = opt.SelfPID
	} else if !opt.SkipSelf {
		e.selfPID = uint32(os.Getpid())
	}
	e.verbose = strings.EqualFold(cfg.Log.Level, "debug")
	if opt.Injector != nil {
		e.SetInjector(opt.Injector)
	}
	if err := e.Apply(cfg); err != nil {
		return nil, err
	}
	return e, nil
}

// SetInjector installs the reply path used by UDP.
func (e *Engine) SetInjector(inj Injector) {
	e.inj.Store(&inj)
}

func (e *Engine) injector() Injector {
	p := e.inj.Load()
	if p == nil || *p == nil {
		return nil
	}
	return *p
}

// Apply installs a new rule set. Existing TCP flows keep their proxy.
func (e *Engine) Apply(cfg *config.Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	snap, err := compile(cfg)
	if err != nil {
		return err
	}
	e.snap.Store(snap)
	e.mu.Lock()
	e.directTCP = newAgeSet[packet.Addr]()
	e.directUDP = newAgeSet[udpKey]()
	e.blockTCP = newAgeSet[packet.Addr]()
	e.blockUDP = newAgeSet[udpKey]()
	e.mu.Unlock()
	return nil
}

// Active is the number of proxied TCP and UDP flows.
func (e *Engine) Active() int64 { return e.active.Load() }

// FlowCounts splits the active proxied flows by protocol.
func (e *Engine) FlowCounts() (tcp, udp int) {
	if e == nil {
		return 0, 0
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, f := range e.byClient {
		if f.live {
			tcp++
		}
	}
	for _, f := range e.udp {
		if f.live {
			udp++
		}
	}
	return tcp, udp
}

// Traffic is the bytes relayed since the engine was created.
func (e *Engine) Traffic() (up, down int64) {
	if e == nil {
		return 0, 0
	}
	return e.bytesUp.Load(), e.bytesDown.Load()
}

// RefreshBypass resolves proxy hostnames so traffic to the proxy itself stays direct.
func (e *Engine) RefreshBypass(ctx context.Context) {
	snap := e.snap.Load()
	if snap == nil {
		return
	}
	m := map[packet.Addr]struct{}{}
	for _, p := range snap.proxies {
		host, _, err := net.SplitHostPort(p.Address)
		if err != nil {
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			m[packet.FromIP(ip, 0)] = struct{}{}
			continue
		}
		ctx2, cancel := context.WithTimeout(ctx, 5*time.Second)
		ips, err := net.DefaultResolver.LookupIP(ctx2, "ip", host)
		cancel()
		if err != nil {
			continue
		}
		for _, ip := range ips {
			m[packet.FromIP(ip, 0)] = struct{}{}
		}
	}
	e.bypass.Store(&m)
}

func compile(cfg *config.Config) (*snapshot, error) {
	r4, err := parseRelay(cfg.Relay.TCP4, 4)
	if err != nil {
		return nil, err
	}
	r6, err := parseRelay(cfg.Relay.TCP6, 6)
	if err != nil {
		return nil, err
	}
	keys := make([]string, len(cfg.Rules))
	for i, r := range cfg.Rules {
		keys[i] = RuleKey(r.Process)
	}
	proxies := make(map[string]config.Proxy, len(cfg.Proxies))
	for _, p := range cfg.Proxies {
		proxies[p.Name] = p
	}
	return &snapshot{
		rules:          rules.Compile(cfg.EffectiveRules()),
		proxies:        proxies,
		dns:            cfg.DNS,
		udpUnsupported: cfg.UDPUnsupported,
		bypassPrivate:  cfg.BypassPrivate,
		relay4:         r4,
		relay6:         r6,
		ruleKeys:       keys,
	}, nil
}

func parseRelay(addr string, ver int) (packet.Addr, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return packet.Addr{}, err
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return packet.Addr{}, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return packet.Addr{}, errors.New("relay address must be an IP")
	}
	a := packet.FromIP(ip, uint16(port))
	if ver == 4 && a.Len != 4 {
		return packet.Addr{}, errors.New("relay tcp4 must be ipv4")
	}
	if ver == 6 && a.Len != 16 {
		return packet.Addr{}, errors.New("relay tcp6 must be ipv6")
	}
	return a, nil
}

// HandlePacket classifies one IPv4 or IPv6 packet.
// final is set when the capture loop has already held the packet and must decide.
func (e *Engine) HandlePacket(pkt []byte, meta Meta, final bool) Result {
	var h packet.Header
	if err := packet.Parse(pkt, &h); err != nil {
		return Result{Action: ActionPass}
	}
	if h.L4Off == 0 {
		// A later fragment carries no ports. Drop it when its first
		// fragment was dropped, or it would reach the destination directly.
		if h.Frag {
			e.mu.Lock()
			drop := e.fragDrop.has(fragOf(&h))
			e.mu.Unlock()
			if drop {
				return Result{Action: ActionDrop}
			}
		}
		return Result{Action: ActionPass}
	}
	e.mu.Lock()
	if res, done := e.fastPath(pkt, &h); done {
		e.mu.Unlock()
		return res
	}
	e.mu.Unlock()

	var proc rules.Process
	found := false
	if e.resolver != nil {
		proc, found = e.resolver.Lookup(h.Proto, h.Src)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if res, done := e.fastPath(pkt, &h); done {
		return res
	}
	return e.decide(pkt, &h, meta, proc, found, final)
}

func (e *Engine) fastPath(pkt []byte, h *packet.Header) (Result, bool) {
	snap := e.snap.Load()
	if snap == nil {
		return Result{Action: ActionPass}, true
	}
	if h.Proto == packet.ProtoTCP {
		if res, ok := e.tcpReturn(pkt, h, snap); ok {
			return res, true
		}
		if h.SYN && !h.ACK {
			if flow := e.byClient[h.Src]; flow != nil && flow.orig.Equal(h.Dst) {
				return e.rewriteForward(pkt, h, flow, snap), true
			}
			if flow := e.byClient[h.Src]; flow != nil {
				e.dropFlowLocked(flow)
			}
			e.directTCP.del(h.Src)
			e.blockTCP.del(h.Src)
		} else if flow := e.byClient[h.Src]; flow != nil {
			return e.rewriteForward(pkt, h, flow, snap), true
		} else if e.directTCP.has(h.Src) {
			return Result{Action: ActionPass}, true
		} else if e.blockTCP.has(h.Src) {
			return Result{Action: ActionDrop}, true
		}
	}
	if h.Proto == packet.ProtoUDP {
		key := udpKey{Src: h.Src, Dst: h.Dst}
		if flow := e.udp[key]; flow != nil {
			if h.Frag {
				// A fragmented datagram cannot be relayed; forwarding the
				// first piece would send a truncated payload.
				e.dropFragment(h)
				return Result{Action: ActionDrop}, true
			}
			flow.touch(e.now())
			n := int64(h.PayloadLen)
			flow.up.Add(n)
			e.bytesUp.Add(n)
			if flow.stat != nil {
				flow.stat.up.Add(n)
			}
			return Result{Action: ActionUDP, UDP: datagram(pkt, h, flow)}, true
		}
		if e.directUDP.has(key) {
			return Result{Action: ActionPass}, true
		}
		if e.blockUDP.has(key) {
			e.dropFragment(h)
			return Result{Action: ActionDrop}, true
		}
	}
	return Result{}, false
}

func (e *Engine) decide(pkt []byte, h *packet.Header, meta Meta, proc rules.Process, found, final bool) Result {
	snap := e.snap.Load()
	if h.Frag && h.PayloadOff == 0 {
		return Result{Action: ActionPass}
	}
	if e.destinationBypass(h.Dst, snap.bypassPrivate) {
		e.rememberDirect(h)
		return Result{Action: ActionPass}
	}
	if !found {
		if !final && (h.Proto == packet.ProtoUDP || (h.SYN && !h.ACK)) {
			return Result{Action: ActionUnknown}
		}
		e.rememberDirect(h)
		return Result{Action: ActionPass}
	}
	if e.selfPID != 0 && proc.PID == e.selfPID {
		e.rememberDirect(h)
		return Result{Action: ActionPass}
	}

	dec := snap.rules.Match(proc)
	parent := dec.Parent
	var stat *ruleStat
	if dec.RuleIndex >= 0 && dec.RuleIndex < len(snap.ruleKeys) {
		stat = e.statFor(snap.ruleKeys[dec.RuleIndex])
	}
	proxyName := dec.Proxy
	action := dec.Action
	if action == "" && h.Dst.Port == 53 && snap.dns.IncludeSystemResolver && rules.IsSystemDNS(proc.Name) {
		action = "proxy"
		proxyName = snap.dns.SystemResolverProxy
	}
	switch action {
	case "direct":
		e.rememberDirect(h)
		e.log(logbuf.Event{
			Process: display(proc),
			PID:     proc.PID,
			Proto:   protoName(h.Proto),
			Dest:    h.Dst.String(),
			Via:     "direct",
			Status:  "direct",
			Parent:  parent,
		})
		return Result{Action: ActionPass}
	case "block":
		e.rememberBlock(h)
		e.dropFragment(h)
		e.log(logbuf.Event{
			Process: display(proc),
			PID:     proc.PID,
			Proto:   protoName(h.Proto),
			Dest:    h.Dst.String(),
			Status:  "blocked",
			Parent:  parent,
		})
		return Result{Action: ActionDrop}
	case "proxy":
		p, ok := snap.proxies[proxyName]
		if !ok {
			e.rememberBlock(h)
			e.log(logbuf.Event{Process: display(proc), PID: proc.PID, Proto: protoName(h.Proto), Dest: h.Dst.String(), Via: proxyName, Status: "error", Error: "unknown proxy"})
			return Result{Action: ActionDrop}
		}
		if h.Proto == packet.ProtoTCP {
			if !(h.SYN && !h.ACK) {
				if dec.KillSwitch {
					return e.resetExisting(h, meta, proc, p, parent)
				}
				e.rememberDirect(h)
				return Result{Action: ActionPass}
			}
			return e.startTCP(pkt, h, meta, proc, p, snap, parent, stat)
		}
		if dec.TCPOnly && h.Dst.Port != 53 {
			// "Only TCP": drop UDP so QUIC and the like fall back to TCP,
			// which goes through the proxy. DNS still goes via the proxy.
			e.rememberBlock(h)
			e.dropFragment(h)
			e.log(logbuf.Event{Process: display(proc), PID: proc.PID, Proto: "UDP", Dest: h.Dst.String(), Via: p.Name, Status: "blocked", Error: "только TCP: UDP отброшен", Parent: parent})
			return Result{Action: ActionDrop}
		}
		return e.startUDP(pkt, h, meta, proc, p, snap, parent, stat, dec.KillSwitch)
	default:
		e.rememberDirect(h)
		return Result{Action: ActionPass}
	}
}

func (e *Engine) startTCP(pkt []byte, h *packet.Header, meta Meta, proc rules.Process, p config.Proxy, snap *snapshot, parent string, stat *ruleStat) Result {
	if h.Frag {
		e.dropFragment(h)
		e.log(logbuf.Event{Process: display(proc), PID: proc.PID, Proto: "TCP", Dest: h.Dst.String(), Via: p.Name, Status: "blocked", Error: "fragmented tcp dropped"})
		return Result{Action: ActionDrop}
	}
	port, release, err := e.alloc.Reserve(h.Ver)
	if err != nil {
		e.log(logbuf.Event{Process: display(proc), PID: proc.PID, Proto: "TCP", Dest: h.Dst.String(), Via: p.Name, Status: "error", Error: err.Error()})
		return Result{Action: ActionDrop}
	}
	flow := &tcpFlow{
		ver:      h.Ver,
		app:      h.Src,
		orig:     h.Dst,
		alloc:    port,
		release:  release,
		proxy:    p,
		proc:     proc,
		ifIdx:    meta.IfIdx,
		subIfIdx: meta.SubIfIdx,
		created:  e.now(),
		live:     true,
		parent:   parent,
		stat:     stat,
	}
	if stat != nil {
		stat.flows.Add(1)
	}
	e.byClient[h.Src] = flow
	e.byAlloc[allocKey{ver: h.Ver, port: port}] = flow
	e.active.Add(1)
	return e.rewriteForward(pkt, h, flow, snap)
}

// resetExisting handles a TCP connection of a proxied application that was
// open before capture started. It cannot be moved to the proxy, so with the
// kill switch it is dropped and the application gets a reset, which makes
// it reconnect through the proxy instead of staying direct.
func (e *Engine) resetExisting(h *packet.Header, meta Meta, proc rules.Process, p config.Proxy, parent string) Result {
	e.rememberBlock(h)
	if inj := e.injector(); inj != nil && !h.RST {
		if rst, err := packet.BuildRST(h.Dst, h.Src, h.Ack); err == nil {
			_ = inj.InjectInbound(rst, meta.IfIdx, meta.SubIfIdx)
		}
	}
	e.log(logbuf.Event{Process: display(proc), PID: proc.PID, Proto: "TCP", Dest: h.Dst.String(), Via: p.Name, Status: "blocked",
		Error: "kill switch: соединение открыто до запуска перехвата, сброшено", Parent: parent})
	return Result{Action: ActionDrop}
}

func (e *Engine) startUDP(pkt []byte, h *packet.Header, meta Meta, proc rules.Process, p config.Proxy, snap *snapshot, parent string, stat *ruleStat, killSwitch bool) Result {
	key := udpKey{Src: h.Src, Dst: h.Dst}
	if h.Frag {
		e.blockUDP.add(key)
		e.dropFragment(h)
		e.log(logbuf.Event{Process: display(proc), PID: proc.PID, Proto: "UDP", Dest: h.Dst.String(), Via: p.Name, Status: "blocked", Error: "fragmented udp dropped"})
		return Result{Action: ActionDrop}
	}
	if p.Type != "socks5" && p.Type != "vless" && h.Dst.Port != 53 {
		if snap.udpUnsupported == "direct" && !killSwitch {
			e.directUDP.add(key)
			e.log(logbuf.Event{Process: display(proc), PID: proc.PID, Proto: "UDP", Dest: h.Dst.String(), Via: "direct", Status: "direct", Error: "http proxy has no udp; sent direct"})
			return Result{Action: ActionPass}
		}
		e.blockUDP.add(key)
		e.log(logbuf.Event{Process: display(proc), PID: proc.PID, Proto: "UDP", Dest: h.Dst.String(), Via: p.Name, Status: "blocked", Error: "http proxy cannot carry this udp flow"})
		return Result{Action: ActionDrop}
	}
	relay := h.Dst
	if h.Dst.Port == 53 && snap.dns.Mode == "proxy" {
		if alt, ok := e.pickDNS(snap); ok {
			relay = alt
		}
	}
	flow := &udpFlow{
		key:    key,
		app:    h.Src,
		orig:   h.Dst,
		relay:  relay,
		proxy:  p,
		proc:   proc,
		ifIdx:  meta.IfIdx,
		sub:    meta.SubIfIdx,
		live:   true,
		parent: parent,
		stat:   stat,
	}
	if stat != nil {
		stat.flows.Add(1)
		stat.up.Add(int64(h.PayloadLen))
	}
	flow.touch(e.now())
	n := int64(h.PayloadLen)
	flow.up.Add(n)
	e.bytesUp.Add(n)
	e.udp[key] = flow
	e.active.Add(1)
	e.log(logbuf.Event{Process: display(proc), PID: proc.PID, Proto: "UDP", Dest: h.Dst.String(), Via: p.Name, Status: "open", Parent: parent})
	return Result{Action: ActionUDP, UDP: datagram(pkt, h, flow)}
}

func (e *Engine) pickDNS(snap *snapshot) (packet.Addr, bool) {
	if len(snap.dns.Servers) == 0 {
		return packet.Addr{}, false
	}
	n := e.dnsRR.Add(1)
	s := snap.dns.Servers[int(n)%len(snap.dns.Servers)]
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return packet.Addr{}, false
	}
	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		return packet.Addr{}, false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return packet.Addr{}, false
	}
	return packet.FromIP(ip, uint16(port)), true
}

func datagram(pkt []byte, h *packet.Header, f *udpFlow) *UDPDatagram {
	var payload []byte
	if h.PayloadLen > 0 && h.PayloadOff >= 0 && h.PayloadOff+h.PayloadLen <= len(pkt) {
		payload = append([]byte(nil), pkt[h.PayloadOff:h.PayloadOff+h.PayloadLen]...)
	}
	return &UDPDatagram{
		Key:       f.key,
		App:       f.app,
		OrigDst:   f.orig,
		RelayDst:  f.relay,
		Payload:   payload,
		IfIdx:     f.ifIdx,
		SubIfIdx:  f.sub,
		ProxyName: f.proxy.Name,
		Process:   display(f.proc),
		PID:       f.proc.PID,
	}
}

func (e *Engine) tcpReturn(pkt []byte, h *packet.Header, snap *snapshot) (Result, bool) {
	var relay packet.Addr
	if h.Ver == 4 {
		relay = snap.relay4
	} else {
		relay = snap.relay6
	}
	if !h.Src.Equal(relay) {
		return Result{}, false
	}
	flow := e.byAlloc[allocKey{ver: h.Ver, port: h.Dst.Port}]
	if flow == nil {
		return Result{Action: ActionPass}, true
	}
	if err := packet.Rewrite(pkt, h, flow.orig, flow.app); err != nil {
		return Result{Action: ActionDrop}, true
	}
	return Result{Action: ActionModified, Inbound: true, IfIdx: flow.ifIdx, SubIfIdx: flow.subIfIdx}, true
}

// loopback6 is ::1, the source of redirected IPv6 handshakes. It is built
// once: rewriteForward runs for every packet of a proxied TCP flow.
var loopback6 = packet.FromIP(net.IPv6loopback, 0)

func (e *Engine) rewriteForward(pkt []byte, h *packet.Header, flow *tcpFlow, snap *snapshot) Result {
	var src, dst packet.Addr
	if h.Ver == 4 {
		src = packet.V4(127, 0, 0, 1, flow.alloc)
		dst = snap.relay4
	} else {
		src = loopback6
		src.Port = flow.alloc
		dst = snap.relay6
	}
	if err := packet.Rewrite(pkt, h, src, dst); err != nil {
		return Result{Action: ActionDrop}
	}
	return Result{Action: ActionModified, IfIdx: flow.ifIdx, SubIfIdx: flow.subIfIdx}
}

func (e *Engine) rememberDirect(h *packet.Header) {
	if h.Proto == packet.ProtoTCP {
		e.directTCP.add(h.Src)
		return
	}
	e.directUDP.add(udpKey{Src: h.Src, Dst: h.Dst})
}

func (e *Engine) rememberBlock(h *packet.Header) {
	if h.Proto == packet.ProtoTCP {
		e.blockTCP.add(h.Src)
		return
	}
	e.blockUDP.add(udpKey{Src: h.Src, Dst: h.Dst})
}

func (e *Engine) destinationBypass(dst packet.Addr, private bool) bool {
	if packet.Loopback(dst) || packet.MulticastOrBroadcast(dst) || packet.LinkLocal(dst) {
		return true
	}
	if private && packet.Private(dst) {
		return true
	}
	m := e.bypass.Load()
	if m == nil {
		return false
	}
	dst.Port = 0
	_, ok := (*m)[dst]
	return ok
}

func (e *Engine) log(ev logbuf.Event) {
	if e.logs == nil {
		return
	}
	if !e.verbose && ev.Proto == "UDP" && (ev.Status == "open" || ev.Status == "closed") && strings.HasSuffix(ev.Dest, ":53") {
		return
	}
	if ev.Time.IsZero() {
		ev.Time = e.now()
	}
	e.logs.Add(ev)
}

func display(p rules.Process) string {
	if p.Name != "" {
		return p.Name
	}
	if p.Path != "" {
		return rules.Base(p.Path)
	}
	return ""
}

func protoName(p uint8) string {
	switch p {
	case packet.ProtoTCP:
		return "TCP"
	case packet.ProtoUDP:
		return "UDP"
	default:
		return "IP"
	}
}
