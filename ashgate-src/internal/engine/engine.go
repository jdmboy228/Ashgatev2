// Package engine decides which packets to redirect and relays the accepted
// TCP connections and UDP payloads through the configured proxy.
package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ashgate/internal/bootstrap"
	"ashgate/internal/config"
	"ashgate/internal/dialer"
	"ashgate/internal/logbuf"
	"ashgate/internal/packet"
	"ashgate/internal/process"
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

// liveResolver also answers without sockets that already closed; see
// process.Resolver.LookupLive. A packet that starts a flow uses it.
type liveResolver interface {
	LookupLive(proto uint8, src packet.Addr) (rules.Process, bool)
}

// ownerResolver is process.Resolver: start as for liveResolver, and before
// the last try (final) it never waits for the IP Helper tables.
type ownerResolver interface {
	Owner(proto uint8, src packet.Addr, start process.Start, final bool) (rules.Process, bool)
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
	// servers holds the proxies' own IP:port; see RefreshBypass.
	servers atomic.Pointer[map[packet.Addr]struct{}]
	inj     atomic.Pointer[Injector]
	// noRelay6 is set when the IPv6 relay could not listen; see
	// DisableIPv6Relay. relay6Logged keeps its log to one line.
	noRelay6     atomic.Bool
	relay6Logged atomic.Bool

	mu        sync.Mutex
	byClient  map[packet.Addr]*tcpFlow
	byAlloc   map[allocKey]*tcpFlow
	directTCP ageSet[packet.Addr]
	directUDP ageSet[udpKey]
	// directPorts indexes directUDP by source port; see udpport.go.
	directPorts map[uint16]map[udpKey]struct{}
	blockTCP    ageSet[packet.Addr]
	blockUDP    ageSet[udpKey]
	// closedTCP holds the app side of proxied TCP flows that ended. Their
	// last packets (FIN, ACK, keepalives, retransmits) often come after the
	// relay closed and after the app exited, when the owner can no longer
	// be found; passing them would send the app's own address to the
	// server directly. Apply keeps it; a new SYN from the address clears it.
	closedTCP ageSet[packet.Addr]
	// fragDrop remembers datagrams whose first fragment was dropped, so
	// their later fragments (which carry no ports) are dropped too instead
	// of reaching the destination directly.
	fragDrop ageSet[fragKey]
	// fragHeld remembers datagrams whose first fragment is held for the
	// owner lookup: their later fragments wait for its decision.
	fragHeld ageSet[fragKey]
	udp      map[udpKey]*udpFlow
	// unknownUDP remembers UDP flows dropped for want of a program. Their
	// next packets skip the hold (a stream of them would fill the capture
	// loop's queue) but are still looked up, so once the owner is known
	// they follow its rule. unknownRot is when it last aged.
	unknownUDP ageSet[udpKey]
	unknownRot time.Time
	// unknownDrops counts packets of no known program dropped since the
	// last log line about them, written at unknownLogAt.
	unknownDrops int
	unknownLogAt time.Time
	// stats are per-rule counters keyed by RuleKey.
	stats map[string]*ruleStat
	// rotatedAt is when the direct/block caches last aged; see sweep.
	rotatedAt time.Time

	dnsSem chan struct{}
	// relays is how TCP relays ended per proxy; see RelayHealth.
	relays relayBook

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
	// dnsServers is where proxied queries go (dns.servers or defaults).
	dnsServers []string
	// sysProxy carries system DNS (see dns.go); nil leaves it alone.
	sysProxy *config.Proxy
	// bypassNames resolve with the provider's DNS even in system DNS.
	bypassNames nameSet
	// strict is set when an enabled rule sends a program through a proxy.
	// A packet whose program stays unknown may then be that program's, and
	// is dropped instead of sent direct.
	strict bool
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
		logs:       opt.Logs,
		alloc:      opt.Alloc,
		dial:       opt.Dialer,
		resolver:   opt.Resolver,
		now:        opt.Now,
		byClient:   map[packet.Addr]*tcpFlow{},
		byAlloc:    map[allocKey]*tcpFlow{},
		directTCP:  newAgeSet[packet.Addr](),
		directUDP:  newAgeSet[udpKey](),
		blockTCP:   newAgeSet[packet.Addr](),
		blockUDP:   newAgeSet[udpKey](),
		closedTCP:  newAgeSet[packet.Addr](),
		fragDrop:   newAgeSet[fragKey](),
		fragHeld:   newAgeSet[fragKey](),
		unknownUDP: newAgeSet[udpKey](),
		udp:        map[udpKey]*udpFlow{},
		dnsSem:     make(chan struct{}, httpDNSParallel),
		stats:      map[string]*ruleStat{},
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
	e.directPorts = nil
	e.blockTCP = newAgeSet[packet.Addr]()
	e.blockUDP = newAgeSet[udpKey]()
	e.unknownUDP = newAgeSet[udpKey]()
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

// lookupIP resolves proxy host names with DoH (see internal/bootstrap), so
// the provider's DNS never sees them; tests count the calls.
var lookupIP = func(ctx context.Context, _, host string) ([]net.IP, error) {
	return bootstrap.Default.LookupIP(ctx, host)
}

// RefreshBypass resolves the proxies' host names. A connection to a proxy
// server's IP:port whose program is unknown passes direct: it is almost
// surely Ashgate's own, whose socket event was missed (a known Ashgate
// socket passes by its PID). Only IP:port, and only for an unknown
// program: a VLESS server behind a CDN shares its IP with other sites, and
// a routed program's connection to them follows its rule.
func (e *Engine) RefreshBypass(ctx context.Context) {
	snap := e.snap.Load()
	if snap == nil {
		return
	}
	m := map[packet.Addr]struct{}{}
	for _, p := range snap.proxies {
		host, portStr, err := net.SplitHostPort(p.Address)
		if err != nil {
			continue
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			m[packet.FromIP(ip, uint16(port))] = struct{}{}
			continue
		}
		ctx2, cancel := context.WithTimeout(ctx, 5*time.Second)
		ips, err := lookupIP(ctx2, "ip", host)
		cancel()
		if err != nil {
			continue
		}
		for _, ip := range ips {
			m[packet.FromIP(ip, uint16(port))] = struct{}{}
		}
	}
	e.servers.Store(&m)
}

// proxyServer reports dst as a proxy server's IP:port; see RefreshBypass.
func (e *Engine) proxyServer(dst packet.Addr) bool {
	m := e.servers.Load()
	if m == nil {
		return false
	}
	_, ok := (*m)[dst]
	return ok
}

// DisableIPv6Relay is for when the IPv6 relay could not listen: another
// program may hold its port, and routed IPv6 TCP would be handed to it.
// Such connections are dropped instead; programs then use IPv4.
func (e *Engine) DisableIPv6Relay() { e.noRelay6.Store(true) }

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
	strict := false
	for _, r := range cfg.EffectiveRules() {
		if r.IsEnabled() && r.Action == "proxy" {
			strict = true
		}
	}
	snap := &snapshot{
		rules:          rules.Compile(cfg.EffectiveRules()),
		proxies:        proxies,
		dns:            cfg.DNS,
		udpUnsupported: cfg.UDPUnsupported,
		bypassPrivate:  cfg.BypassPrivate,
		relay4:         r4,
		relay6:         r6,
		ruleKeys:       keys,
		dnsServers:     cfg.DNS.ProxyDNSServers(),
		bypassNames:    newNameSet(cfg.BypassDomains()),
		strict:         strict,
	}
	if p, ok := systemProxy(cfg, proxies); ok {
		snap.sysProxy = &p
	}
	return snap, nil
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
		// No transport header means no ports to route by. Dropping would
		// risk odd but legitimate traffic (offload packets).
		return Result{Action: ActionPass}
	}
	if h.L4Off == 0 {
		return e.laterFragment(&h, final)
	}
	e.mu.Lock()
	if res, done := e.fastPath(pkt, &h); done {
		e.firstFragmentLocked(&h, res.Action)
		e.mu.Unlock()
		return res
	}
	again := !final && h.Proto == packet.ProtoUDP && e.unknownUDP.has(udpKey{Src: h.Src, Dst: h.Dst})
	e.mu.Unlock()

	var proc rules.Process
	found := false
	if e.resolver != nil {
		proc, found = e.lookup(&h, final)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	res, done := e.fastPath(pkt, &h)
	if !done {
		res = e.decide(pkt, &h, meta, proc, found, final || again)
	}
	e.firstFragmentLocked(&h, res.Action)
	return res
}

// lookup finds the program of the packet's socket. A packet that starts a
// flow (a TCP SYN, any UDP) is never credited to a socket that already
// closed: its port may be another program's by now, whose event is still
// on the way. The last packets of a connection keep the closed socket's
// owner for a while. UDP other than DNS is the exception for a moment: a
// program that sends one datagram and closes has its socket closed by the
// time the packet is decided, and dropping it for that would lose syslog,
// STUN and NTP.
func (e *Engine) lookup(h *packet.Header, final bool) (rules.Process, bool) {
	start := process.Continuing
	switch {
	case h.Proto == packet.ProtoUDP && h.Dst.Port != 53:
		start = process.NewDatagram
	case h.Proto == packet.ProtoUDP, h.SYN && !h.ACK:
		start = process.NewFlow
	}
	switch r := e.resolver.(type) {
	case ownerResolver:
		return r.Owner(h.Proto, h.Src, start, final)
	case liveResolver:
		if start != process.Continuing {
			return r.LookupLive(h.Proto, h.Src)
		}
	}
	return e.resolver.Lookup(h.Proto, h.Src)
}

// laterFragment decides a fragment without ports. It is dropped when its
// first fragment was, or it would reach the destination directly, and it
// waits while the first one is held.
func (e *Engine) laterFragment(h *packet.Header, final bool) Result {
	if !h.Frag {
		return Result{Action: ActionPass}
	}
	k := fragOf(h)
	e.mu.Lock()
	drop := e.fragDrop.has(k)
	held := !drop && e.fragHeld.has(k)
	e.mu.Unlock()
	switch {
	case drop:
		return Result{Action: ActionDrop}
	case held && !final:
		return Result{Action: ActionUnknown}
	case held:
		if snap := e.snap.Load(); snap != nil && snap.strict {
			return Result{Action: ActionDrop}
		}
	}
	return Result{Action: ActionPass}
}

// firstFragmentLocked notes whether h, when a first fragment, is held.
func (e *Engine) firstFragmentLocked(h *packet.Header, a Action) {
	if !h.Frag {
		return
	}
	if a == ActionUnknown {
		if e.fragHeld.len() >= maxFragHeld {
			e.fragHeld.rotate()
		}
		e.fragHeld.add(fragOf(h))
	} else {
		e.fragHeld.del(fragOf(h))
	}
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
			if flow := e.byClient[h.Src]; flow != nil && flow.orig.Equal(h.Dst) && flow.closedAt.IsZero() {
				return e.rewriteForward(pkt, h, flow, snap), true
			}
			if flow := e.byClient[h.Src]; flow != nil {
				e.dropFlowLocked(flow)
			}
			e.directTCP.del(h.Src)
			e.blockTCP.del(h.Src)
			e.closedTCP.del(h.Src)
		} else if flow := e.byClient[h.Src]; flow != nil {
			return e.rewriteForward(pkt, h, flow, snap), true
		} else if e.closedTCP.has(h.Src) {
			return Result{Action: ActionDrop}, true
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
			if flow.sys {
				// One socket of the DNS client may ask for a bypass name next.
				if name, _, _, ok := question(payloadOf(pkt, h)); ok && snap.bypassNames.bypass(name) {
					return Result{Action: ActionPass}, true
				}
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
	// DNS is never exempt as a private or link-local destination: a
	// proxied app asking the router (192.168.1.1:53, fe80::1:53) would leak
	// its names outside the tunnel. Direct UDP DNS is not cached either: a
	// port another program used a moment ago must not pass a routed
	// program's query.
	dns := h.Dst.Port == 53
	if destinationBypass(h.Dst, snap.bypassPrivate && !dns, dns) {
		e.rememberDirectExceptDNS(h)
		return Result{Action: ActionPass}
	}
	if !found {
		if !final && (h.Proto == packet.ProtoUDP || h.Proto == packet.ProtoTCP) {
			return Result{Action: ActionUnknown}
		}
		if e.proxyServer(h.Dst) {
			e.rememberDirectExceptDNS(h)
			return Result{Action: ActionPass}
		}
		if dns {
			// Any program may have sent it, a routed one included.
			return e.systemDNS(pkt, h, meta, rules.Process{}, snap)
		}
		if h.Proto == packet.ProtoTCP && !(h.SYN && !h.ACK) {
			// A mid-connection packet with no process behind it: the app
			// exited and Windows still closes its socket (keepalives, the
			// last FIN/ACK). If that connection was proxied before a restart
			// of capture, passing it would put the app's own address on the
			// wire. A dead socket loses nothing by being dropped.
			e.rememberBlock(h)
			return Result{Action: ActionDrop}
		}
		if snap.strict {
			// A new connection or UDP of a program still unknown after the
			// hold may be a routed program's. It is not remembered: a
			// retransmit is decided again, by then often with its owner.
			e.dropFragment(h)
			if h.Proto == packet.ProtoUDP {
				if now := e.now(); now.Sub(e.unknownRot) >= unknownKeep {
					e.unknownUDP.rotate()
					e.unknownRot = now
				}
				e.unknownUDP.add(udpKey{Src: h.Src, Dst: h.Dst})
			}
			e.unknownDropLocked()
			return Result{Action: ActionDrop}
		}
		e.rememberDirect(h)
		return Result{Action: ActionPass}
	}
	if e.selfPID != 0 && proc.PID == e.selfPID {
		e.rememberDirectExceptDNS(h)
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
	// A running process whose image cannot be read (a protected one, and
	// the Windows DNS client can be one) has no name for a rule to match.
	// Its DNS is treated like the DNS client's, never sent direct.
	if action == "" && (rules.IsSystemDNS(proc.Name) || (proc.Name == "" && proc.Path == "")) {
		if dns {
			return e.systemDNS(pkt, h, meta, proc, snap)
		}
		if encryptedDNS(h) {
			return e.systemEncryptedDNS(pkt, h, meta, proc, snap)
		}
	}
	switch action {
	case "direct":
		e.rememberDirectExceptDNS(h)
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
			return e.startTCP(pkt, h, meta, proc, p, snap, parent, stat, false)
		}
		if dec.TCPOnly && h.Dst.Port != 53 {
			// "Only TCP": drop UDP so QUIC and the like fall back to TCP,
			// which goes through the proxy. DNS still goes via the proxy.
			e.rememberBlock(h)
			e.dropFragment(h)
			e.log(logbuf.Event{Process: display(proc), PID: proc.PID, Proto: "UDP", Dest: h.Dst.String(), Via: p.Name, Status: "blocked", Error: "только TCP: UDP отброшен", Parent: parent})
			return Result{Action: ActionDrop}
		}
		return e.startUDP(pkt, h, meta, proc, p, snap, parent, stat, dec.KillSwitch, false)
	default:
		e.rememberDirectExceptDNS(h)
		return Result{Action: ActionPass}
	}
}

// startTCP maps a new connection to the relay. sys marks system DNS.
func (e *Engine) startTCP(pkt []byte, h *packet.Header, meta Meta, proc rules.Process, p config.Proxy, snap *snapshot, parent string, stat *ruleStat, sys bool) Result {
	if h.Ver == 6 && e.noRelay6.Load() {
		if !e.relay6Logged.Swap(true) {
			e.log(logbuf.Event{Process: display(proc), PID: proc.PID, Proto: "TCP", Dest: h.Dst.String(), Via: p.Name, Status: "blocked",
				Error: "IPv6-приёмник не открыт: IPv6-соединения программ с правилом отброшены, они пойдут по IPv4"})
		}
		return Result{Action: ActionDrop}
	}
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
	if h.Dst.Port == 53 && (snap.dns.Mode == "proxy" || sys) {
		// DNS over TCP goes to the configured servers like UDP does, not
		// to the resolver the program chose (the provider's).
		if alt, ok := e.pickDNS(snap); ok {
			flow.dial = alt
		}
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
	e.reset(h, meta)
	e.log(logbuf.Event{Process: display(proc), PID: proc.PID, Proto: "TCP", Dest: h.Dst.String(), Via: p.Name, Status: "blocked",
		Error: "kill switch: соединение открыто до запуска перехвата, сброшено", Parent: parent})
	return Result{Action: ActionDrop}
}

// reset drops a connection that cannot be moved to the proxy and sends the
// program a reset, so it reconnects (through the proxy) at once.
func (e *Engine) reset(h *packet.Header, meta Meta) {
	e.rememberBlock(h)
	if inj := e.injector(); inj != nil && !h.RST {
		if rst, err := packet.BuildRST(h.Dst, h.Src, h.Ack); err == nil {
			_ = inj.InjectInbound(rst, meta.IfIdx, meta.SubIfIdx)
		}
	}
}

const (
	// unknownLogEvery bounds the log lines about packets of no known program.
	unknownLogEvery = 10 * time.Second
	// unknownKeep is how long unknownUDP remembers a flow without packets.
	unknownKeep = 30 * time.Second
	// maxFragHeld bounds fragHeld; a full set ages at once.
	maxFragHeld = 4096
)

// unknownDropLocked counts a dropped packet of no known program and logs
// the count at most once per unknownLogEvery.
func (e *Engine) unknownDropLocked() {
	e.unknownDrops++
	now := e.now()
	if !e.unknownLogAt.IsZero() && now.Sub(e.unknownLogAt) < unknownLogEvery {
		return
	}
	e.unknownLogAt = now
	e.log(logbuf.Event{Status: "blocked", Error: fmt.Sprintf("программа не определена: пакеты отброшены (%d)", e.unknownDrops)})
	e.unknownDrops = 0
}

// startUDP opens a proxied UDP flow. sys marks system DNS (see dns.go).
func (e *Engine) startUDP(pkt []byte, h *packet.Header, meta Meta, proc rules.Process, p config.Proxy, snap *snapshot, parent string, stat *ruleStat, killSwitch, sys bool) Result {
	key := udpKey{Src: h.Src, Dst: h.Dst}
	if h.Frag {
		e.blockUDP.add(key)
		e.dropFragment(h)
		e.log(logbuf.Event{Process: display(proc), PID: proc.PID, Proto: "UDP", Dest: h.Dst.String(), Via: p.Name, Status: "blocked", Error: "fragmented udp dropped"})
		return Result{Action: ActionDrop}
	}
	if p.Type != "socks5" && p.Type != "vless" && h.Dst.Port != 53 {
		if snap.udpUnsupported == "direct" && !killSwitch {
			e.addDirectUDP(key)
			e.log(logbuf.Event{Process: display(proc), PID: proc.PID, Proto: "UDP", Dest: h.Dst.String(), Via: "direct", Status: "direct", Error: "http proxy has no udp; sent direct"})
			return Result{Action: ActionPass}
		}
		e.blockUDP.add(key)
		e.log(logbuf.Event{Process: display(proc), PID: proc.PID, Proto: "UDP", Dest: h.Dst.String(), Via: p.Name, Status: "blocked", Error: "http proxy cannot carry this udp flow"})
		return Result{Action: ActionDrop}
	}
	relay := h.Dst
	if h.Dst.Port == 53 && (snap.dns.Mode == "proxy" || sys) {
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
		sys:    sys,
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
	return dnsRelay(snap.dnsServers, e.dnsRR.Add(1))
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
	if h.Frag {
		// Only the first fragment has ports to rewrite; the rest would
		// reach the site with the app's own address. TCP resends.
		e.dropFragment(h)
		return Result{Action: ActionDrop}
	}
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
	e.addDirectUDP(udpKey{Src: h.Src, Dst: h.Dst})
}

// rememberDirectExceptDNS is rememberDirect for anything but UDP to port
// 53. A DNS socket's port is soon another program's, and the cache is keyed
// by address. TCP is safe: a new connection's SYN clears the entry.
func (e *Engine) rememberDirectExceptDNS(h *packet.Header) {
	if h.Proto != packet.ProtoUDP || h.Dst.Port != 53 {
		e.rememberDirect(h)
	}
}

func (e *Engine) rememberBlock(h *packet.Header) {
	if h.Proto == packet.ProtoTCP {
		e.blockTCP.add(h.Src)
		return
	}
	e.blockUDP.add(udpKey{Src: h.Src, Dst: h.Dst})
}

// destinationBypass reports a destination that never leaves the machine or
// the LAN this way: loopback, multicast, link-local (not DNS) and, when
// private is set, private networks.
func destinationBypass(dst packet.Addr, private, dns bool) bool {
	if packet.Loopback(dst) || packet.MulticastOrBroadcast(dst) {
		return true
	}
	if packet.LinkLocal(dst) && !dns {
		return true
	}
	return private && packet.Private(dst)
}

func (e *Engine) log(ev logbuf.Event) {
	if e.logs == nil {
		return
	}
	if !e.verbose && ev.Proto == "UDP" && (ev.Status == "open" || ev.Status == "closed" || ev.Status == "direct") && strings.HasSuffix(ev.Dest, ":53") {
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
	if p.PID != 0 {
		// Known, but its image cannot be read (a protected process).
		return "PID " + strconv.FormatUint(uint64(p.PID), 10)
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
