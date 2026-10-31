//go:build windows

package runtime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"ashgate/internal/config"
	"ashgate/internal/engine"
	"ashgate/internal/logbuf"
	"ashgate/internal/process"
	"ashgate/internal/vless"
	"ashgate/internal/windivert"
	"golang.org/x/sys/windows"
)

const (
	holdFor    = 50 * time.Millisecond
	holdTick   = 15 * time.Millisecond
	maxPending = 256
	udpWorkers = 4
)

// Start loads WinDivert, diverts outbound TCP/UDP, and relays flows selected
// by the configuration. Other applications are reinjected unchanged.
// VLESS bridges created here close when capture stops.
func Start(parent context.Context, cfg *config.Config, logs *logbuf.Buffer) (*Session, error) {
	return start(parent, cfg, logs, nil)
}

// StartWith is Start, but VLESS bridges come from an existing manager.
// The caller keeps that manager running after capture stops.
func StartWith(parent context.Context, cfg *config.Config, logs *logbuf.Buffer, bridges *vless.Manager) (*Session, error) {
	return start(parent, cfg, logs, bridges)
}

func start(parent context.Context, cfg *config.Config, logs *logbuf.Buffer, bridges *vless.Manager) (sess *Session, err error) {
	if parent == nil {
		parent = context.Background()
	}
	defer func() {
		if err != nil {
			err = annotateStart(err)
		}
	}()
	vless.PortOwner = process.TCPOwner
	cp, err := cloneConfig(cfg)
	if err != nil {
		return nil, err
	}
	if !elevated() {
		return nil, errors.New("Ashgate запущен без прав администратора.")
	}
	mutex, err := acquireEngine()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	ownBridges := bridges == nil
	if ownBridges {
		bridges = vless.NewManager()
	}
	ok := false
	defer func() {
		if !ok {
			if ownBridges {
				bridges.Close()
			}
			cancel()
			windows.CloseHandle(mutex)
		}
	}()
	statuses, err := WireVLESS(ctx, bridges, cp)
	if ownBridges {
		LogBridges(logs, statuses)
	}
	if err != nil {
		return nil, err
	}

	res := process.New()
	eng, err := engine.New(cp, engine.Options{Logs: logs, Resolver: res})
	if err != nil {
		return nil, err
	}
	netH, err := windivert.Open("outbound and !impostor and (tcp or udp)", windivert.LayerNetwork, 0, 0)
	if err != nil {
		return nil, err
	}
	opened := []windivert.Handle{netH}
	defer func() {
		if !ok {
			for _, h := range opened {
				h.Close()
			}
		}
	}()
	sockH, err := windivert.Open(
		"(tcp or udp) and (event == BIND or event == CONNECT or event == ACCEPT or event == CLOSE)",
		windivert.LayerSocket, 0, windivert.FlagSniff|windivert.FlagRecvOnly)
	if err != nil {
		return nil, err
	}
	opened = append(opened, sockH)
	flowH, err := windivert.Open("(tcp or udp) and event == ESTABLISHED", windivert.LayerFlow, 0, windivert.FlagSniff|windivert.FlagRecvOnly)
	if err != nil {
		return nil, err
	}
	opened = append(opened, flowH)
	_ = netH.ConfigureQueue()

	div := &divert{h: netH}
	eng.SetInjector(div)

	ln4, err := net.Listen("tcp", cp.Relay.TCP4)
	if err != nil {
		return nil, fmt.Errorf("локальный приёмник %s: %w", cp.Relay.TCP4, err)
	}
	var ln6 net.Listener
	ln6, err = net.Listen("tcp", cp.Relay.TCP6)
	if err != nil && logs != nil {
		logs.Add(logbuf.Event{Proto: "TCP", Dest: cp.Relay.TCP6, Status: "error", Error: "IPv6-приёмник не открыт: " + err.Error()})
		err = nil
	}

	s := &Session{eng: eng, cancel: cancel, done: make(chan struct{}), bridges: bridges, bctx: ctx}
	var wg sync.WaitGroup
	udpCh := make(chan engine.UDPDatagram, 256)
	for i := 0; i < udpWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for d := range udpCh {
				_ = eng.ForwardUDP(ctx, d)
			}
		}()
	}
	wg.Add(1)
	go readEvents(ctx, sockH, res, &wg)
	wg.Add(1)
	go readEvents(ctx, flowH, res, &wg)
	pkts := make(chan netMsg, 512)
	wg.Add(1)
	go recvNet(ctx, cancel, s, netH, pkts, &wg)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(udpCh)
		consume(ctx, eng, div, logs, pkts, udpCh)
	}()
	wg.Add(1)
	go acceptLoop(ln4, eng, &wg)
	if ln6 != nil {
		wg.Add(1)
		go acceptLoop(ln6, eng, &wg)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		eng.Janitor(ctx)
	}()
	wg.Add(1)
	go refreshLoop(ctx, eng, &wg)

	go func() {
		<-ctx.Done()
		if ownBridges {
			bridges.Close()
		}
		_ = netH.Shutdown(windivert.ShutdownBoth)
		_ = sockH.Shutdown(windivert.ShutdownBoth)
		_ = flowH.Shutdown(windivert.ShutdownBoth)
		_ = ln4.Close()
		if ln6 != nil {
			_ = ln6.Close()
		}
		wg.Wait()
		res.Close()
		_ = netH.Close()
		_ = sockH.Close()
		_ = flowH.Close()
		windows.CloseHandle(mutex)
		close(s.done)
	}()
	if logs != nil {
		logs.Add(logbuf.Event{Process: "ashgate", Proto: "TCP", Dest: cp.Relay.TCP4, Status: "open", Via: "relay"})
	}
	ok = true
	return s, nil
}

func readEvents(ctx context.Context, h windivert.Handle, res *process.Resolver, wg *sync.WaitGroup) {
	defer wg.Done()
	var addr windivert.Address
	for {
		if ctx.Err() != nil {
			return
		}
		if _, err := h.Recv(nil, &addr); err != nil {
			return
		}
		ev := addr.Event()
		closing := ev == windivert.EventSocketClose || ev == windivert.EventFlowDeleted
		res.Observe(addr.Protocol(), addr.Local(), addr.ProcessID(), closing)
	}
}

type netMsg struct {
	pkt  []byte
	addr windivert.Address
}

type held struct {
	pkt  []byte
	addr windivert.Address
	at   time.Time
}

func recvNet(ctx context.Context, cancel context.CancelFunc, s *Session, h windivert.Handle, out chan<- netMsg, wg *sync.WaitGroup) {
	defer wg.Done()
	defer close(out)
	buf := make([]byte, 65535)
	var addr windivert.Address
	for {
		n, err := h.Recv(buf, &addr)
		if err != nil {
			if ctx.Err() == nil && !windivert.IsNoData(err) {
				s.setErr(fmt.Errorf("WinDivertRecv: %s", windivert.FormatError(err)))
				cancel()
			}
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		msg := netMsg{pkt: pkt, addr: addr}
		select {
		case out <- msg:
		case <-ctx.Done():
			return
		}
	}
}

func consume(ctx context.Context, eng *engine.Engine, div *divert, logs *logbuf.Buffer, in <-chan netMsg, udpCh chan<- engine.UDPDatagram) {
	tick := time.NewTicker(holdTick)
	defer tick.Stop()
	var pending []held
	flush := func(force bool) {
		now := time.Now()
		keep := pending[:0]
		for _, h := range pending {
			if force || now.Sub(h.at) >= holdFor {
				queue(eng, div, logs, udpCh, &keep, h.pkt, h.addr, true)
				continue
			}
			// The owning socket's event has often arrived by now. Decide
			// on this tick instead of always waiting the full holdFor.
			meta := engine.Meta{IfIdx: h.addr.IfIdx(), SubIfIdx: h.addr.SubIfIdx()}
			res := eng.HandlePacket(h.pkt, meta, false)
			if res.Action == engine.ActionUnknown {
				keep = append(keep, h)
				continue
			}
			apply(div, logs, udpCh, h.pkt, h.addr, res)
		}
		pending = keep
	}
	for {
		select {
		case <-ctx.Done():
			flush(true)
			return
		case msg, ok := <-in:
			if !ok {
				flush(true)
				return
			}
			if len(pending) >= maxPending {
				flush(true)
			}
			queue(eng, div, logs, udpCh, &pending, msg.pkt, msg.addr, false)
		case <-tick.C:
			flush(false)
		}
	}
}

func queue(eng *engine.Engine, div *divert, logs *logbuf.Buffer, udpCh chan<- engine.UDPDatagram, pending *[]held, pkt []byte, addr windivert.Address, final bool) {
	meta := engine.Meta{IfIdx: addr.IfIdx(), SubIfIdx: addr.SubIfIdx()}
	res := eng.HandlePacket(pkt, meta, final)
	if res.Action == engine.ActionUnknown && !final && len(*pending) < maxPending {
		*pending = append(*pending, held{pkt: pkt, addr: addr, at: time.Now()})
		return
	}
	if res.Action == engine.ActionUnknown {
		res = eng.HandlePacket(pkt, meta, true)
		if res.Action == engine.ActionUnknown {
			res.Action = engine.ActionPass
		}
	}
	apply(div, logs, udpCh, pkt, addr, res)
}

func apply(div *divert, logs *logbuf.Buffer, udpCh chan<- engine.UDPDatagram, pkt []byte, addr windivert.Address, res engine.Result) {
	switch res.Action {
	case engine.ActionDrop:
		return
	case engine.ActionUDP:
		if res.UDP == nil {
			return
		}
		select {
		case udpCh <- *res.UDP:
		default:
			if logs != nil {
				logs.Add(logbuf.Event{Process: res.UDP.Process, PID: res.UDP.PID, Proto: "UDP", Dest: res.UDP.OrigDst.String(), Via: res.UDP.ProxyName, Status: "blocked", Error: "очередь UDP переполнена"})
			}
		}
		return
	case engine.ActionModified:
		// Impostor stops this handle from taking the packet again.
		// WinDivert decrements TTL on impostor packets; that is acceptable
		// because the packet was rewritten. Unmodified packets keep the
		// address WinDivertRecv returned, so their TTL and checksum offload
		// flags stay as they were.
		addr.SetImpostor(true)
		if res.Inbound {
			addr.SetOutbound(false)
			addr.SetIfIdx(res.IfIdx)
			addr.SetSubIfIdx(res.SubIfIdx)
		}
		windivert.MarkValidChecksums(&addr, pkt)
		_ = div.send(pkt, &addr)
	default:
		_ = div.send(pkt, &addr)
	}
}

func acceptLoop(ln net.Listener, eng *engine.Engine, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go eng.ServeConn(c)
	}
}

// bypassEvery is how often proxy host names are resolved again. Each
// lookup goes to the system resolver outside the tunnel, so a short period
// would announce the proxy server on a fixed rhythm; Session.Apply resolves
// at once when the proxies change.
const bypassEvery = 30 * time.Minute

func refreshLoop(ctx context.Context, eng *engine.Engine, wg *sync.WaitGroup) {
	defer wg.Done()
	eng.RefreshBypass(ctx)
	tick := time.NewTicker(bypassEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			eng.RefreshBypass(ctx)
		}
	}
}

type divert struct {
	h  windivert.Handle
	mu sync.Mutex
}

func (d *divert) send(pkt []byte, addr *windivert.Address) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.h.Send(pkt, addr)
}

func (d *divert) InjectInbound(pkt []byte, ifIdx, subIfIdx uint32) error {
	var addr windivert.Address
	addr.SetLayer(windivert.LayerNetwork)
	addr.SetEvent(windivert.EventNetworkPacket)
	addr.SetOutbound(false)
	addr.SetImpostor(true)
	addr.SetIfIdx(ifIdx)
	addr.SetSubIfIdx(subIfIdx)
	windivert.MarkValidChecksums(&addr, pkt)
	return d.send(pkt, &addr)
}

func acquireEngine() (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(`Global\AshgateEngine`)
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateMutex(nil, false, name)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		if h != 0 {
			windows.CloseHandle(h)
		}
		return 0, errors.New("движок Ashgate уже запущен")
	}
	if err != nil {
		return 0, err
	}
	if h == 0 {
		return 0, errors.New("не удалось создать мьютекс движка")
	}
	return h, nil
}

func elevated() bool {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}

func annotateStart(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if accessDenied(err) && !strings.Contains(msg, "перехват уже занят") {
		msg = windivert.FormatError(syscall.Errno(5))
	}
	if !elevated() && !strings.Contains(msg, "без прав администратора") {
		msg = "Ashgate запущен без прав администратора. " + msg
	}
	if accessDenied(err) || !elevated() || strings.Contains(msg, "WinDivert") || strings.Contains(msg, "перехват уже занят") || strings.Contains(msg, "без прав администратора") {
		if list := process.Conflicts(); len(list) > 0 && !strings.Contains(msg, "Сейчас запущены:") {
			msg += " Сейчас запущены: " + strings.Join(list, ", ") + "."
		}
	}
	if msg == err.Error() {
		return err
	}
	return errors.New(msg)
}

func accessDenied(err error) bool {
	var n syscall.Errno
	if errors.As(err, &n) && n == syscall.Errno(5) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "access is denied")
}
