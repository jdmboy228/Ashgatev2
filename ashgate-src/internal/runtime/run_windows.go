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
	port4, err := relayPort(cp.Relay.TCP4)
	if err != nil {
		return nil, err
	}
	port6, err := relayPort(cp.Relay.TCP6)
	if err != nil {
		return nil, err
	}
	netH, err := windivert.Open(netFilter(port4, port6), windivert.LayerNetwork, 0, 0)
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
	// Socket events bunch up too: a burst lost there leaves packets
	// without a program until holdFor runs out.
	for _, h := range opened {
		_ = h.ConfigureQueue()
	}

	div := &divert{h: netH}
	eng.SetInjector(div)

	ln4, err := net.Listen("tcp", cp.Relay.TCP4)
	if err != nil {
		return nil, fmt.Errorf("локальный приёмник %s: %w", cp.Relay.TCP4, err)
	}
	var ln6 net.Listener
	ln6, err = net.Listen("tcp", cp.Relay.TCP6)
	if err != nil {
		// Whatever holds the port must not get routed IPv6 TCP.
		eng.DisableIPv6Relay()
		if logs != nil {
			logs.Add(logbuf.Event{Proto: "TCP", Dest: cp.Relay.TCP6, Status: "error", Error: "IPv6-приёмник не открыт: " + err.Error()})
		}
		err = nil
	}

	s := &Session{eng: eng, cancel: cancel, done: make(chan struct{}), bridges: bridges, bctx: ctx}
	var wg sync.WaitGroup
	udp := newUDPQueue(udpShards, udpShardDepth, logs, func(d engine.UDPDatagram) {
		_ = eng.ForwardUDP(ctx, d)
	})
	wg.Add(1)
	go readEvents(ctx, sockH, res, eng, &wg)
	wg.Add(1)
	go readEvents(ctx, flowH, res, eng, &wg)
	// Up to 16 batches (1024 packets) wait for consume; the driver's
	// queue holds the rest.
	pkts := make(chan netBatch, 16)
	wg.Add(1)
	go recvNet(ctx, cancel, s, netH, pkts, &wg)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer udp.close()
		consume(ctx, newCapture(eng, div, udp), pkts)
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
		// The driver does not unload by itself. Stop it before releasing
		// the engine mutex, so a new Start cannot race the unload.
		if err := windivert.StopDriver(); err != nil && logs != nil {
			logs.Add(logbuf.Event{Process: "ashgate", Status: "error", Error: "WinDivert: " + err.Error()})
		}
		windows.CloseHandle(mutex)
		close(s.done)
	}()
	if logs != nil {
		logs.Add(logbuf.Event{Process: "ashgate", Proto: "TCP", Dest: cp.Relay.TCP4, Status: "open", Via: "relay"})
	}
	ok = true
	return s, nil
}

// udpProto is IPPROTO_UDP in a socket event.
const udpProto = 17

func readEvents(ctx context.Context, h windivert.Handle, res *process.Resolver, eng *engine.Engine, wg *sync.WaitGroup) {
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
		if ev == windivert.EventSocketClose && addr.Protocol() == udpProto {
			// The port's next socket may be a routed program's.
			eng.ForgetUDPPort(addr.Local().Port)
		}
	}
}

// recvNet reads up to recvBatch packets per call into one reused buffer.
// Each batch is copied once, and its packets are slices of that copy.
func recvNet(ctx context.Context, cancel context.CancelFunc, s *Session, h windivert.Handle, out chan<- netBatch, wg *sync.WaitGroup) {
	defer wg.Done()
	defer close(out)
	buf := make([]byte, recvBatch*windivert.MTUMax)
	addrs := make([]windivert.Address, recvBatch)
	for {
		n, count, err := h.RecvBatch(buf, addrs)
		if err != nil {
			if ctx.Err() == nil && !windivert.IsNoData(err) {
				s.setErr(fmt.Errorf("WinDivertRecv: %s", windivert.FormatError(err)))
				cancel()
			}
			return
		}
		if n == 0 || count == 0 {
			continue
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		b := netBatch{pkts: windivert.SplitBatch(data, count, make([][]byte, 0, count))}
		b.addrs = append([]windivert.Address(nil), addrs[:len(b.pkts)]...)
		select {
		case out <- b:
		case <-ctx.Done():
			return
		}
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

func (d *divert) sendBatch(b *windivert.Batch) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.h.SendBatch(b.Buf, b.Addrs)
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
