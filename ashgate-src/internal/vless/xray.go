package vless

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"time"

	applog "github.com/xtls/xray-core/app/log"
	xraylog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"

	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/dns"
	_ "github.com/xtls/xray-core/app/geodata"
	_ "github.com/xtls/xray-core/app/log"
	_ "github.com/xtls/xray-core/app/policy"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/app/router"
	_ "github.com/xtls/xray-core/app/stats"
	_ "github.com/xtls/xray-core/main/json"
	_ "github.com/xtls/xray-core/proxy/blackhole"
	_ "github.com/xtls/xray-core/proxy/dns"
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/http"
	_ "github.com/xtls/xray-core/proxy/socks"
	_ "github.com/xtls/xray-core/proxy/tun"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/transport/internet/grpc"
	_ "github.com/xtls/xray-core/transport/internet/headers/http"
	_ "github.com/xtls/xray-core/transport/internet/headers/noop"
	_ "github.com/xtls/xray-core/transport/internet/httpupgrade"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/splithttp"
	_ "github.com/xtls/xray-core/transport/internet/tagged/taggedimpl"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
	_ "github.com/xtls/xray-core/transport/internet/udp"
	_ "github.com/xtls/xray-core/transport/internet/websocket"
)

// The Xray runtime lives in this file and inproc.go. The rest of the
// package builds Xray's JSON and manages bridges without importing Xray.

// instance is a running Xray core.
type instance = core.Instance

func init() {
	// Xray's console logger is created per instance. Swap that creator for a
	// ring buffer so dial failures can be turned into Russian log lines.
	_ = applog.RegisterHandlerCreator(applog.LogType_Console, func(applog.LogType, applog.HandlerCreatorOptions) (xraylog.Handler, error) {
		return logHook{}, nil
	})
}

type logHook struct{}

func (logHook) Severity() xraylog.Severity { return xraylog.Severity_Info }

func (logHook) Handle(msg xraylog.Message) {
	if msg == nil {
		return
	}
	switch msg.(type) {
	case *xraylog.AccessMessage, *xraylog.DNSLog:
		return
	}
	pushLog(msg.String())
}

func loadAndStart(raw []byte) (*instance, error) {
	cfg, err := serial.LoadJSONConfig(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	inst, err := core.New(cfg)
	if err != nil {
		return nil, err
	}
	if err := inst.Start(); err != nil {
		_ = inst.Close()
		return nil, err
	}
	return inst, nil
}

// Run starts Xray with a ready JSON document. Closing the result stops it
// and closes every outbound socket it still holds open (including live UDP
// flows whose TUN queues Xray's stack.Close does not close).
// The Android core uses it; the desktop goes through Listen.
func Run(raw []byte) (io.Closer, error) {
	clearLog()
	tr := newRunTracker()
	setActiveTracker(tr)
	inst, err := loadAndStart(raw)
	if err != nil {
		tr.closeAll()
		clearActiveTracker(tr)
		return nil, err
	}
	// Capture GeneralMessage dial/handshake failures in the in-memory ring
	// buffer even when the config's log section is "none" (nothing ever goes
	// to stdout or logcat).
	xraylog.RegisterHandler(logHook{})
	return &runInstance{inst: inst, tr: tr}, nil
}

// Probe settings for Verify and Check. Tests point ProbeHost and ProbePort
// at a local HTTP server and shorten ProbePause / ProbeWait.
var (
	ProbeHost         = "www.gstatic.com"
	ProbePort  uint16 = 80
	ProbePause        = 300 * time.Millisecond
	ProbeWait         = 6 * time.Second
)

const probeUA = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"

func probeOnce(parent context.Context, inst *instance) error {
	ctx, cancel := context.WithTimeout(parent, ProbeWait)
	defer cancel()
	// Tag "dns-in" (not "tun") ensures the probe always routes through the
	// proxy outbound, even when tests point ProbeHost at a LAN/loopback IP.
	conn, err := dialInstance(ctx, inst, "dns-in", ProbeHost, ProbePort)
	if err != nil {
		return err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	pad := make([]byte, 4+rand.IntN(44))
	for i := range pad {
		pad[i] = "0123456789abcdef"[rand.IntN(16)]
	}
	req := "GET /generate_204 HTTP/1.1\r\nHost: " + ProbeHost +
		"\r\nUser-Agent: " + probeUA +
		"\r\nAccept: */*\r\nX-Request-Id: " + string(pad) +
		"\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return nil
}

// isHardFailure reports errors that cannot recover on an immediate retry
// (handshake/key/cert/path/DNS/refused or a full probe timeout).
func isHardFailure(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.HasPrefix(s, "REALITY:") ||
		s == certFailed ||
		strings.Contains(s, "отклонил") ||
		strings.Contains(s, "не удалось найти адрес") ||
		strings.Contains(s, "(таймаут)")
}

// Verify checks that a running instance actually connects to its proxy
// server and carries traffic stably (two consecutive round-trips separated
// by ProbePause).
func Verify(c io.Closer) error {
	r, ok := c.(*runInstance)
	if !ok || r == nil || r.inst == nil {
		return errors.New("VLESS: локальный мост не запущен")
	}
	const need = 2
	const maxTries = 3
	good := 0
	hadGood := false
	var lastErr error
	for try := 0; try < maxTries && good < need; try++ {
		if try > 0 {
			select {
			case <-r.tr.ctx.Done():
				return r.tr.ctx.Err()
			case <-time.After(ProbePause):
			}
		}
		start := time.Now()
		err := probeOnce(r.tr.ctx, r.inst)
		if r.tr.ctx.Err() != nil {
			return r.tr.ctx.Err()
		}
		if err == nil {
			good++
			hadGood = true
			continue
		}
		good = 0
		lastErr = TunnelError(start, err)
		if !hadGood && (isHardFailure(lastErr) || try >= 1) {
			return lastErr
		}
	}
	if good >= need {
		return nil
	}
	if hadGood {
		return errors.New("VLESS: соединение нестабильно (оборвалось после подключения)")
	}
	if lastErr != nil {
		return lastErr
	}
	return errors.New("VLESS: сервер не ответил. Проверьте адрес и порт сервера, UUID и ключи")
}

// Check probes a running instance to verify that the tunnel is still alive.
// A single failure is retried once after ProbePause before reporting an error.
func Check(c io.Closer) error {
	r, ok := c.(*runInstance)
	if !ok || r == nil || r.inst == nil {
		return errors.New("VLESS: локальный мост не запущен")
	}
	var lastErr error
	for try := 0; try < 2; try++ {
		if try > 0 {
			select {
			case <-r.tr.ctx.Done():
				return r.tr.ctx.Err()
			case <-time.After(ProbePause):
			}
		}
		start := time.Now()
		err := probeOnce(r.tr.ctx, r.inst)
		if r.tr.ctx.Err() != nil {
			return r.tr.ctx.Err()
		}
		if err == nil {
			return nil
		}
		lastErr = TunnelError(start, err)
	}
	return lastErr
}

type runInstance struct {
	inst *instance
	tr   *runTracker
	once sync.Once
}

func (r *runInstance) Close() error {
	var err error
	r.once.Do(func() {
		clearActiveTracker(r.tr)
		r.tr.cancel()
		err = r.inst.Close()
		r.tr.closeAll()
	})
	return err
}
