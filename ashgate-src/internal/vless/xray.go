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
	"sync/atomic"
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

// Severity_Info нужен, т.к. Xray пишет часть ошибок splithttp/REALITY на уровне Info;
// рутинные Info-сообщения на каждое соединение отбрасываются в Handle до захвата logMu.
func (logHook) Severity() xraylog.Severity { return xraylog.Severity_Info }

func (logHook) Handle(msg xraylog.Message) {
	if msg == nil {
		return
	}
	switch m := msg.(type) {
	case *xraylog.AccessMessage, *xraylog.DNSLog:
		return
	case *xraylog.GeneralMessage:
		s := msg.String()
		// Если цикл чтения TUN-дескриптора в Xray завершился ошибкой, помечаем активный инстанс.
		if strings.Contains(s, "[tun]") && strings.Contains(strings.ToLower(s), "failed to read") {
			markActiveTunDead()
		}
		// Пропускаем рутинные Info-логи на горячем пути соединений, чтобы не брать logMu,
		// не удерживать домены в памяти и не вытеснять ошибки handshake из 64-строчного буфера.
		if m.Severity > xraylog.Severity_Warning && !isDiagnosticInfo(s) {
			return
		}
		pushLog(s)
		return
	}
	s := msg.String()
	if strings.Contains(s, "[tun]") && strings.Contains(strings.ToLower(s), "failed to read") {
		markActiveTunDead()
	}
	pushLog(s)
}

func isDiagnosticInfo(s string) bool {
	low := strings.ToLower(s)
	if strings.Contains(low, "processing from ") || strings.Contains(low, "connection ends") || strings.Contains(low, "taking detour") {
		return false
	}
	return strings.Contains(low, "fail") ||
		strings.Contains(low, "error") ||
		strings.Contains(low, "unexpected status") ||
		strings.Contains(low, "bad status") ||
		strings.Contains(low, "reality") ||
		strings.Contains(low, "splithttp") ||
		strings.Contains(low, "x509:") ||
		strings.Contains(low, "certificate") ||
		strings.Contains(low, "handshake") ||
		strings.Contains(low, "refused") ||
		strings.Contains(low, "timeout")
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
	r := &runInstance{inst: inst, tr: tr}
	setActiveRun(r)
	// Capture GeneralMessage dial/handshake failures in the in-memory ring
	// buffer even when the config's log section is "none" (nothing ever goes
	// to stdout or logcat).
	xraylog.RegisterHandler(logHook{})
	return r, nil
}

const (
	defaultProbeHost         = "www.gstatic.com"
	defaultProbePort  uint16 = 80
)

// Настройки пробы для Verify и Check. Тесты перенаправляют ProbeHost и ProbePort
// на локальный HTTP-сервер и сокращают ProbePause / ProbeWait.
var (
	ProbeHost                = defaultProbeHost
	ProbePort         uint16 = defaultProbePort
	ProbeFallbackHost        = "cp.cloudflare.com"
	ProbeFallbackPort uint16 = 80
	ProbePause               = 300 * time.Millisecond
	ProbeWait                = 6 * time.Second
)

const probeUA = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"

type probeStatusError struct {
	code int
}

func (e probeStatusError) Error() string {
	if e.code == http.StatusProxyAuthRequired {
		return "VLESS: отклонена авторизация прокси"
	}
	return fmt.Errorf("unexpected status %d", e.code).Error()
}

func probeTarget(parent context.Context, inst *instance, host string, port uint16) error {
	ctx, cancel := context.WithTimeout(parent, ProbeWait)
	defer cancel()
	// Тег "dns-in" (а не "tun") гарантирует маршрутизацию пробы через прокси-outbound,
	// даже когда тесты направляют ProbeHost на loopback/LAN.
	conn, err := dialInstance(ctx, inst, "dns-in", host, port)
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
	req := "GET /generate_204 HTTP/1.1\r\nHost: " + host +
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
	// Любой HTTP-ответ 2xx-4xx (кроме 407 Proxy Auth Required) подтверждает,
	// что туннель пропустил запрос и вернул ответ (даже если Google отдал 403/302 на VPS IP).
	if resp.StatusCode >= 200 && resp.StatusCode < 500 && resp.StatusCode != http.StatusProxyAuthRequired {
		return nil
	}
	return probeStatusError{code: resp.StatusCode}
}

func probeOnce(parent context.Context, inst *instance, attempt int) error {
	// Если тесты переопределили ProbeHost/ProbePort, используем только тестовую цель.
	useFallback := ProbeHost == defaultProbeHost && ProbePort == defaultProbePort && ProbeFallbackHost != ""
	host, port := ProbeHost, ProbePort
	altHost, altPort := ProbeFallbackHost, ProbeFallbackPort
	if useFallback && attempt%2 == 1 {
		host, port, altHost, altPort = altHost, altPort, host, port
	}
	err := probeTarget(parent, inst, host, port)
	if err == nil || !useFallback || parent.Err() != nil {
		return err
	}
	// При 5xx от первого контрольного хоста сразу пробуем резервный хост,
	// чтобы временный сбой gstatic/cloudflare не ломал проверку туннеля.
	var statusErr probeStatusError
	if errors.As(err, &statusErr) && statusErr.code >= 500 {
		return probeTarget(parent, inst, altHost, altPort)
	}
	return err
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
		strings.Contains(s, "отклонена авторизация") ||
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
		err := probeOnce(r.tr.ctx, r.inst, try)
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
	if r.tunDead.Load() {
		return errors.New("VLESS: локальный интерфейс TUN остановился")
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
		if r.tunDead.Load() {
			return errors.New("VLESS: локальный интерфейс TUN остановился")
		}
		start := time.Now()
		err := probeOnce(r.tr.ctx, r.inst, try)
		if r.tr.ctx.Err() != nil {
			return r.tr.ctx.Err()
		}
		if err == nil {
			if r.tunDead.Load() {
				return errors.New("VLESS: локальный интерфейс TUN остановился")
			}
			return nil
		}
		lastErr = TunnelError(start, err)
		if isHardFailure(lastErr) {
			return lastErr
		}
	}
	return lastErr
}

var (
	activeRunMu sync.Mutex
	activeRun   *runInstance
)

func setActiveRun(r *runInstance) {
	activeRunMu.Lock()
	activeRun = r
	activeRunMu.Unlock()
}

func clearActiveRun(r *runInstance) {
	activeRunMu.Lock()
	if activeRun == r {
		activeRun = nil
	}
	activeRunMu.Unlock()
}

func markActiveTunDead() {
	activeRunMu.Lock()
	r := activeRun
	activeRunMu.Unlock()
	if r != nil {
		r.tunDead.Store(true)
	}
}

type runInstance struct {
	inst    *instance
	tr      *runTracker
	tunDead atomic.Bool
	once    sync.Once
}

func (r *runInstance) Close() error {
	var err error
	r.once.Do(func() {
		clearActiveRun(r)
		clearActiveTracker(r.tr)
		r.tr.cancel()
		// Сначала принудительно закрываем активные сокеты, чтобы не блокироваться внутри inst.Close().
		r.tr.closeAll()
		err = r.inst.Close()
	})
	return err
}
