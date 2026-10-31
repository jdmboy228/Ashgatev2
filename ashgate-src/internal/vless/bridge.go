package vless

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	applog "github.com/xtls/xray-core/app/log"
	xraylog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"

	_ "github.com/xtls/xray-core/main/distro/all"
)

func init() {
	// Xray's console logger is created per instance. Swap that creator for a
	// ring buffer so dial failures can be turned into Russian log lines.
	_ = applog.RegisterHandlerCreator(applog.LogType_Console, func(applog.LogType, applog.HandlerCreatorOptions) (xraylog.Handler, error) {
		return logHook{}, nil
	})
}

type logHook struct{}

func (logHook) Handle(msg xraylog.Message) {
	if msg == nil {
		return
	}
	pushLog(msg.String())
}

// Inbound is the localhost SOCKS5 (and optional HTTP) listener for one bridge.
// Port 0 asks for a random port and does not publish HTTP.
type Inbound struct {
	Port int    `json:"port,omitempty"`
	User string `json:"user,omitempty"`
	Pass string `json:"pass,omitempty"`
}

// Bridge is one local SOCKS5 inbound in front of a VLESS outbound.
type Bridge struct {
	Addr string
	HTTP string
	inst *core.Instance
	stop chan struct{}
	once sync.Once
}

// Close stops the embedded Xray instance. It is safe to call more than once.
func (b *Bridge) Close() {
	if b == nil {
		return
	}
	b.once.Do(func() {
		close(b.stop)
		if b.inst != nil {
			_ = b.inst.Close()
		}
	})
}

// Listen starts a SOCKS5 inbound on 127.0.0.1 and a VLESS outbound to serverAddr.
// A fixed Inbound.Port also publishes an HTTP proxy on the next port.
// The bridge stops when ctx is cancelled or Close is called.
func Listen(ctx context.Context, serverAddr string, p Params, in Inbound) (*Bridge, error) {
	b, err := listen(ctx, serverAddr, p, in)
	if err != nil {
		// The error reaches the window and ashgate.log.
		return nil, maskSecrets(err, p)
	}
	return b, nil
}

func listen(ctx context.Context, serverAddr string, p Params, in Inbound) (*Bridge, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := p.Normalize(); err != nil {
		return nil, err
	}
	if in.Port < 0 || in.Port > 65535 {
		return nil, errors.New("VLESS: неверный локальный SOCKS5-порт")
	}
	host, portStr, err := net.SplitHostPort(serverAddr)
	if err != nil || host == "" {
		return nil, errors.New("VLESS: неверный адрес сервера")
	}
	serverPort, err := net.LookupPort("tcp", portStr)
	if err != nil || serverPort < 1 || serverPort > 65535 {
		return nil, errors.New("VLESS: неверный адрес сервера")
	}
	if in.Port != 0 {
		return listenFixed(ctx, host, serverPort, p, in)
	}
	var last error
	for attempt := 0; attempt < 5; attempt++ {
		port, err := freePort()
		if err != nil {
			return nil, err
		}
		b, err := startBridge(ctx, host, serverPort, port, 0, Inbound{}, p)
		if err != nil {
			last = err
			if bindConflict(err) {
				continue
			}
			return nil, humanizeStart(err)
		}
		return b, nil
	}
	if last == nil {
		last = errors.New("VLESS: не удалось запустить локальный мост")
	}
	return nil, humanizeStart(last)
}

func listenFixed(ctx context.Context, host string, serverPort int, p Params, in Inbound) (*Bridge, error) {
	httpPort := 0
	if in.Port < 65535 {
		httpPort = in.Port + 1
	}
	if err := portFree(in.Port, true); err != nil {
		return nil, portBusy(in.Port)
	}
	if httpPort != 0 {
		if err := portFree(httpPort, false); err != nil {
			return nil, fmt.Errorf("VLESS: HTTP-порт %d занят. Выберите другой локальный SOCKS5-порт", httpPort)
		}
	}
	b, err := startBridge(ctx, host, serverPort, in.Port, httpPort, in, p)
	if err != nil {
		if bindConflict(err) {
			return nil, portBusy(in.Port)
		}
		return nil, humanizeStart(err)
	}
	return b, nil
}

func startBridge(ctx context.Context, host string, serverPort, socksPort, httpPort int, in Inbound, p Params) (*Bridge, error) {
	raw, err := ClientJSON("127.0.0.1", socksPort, httpPort, host, serverPort, in.User, in.Pass, p)
	if err != nil {
		return nil, err
	}
	inst, err := loadAndStart(raw)
	if err != nil {
		return nil, err
	}
	b := &Bridge{Addr: fmt.Sprintf("127.0.0.1:%d", socksPort), inst: inst, stop: make(chan struct{})}
	if httpPort != 0 {
		b.HTTP = fmt.Sprintf("127.0.0.1:%d", httpPort)
	}
	go func() {
		select {
		case <-ctx.Done():
			b.Close()
		case <-b.stop:
		}
	}()
	if err := waitPort(b.Addr, 2*time.Second); err != nil {
		b.Close()
		return nil, err
	}
	if b.HTTP != "" {
		if err := waitPort(b.HTTP, 2*time.Second); err != nil {
			b.Close()
			return nil, fmt.Errorf("VLESS: HTTP-порт %d не открылся", httpPort)
		}
	}
	return b, nil
}

// ClientJSON is the Xray client document for one VLESS outbound.
// httpPort 0 omits the HTTP inbound. socksPort is the SOCKS5 listen port.
func ClientJSON(listen string, socksPort, httpPort int, serverHost string, serverPort int, user, pass string, p Params) ([]byte, error) {
	if err := p.Normalize(); err != nil {
		return nil, err
	}
	vuser := map[string]any{
		"id":         p.UUID,
		"encryption": "none",
	}
	if flow := p.DialFlow(); flow != "" {
		vuser["flow"] = flow
	}
	network := p.Network
	if network == "tcp" {
		// Xray calls TCP "raw" since v24.9.30; config.json keeps "tcp".
		network = "raw"
	}
	stream := map[string]any{
		"network":  network,
		"security": p.Security,
	}
	switch p.Security {
	case "reality":
		stream["realitySettings"] = map[string]any{
			"serverName":  p.SNI,
			"fingerprint": p.Fingerprint,
			"publicKey":   p.PublicKey,
			"shortId":     p.ShortID,
			"spiderX":     p.SpiderX,
		}
	case "tls":
		tls := map[string]any{
			"serverName":    p.SNI,
			"fingerprint":   p.Fingerprint,
			"allowInsecure": p.AllowInsecure,
		}
		if p.ALPN != "" {
			tls["alpn"] = splitComma(p.ALPN)
		}
		stream["tlsSettings"] = tls
	}
	switch p.Network {
	case "xhttp":
		xs := map[string]any{}
		if p.Path != "" {
			xs["path"] = p.Path
		}
		if p.Host != "" {
			xs["host"] = p.Host
		}
		if p.Mode != "" {
			xs["mode"] = p.Mode
		}
		if len(p.Extra) > 0 {
			xs["extra"] = json.RawMessage(p.Extra)
		}
		stream["xhttpSettings"] = xs
	case "ws":
		ws := map[string]any{}
		if p.Path != "" {
			ws["path"] = p.Path
		}
		if p.Host != "" {
			ws["host"] = p.Host
		}
		stream["wsSettings"] = ws
	case "grpc":
		gs := map[string]any{"serviceName": p.ServiceName}
		if p.Authority != "" {
			gs["authority"] = p.Authority
		}
		if p.Mode == "multi" {
			gs["multiMode"] = true
		}
		stream["grpcSettings"] = gs
	case "httpupgrade":
		hs := map[string]any{}
		if p.Path != "" {
			hs["path"] = p.Path
		}
		if p.Host != "" {
			hs["host"] = p.Host
		}
		stream["httpupgradeSettings"] = hs
	default:
		if p.HeaderType != "" && !strings.EqualFold(p.HeaderType, "none") {
			stream["rawSettings"] = map[string]any{
				"header": map[string]any{"type": p.HeaderType},
			}
		}
	}
	inbounds := []any{map[string]any{
		"listen":   listen,
		"port":     socksPort,
		"protocol": "socks",
		"settings": socksSettings(user, pass),
	}}
	if httpPort != 0 {
		inbounds = append(inbounds, map[string]any{
			"listen":   listen,
			"port":     httpPort,
			"protocol": "http",
			"settings": httpSettings(user, pass),
		})
	}
	doc := map[string]any{
		"log":      map[string]any{"loglevel": "info"},
		"inbounds": inbounds,
		"outbounds": []any{map[string]any{
			"protocol": "vless",
			"settings": map[string]any{
				"vnext": []any{map[string]any{
					"address": serverHost,
					"port":    serverPort,
					"users":   []any{vuser},
				}},
			},
			"streamSettings": stream,
		}},
	}
	return json.Marshal(doc)
}

func loadAndStart(raw []byte) (*core.Instance, error) {
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

func socksSettings(user, pass string) map[string]any {
	if user == "" {
		return map[string]any{"auth": "noauth", "udp": true}
	}
	return map[string]any{
		"auth":     "password",
		"udp":      true,
		"accounts": []any{map[string]string{"user": user, "pass": pass}},
	}
}

func httpSettings(user, pass string) map[string]any {
	if user == "" {
		return map[string]any{}
	}
	return map[string]any{
		"accounts": []any{map[string]string{"user": user, "pass": pass}},
	}
}

func portFree(port int, udp bool) error {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	_ = ln.Close()
	if !udp {
		return nil
	}
	pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	_ = pc.Close()
	return nil
}

// PortOwner, when set by the Windows host, names the process bound to a local port.
var PortOwner func(port int) (name string, pid uint32, ok bool)

func portBusy(port int) error {
	if PortOwner != nil {
		name, pid, ok := PortOwner(port)
		if ok && name != "" {
			return fmt.Errorf("VLESS: порт %d занят процессом %s (PID %d). Выберите другой локальный SOCKS5-порт", port, name, pid)
		}
		if ok && pid != 0 {
			return fmt.Errorf("VLESS: порт %d занят процессом PID %d. Выберите другой локальный SOCKS5-порт", port, pid)
		}
	}
	return fmt.Errorf("VLESS: порт %d занят. Выберите другой локальный SOCKS5-порт", port)
}

func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port, nil
}

func waitPort(addr string, d time.Duration) error {
	deadline := time.Now().Add(d)
	var last error
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return nil
		}
		last = err
		time.Sleep(20 * time.Millisecond)
	}
	if last == nil {
		last = errors.New("VLESS: локальный мост не открыл порт")
	}
	return last
}

func bindConflict(err error) bool {
	if err == nil {
		return false
	}
	low := strings.ToLower(err.Error())
	return strings.Contains(low, "bind") || strings.Contains(low, "address already in use") || strings.Contains(low, "only one usage")
}

func humanizeStart(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.Contains(msg, "Не удалось разобрать ссылку VLESS") || strings.HasPrefix(msg, "VLESS:") || strings.HasPrefix(msg, "REALITY:") {
		return err
	}
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "reality") && (strings.Contains(low, "public") || strings.Contains(low, "key") || strings.Contains(low, "short")):
		return errors.New("REALITY: рукопожатие не удалось. Проверьте публичный ключ, short id и SNI")
	case strings.Contains(low, "timeout") || strings.Contains(low, "deadline"):
		return errors.New("VLESS: нет ответа от сервера (таймаут)")
	default:
		return fmt.Errorf("VLESS: не удалось запустить локальный мост: %s", msg)
	}
}

// maskSecrets hides the UUID, public key and short id if an Xray error
// quotes them. A short id under 4 characters could match ordinary words
// and is left alone.
func maskSecrets(err error, p Params) error {
	msg := err.Error()
	out := msg
	for _, v := range []string{p.UUID, strings.ReplaceAll(p.UUID, "-", ""), p.PublicKey, p.ShortID} {
		if len(v) >= 4 {
			out = strings.ReplaceAll(out, v, "***")
		}
	}
	if out == msg {
		return err
	}
	return errors.New(out)
}

func splitComma(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
