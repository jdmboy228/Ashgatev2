// Package probe checks that a configured proxy accepts a connection.
package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"ashgate/internal/config"
	"ashgate/internal/httpproxy"
	"ashgate/internal/socks5"
	"ashgate/internal/vless"
)

// Report is the result of one health check.
type Report struct {
	OK     bool   `json:"ok"`
	UDP    bool   `json:"udp"`
	Millis int64  `json:"ms"`
	Label  string `json:"label"`
	Detail string `json:"detail,omitempty"`
}

// Check dials 1.1.1.1:443 through the proxy. SOCKS5 also tries UDP ASSOCIATE.
func Check(ctx context.Context, p config.Proxy) Report {
	return CheckTarget(ctx, p, "1.1.1.1", 443)
}

// CheckTarget is Check with an explicit destination. Tests point it at localhost.
func CheckTarget(ctx context.Context, p config.Proxy, host string, port uint16) Report {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	start := time.Now()
	switch p.Type {
	case "socks5":
		conn, err := socks5.Dial(ctx, p, host, port)
		if err != nil {
			return failed(err)
		}
		_ = conn.Close()
		ms := millis(start)
		rep := Report{OK: true, Millis: ms, Label: fmt.Sprintf("%d мс", ms), Detail: "TCP доступен"}
		actx, acancel := context.WithTimeout(ctx, 3*time.Second)
		assoc, err := socks5.Associate(actx, p)
		acancel()
		if err == nil {
			rep.UDP = true
			rep.Detail = "TCP и UDP"
			_ = assoc.Close()
		} else {
			rep.Detail = "TCP доступен, UDP ASSOCIATE не удался"
		}
		return rep
	case "http":
		conn, err := httpproxy.Dial(ctx, p, host, port)
		if err != nil {
			return failed(err)
		}
		_ = conn.Close()
		ms := millis(start)
		return Report{OK: true, Millis: ms, Label: fmt.Sprintf("%d мс", ms), Detail: "только TCP"}
	case "vless":
		if err := p.Prepare(); err != nil {
			return failed(err)
		}
		if p.VLESS == nil {
			return failed(fmt.Errorf("Не удалось разобрать ссылку VLESS"))
		}
		br, err := vless.Listen(ctx, p.Address, *p.VLESS, vless.Inbound{})
		if err != nil {
			return failed(vless.Explain(err))
		}
		defer br.Close()
		via := config.Proxy{Type: "socks5", Address: br.Addr}
		conn, err := socks5.Dial(ctx, via, host, port)
		if err != nil {
			return failed(vless.Explain(err))
		}
		err = confirmTunnel(ctx, conn, host)
		_ = conn.Close()
		if err != nil {
			return failed(vless.TunnelError(start, err))
		}
		ms := millis(start)
		rep := Report{OK: true, Millis: ms, Label: fmt.Sprintf("%d мс", ms), Detail: "TCP доступен"}
		actx, acancel := context.WithTimeout(ctx, 3*time.Second)
		assoc, err := socks5.Associate(actx, via)
		acancel()
		if err == nil {
			rep.UDP = true
			rep.Detail = "TCP и UDP"
			_ = assoc.Close()
		} else {
			rep.Detail = "TCP доступен, UDP ASSOCIATE не удался"
		}
		return rep
	default:
		return Report{Label: "нет ответа", Detail: "неизвестный тип прокси"}
	}
}

// confirmTunnel waits for the target's first bytes through a VLESS bridge.
// Xray's SOCKS inbound answers CONNECT before it reaches the server, so a
// successful CONNECT proves only that the local bridge runs. A TLS
// ClientHello makes the target answer: 1.1.1.1:443 completes the handshake,
// another service answers with an error or an echo. No bytes back means the
// server was not reached or refused the client. Nothing secret is sent, so
// the certificate is not checked.
func confirmTunnel(ctx context.Context, conn net.Conn, host string) error {
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	cc := &countConn{Conn: conn}
	cfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // liveness check only
	if net.ParseIP(host) == nil {
		cfg.ServerName = host
	}
	err := tls.Client(cc, cfg).HandshakeContext(ctx)
	if err == nil || cc.got {
		return nil
	}
	return err
}

// countConn notes whether anything was read.
type countConn struct {
	net.Conn
	got bool
}

func (c *countConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.got = true
	}
	return n, err
}

func failed(err error) Report {
	detail := "нет ответа"
	if err != nil && err.Error() != "" {
		detail = err.Error()
	}
	return Report{Label: "нет ответа", Detail: detail}
}

func millis(start time.Time) int64 {
	ms := time.Since(start).Milliseconds()
	if ms < 1 {
		return 1
	}
	return ms
}
