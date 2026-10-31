// Package dialer opens TCP and UDP connections through the configured proxies.
package dialer

import (
	"context"
	"errors"
	"net"

	"ashgate/internal/config"
	"ashgate/internal/httpproxy"
	"ashgate/internal/socks5"
	"ashgate/internal/vless"
)

// ErrUDPUnsupported is returned for UDP through a proxy that has no UDP transport.
var ErrUDPUnsupported = errors.New("proxy does not support UDP")

// Session is one SOCKS5 UDP association.
type Session interface {
	Send(ctx context.Context, dst *net.UDPAddr, payload []byte) error
	Recv(ctx context.Context) (*net.UDPAddr, []byte, error)
	Close() error
}

// Dialer opens upstream connections.
type Dialer interface {
	DialTCP(ctx context.Context, p config.Proxy, host string, port uint16) (net.Conn, error)
	DialUDP(ctx context.Context, p config.Proxy) (Session, error)
}

// Net is the production dialer.
type Net struct{}

// DialTCP connects through SOCKS5, HTTP CONNECT, or a local VLESS bridge.
func (Net) DialTCP(ctx context.Context, p config.Proxy, host string, port uint16) (net.Conn, error) {
	switch p.Type {
	case "socks5":
		return socks5.Dial(ctx, p, host, port)
	case "http":
		return httpproxy.Dial(ctx, p, host, port)
	case "vless":
		via, err := vlessSocks(p)
		if err != nil {
			return nil, err
		}
		c, err := socks5.Dial(ctx, via, host, port)
		if err != nil {
			return nil, vless.Explain(err)
		}
		return c, nil
	default:
		return nil, errors.New("unknown proxy type " + p.Type)
	}
}

// DialUDP opens a SOCKS5 UDP association. HTTP proxies do not support general UDP.
// VLESS sends UDP into its bridge inside this process.
func (Net) DialUDP(ctx context.Context, p config.Proxy) (Session, error) {
	switch p.Type {
	case "socks5":
		return socks5.Associate(ctx, p)
	case "vless":
		if p.Local == "" {
			return nil, errors.New("VLESS: локальный мост не запущен")
		}
		// In-process: the bridge's SOCKS5 inbound has no UDP ASSOCIATE.
		s, err := vless.DialUDP(p.Local)
		if err != nil {
			return nil, err
		}
		return s, nil
	default:
		return nil, ErrUDPUnsupported
	}
}

func vlessSocks(p config.Proxy) (config.Proxy, error) {
	if p.Local == "" {
		return config.Proxy{}, errors.New("VLESS: локальный мост не запущен")
	}
	// The private inbound's login is made up on every start; see
	// runtime.WireVLESS.
	return config.Proxy{
		Name: p.Name, Type: "socks5", Address: p.Local,
		Username: p.LocalAuthUser, Password: p.LocalAuthPass,
	}, nil
}
