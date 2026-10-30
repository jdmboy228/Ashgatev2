// Package socks5 is a small SOCKS5 client (RFC 1928 and RFC 1929).
package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"ashgate/internal/config"
)

const (
	ver5       = 0x05
	cmdConnect = 0x01
	cmdUDP     = 0x03
	atypIPv4   = 0x01
	atypName   = 0x03
	atypIPv6   = 0x04
	authNone   = 0x00
	authUser   = 0x02
	authNoneOK = 0x00
)

// Dial opens a TCP connection to dest through a SOCKS5 proxy.
func Dial(ctx context.Context, p config.Proxy, host string, port uint16) (net.Conn, error) {
	conn, err := dialProxy(ctx, p.Address)
	if err != nil {
		return nil, err
	}
	done := bound(ctx, conn)
	err = handshake(conn, p)
	if err == nil {
		err = writeRequest(conn, cmdConnect, host, port)
	}
	if err == nil {
		_, err = readReply(conn)
	}
	if derr := done(); err == nil {
		err = derr
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// bound limits the whole negotiation to ctx's deadline (15 s without one)
// and aborts it when ctx is cancelled. Without it a proxy that accepts TCP
// and then stays silent would hang the caller forever. The returned func
// clears the deadline and reports whether ctx ended first.
func bound(ctx context.Context, conn net.Conn) func() error {
	_ = conn.SetDeadline(deadline(ctx, 15*time.Second))
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	return func() error {
		if !stop() {
			return ctx.Err()
		}
		_ = conn.SetDeadline(time.Time{})
		return nil
	}
}

// Assoc is a SOCKS5 UDP association. The TCP control connection stays open.
type Assoc struct {
	tcp   net.Conn
	udp   net.PacketConn
	relay *net.UDPAddr
	// buf is Recv's read buffer, reused for every datagram. DecodeUDP copies
	// the payload out, so it is not retained.
	buf []byte
}

// Associate negotiates a UDP association. The returned Assoc is ready for Send and Recv.
func Associate(ctx context.Context, p config.Proxy) (*Assoc, error) {
	conn, err := dialProxy(ctx, p.Address)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()
	done := bound(ctx, conn)
	err = handshake(conn, p)
	if err == nil {
		err = writeRequest(conn, cmdUDP, "0.0.0.0", 0)
	}
	var bnd *net.UDPAddr
	if err == nil {
		bnd, err = readReply(conn)
	}
	if derr := done(); err == nil {
		err = derr
	}
	if err != nil {
		return nil, err
	}
	if bnd.IP.IsUnspecified() {
		tcpAddr, _ := conn.RemoteAddr().(*net.TCPAddr)
		if tcpAddr == nil {
			return nil, errors.New("socks5: proxy address is unspecified and the control connection has no remote IP")
		}
		bnd.IP = tcpAddr.IP
	}
	network := "udp4"
	if bnd.IP.To4() == nil {
		network = "udp6"
	}
	pc, err := net.ListenPacket(network, net.JoinHostPort(bindHost(network), "0"))
	if err != nil {
		return nil, err
	}
	a := &Assoc{tcp: conn, udp: pc, relay: bnd}
	go func() {
		_, _ = io.Copy(io.Discard, conn)
		pc.Close()
	}()
	ok = true
	return a, nil
}

// Send encapsulates payload for dst and writes it to the relay.
func (a *Assoc) Send(ctx context.Context, dst *net.UDPAddr, payload []byte) error {
	pkt, err := EncodeUDP(dst, payload)
	if err != nil {
		return err
	}
	if err := a.udp.SetWriteDeadline(deadline(ctx, 15*time.Second)); err != nil {
		return err
	}
	_, err = a.udp.WriteTo(pkt, a.relay)
	return err
}

// Recv reads one unfragmented datagram from the relay. It reuses one read
// buffer, so only one goroutine may call it at a time.
func (a *Assoc) Recv(ctx context.Context) (*net.UDPAddr, []byte, error) {
	if a.buf == nil {
		a.buf = make([]byte, 65535)
	}
	buf := a.buf
	if err := a.udp.SetReadDeadline(deadline(ctx, 2*time.Minute)); err != nil {
		return nil, nil, err
	}
	for {
		n, from, err := a.udp.ReadFrom(buf)
		if err != nil {
			return nil, nil, err
		}
		if !sameUDP(from, a.relay) {
			continue
		}
		addr, payload, err := DecodeUDP(buf[:n])
		if err != nil {
			// One malformed or fragmented datagram must not end the flow.
			continue
		}
		return addr, payload, nil
	}
}

// Close closes the UDP socket and the TCP control connection.
func (a *Assoc) Close() error {
	err1 := a.udp.Close()
	err2 := a.tcp.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

// RelayAddr is the UDP endpoint returned by the proxy.
func (a *Assoc) RelayAddr() *net.UDPAddr { return a.relay }

// EncodeUDP builds a SOCKS5 UDP request header in front of payload.
func EncodeUDP(dst *net.UDPAddr, payload []byte) ([]byte, error) {
	if dst == nil {
		return nil, errors.New("socks5: nil destination")
	}
	head, err := addrBytes(dst.IP.String(), uint16(dst.Port))
	if err != nil {
		return nil, err
	}
	out := make([]byte, 3+len(head)+len(payload))
	out[0], out[1], out[2] = 0, 0, 0
	copy(out[3:], head)
	copy(out[3+len(head):], payload)
	return out, nil
}

// DecodeUDP parses a SOCKS5 UDP packet. Fragmented packets are rejected.
func DecodeUDP(pkt []byte) (*net.UDPAddr, []byte, error) {
	if len(pkt) < 4 {
		return nil, nil, errors.New("socks5: short udp packet")
	}
	if pkt[2] != 0 {
		return nil, nil, errors.New("socks5: fragmented udp is not supported")
	}
	host, port, n, err := parseAddr(pkt[3:])
	if err != nil {
		return nil, nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, nil, fmt.Errorf("socks5: udp reply address %q is not an IP", host)
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	return &net.UDPAddr{IP: ip, Port: int(port)}, append([]byte(nil), pkt[3+n:]...), nil
}

func dialProxy(ctx context.Context, address string) (net.Conn, error) {
	d := net.Dialer{Timeout: 15 * time.Second}
	return d.DialContext(ctx, "tcp", address)
}

// handshake runs under the deadline set by bound.
func handshake(conn net.Conn, p config.Proxy) error {
	var greet []byte
	if p.Username != "" || p.Password != "" {
		greet = []byte{ver5, 1, authUser}
	} else {
		greet = []byte{ver5, 1, authNone}
	}
	if _, err := conn.Write(greet); err != nil {
		return err
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(conn, rep); err != nil {
		return err
	}
	if rep[0] != ver5 {
		return fmt.Errorf("socks5: unexpected version %d", rep[0])
	}
	switch rep[1] {
	case authNone:
		if p.Username != "" || p.Password != "" {
			return errors.New("socks5: proxy ignored username/password")
		}
		return nil
	case authUser:
		return userPass(conn, p.Username, p.Password)
	default:
		return fmt.Errorf("socks5: proxy rejected authentication methods (0x%02x)", rep[1])
	}
}

func userPass(conn net.Conn, user, pass string) error {
	if len(user) > 255 || len(pass) > 255 {
		return errors.New("socks5: username or password is too long")
	}
	buf := make([]byte, 0, 3+len(user)+len(pass))
	buf = append(buf, 0x01, byte(len(user)))
	buf = append(buf, user...)
	buf = append(buf, byte(len(pass)))
	buf = append(buf, pass...)
	if _, err := conn.Write(buf); err != nil {
		return err
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(conn, rep); err != nil {
		return err
	}
	if rep[1] != authNoneOK {
		return errors.New("socks5: authentication failed")
	}
	return nil
}

func writeRequest(conn net.Conn, cmd byte, host string, port uint16) error {
	addr, err := addrBytes(host, port)
	if err != nil {
		return err
	}
	buf := make([]byte, 0, 3+len(addr))
	buf = append(buf, ver5, cmd, 0x00)
	buf = append(buf, addr...)
	_, err = conn.Write(buf)
	return err
}

func readReply(conn net.Conn) (*net.UDPAddr, error) {
	hdr := make([]byte, 3)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != ver5 {
		return nil, fmt.Errorf("socks5: bad reply version %d", hdr[0])
	}
	if hdr[1] != 0 {
		return nil, fmt.Errorf("socks5: %s", replyText(hdr[1]))
	}
	atyp := make([]byte, 1)
	if _, err := io.ReadFull(conn, atyp); err != nil {
		return nil, err
	}
	rest, err := readAddrRest(conn, atyp[0])
	if err != nil {
		return nil, err
	}
	host, port, _, err := parseAddr(append(atyp, rest...))
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		ip = net.IPv4zero
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return &net.UDPAddr{IP: ip, Port: int(port)}, nil
}

func readAddrRest(conn net.Conn, atyp byte) ([]byte, error) {
	switch atyp {
	case atypIPv4:
		b := make([]byte, 4+2)
		_, err := io.ReadFull(conn, b)
		return b, err
	case atypIPv6:
		b := make([]byte, 16+2)
		_, err := io.ReadFull(conn, b)
		return b, err
	case atypName:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(conn, lb); err != nil {
			return nil, err
		}
		b := make([]byte, int(lb[0])+2)
		if _, err := io.ReadFull(conn, b); err != nil {
			return nil, err
		}
		return append(lb, b...), nil
	default:
		return nil, fmt.Errorf("socks5: unknown atyp %d", atyp)
	}
}

func parseAddr(b []byte) (string, uint16, int, error) {
	if len(b) < 1 {
		return "", 0, 0, errors.New("socks5: short address")
	}
	switch b[0] {
	case atypIPv4:
		if len(b) < 1+4+2 {
			return "", 0, 0, errors.New("socks5: short ipv4 address")
		}
		ip := net.IP(b[1:5])
		port := binary.BigEndian.Uint16(b[5:7])
		return ip.String(), port, 7, nil
	case atypIPv6:
		if len(b) < 1+16+2 {
			return "", 0, 0, errors.New("socks5: short ipv6 address")
		}
		ip := net.IP(b[1:17])
		port := binary.BigEndian.Uint16(b[17:19])
		return ip.String(), port, 19, nil
	case atypName:
		if len(b) < 2 {
			return "", 0, 0, errors.New("socks5: short domain address")
		}
		n := int(b[1])
		if len(b) < 2+n+2 {
			return "", 0, 0, errors.New("socks5: short domain address")
		}
		port := binary.BigEndian.Uint16(b[2+n : 4+n])
		return string(b[2 : 2+n]), port, 2 + n + 2, nil
	default:
		return "", 0, 0, fmt.Errorf("socks5: unknown atyp %d", b[0])
	}
}

func addrBytes(host string, port uint16) ([]byte, error) {
	var portb [2]byte
	binary.BigEndian.PutUint16(portb[:], port)
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out := make([]byte, 1+4+2)
			out[0] = atypIPv4
			copy(out[1:5], v4)
			copy(out[5:], portb[:])
			return out, nil
		}
		out := make([]byte, 1+16+2)
		out[0] = atypIPv6
		copy(out[1:17], ip.To16())
		copy(out[17:], portb[:])
		return out, nil
	}
	if len(host) == 0 || len(host) > 255 {
		return nil, fmt.Errorf("socks5: invalid host %q", host)
	}
	out := make([]byte, 1+1+len(host)+2)
	out[0] = atypName
	out[1] = byte(len(host))
	copy(out[2:], host)
	copy(out[2+len(host):], portb[:])
	return out, nil
}

func replyText(code byte) string {
	switch code {
	case 0:
		return "succeeded"
	case 1:
		return "general failure"
	case 2:
		return "connection not allowed"
	case 3:
		return "network unreachable"
	case 4:
		return "host unreachable"
	case 5:
		return "connection refused"
	case 6:
		return "ttl expired"
	case 7:
		return "command not supported"
	case 8:
		return "address type not supported"
	default:
		return fmt.Sprintf("reply code %d", code)
	}
}

func deadline(ctx context.Context, fallback time.Duration) time.Time {
	if ctx == nil {
		return time.Now().Add(fallback)
	}
	if dl, ok := ctx.Deadline(); ok {
		return dl
	}
	return time.Now().Add(fallback)
}

func bindHost(network string) string {
	if network == "udp6" {
		return "::"
	}
	return "0.0.0.0"
}

func sameUDP(from net.Addr, relay *net.UDPAddr) bool {
	ua, ok := from.(*net.UDPAddr)
	if !ok || relay == nil {
		return false
	}
	return ua.Port == relay.Port && ua.IP.Equal(relay.IP)
}
