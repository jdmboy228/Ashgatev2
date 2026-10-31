// Package testkit contains local proxy servers used by tests.
package testkit

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
)

// SOCKS is a minimal SOCKS5 server. CONNECT is dialed for real.
// UDP ASSOCIATE echoes the payload back to the client.
type SOCKS struct {
	Addr string
	User string
	Pass string
	// Dial, when set, replaces net.Dial for CONNECT, so a test can send
	// a destination somewhere else. Set it before the first connection.
	Dial func(network, addr string) (net.Conn, error)

	ln  net.Listener
	udp net.PacketConn
	wg  sync.WaitGroup
}

// ListenSOCKS starts a server on 127.0.0.1.
func ListenSOCKS(user, pass string) (*SOCKS, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		ln.Close()
		return nil, err
	}
	s := &SOCKS{Addr: ln.Addr().String(), User: user, Pass: pass, ln: ln, udp: udp}
	s.wg.Add(2)
	go func() { defer s.wg.Done(); s.accept() }()
	go func() { defer s.wg.Done(); s.udpEcho() }()
	return s, nil
}

// Close stops the server.
func (s *SOCKS) Close() error {
	err1 := s.ln.Close()
	err2 := s.udp.Close()
	s.wg.Wait()
	if err1 != nil {
		return err1
	}
	return err2
}

func (s *SOCKS) accept() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.serve(c)
	}
}

func (s *SOCKS) serve(c net.Conn) {
	defer c.Close()
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	if hdr[0] != 5 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	needAuth := s.User != "" || s.Pass != ""
	if needAuth {
		if !contains(methods, 0x02) {
			_, _ = c.Write([]byte{5, 0xff})
			return
		}
		if _, err := c.Write([]byte{5, 0x02}); err != nil {
			return
		}
		if err := s.readAuth(c); err != nil {
			return
		}
	} else {
		if _, err := c.Write([]byte{5, 0x00}); err != nil {
			return
		}
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	host, port, err := readSOCKSAddr(c, req[3])
	if err != nil {
		return
	}
	switch req[1] {
	case 1:
		s.connect(c, host, port)
	case 3:
		s.associate(c)
	default:
		_, _ = c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
	}
}

func (s *SOCKS) readAuth(c net.Conn) error {
	h := make([]byte, 2)
	if _, err := io.ReadFull(c, h); err != nil {
		return err
	}
	user := make([]byte, int(h[1]))
	if _, err := io.ReadFull(c, user); err != nil {
		return err
	}
	pl := make([]byte, 1)
	if _, err := io.ReadFull(c, pl); err != nil {
		return err
	}
	pass := make([]byte, int(pl[0]))
	if _, err := io.ReadFull(c, pass); err != nil {
		return err
	}
	if string(user) != s.User || string(pass) != s.Pass {
		_, _ = c.Write([]byte{1, 1})
		return errors.New("auth")
	}
	_, err := c.Write([]byte{1, 0})
	return err
}

func (s *SOCKS) connect(c net.Conn, host string, port uint16) {
	dial := s.Dial
	if dial == nil {
		dial = net.Dial
	}
	dst, err := dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer dst.Close()
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	errc := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(dst, c); errc <- struct{}{} }()
	go func() { _, _ = io.Copy(c, dst); errc <- struct{}{} }()
	<-errc
}

func (s *SOCKS) associate(c net.Conn) {
	ua, ok := s.udp.LocalAddr().(*net.UDPAddr)
	if !ok {
		return
	}
	ip := ua.IP.To4()
	if ip == nil {
		return
	}
	rep := []byte{5, 0, 0, 1}
	rep = append(rep, ip...)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], uint16(ua.Port))
	rep = append(rep, port[:]...)
	if _, err := c.Write(rep); err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, c)
}

func (s *SOCKS) udpEcho() {
	buf := make([]byte, 65535)
	for {
		n, from, err := s.udp.ReadFrom(buf)
		if err != nil {
			return
		}
		dst, payload, err := decodeUDP(buf[:n])
		if err != nil {
			continue
		}
		out, err := encodeUDP(dst, payload)
		if err != nil {
			continue
		}
		_, _ = s.udp.WriteTo(out, from)
	}
}

func readSOCKSAddr(c net.Conn, atyp byte) (string, uint16, error) {
	switch atyp {
	case 1:
		b := make([]byte, 6)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, err
		}
		return net.IP(b[:4]).String(), binary.BigEndian.Uint16(b[4:]), nil
	case 4:
		b := make([]byte, 18)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, err
		}
		return net.IP(b[:16]).String(), binary.BigEndian.Uint16(b[16:]), nil
	case 3:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(c, lb); err != nil {
			return "", 0, err
		}
		b := make([]byte, int(lb[0])+2)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, err
		}
		return string(b[:lb[0]]), binary.BigEndian.Uint16(b[lb[0]:]), nil
	default:
		return "", 0, errors.New("atyp")
	}
}

func decodeUDP(pkt []byte) (*net.UDPAddr, []byte, error) {
	if len(pkt) < 10 || pkt[2] != 0 || pkt[3] != 1 {
		return nil, nil, errors.New("udp")
	}
	ip := net.IPv4(pkt[4], pkt[5], pkt[6], pkt[7])
	port := int(binary.BigEndian.Uint16(pkt[8:10]))
	return &net.UDPAddr{IP: ip, Port: port}, append([]byte(nil), pkt[10:]...), nil
}

func encodeUDP(dst *net.UDPAddr, payload []byte) ([]byte, error) {
	ip := dst.IP.To4()
	if ip == nil {
		return nil, errors.New("ipv4 only")
	}
	out := make([]byte, 10+len(payload))
	out[3] = 1
	copy(out[4:8], ip)
	binary.BigEndian.PutUint16(out[8:10], uint16(dst.Port))
	copy(out[10:], payload)
	return out, nil
}

func contains(b []byte, v byte) bool {
	for _, x := range b {
		if x == v {
			return true
		}
	}
	return false
}
