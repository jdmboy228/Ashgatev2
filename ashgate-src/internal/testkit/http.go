package testkit

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// HTTP is a minimal HTTP CONNECT proxy. Port 53 is answered as DNS-over-TCP.
// Other ports are a byte echo.
type HTTP struct {
	Addr string
	User string
	Pass string
	// Dial, when set, makes CONNECT to ports other than 53 dial for real
	// (through Dial) instead of echoing. Set it before the first connection.
	Dial func(network, addr string) (net.Conn, error)
	ln   net.Listener
}

// ListenHTTP starts a proxy on 127.0.0.1.
func ListenHTTP(user, pass string) (*HTTP, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	h := &HTTP{Addr: ln.Addr().String(), User: user, Pass: pass, ln: ln}
	go h.accept()
	return h, nil
}

// Close stops the proxy.
func (h *HTTP) Close() error { return h.ln.Close() }

func (h *HTTP) accept() {
	for {
		c, err := h.ln.Accept()
		if err != nil {
			return
		}
		go h.serve(c)
	}
}

func (h *HTTP) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if h.User != "" || h.Pass != "" {
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(h.User+":"+h.Pass))
		if req.Header.Get("Proxy-Authorization") != want {
			_, _ = io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"ashgate\"\r\nContent-Length: 0\r\n\r\n")
			return
		}
	}
	if !strings.EqualFold(req.Method, "CONNECT") {
		_, _ = io.WriteString(c, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
		return
	}
	_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
	_, port, err := net.SplitHostPort(req.Host)
	if err != nil {
		return
	}
	if port == "53" {
		dnsTCP(c)
		return
	}
	if h.Dial != nil {
		dst, err := h.Dial("tcp", req.Host)
		if err != nil {
			return
		}
		defer dst.Close()
		go func() { _, _ = io.Copy(dst, br) }()
		_, _ = io.Copy(c, dst)
		return
	}
	_, _ = io.Copy(c, c)
}

func dnsTCP(c net.Conn) {
	var nbuf [2]byte
	if _, err := io.ReadFull(c, nbuf[:]); err != nil {
		return
	}
	n := binary.BigEndian.Uint16(nbuf[:])
	q := make([]byte, n)
	if _, err := io.ReadFull(c, q); err != nil {
		return
	}
	if len(q) >= 3 {
		q[2] |= 0x80
	}
	binary.BigEndian.PutUint16(nbuf[:], uint16(len(q)))
	_, _ = c.Write(nbuf[:])
	_, _ = c.Write(q)
}

// HostPort is a small helper for tests that print endpoints.
func HostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}
