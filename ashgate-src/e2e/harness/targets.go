//go:build windows && e2e

package harness

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"ashgate/e2e/stream"
)

// Origin says who opened a connection to a target.
const (
	OriginTunnel = "tunnel" // the harness's own Xray server: it came through the tunnel
	OriginDirect = "direct" // ashgate.exe itself: it bypassed the tunnel
)

// Hit is one request a recorder saw.
type Hit struct {
	Time   time.Time `json:"time"`
	Origin string    `json:"origin"` // tunnel, direct, or an image name
	Host   string    `json:"host"`
	Path   string    `json:"path"`
}

// originListener tags every accepted connection with its origin.
type originListener struct {
	net.Listener
}

type originConn struct {
	net.Conn
	origin string
}

func (l originListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &originConn{Conn: c, origin: originOf(c)}, nil
}

func originOf(c net.Conn) string {
	local, _ := c.LocalAddr().(*net.TCPAddr)
	remote, _ := c.RemoteAddr().(*net.TCPAddr)
	if local == nil || remote == nil {
		return "?"
	}
	pid := OwnerOf(remote, local)
	switch {
	case pid == 0:
		return "?"
	case pid == uint32(os.Getpid()):
		return OriginTunnel
	}
	name := filepath.Base(ImagePath(pid))
	if strings.EqualFold(name, "ashgate.exe") {
		return OriginDirect
	}
	return name
}

type ctxKey struct{}

func originFrom(r *http.Request) string {
	if c, ok := r.Context().Value(ctxKey{}).(*originConn); ok {
		return c.origin
	}
	return "?"
}

func serveRecorded(ln net.Listener, h http.Handler) *http.Server {
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if oc, ok := c.(*originConn); ok {
				return context.WithValue(ctx, ctxKey{}, oc)
			}
			return ctx
		},
	}
	go func() { _ = srv.Serve(originListener{ln}) }()
	return srv
}

// Recorder keeps the hits of one server.
type Recorder struct {
	Addr string
	mu   sync.Mutex
	hits []Hit
	srv  *http.Server
}

func (r *Recorder) add(req *http.Request) {
	r.mu.Lock()
	r.hits = append(r.hits, Hit{Time: time.Now(), Origin: originFrom(req), Host: req.Host, Path: req.URL.Path})
	r.mu.Unlock()
}

// Hits returns the hits so far.
func (r *Recorder) Hits() []Hit {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Hit(nil), r.hits...)
}

// Since returns the hits at or after t.
func (r *Recorder) Since(t time.Time) []Hit {
	var out []Hit
	for _, h := range r.Hits() {
		if !h.Time.Before(t) {
			out = append(out, h)
		}
	}
	return out
}

// Close stops the server.
func (r *Recorder) Close() {
	if r.srv != nil {
		_ = r.srv.Close()
	}
}

// StartHealth answers generate_204 the way www.gstatic.com does. The Xray
// server sends Ashgate's health checks here.
func StartHealth() (*Recorder, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	r := &Recorder{Addr: ln.Addr().String()}
	r.srv = serveRecorded(ln, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.add(req)
		if req.URL.Path == "/generate_204" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, req)
	}))
	return r, nil
}

// SubServer serves a 3x-ui style subscription: base64 of one link per line.
type SubServer struct {
	Recorder
	token string
	mu2   sync.Mutex
	links []string
}

// StartSub serves links at /sub/<token>.
func StartSub(token string, links []string) (*SubServer, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &SubServer{token: token, links: links}
	s.Addr = ln.Addr().String()
	s.srv = serveRecorded(ln, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		s.add(req)
		if req.URL.Path != "/sub/"+s.token {
			http.NotFound(w, req)
			return
		}
		s.mu2.Lock()
		body := base64.StdEncoding.EncodeToString([]byte(strings.Join(s.links, "\n")))
		s.mu2.Unlock()
		h := w.Header()
		h.Set("Content-Type", "text/plain; charset=utf-8")
		h.Set("Profile-Title", "base64:"+base64.StdEncoding.EncodeToString([]byte("e2e")))
		h.Set("Profile-Update-Interval", "12")
		h.Set("Subscription-Userinfo", "upload=0; download=0; total=0; expire=0")
		_, _ = io.WriteString(w, body)
	}))
	return s, nil
}

// URL is the subscription address with its token.
func (s *SubServer) URL() string { return "http://" + s.Addr + "/sub/" + s.token }

// SetLinks changes what the subscription returns.
func (s *SubServer) SetLinks(links []string) {
	s.mu2.Lock()
	s.links = links
	s.mu2.Unlock()
}

// Target is where the test apps' traffic lands after the tunnel.
type Target struct {
	Recorder
	udp  net.PacketConn
	stun net.PacketConn
	// UDP counts echoed datagrams.
	udpMu   sync.Mutex
	udpHits int
}

// StartTarget listens on the fixed local ports the servers redirect to.
func StartTarget() (*Target, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", targetTCPPort))
	if err != nil {
		return nil, fmt.Errorf("target tcp %d: %w", targetTCPPort, err)
	}
	t := &Target{}
	t.Addr = ln.Addr().String()
	t.srv = serveRecorded(ln, http.HandlerFunc(t.serveHTTP))
	if t.udp, err = net.ListenPacket("udp4", fmt.Sprintf("127.0.0.1:%d", targetUDPPort)); err != nil {
		t.Close()
		return nil, fmt.Errorf("target udp %d: %w", targetUDPPort, err)
	}
	if t.stun, err = net.ListenPacket("udp4", fmt.Sprintf("127.0.0.1:%d", stunPort)); err != nil {
		t.Close()
		return nil, fmt.Errorf("stun udp %d: %w", stunPort, err)
	}
	go t.echo(t.udp, false)
	go t.echo(t.stun, true)
	return t, nil
}

// Close stops the target.
func (t *Target) Close() {
	t.Recorder.Close()
	if t.udp != nil {
		_ = t.udp.Close()
	}
	if t.stun != nil {
		_ = t.stun.Close()
	}
}

// UDPHits is the number of datagrams answered.
func (t *Target) UDPHits() int {
	t.udpMu.Lock()
	defer t.udpMu.Unlock()
	return t.udpHits
}

func (t *Target) echo(pc net.PacketConn, stun bool) {
	buf := make([]byte, 64<<10)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		t.udpMu.Lock()
		t.udpHits++
		t.udpMu.Unlock()
		out := append([]byte(nil), buf[:n]...)
		if stun {
			out = stunReply(buf[:n], from)
		}
		if out != nil {
			_, _ = pc.WriteTo(out, from)
		}
	}
}

// stunReply answers a STUN binding request with XOR-MAPPED-ADDRESS.
func stunReply(req []byte, from net.Addr) []byte {
	if len(req) < 20 || binary.BigEndian.Uint16(req) != 0x0001 || binary.BigEndian.Uint32(req[4:]) != 0x2112A442 {
		return nil
	}
	ua, _ := from.(*net.UDPAddr)
	if ua == nil || ua.IP.To4() == nil {
		return nil
	}
	ip := ua.IP.To4()
	attr := make([]byte, 12)
	binary.BigEndian.PutUint16(attr[0:], 0x0020) // XOR-MAPPED-ADDRESS
	binary.BigEndian.PutUint16(attr[2:], 8)
	attr[5] = 0x01
	binary.BigEndian.PutUint16(attr[6:], uint16(ua.Port)^0x2112)
	cookie := []byte{0x21, 0x12, 0xA4, 0x42}
	for i := 0; i < 4; i++ {
		attr[8+i] = ip[i] ^ cookie[i]
	}
	out := make([]byte, 20, 32)
	binary.BigEndian.PutUint16(out[0:], 0x0101)
	binary.BigEndian.PutUint16(out[2:], uint16(len(attr)))
	copy(out[4:20], req[4:20])
	return append(out, attr...)
}

// serveHTTP:
//
//	GET  /bytes?n=N&seed=S         N deterministic bytes
//	GET  /hold?secs=T&rate=R&seed=S  R bytes/s for T seconds (long session)
//	POST /upload                   SHA-256 and length of the body
//	GET  /ok                       "ok"
func (t *Target) serveHTTP(w http.ResponseWriter, r *http.Request) {
	t.add(r)
	q := r.URL.Query()
	switch r.URL.Path {
	case "/bytes":
		n, _ := strconv.ParseInt(q.Get("n"), 10, 64)
		w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.Copy(w, stream.Reader(q.Get("seed"), n))
	case "/hold":
		secs, _ := strconv.Atoi(q.Get("secs"))
		rate, _ := strconv.Atoi(q.Get("rate"))
		if rate <= 0 {
			rate = 64 << 10
		}
		total := int64(secs) * int64(rate)
		w.Header().Set("Content-Length", strconv.FormatInt(total, 10))
		src := stream.Reader(q.Get("seed"), total)
		fl, _ := w.(http.Flusher)
		buf := make([]byte, rate/10+1)
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for range tick.C {
			n, err := io.ReadFull(src, buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					return
				}
				if fl != nil {
					fl.Flush()
				}
			}
			if err != nil {
				return
			}
		}
	case "/upload":
		h := sha256.New()
		n, _ := io.Copy(h, r.Body)
		fmt.Fprintf(w, "%s %d", hex.EncodeToString(h.Sum(nil)), n)
	case "/ok":
		_, _ = io.WriteString(w, "ok")
	default:
		http.NotFound(w, r)
	}
}
