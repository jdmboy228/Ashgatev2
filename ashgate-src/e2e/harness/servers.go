//go:build windows && e2e

package harness

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"

	"ashgate/internal/testkit"
	_ "ashgate/internal/vless" // registers every Xray feature (distro/all)
)

// Documentation address ranges the test apps connect to. Nothing on the
// internet answers them; the test servers redirect them to local targets,
// so any packet to them on the network card is a leak.
var (
	TargetTCP    = "198.51.100.10:18080" // proxied TCP: deterministic bytes
	TargetUDP    = "198.51.100.11:18081" // proxied UDP: echo
	TargetQUIC   = "198.51.100.11:443"   // QUIC-like UDP 443
	TargetSTUN   = "198.51.100.12:3478"  // STUN binding
	TargetHostIP = "198.51.100.20:18080" // Host-header routing (tunnel)
	DirectHostIP = "198.51.100.150:18080"
	ControlIP    = "198.51.100.200:18080" // the app without a rule
	TargetV6     = "[2001:db8:2::10]:18080"
	TargetV6UDP  = "[2001:db8:2::10]:18081"
	TestNet4     = mustCIDR("198.51.100.0/24")
	TestNet6     = mustCIDR("2001:db8:2::/48")
	// DoHIPs are the resolvers Xray's DNS reaches over DoH through the
	// tunnel (internal/vless/inproc.go DNSServers).
	DoHIPs = []string{"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "77.88.8.8", "77.88.8.1"}
)

// Local ports of the targets; the servers' redirect keeps the port.
const (
	targetTCPPort = 18080
	targetUDPPort = 18081
	stunPort      = 3478
	realitySNI    = "www.microsoft.com"
)

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// Gate modes.
const (
	GatePass      = int32(0)
	GateRefuse    = int32(1) // every connection is reset
	GateBlackhole = int32(2) // accepted, nothing ever comes back
)

// Gate sits in front of one Xray inbound and can cut it off the way a
// censor or a dead network would.
type Gate struct {
	Name     string
	Addr     string
	target   string
	ln       net.Listener
	mode     atomic.Int32
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	Accepted atomic.Int64
}

func newGate(name, target string) (*Gate, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	g := &Gate{Name: name, Addr: ln.Addr().String(), target: target, ln: ln, conns: map[net.Conn]struct{}{}}
	go g.accept()
	return g, nil
}

// Set changes the mode. Refuse also resets the open connections.
func (g *Gate) Set(mode int32) {
	g.mode.Store(mode)
	if mode == GateRefuse {
		g.mu.Lock()
		for c := range g.conns {
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetLinger(0)
			}
			_ = c.Close()
		}
		g.mu.Unlock()
	}
}

// Mode is the current mode.
func (g *Gate) Mode() int32 { return g.mode.Load() }

func (g *Gate) track(c net.Conn, on bool) {
	g.mu.Lock()
	if on {
		g.conns[c] = struct{}{}
	} else {
		delete(g.conns, c)
	}
	g.mu.Unlock()
}

func (g *Gate) accept() {
	for {
		c, err := g.ln.Accept()
		if err != nil {
			return
		}
		g.Accepted.Add(1)
		go g.serve(c)
	}
}

func (g *Gate) serve(c net.Conn) {
	switch g.mode.Load() {
	case GateRefuse:
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		_ = c.Close()
		return
	case GateBlackhole:
		g.track(c, true)
		_, _ = io.Copy(io.Discard, c)
		g.track(c, false)
		_ = c.Close()
		return
	}
	up, err := net.Dial("tcp", g.target)
	if err != nil {
		_ = c.Close()
		return
	}
	g.track(c, true)
	g.track(up, true)
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		buf := make([]byte, 32<<10)
		for {
			n, err := src.Read(buf)
			if n > 0 && g.mode.Load() == GatePass {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}
	go pipe(up, c)
	go pipe(c, up)
	<-done
	_ = c.Close()
	_ = up.Close()
	<-done
	g.track(c, false)
	g.track(up, false)
}

func (g *Gate) close() { _ = g.ln.Close(); g.Set(GateRefuse) }

// Fixture is everything a connectivity test needs on the runner: two
// Xray servers like a 3x-ui panel gives, the subscription, the targets.
type Fixture struct {
	Dir       string
	XHTTP     *Gate
	RAW       *Gate
	XHTTPLink string
	RAWLink   string
	SubURL    string
	SubToken  string
	Target    *Target
	Health    *Recorder
	Sub       *SubServer
	SOCKS     *testkit.SOCKS
	HTTP      *testkit.HTTP
	// doh carries the server's DoH to the internet; SetDoH(false) cuts it
	// off like a resolver that never answers.
	doh       *testkit.SOCKS
	dohDown   atomic.Bool
	dohBytes  atomic.Int64
	dohMu     sync.Mutex
	dohConns  map[net.Conn]struct{}
	ProxyUser string
	ProxyPass string
	// Plain is a VLESS link to the XHTTP server with its own user, for a
	// non-subscription proxy (its UUID may sit in config.json).
	PlainLink string
	accessLog string
	xray      *core.Instance
	dest      net.Listener
}

// StartFixture starts the servers. Every key, UUID and token is new.
func StartFixture(env *Env) (*Fixture, error) {
	f := &Fixture{Dir: env.Path("fixture", "x")}
	f.Dir = filepath.Dir(f.Dir)
	sec := env.Secrets

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	privKey := base64.RawURLEncoding.EncodeToString(priv.Bytes())
	pubKey := base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
	sec.Add("reality-private", privKey, false)
	sec.Add("reality-public", pubKey, true)
	sid := sec.Add("reality-sid", RandHex(8), true)
	uuidX := sec.Add("uuid-xhttp", RandUUID(), false)
	uuidR := sec.Add("uuid-raw", RandUUID(), false)
	uuidP := sec.Add("uuid-plain", RandUUID(), true)
	f.SubToken = sec.Add("sub-token", RandHex(16), false)
	f.ProxyUser = sec.Add("proxy-user", "e2e"+RandHex(4), true)
	f.ProxyPass = sec.Add("proxy-pass", RandHex(12), true)

	if f.dest, err = tlsDest(); err != nil {
		return nil, err
	}
	if f.Target, err = StartTarget(); err != nil {
		f.Close()
		return nil, err
	}
	if f.Health, err = StartHealth(); err != nil {
		f.Close()
		return nil, err
	}
	if f.doh, err = testkit.ListenSOCKS("", ""); err != nil {
		f.Close()
		return nil, err
	}
	f.dohConns = map[net.Conn]struct{}{}
	f.doh.Dial = func(network, addr string) (net.Conn, error) {
		if f.dohDown.Load() {
			return nil, fmt.Errorf("e2e: DoH is down")
		}
		c, err := net.Dial(network, addr)
		if err != nil {
			return nil, err
		}
		cc := &countedConn{Conn: c, f: f}
		f.dohMu.Lock()
		f.dohConns[cc] = struct{}{}
		f.dohMu.Unlock()
		return cc, nil
	}
	_, dohPort, _ := net.SplitHostPort(f.doh.Addr)

	innerX, innerR := freePort(), freePort()
	f.accessLog = filepath.Join(f.Dir, "xray-access.log")
	_ = os.MkdirAll(f.Dir, 0o755)
	reality := func() map[string]any {
		return map[string]any{
			"dest": f.dest.Addr().String(), "serverNames": []string{realitySNI},
			"privateKey": privKey, "shortIds": []string{sid},
		}
	}
	allow := []any{map[string]any{"action": "allow"}}
	doc := map[string]any{
		"log": map[string]any{
			"access": f.accessLog, "error": filepath.Join(f.Dir, "xray-error.log"), "loglevel": "warning",
		},
		"inbounds": []any{
			map[string]any{
				"tag": "in-xhttp", "listen": "127.0.0.1", "port": innerX, "protocol": "vless",
				"settings": map[string]any{"decryption": "none", "clients": []any{
					map[string]any{"id": uuidX, "email": "xhttp@e2e"},
					map[string]any{"id": uuidP, "email": "plain@e2e"},
				}},
				"streamSettings": map[string]any{
					"network": "xhttp", "security": "reality",
					"xhttpSettings":   map[string]any{"path": "/xh", "mode": "auto"},
					"realitySettings": reality(),
				},
			},
			map[string]any{
				"tag": "in-raw", "listen": "127.0.0.1", "port": innerR, "protocol": "vless",
				"settings": map[string]any{"decryption": "none", "clients": []any{
					map[string]any{"id": uuidR, "flow": "xtls-rprx-vision", "email": "raw@e2e"},
				}},
				"streamSettings": map[string]any{
					"network": "raw", "security": "reality", "realitySettings": reality(),
				},
			},
		},
		"outbounds": []any{
			// First outbound = default: nothing leaves the runner unless a rule says so.
			map[string]any{"tag": "block", "protocol": "blackhole"},
			map[string]any{"tag": "target", "protocol": "freedom",
				"settings": map[string]any{"redirect": "127.0.0.1:0", "finalRules": allow}},
			map[string]any{"tag": "health", "protocol": "freedom",
				"settings": map[string]any{"redirect": f.Health.Addr, "finalRules": allow}},
			map[string]any{"tag": "local", "protocol": "freedom",
				"settings": map[string]any{"finalRules": allow}},
			// DoH through the tunnel really resolves, like a VPS would,
			// through a switch that can cut it off (SetDoH).
			map[string]any{"tag": "internet", "protocol": "socks",
				"settings": map[string]any{"address": "127.0.0.1", "port": json.Number(dohPort)}},
		},
		"routing": map[string]any{
			"domainStrategy": "AsIs",
			"rules": []any{
				map[string]any{"type": "field", "domain": []string{"full:www.gstatic.com"}, "outboundTag": "health"},
				map[string]any{"type": "field", "ip": []string{TestNet4.String(), "2001:db8::/32"}, "outboundTag": "target"},
				map[string]any{"type": "field", "ip": []string{"127.0.0.0/8", "::1/128"}, "outboundTag": "local"},
				// DoH only. Port 53 (other query types, sent as they are) stays
				// closed: from this machine such a query would show on the card
				// in plain text, while a real VPS sends it from far away.
				map[string]any{"type": "field", "ip": DoHIPs, "port": "443", "outboundTag": "internet"},
			},
		},
	}
	raw, _ := json.Marshal(doc)
	cfg, err := serial.LoadJSONConfig(bytes.NewReader(raw))
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("xray server config: %w", err)
	}
	if f.xray, err = core.New(cfg); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.xray.Start(); err != nil {
		f.Close()
		return nil, err
	}
	if f.XHTTP, err = newGate("xhttp", fmt.Sprintf("127.0.0.1:%d", innerX)); err != nil {
		f.Close()
		return nil, err
	}
	if f.RAW, err = newGate("raw", fmt.Sprintf("127.0.0.1:%d", innerR)); err != nil {
		f.Close()
		return nil, err
	}

	q := func(kv ...string) string {
		v := url.Values{}
		for i := 0; i+1 < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		return v.Encode()
	}
	f.XHTTPLink = fmt.Sprintf("vless://%s@%s?%s#e2e-xhttp", uuidX, f.XHTTP.Addr, q(
		"type", "xhttp", "security", "reality", "encryption", "none", "pbk", pubKey, "fp", "firefox",
		"sni", realitySNI, "sid", sid, "spx", "/", "path", "/xh", "mode", "auto"))
	f.RAWLink = fmt.Sprintf("vless://%s@%s?%s#e2e-raw", uuidR, f.RAW.Addr, q(
		"type", "tcp", "security", "reality", "encryption", "none", "flow", "xtls-rprx-vision",
		"pbk", pubKey, "fp", "firefox", "sni", realitySNI, "sid", sid, "spx", "/", "headerType", "none"))
	f.PlainLink = fmt.Sprintf("vless://%s@%s?%s#e2e-plain", uuidP, f.XHTTP.Addr, q(
		"type", "xhttp", "security", "reality", "encryption", "none", "pbk", pubKey, "fp", "firefox",
		"sni", realitySNI, "sid", sid, "spx", "/", "path", "/xh", "mode", "auto"))
	sec.Add("link-xhttp", f.XHTTPLink, false)
	sec.Add("link-raw", f.RAWLink, false)
	sec.Add("link-plain", f.PlainLink, true)

	// RAW first: Ashgate must still pick XHTTP as the primary.
	if f.Sub, err = StartSub(f.SubToken, []string{f.RAWLink, f.XHTTPLink}); err != nil {
		f.Close()
		return nil, err
	}
	f.SubURL = sec.Add("sub-url", f.Sub.URL(), false)

	redirect := func(network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if ip := net.ParseIP(host); ip != nil && (TestNet4.Contains(ip) || TestNet6.Contains(ip)) {
			addr = net.JoinHostPort("127.0.0.1", port)
		}
		return net.Dial(network, addr)
	}
	if f.SOCKS, err = testkit.ListenSOCKS(f.ProxyUser, f.ProxyPass); err != nil {
		f.Close()
		return nil, err
	}
	f.SOCKS.Dial = redirect
	if f.HTTP, err = testkit.ListenHTTP(f.ProxyUser, f.ProxyPass); err != nil {
		f.Close()
		return nil, err
	}
	f.HTTP.Dial = redirect
	return f, nil
}

// Close stops every server.
func (f *Fixture) Close() {
	for _, g := range []*Gate{f.XHTTP, f.RAW} {
		if g != nil {
			g.close()
		}
	}
	if f.xray != nil {
		_ = f.xray.Close()
	}
	if f.Sub != nil {
		f.Sub.Close()
	}
	if f.Target != nil {
		f.Target.Close()
	}
	if f.Health != nil {
		f.Health.Close()
	}
	if f.SOCKS != nil {
		_ = f.SOCKS.Close()
	}
	if f.doh != nil {
		_ = f.doh.Close()
	}
	if f.HTTP != nil {
		_ = f.HTTP.Close()
	}
	if f.dest != nil {
		_ = f.dest.Close()
	}
}

// SetDoH lets the server's DoH through (true) or cuts it off (false), open
// connections included: Ashgate's lookups through the tunnel then get no
// answer, and browsers fall back to the Windows resolver.
func (f *Fixture) SetDoH(up bool) {
	f.dohDown.Store(!up)
	if up {
		return
	}
	// Close outside the lock: countedConn.Close takes it too.
	f.dohMu.Lock()
	open := make([]net.Conn, 0, len(f.dohConns))
	for c := range f.dohConns {
		open = append(open, c)
	}
	f.dohMu.Unlock()
	for _, c := range open {
		_ = c.Close()
	}
}

// DoHBytes counts the bytes the server's DoH carried so far. Xray keeps
// one DoH connection and reuses it, so new connections say little.
func (f *Fixture) DoHBytes() int64 { return f.dohBytes.Load() }

// countedConn is one DoH connection of the server.
type countedConn struct {
	net.Conn
	f    *Fixture
	once sync.Once
}

func (c *countedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.f.dohBytes.Add(int64(n))
	return n, err
}

func (c *countedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.f.dohBytes.Add(int64(n))
	return n, err
}

func (c *countedConn) Close() error {
	c.once.Do(func() {
		c.f.dohMu.Lock()
		delete(c.f.dohConns, c)
		c.f.dohMu.Unlock()
	})
	return c.Conn.Close()
}

// Access is one line of the Xray server's access log.
type Access struct {
	Time     time.Time
	Network  string // tcp or udp
	Dest     string
	Inbound  string // in-xhttp or in-raw
	Outbound string
	Email    string
}

var accessRE = regexp.MustCompile(`^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d(?:\.\d+)?) from (\S+) accepted (tcp|udp):(\S+) \[(\S+) (?:->|>>) (\S+)\](?: email: (\S+))?`)

// AccessLog parses the access log so far.
func (f *Fixture) AccessLog() []Access {
	b, err := os.ReadFile(f.accessLog)
	if err != nil {
		return nil
	}
	var out []Access
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		m := accessRE.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		t, _ := time.ParseInLocation("2006/01/02 15:04:05.999999", m[1], time.Local)
		out = append(out, Access{Time: t, Network: m[3], Dest: m[4], Inbound: m[5], Outbound: m[6], Email: m[7]})
	}
	return out
}

// AccessSince returns the lines at or after t whose destination contains dest.
func (f *Fixture) AccessSince(t time.Time, dest string) []Access {
	var out []Access
	for _, a := range f.AccessLog() {
		if !a.Time.Before(t.Add(-time.Second)) && strings.Contains(a.Dest, dest) {
			out = append(out, a)
		}
	}
	return out
}

// Info is what other processes (the Playwright job) need from the fixture.
type Info struct {
	XHTTPLink string `json:"xhttpLink"`
	RAWLink   string `json:"rawLink"`
	PlainLink string `json:"plainLink"`
	SubURL    string `json:"subURL"`
	SOCKS     string `json:"socks"`
	HTTP      string `json:"http"`
	User      string `json:"user"`
	Pass      string `json:"pass"`
}

// Info describes the fixture.
func (f *Fixture) Info() Info {
	return Info{f.XHTTPLink, f.RAWLink, f.PlainLink, f.SubURL, f.SOCKS.Addr, f.HTTP.Addr, f.ProxyUser, f.ProxyPass}
}

func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// tlsDest is the REALITY decoy: a local TLS 1.3 server with a self-signed
// certificate for realitySNI, so no handshake goes to the internet.
func tlsDest() (net.Listener, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: realitySNI},
		DNSNames:     []string{realitySNI},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	return ln, nil
}
