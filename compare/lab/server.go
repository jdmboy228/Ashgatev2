package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	modePass      = int32(0)
	modeRefuse    = int32(1)
	modeBlackhole = int32(2)

	echoPortA   = 18080
	echoPortB   = 18081
	healthPort  = 18082
	realitySNI  = "www.microsoft.com"
	fingerprint = "firefox"
	xhttpPath   = "/xh"
)

// Fixture is the description written to lab.json. The private key stays in
// this file so the run can be debugged; the publisher strips it from the
// blind artifact.
type Fixture struct {
	XHTTP            endpoint `json:"xhttp"`
	RAW              endpoint `json:"raw"`
	RealityPublicKey string   `json:"realityPublicKey"`
	RealityPrivate   string   `json:"realityPrivateKey"`
	ShortID          string   `json:"shortId"`
	SNI              string   `json:"sni"`
	Fingerprint      string   `json:"fingerprint"`
	SubscriptionURL  string   `json:"subscriptionUrl"`
	ControlURL       string   `json:"controlUrl"`
	RawNetwork       string   `json:"rawNetwork"`
	EchoPing         string   `json:"echoPing"`
	EchoDown         string   `json:"echoDown"`
	EchoUp           string   `json:"echoUp"`
	EchoV6           string   `json:"echoV6"`
	EchoControl      string   `json:"echoControl"`
}

type endpoint struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	UUID string `json:"uuid"`
	Link string `json:"link"`
}

type lab struct {
	fix     Fixture
	xhttp   *gate
	raw     *gate
	echoHit atomic.Int64
	xray    *exec.Cmd
	closers []io.Closer
}

func serve(xrayPath, outDir string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	l, err := startLab(xrayPath, outDir)
	if err != nil {
		return err
	}
	defer l.close()
	raw, err := json.MarshalIndent(l.fix, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "lab.json"), raw, 0o644); err != nil {
		return err
	}
	fmt.Println("ready")
	select {}
}

func startLab(xrayPath, outDir string) (*lab, error) {
	l := &lab{}
	priv, pub, err := x25519()
	if err != nil {
		return nil, err
	}
	sid, err := randHex(8)
	if err != nil {
		return nil, err
	}
	uuidX, err := randUUID()
	if err != nil {
		return nil, err
	}
	uuidR, err := randUUID()
	if err != nil {
		return nil, err
	}
	dest, err := listenReality()
	if err != nil {
		return nil, err
	}
	l.closers = append(l.closers, dest)
	echo, err := listenEcho(&l.echoHit, echoPortA)
	if err != nil {
		l.close()
		return nil, err
	}
	l.closers = append(l.closers, echo)
	echoB, err := listenEcho(&l.echoHit, echoPortB)
	if err != nil {
		l.close()
		return nil, err
	}
	l.closers = append(l.closers, echoB)
	health, err := listenHealth(healthPort)
	if err != nil {
		l.close()
		return nil, err
	}
	l.closers = append(l.closers, health)

	innerX, innerR := freePort(), freePort()
	network, err := l.launchXray(xrayPath, outDir, priv, sid, uuidX, uuidR, dest.Addr().String(), innerX, innerR)
	if err != nil {
		l.close()
		return nil, err
	}
	gx, err := newGate(fmt.Sprintf("127.0.0.1:%d", innerX))
	if err != nil {
		l.close()
		return nil, err
	}
	gr, err := newGate(fmt.Sprintf("127.0.0.1:%d", innerR))
	if err != nil {
		gx.close()
		l.close()
		return nil, err
	}
	l.xhttp, l.raw = gx, gr
	token, err := randHex(8)
	if err != nil {
		l.close()
		return nil, err
	}
	xLink := vlessLink(uuidX, gx.addr, xhttpQuery(pub, sid), "bench-xhttp")
	rLink := vlessLink(uuidR, gr.addr, rawQuery(pub, sid), "bench-raw")
	subLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		l.close()
		return nil, err
	}
	l.closers = append(l.closers, subLn)
	subMux := http.NewServeMux()
	body := base64.StdEncoding.EncodeToString([]byte(rLink + "\n" + xLink + "\n"))
	subMux.HandleFunc("/sub/"+token, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, body)
	})
	go http.Serve(subLn, subMux)

	ctl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		l.close()
		return nil, err
	}
	l.closers = append(l.closers, ctl)
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"xhttp":         gx.passed.Load(),
			"raw":           gr.passed.Load(),
			"xhttpAccepted": gx.accepted.Load(),
			"rawAccepted":   gr.accepted.Load(),
			"echo":          l.echoHit.Load(),
		})
	})
	mux.HandleFunc("/gate", func(w http.ResponseWriter, r *http.Request) {
		g := gx
		if r.URL.Query().Get("name") == "raw" {
			g = gr
		}
		switch r.URL.Query().Get("mode") {
		case "refuse":
			g.set(modeRefuse)
		case "blackhole":
			g.set(modeBlackhole)
		default:
			g.set(modePass)
		}
		fmt.Fprintln(w, "ok")
	})
	go http.Serve(ctl, mux)

	_, xPort, _ := net.SplitHostPort(gx.addr)
	_, rPort, _ := net.SplitHostPort(gr.addr)
	xi, _ := strconv.Atoi(xPort)
	ri, _ := strconv.Atoi(rPort)
	l.fix = Fixture{
		XHTTP:            endpoint{Host: "127.0.0.1", Port: xi, UUID: uuidX, Link: xLink},
		RAW:              endpoint{Host: "127.0.0.1", Port: ri, UUID: uuidR, Link: rLink},
		RealityPublicKey: pub,
		RealityPrivate:   priv,
		ShortID:          sid,
		SNI:              realitySNI,
		Fingerprint:      fingerprint,
		SubscriptionURL:  "http://" + subLn.Addr().String() + "/sub/" + token,
		ControlURL:       "http://" + ctl.Addr().String(),
		RawNetwork:       network,
		EchoPing:         fmt.Sprintf("http://198.51.100.10:%d/ping", echoPortA),
		EchoDown:         fmt.Sprintf("http://198.51.100.10:%d/down", echoPortB),
		EchoUp:           fmt.Sprintf("http://198.51.100.10:%d/up", echoPortB),
		EchoV6:           fmt.Sprintf("http://[2001:db8:2::10]:%d/ping", echoPortA),
		EchoControl:      fmt.Sprintf("http://198.51.100.200:%d/ping", echoPortA),
	}
	return l, nil
}

func (l *lab) close() {
	if l.xray != nil && l.xray.Process != nil {
		_ = l.xray.Process.Kill()
		_, _ = l.xray.Process.Wait()
	}
	if l.xhttp != nil {
		l.xhttp.close()
	}
	if l.raw != nil {
		l.raw.close()
	}
	for _, c := range l.closers {
		_ = c.Close()
	}
}

func xrayCombined(xrayPath string, args ...string) ([]byte, error) {
	cmd := exec.Command(xrayPath, args...)
	cmd.Dir = filepath.Dir(xrayPath)
	return cmd.CombinedOutput()
}

func (l *lab) launchXray(xrayPath, outDir, priv, sid, uuidX, uuidR, dest string, innerX, innerR int) (string, error) {
	for _, network := range []string{"raw", "tcp"} {
		cfg := serverConfig(priv, sid, uuidX, uuidR, dest, innerX, innerR, network, filepath.Join(outDir, "xray-access.log"), filepath.Join(outDir, "xray-error.log"))
		path := filepath.Join(outDir, "xray-server.json")
		raw, _ := json.MarshalIndent(cfg, "", "  ")
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			return "", err
		}
		configFlag := "-config"
		out, err := xrayCombined(xrayPath, "run", "-test", "-config", path)
		if err != nil && (bytes.Contains(bytes.ToLower(out), []byte("unknown")) || bytes.Contains(bytes.ToLower(out), []byte("flag"))) {
			configFlag = "-c"
			out, err = xrayCombined(xrayPath, "run", "-test", "-c", path)
		}
		if err != nil {
			if network == "tcp" {
				return "", fmt.Errorf("xray rejected the server config: %v: %s", err, out)
			}
			continue
		}
		logf, err := os.Create(filepath.Join(outDir, "xray-server.stderr"))
		if err != nil {
			return "", err
		}
		cmd := exec.Command(xrayPath, "run", configFlag, path)
		cmd.Dir = filepath.Dir(xrayPath)
		cmd.Stdout = logf
		cmd.Stderr = logf
		if err := cmd.Start(); err != nil {
			return "", err
		}
		l.xray = cmd
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", innerX), 200*time.Millisecond)
			if err == nil {
				c.Close()
				return network, nil
			}
			time.Sleep(100 * time.Millisecond)
		}
		return "", fmt.Errorf("xray did not listen on the xhttp inbound")
	}
	return "", fmt.Errorf("xray did not accept a server config")
}

func serverConfig(priv, sid, uuidX, uuidR, dest string, innerX, innerR int, network, access, errlog string) map[string]any {
	reality := map[string]any{
		"dest": dest, "serverNames": []string{realitySNI},
		"privateKey": priv, "shortIds": []string{sid},
	}
	// Xray 26 refuses to send a proxied connection to loopback or a private
	// address unless finalRules allows it. The echo and the connectivity
	// responder both live on 127.0.0.1.
	allow := []any{map[string]any{"action": "allow"}}
	return map[string]any{
		"log": map[string]any{"access": access, "error": errlog, "loglevel": "warning"},
		"inbounds": []any{
			map[string]any{
				"tag": "in-xhttp", "listen": "127.0.0.1", "port": innerX, "protocol": "vless",
				"settings": map[string]any{"decryption": "none", "clients": []any{
					map[string]any{"id": uuidX, "email": "xhttp"},
				}},
				"streamSettings": map[string]any{
					"network": "xhttp", "security": "reality",
					"xhttpSettings":   map[string]any{"path": xhttpPath, "mode": "auto"},
					"realitySettings": reality,
				},
			},
			map[string]any{
				"tag": "in-raw", "listen": "127.0.0.1", "port": innerR, "protocol": "vless",
				"settings": map[string]any{"decryption": "none", "clients": []any{
					map[string]any{"id": uuidR, "flow": "xtls-rprx-vision", "email": "raw"},
				}},
				"streamSettings": map[string]any{
					"network": network, "security": "reality", "realitySettings": reality,
				},
			},
		},
		"outbounds": []any{
			map[string]any{"tag": "block", "protocol": "blackhole"},
			map[string]any{"tag": "target", "protocol": "freedom", "settings": map[string]any{"redirect": "127.0.0.1:0", "finalRules": allow}},
			map[string]any{"tag": "health", "protocol": "freedom", "settings": map[string]any{"redirect": fmt.Sprintf("127.0.0.1:%d", healthPort), "finalRules": allow}},
		},
		"routing": map[string]any{
			"domainStrategy": "AsIs",
			"rules": []any{
				map[string]any{"type": "field", "domain": []string{
					"full:www.gstatic.com", "full:www.google.com", "full:www.youtube.com", "full:www.googlevideo.com",
				}, "outboundTag": "health"},
				map[string]any{"type": "field", "ip": []string{"198.51.100.0/24", "2001:db8:2::/48"}, "outboundTag": "target"},
			},
		},
	}
}

func xhttpQuery(pub, sid string) url.Values {
	v := url.Values{}
	v.Set("type", "xhttp")
	v.Set("security", "reality")
	v.Set("encryption", "none")
	v.Set("pbk", pub)
	v.Set("fp", fingerprint)
	v.Set("sni", realitySNI)
	v.Set("sid", sid)
	v.Set("spx", "/")
	v.Set("path", xhttpPath)
	v.Set("mode", "auto")
	return v
}

func rawQuery(pub, sid string) url.Values {
	v := url.Values{}
	v.Set("type", "tcp")
	v.Set("security", "reality")
	v.Set("encryption", "none")
	v.Set("flow", "xtls-rprx-vision")
	v.Set("pbk", pub)
	v.Set("fp", fingerprint)
	v.Set("sni", realitySNI)
	v.Set("sid", sid)
	v.Set("spx", "/")
	v.Set("headerType", "none")
	return v
}

func vlessLink(uuid, addr string, q url.Values, name string) string {
	return fmt.Sprintf("vless://%s@%s?%s#%s", uuid, addr, q.Encode(), url.PathEscape(name))
}

type gate struct {
	addr     string
	target   string
	ln       net.Listener
	mode     atomic.Int32
	accepted atomic.Int64
	passed   atomic.Int64
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
}

func newGate(target string) (*gate, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	g := &gate{addr: ln.Addr().String(), target: target, ln: ln, conns: map[net.Conn]struct{}{}}
	go g.accept()
	return g, nil
}

func (g *gate) set(mode int32) {
	g.mode.Store(mode)
	if mode == modeRefuse {
		g.mu.Lock()
		for c := range g.conns {
			_ = c.Close()
		}
		g.mu.Unlock()
	}
}

func (g *gate) track(c net.Conn, on bool) {
	g.mu.Lock()
	if on {
		g.conns[c] = struct{}{}
	} else {
		delete(g.conns, c)
	}
	g.mu.Unlock()
}

func (g *gate) accept() {
	for {
		c, err := g.ln.Accept()
		if err != nil {
			return
		}
		g.accepted.Add(1)
		go g.serve(c)
	}
}

func (g *gate) serve(c net.Conn) {
	if g.mode.Load() == modeRefuse {
		_ = c.Close()
		return
	}
	if g.mode.Load() == modeBlackhole {
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
	g.passed.Add(1)
	g.track(c, true)
	g.track(up, true)
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
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

func (g *gate) close() { _ = g.ln.Close(); g.set(modeRefuse) }

func listenEcho(hits *atomic.Int64, port int) (net.Listener, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, fmt.Errorf("echo port %d: %w", port, err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "pong")
	})
	mux.HandleFunc("/down", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		if n < 0 {
			n = 0
		}
		if n > 32<<20 {
			n = 32 << 20
		}
		hits.Add(1)
		w.Header().Set("Content-Length", strconv.Itoa(n))
		buf := make([]byte, 32<<10)
		left := n
		for left > 0 {
			chunk := len(buf)
			if chunk > left {
				chunk = left
			}
			if _, err := w.Write(buf[:chunk]); err != nil {
				return
			}
			left -= chunk
		}
	})
	mux.HandleFunc("/up", func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		hits.Add(1)
		fmt.Fprintf(w, "%d", n)
	})
	go http.Serve(ln, mux)
	return ln, nil
}

func listenHealth(port int) (net.Listener, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, fmt.Errorf("health port %d: %w", port, err)
	}
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	return ln, nil
}

func listenReality() (net.Listener, error) {
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
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	return ln, nil
}

func freePort() int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0
	}
	p := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return p
}

func x25519() (priv, pub string, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(k.Bytes()), base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func randUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
