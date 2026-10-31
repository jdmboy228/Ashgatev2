//go:build !race

// Xray's VLESS outbound uses unsafe pointer arithmetic. The race detector
// turns that into a fatal checkptr error, so the live bridge is covered by
// `go test` without -race. The share-link tests in this package still run
// under -race.
package vless_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"ashgate/internal/config"
	"ashgate/internal/dialer"
	"ashgate/internal/probe"
	"ashgate/internal/runtime"
	"ashgate/internal/socks5"
	"ashgate/internal/vless"
)

func TestTCPRealityEcho(t *testing.T) {
	const (
		uuid = "11111111-1111-4111-8111-111111111111"
		priv = realityPrivate
		pub  = realityPublic
		sid  = realityShort
		sni  = realitySNI
	)
	dest := tlsDest(t)
	port := mustFree(t)
	raw := mustServer(t, map[string]any{
		"log": map[string]any{"loglevel": "info"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": port, "protocol": "vless",
			"settings": map[string]any{
				"decryption": "none",
				"clients":    []any{map[string]any{"id": uuid, "flow": "xtls-rprx-vision"}},
			},
			"streamSettings": map[string]any{
				"network": "tcp", "security": "reality",
				"realitySettings": map[string]any{
					"dest": dest, "serverNames": []string{sni},
					"privateKey": priv, "shortIds": []string{sid},
				},
			},
		}},
		"outbounds": []any{testFreedom},
	})
	stop, err := vless.StartRaw(raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)

	echo, echoAddr := tcpEcho(t)
	_ = echo
	params := vless.Params{
		UUID: uuid, Network: "tcp", Security: "reality", Flow: "xtls-rprx-vision",
		SNI: sni, Fingerprint: "chrome", PublicKey: pub, ShortID: sid,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	br, err := vless.Listen(ctx, net.JoinHostPort("127.0.0.1", itoa(port)), params, vless.Inbound{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(br.Close)

	host, eport := splitHostPort(t, echoAddr)
	conn, err := dialer.Net{}.DialTCP(ctx, config.Proxy{
		Name: "aeza", Type: "vless", Address: net.JoinHostPort("127.0.0.1", itoa(port)),
		Local: br.Addr, VLESS: &params,
	}, host, eport)
	if err != nil {
		t.Fatalf("dial: %v\n%s", err, vless.RecentLog(time.Now().Add(-20*time.Second)))
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ashgate-vless")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 13)
	_ = conn.SetReadDeadline(time.Now().Add(12 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v\n%s", err, vless.RecentLog(time.Now().Add(-30*time.Second)))
	}
	if string(buf) != "ashgate-vless" {
		t.Fatalf("echo %q", buf)
	}

	udpAddr := udpEcho(t)
	assoc, err := dialer.Net{}.DialUDP(ctx, config.Proxy{Type: "vless", Local: br.Addr, VLESS: &params})
	if err != nil {
		t.Fatal(err)
	}
	defer assoc.Close()
	dst, err := net.ResolveUDPAddr("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	if err := assoc.Send(ctx, dst, []byte("udp-ok")); err != nil {
		t.Fatal(err)
	}
	uctx, ucancel := context.WithTimeout(ctx, 5*time.Second)
	defer ucancel()
	_, data, err := assoc.Recv(uctx)
	if err != nil {
		t.Fatalf("udp: %v\n%s", err, vless.RecentLog(time.Now().Add(-20*time.Second)))
	}
	if string(data) != "udp-ok" {
		t.Fatalf("udp echo %q", data)
	}

	rep := probe.CheckTarget(ctx, config.Proxy{
		Name: "aeza", Type: "vless", Address: net.JoinHostPort("127.0.0.1", itoa(port)), VLESS: &params,
	}, host, eport)
	if !rep.OK {
		t.Fatalf("probe: %+v", rep)
	}
}

func TestXHTTPRealityEcho(t *testing.T) {
	const (
		uuid = "22222222-2222-4222-8222-222222222222"
		priv = realityPrivate
		pub  = realityPublic
		sid  = realityShort
		sni  = realitySNI
	)
	dest := tlsDest(t)
	port := mustFree(t)
	raw := mustServer(t, map[string]any{
		"log": map[string]any{"loglevel": "info"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": port, "protocol": "vless",
			"settings": map[string]any{
				"decryption": "none",
				"clients":    []any{map[string]any{"id": uuid}},
			},
			"streamSettings": map[string]any{
				"network": "xhttp", "security": "reality",
				"xhttpSettings": map[string]any{"path": "/xh", "mode": "auto"},
				"realitySettings": map[string]any{
					"dest": dest, "serverNames": []string{sni},
					"privateKey": priv, "shortIds": []string{sid},
				},
			},
		}},
		"outbounds": []any{testFreedom},
	})
	stop, err := vless.StartRaw(raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)

	_, echoAddr := tcpEcho(t)
	params := vless.Params{
		UUID: uuid, Network: "xhttp", Security: "reality",
		SNI: sni, PublicKey: pub, ShortID: sid, Path: "/xh", Mode: "auto",
		Flow: "xtls-rprx-vision",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	br, err := vless.Listen(ctx, net.JoinHostPort("127.0.0.1", itoa(port)), params, vless.Inbound{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(br.Close)
	host, eport := splitHostPort(t, echoAddr)
	conn, err := socks5.Dial(ctx, config.Proxy{Type: "socks5", Address: br.Addr}, host, eport)
	if err != nil {
		t.Fatalf("xhttp dial: %v\n%s", err, vless.RecentLog(time.Now().Add(-20*time.Second)))
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "xhttp"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	_ = conn.SetReadDeadline(time.Now().Add(12 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("xhttp read: %v\n%s", err, vless.RecentLog(time.Now().Add(-30*time.Second)))
	}
	if string(buf) != "xhttp" {
		t.Fatalf("%q", buf)
	}
}

func TestTLSWSEcho(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeCert(t, dir, "ashgate.test")
	const uuid = "33333333-3333-4333-8333-333333333333"
	port := mustFree(t)
	raw := mustServer(t, map[string]any{
		"log": map[string]any{"loglevel": "info"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": port, "protocol": "vless",
			"settings": map[string]any{
				"decryption": "none",
				"clients":    []any{map[string]any{"id": uuid}},
			},
			"streamSettings": map[string]any{
				"network": "ws", "security": "tls",
				"wsSettings": map[string]any{"path": "/ws"},
				"tlsSettings": map[string]any{
					"certificates": []any{map[string]any{"certificateFile": cert, "keyFile": key}},
				},
			},
		}},
		"outbounds": []any{testFreedom},
	})
	stop, err := vless.StartRaw(raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	_, echoAddr := tcpEcho(t)
	params := vless.Params{
		UUID: uuid, Network: "ws", Security: "tls", SNI: "ashgate.test",
		Path: "/ws", PinnedSHA256: certPin(t, cert),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	br, err := vless.Listen(ctx, net.JoinHostPort("127.0.0.1", itoa(port)), params, vless.Inbound{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(br.Close)
	host, eport := splitHostPort(t, echoAddr)
	conn, err := socks5.Dial(ctx, config.Proxy{Type: "socks5", Address: br.Addr}, host, eport)
	if err != nil {
		t.Fatalf("tls dial: %v\n%s", err, vless.RecentLog(time.Now().Add(-20*time.Second)))
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "tls-ok"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 6)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "tls-ok" {
		t.Fatalf("%q", buf)
	}
}

func TestBadRealityKeyIsRussian(t *testing.T) {
	const (
		uuid = "44444444-4444-4444-8444-444444444444"
		priv = realityPrivate
		sid  = realityShort
		sni  = realitySNI
	)
	dest := tlsDest(t)
	port := mustFree(t)
	raw := mustServer(t, map[string]any{
		"log": map[string]any{"loglevel": "info"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": port, "protocol": "vless",
			"settings": map[string]any{
				"decryption": "none",
				"clients":    []any{map[string]any{"id": uuid, "flow": ""}},
			},
			"streamSettings": map[string]any{
				"network": "tcp", "security": "reality",
				"realitySettings": map[string]any{
					"dest": dest, "serverNames": []string{sni},
					"privateKey": priv, "shortIds": []string{sid, ""},
				},
			},
		}},
		"outbounds": []any{testFreedom},
	})
	stop, err := vless.StartRaw(raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)

	// A different key of the right length. The handshake must fail in Russian.
	wrong := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	params := vless.Params{
		UUID: uuid, Network: "tcp", Security: "reality", SNI: sni,
		PublicKey: wrong, ShortID: sid,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	br, err := vless.Listen(ctx, net.JoinHostPort("127.0.0.1", itoa(port)), params, vless.Inbound{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(br.Close)
	conn, err := socks5.Dial(ctx, config.Proxy{Type: "socks5", Address: br.Addr}, "127.0.0.1", 9)
	if err != nil {
		got := vless.Explain(err)
		if !wrongKeyExplained(got) {
			t.Fatalf("err %v\nexplained %v\nlog:\n%s", err, got, vless.RecentLog(time.Now().Add(-30*time.Second)))
		}
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))
	_, err = conn.Write([]byte("x"))
	if err == nil {
		buf := make([]byte, 4)
		_, err = conn.Read(buf)
	}
	if err == nil {
		t.Fatal("expected handshake failure")
	}
	got := vless.Explain(err)
	if !wrongKeyExplained(got) {
		t.Fatalf("err %v\nexplained %v\nlog:\n%s", err, got, vless.RecentLog(time.Now().Add(-20*time.Second)))
	}
}

const (
	// Key pair from Xray's own VLESS+REALITY scenario test.
	realityPrivate = "aGSYystUbf59_9_6LKRxD27rmSW_-2_nyd9YG_Gwbks"
	realityPublic  = "E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM"
	realityShort   = "0123456789abcdef"
	realitySNI     = "www.microsoft.com"
)

func tlsDest(t *testing.T) string {
	t.Helper()
	certFile, keyFile := writeCert(t, t.TempDir(), realitySNI)
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(8 * time.Second))
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestFixedSOCKSCurl(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Fatal("curl is required")
	}
	const uuid = "33333333-3333-4333-8333-333333333333"
	srvPort := mustFree(t)
	stop, err := vless.StartRaw(mustServer(t, map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": srvPort, "protocol": "vless",
			"settings": map[string]any{
				"decryption": "none",
				"clients":    []any{map[string]any{"id": uuid}},
			},
		}},
		"outbounds": []any{testFreedom},
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)

	origin := httpOrigin(t, "ashgate-fixed")
	params := vless.Params{UUID: uuid, Network: "tcp", Security: "none"}
	cfg := config.Default()
	cfg.Proxies = []config.Proxy{{
		Name: "aeza", Type: "vless", SOCKSPort: 10808,
		Address: net.JoinHostPort("127.0.0.1", itoa(srvPort)),
		VLESS:   &params,
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	m := vless.NewManager()
	t.Cleanup(m.Close)
	st, err := runtime.WireVLESS(ctx, m, cfg)
	if err != nil {
		t.Fatalf("bridge: %v\n%s", err, vless.RecentLog(time.Now().Add(-20*time.Second)))
	}
	if cfg.Proxies[0].Local != "127.0.0.1:10808" || !st["aeza"].Up || st["aeza"].HTTP != "127.0.0.1:10809" {
		t.Fatalf("local %s status %+v", cfg.Proxies[0].Local, st["aeza"])
	}

	body := curlOut(t, "http://"+origin+"/", "--socks5-hostname", "127.0.0.1:10808")
	if !strings.Contains(body, "ashgate-fixed") {
		t.Fatalf("socks body %q", body)
	}
	httpBody := curlOut(t, "http://"+origin+"/", "-x", "http://127.0.0.1:10809")
	if !strings.Contains(httpBody, "ashgate-fixed") {
		t.Fatalf("http body %q", httpBody)
	}

	udpAddr := udpEcho(t)
	assoc, err := dialer.Net{}.DialUDP(ctx, config.Proxy{Type: "vless", Local: "127.0.0.1:10808", VLESS: &params})
	if err != nil {
		t.Fatal(err)
	}
	defer assoc.Close()
	dst, err := net.ResolveUDPAddr("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	if err := assoc.Send(ctx, dst, []byte("udp-ok")); err != nil {
		t.Fatal(err)
	}
	uctx, ucancel := context.WithTimeout(ctx, 8*time.Second)
	defer ucancel()
	_, data, err := assoc.Recv(uctx)
	if err != nil {
		t.Fatalf("udp: %v\n%s", err, vless.RecentLog(time.Now().Add(-20*time.Second)))
	}
	if string(data) != "udp-ok" {
		t.Fatalf("udp echo %q", data)
	}

	direct, derr := exec.Command("curl", "-fsS", "--max-time", "12", "https://example.com").CombinedOutput()
	if derr == nil && strings.Contains(string(direct), "Example Domain") {
		out := curlOut(t, "https://example.com", "--socks5-hostname", "127.0.0.1:10808")
		if !strings.Contains(out, "Example Domain") {
			t.Fatalf("proxied example.com: %q", out)
		}
	} else {
		t.Logf("direct internet unavailable, local origin was used: %v", derr)
	}

	authPort := 10818
	cfg.Proxies[0].SOCKSPort = authPort
	cfg.Proxies[0].LocalUser = "dolphin"
	cfg.Proxies[0].LocalPass = "secret"
	st, err = runtime.WireVLESS(ctx, m, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !st["aeza"].Up || cfg.Proxies[0].Local != "127.0.0.1:10818" {
		t.Fatalf("%+v %s", st["aeza"], cfg.Proxies[0].Local)
	}
	authed := curlOut(t, "http://"+origin+"/", "--socks5-hostname", "dolphin:secret@127.0.0.1:10818")
	if !strings.Contains(authed, "ashgate-fixed") {
		t.Fatalf("auth body %q", authed)
	}
	bad := exec.Command("curl", "-fsS", "--max-time", "8", "--socks5-hostname", "dolphin:wrong@127.0.0.1:10818", "http://"+origin+"/")
	if err := bad.Run(); err == nil {
		t.Fatal("wrong password was accepted")
	}
}

func httpOrigin(t *testing.T, body string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func curlOut(t *testing.T, url string, proxyArgs ...string) string {
	t.Helper()
	args := []string{"-fsS", "--max-time", "20"}
	args = append(args, proxyArgs...)
	args = append(args, url)
	cmd := exec.Command("curl", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("curl %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func mustServer(t *testing.T, doc map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustFree(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func tcpEcho(t *testing.T) (net.Listener, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln, ln.Addr().String()
}

func udpEcho(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteToUDP(buf[:n], addr)
		}
	}()
	return pc.LocalAddr().String()
}

func splitHostPort(t *testing.T, addr string) (string, uint16) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	n, err := net.LookupPort("tcp", portStr)
	if err != nil {
		t.Fatal(err)
	}
	return host, uint16(n)
}

func itoa(n int) string {
	return jsonNumber(n)
}

func jsonNumber(n int) string {
	return strconvItoa(n)
}

func strconvItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func writeCert(t *testing.T, dir, host string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

// testFreedom is the test servers' outbound. Since v26 Xray's freedom
// blocks private and loopback targets unless a final rule allows them; the
// echo servers here listen on 127.0.0.1.
var testFreedom = map[string]any{
	"protocol": "freedom",
	"settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow"}}},
}

// wrongKeyExplained accepts both Russian explanations of a wrong REALITY
// key. Against a real server Xray logs "REALITY: received real
// certificate"; here the decoy's certificate is self-signed, so since v26
// the client stops at its x509 check first.
func wrongKeyExplained(err error) bool {
	switch err.Error() {
	case "REALITY: рукопожатие не удалось. Проверьте публичный ключ, short id и SNI",
		"VLESS: сервер не прошёл проверку подлинности. Для REALITY проверьте публичный ключ, short id и SNI, для TLS — сертификат сервера (pcs)":
		return true
	}
	return false
}

// certPin is the SHA-256 of the certificate in a PEM file, as pcs.
func certPin(t *testing.T, file string) string {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("no PEM block in", file)
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])
}

// startRealityServer runs a VLESS+REALITY server on 127.0.0.1:port whose
// only user needs flow ("" for none). It returns the stop function.
func startRealityServer(t *testing.T, port int, uuid, flow, dest string) func() {
	t.Helper()
	raw := mustServer(t, map[string]any{
		"log": map[string]any{"loglevel": "info"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": port, "protocol": "vless",
			"settings": map[string]any{
				"decryption": "none",
				"clients":    []any{map[string]any{"id": uuid, "flow": flow}},
			},
			"streamSettings": map[string]any{
				"network": "raw", "security": "reality",
				"realitySettings": map[string]any{
					"dest": dest, "serverNames": []string{realitySNI},
					"privateKey": realityPrivate, "shortIds": []string{realityShort},
				},
			},
		}},
		"outbounds": []any{testFreedom},
	})
	stop, err := vless.StartRaw(raw)
	if err != nil {
		t.Fatal(err)
	}
	return stop
}

func rawRealityParams(uuid, flow, fp string) vless.Params {
	return vless.Params{
		UUID: uuid, Network: "tcp", Security: "reality", Flow: flow, SNI: realitySNI,
		Fingerprint: fp, PublicKey: realityPublic, ShortID: realityShort,
	}
}

// echoThrough sends a line through the bridge to an echo server and waits
// for it to come back.
func echoThrough(ctx context.Context, br *vless.Bridge, params vless.Params, echoAddr string) error {
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port, _ := strconv.Atoi(portStr)
	conn, err := dialer.Net{}.DialTCP(ctx, config.Proxy{Type: "vless", Local: br.Addr, VLESS: &params}, host, uint16(port))
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		return err
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if string(buf) != "ping" {
		return fmt.Errorf("echo %q", buf)
	}
	return nil
}

// A Vision server refuses a client without the flow. TestTCPRealityEcho
// passing therefore means Vision is really in use, and the probe must not
// call such a proxy healthy.
func TestVisionRequiredByServer(t *testing.T) {
	const uuid = "55555555-5555-4555-8555-555555555555"
	port := mustFree(t)
	t.Cleanup(startRealityServer(t, port, uuid, "xtls-rprx-vision", tlsDest(t)))
	_, echoAddr := tcpEcho(t)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	addr := net.JoinHostPort("127.0.0.1", itoa(port))
	noFlow := rawRealityParams(uuid, "", "chrome")
	br, err := vless.Listen(ctx, addr, noFlow, vless.Inbound{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(br.Close)
	if err := echoThrough(ctx, br, noFlow, echoAddr); err == nil {
		t.Fatal("a Vision server accepted a client without flow")
	}
	host, eport := splitHostPort(t, echoAddr)
	if rep := probe.CheckTarget(ctx, config.Proxy{Name: "x", Type: "vless", Address: addr, VLESS: &noFlow}, host, eport); rep.OK {
		t.Fatalf("probe called a refused proxy healthy: %+v", rep)
	}
	vision := rawRealityParams(uuid, "xtls-rprx-vision", "chrome")
	if rep := probe.CheckTarget(ctx, config.Proxy{Name: "x", Type: "vless", Address: addr, VLESS: &vision}, host, eport); !rep.OK {
		t.Fatalf("probe with Vision: %+v", rep)
	}
}

// The server goes away and comes back on the same port: the bridge keeps
// running, the probe reports the outage in Russian, and new connections
// work again without restarting anything.
func TestServerDownThenBack(t *testing.T) {
	const uuid = "66666666-6666-4666-8666-666666666666"
	dest := tlsDest(t)
	port := mustFree(t)
	stop := startRealityServer(t, port, uuid, "xtls-rprx-vision", dest)
	_, echoAddr := tcpEcho(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	addr := net.JoinHostPort("127.0.0.1", itoa(port))
	params := rawRealityParams(uuid, "xtls-rprx-vision", "firefox")
	br, err := vless.Listen(ctx, addr, params, vless.Inbound{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(br.Close)
	if err := echoThrough(ctx, br, params, echoAddr); err != nil {
		t.Fatalf("before: %v", err)
	}
	stop()
	if err := echoThrough(ctx, br, params, echoAddr); err == nil {
		t.Fatal("echo through a stopped server")
	}
	host, eport := splitHostPort(t, echoAddr)
	rep := probe.CheckTarget(ctx, config.Proxy{Name: "x", Type: "vless", Address: addr, VLESS: &params}, host, eport)
	if rep.OK || !(strings.HasPrefix(rep.Detail, "VLESS:") || strings.HasPrefix(rep.Detail, "REALITY:")) {
		t.Fatalf("probe while down: %+v", rep)
	}
	t.Cleanup(startRealityServer(t, port, uuid, "xtls-rprx-vision", dest))
	if err := echoThrough(ctx, br, params, echoAddr); err != nil {
		t.Fatalf("after the server came back: %v", err)
	}
}

// One proxy switched from RAW to XHTTP keeps its fixed SOCKS5 port: the old
// bridge must release the port before the new one takes it.
func TestManagerSwitchesTransportOnFixedPort(t *testing.T) {
	port := 0
	for i := 0; i < 20 && port == 0; i++ {
		p := mustFree(t)
		if ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", itoa(p+1))); err == nil {
			_ = ln.Close()
			port = p
		}
	}
	if port == 0 {
		t.Skip("no two free ports in a row")
	}
	m := vless.NewManager()
	t.Cleanup(m.Close)
	ctx := context.Background()
	ep := vless.Endpoint{
		Name: "p", Address: "127.0.0.1:9",
		Params:  rawRealityParams("77777777-7777-4777-8777-777777777777", "xtls-rprx-vision", "chrome"),
		Inbound: vless.Inbound{Port: port},
	}
	want := "127.0.0.1:" + itoa(port)
	for _, network := range []string{"tcp", "xhttp", "tcp"} {
		ep.Params.Network = network
		st, err := m.Sync(ctx, []vless.Endpoint{ep})
		if err != nil || !st["p"].Up || st["p"].SOCKS != want {
			t.Fatalf("%s: %+v %v", network, st["p"], err)
		}
	}
	// The published SOCKS5 and HTTP ports listen on loopback only: the
	// machine's other addresses must not answer on them.
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.IsLoopback() || ipn.IP.To4() == nil {
			continue
		}
		for _, p := range []int{port, port + 1} {
			if c, err := net.DialTimeout("tcp", net.JoinHostPort(ipn.IP.String(), itoa(p)), time.Second); err == nil {
				_ = c.Close()
				t.Fatalf("port %d answers on %s", p, ipn.IP)
			}
		}
	}
}

// The REALITY ClientHello must look like the chosen browser: Chrome sends
// GREASE values, Firefox does not; both offer h2 and http/1.1; the SNI is
// the configured one; nothing names Xray or Ashgate.
func TestClientHelloLooksLikeBrowser(t *testing.T) {
	for _, fp := range []string{"chrome", "firefox"} {
		t.Run(fp, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = ln.Close() })
			hello := make(chan []byte, 1)
			go func() {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				hdr := make([]byte, 5)
				if _, err := io.ReadFull(c, hdr); err != nil {
					return
				}
				body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
				if _, err := io.ReadFull(c, body); err != nil {
					return
				}
				hello <- append(hdr, body...)
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			params := rawRealityParams("88888888-8888-4888-8888-888888888888", "xtls-rprx-vision", fp)
			br, err := vless.Listen(ctx, ln.Addr().String(), params, vless.Inbound{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(br.Close)
			go func() {
				conn, err := socks5.Dial(ctx, config.Proxy{Type: "socks5", Address: br.Addr}, "1.1.1.1", 443)
				if err == nil {
					_, _ = conn.Write([]byte("x"))
					<-ctx.Done()
					_ = conn.Close()
				}
			}()
			var rec []byte
			select {
			case rec = <-hello:
			case <-time.After(15 * time.Second):
				t.Fatal("no ClientHello")
			}
			ch := parseClientHello(t, rec)
			if ch.sni != realitySNI {
				t.Errorf("SNI %q", ch.sni)
			}
			if strings.Join(ch.alpn, ",") != "h2,http/1.1" {
				t.Errorf("ALPN %v", ch.alpn)
			}
			grease := false
			for _, c := range ch.ciphers {
				grease = grease || (c&0x0f0f == 0x0a0a && c>>8 == c&0xff)
			}
			if grease != (fp == "chrome") {
				t.Errorf("GREASE in ciphers = %v for %s", grease, fp)
			}
			low := strings.ToLower(string(rec))
			if strings.Contains(low, "xray") || strings.Contains(low, "ashgate") {
				t.Error("ClientHello names Xray or Ashgate")
			}
		})
	}
}

type clientHello struct {
	ciphers []uint16
	sni     string
	alpn    []string
}

// parseClientHello reads the fields TestClientHelloLooksLikeBrowser checks
// from one TLS record holding a ClientHello.
func parseClientHello(t *testing.T, rec []byte) clientHello {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("malformed ClientHello: %v", r)
		}
	}()
	if rec[0] != 0x16 || rec[5] != 1 {
		t.Fatalf("not a ClientHello: % x", rec[:6])
	}
	b := rec[5+4+2+32:] // record and handshake headers, version, random
	b = b[1+int(b[0]):] // session id
	var ch clientHello
	n := int(b[0])<<8 | int(b[1])
	for cs := b[2 : 2+n]; len(cs) >= 2; cs = cs[2:] {
		ch.ciphers = append(ch.ciphers, uint16(cs[0])<<8|uint16(cs[1]))
	}
	b = b[2+n:]
	b = b[1+int(b[0]):] // compression methods
	ext := b[2 : 2+(int(b[0])<<8|int(b[1]))]
	for len(ext) >= 4 {
		typ := int(ext[0])<<8 | int(ext[1])
		l := int(ext[2])<<8 | int(ext[3])
		data := ext[4 : 4+l]
		ext = ext[4+l:]
		switch typ {
		case 0: // server_name: list length, type, name length, name
			ch.sni = string(data[5 : 5+(int(data[3])<<8|int(data[4]))])
		case 16: // ALPN: list length, then length-prefixed names
			for d := data[2:]; len(d) > 0; d = d[1+int(d[0]):] {
				ch.alpn = append(ch.alpn, string(d[1:1+int(d[0])]))
			}
		}
	}
	return ch
}
