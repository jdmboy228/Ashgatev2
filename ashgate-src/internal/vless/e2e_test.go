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
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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
