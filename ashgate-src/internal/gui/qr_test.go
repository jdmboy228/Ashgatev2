package gui

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"ashgate/internal/config"
	"ashgate/internal/failover"
	"ashgate/internal/subs"
	"ashgate/internal/vless"
)

const (
	qrTestUUID = "b7e2c1a0-4f3a-4c2b-9a11-111111111111"
	qrTestPBK  = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
)

func TestEncodeProxyQRPlainProxies(t *testing.T) {
	tests := []struct {
		name         string
		proxy        config.Proxy
		wantPayload  string
		wantSubtitle string
		wantErr      bool
	}{
		{
			name: "socks5 user and pass",
			proxy: config.Proxy{
				Name:     "Home",
				Type:     "socks5",
				Address:  "192.168.1.1:1080",
				Username: "alice",
				Password: "secret123",
			},
			wantPayload:  "socks5://alice:secret123@192.168.1.1:1080#Home",
			wantSubtitle: "SOCKS5 · 192.168.1.1:1080",
		},
		{
			name: "socks5 user only",
			proxy: config.Proxy{
				Name:     "Home",
				Type:     "socks5",
				Address:  "192.168.1.1:1080",
				Username: "alice",
			},
			wantPayload:  "socks5://alice@192.168.1.1:1080#Home",
			wantSubtitle: "SOCKS5 · 192.168.1.1:1080",
		},
		{
			name: "socks5 no auth omits @",
			proxy: config.Proxy{
				Name:    "Local",
				Type:    "socks5",
				Address: "10.0.0.1:1080",
			},
			wantPayload:  "socks5://10.0.0.1:1080#Local",
			wantSubtitle: "SOCKS5 · 10.0.0.1:1080",
		},
		{
			name: "socks5 name equals host omits fragment",
			proxy: config.Proxy{
				Name:    "192.168.1.1",
				Type:    "socks5",
				Address: "192.168.1.1:1080",
			},
			wantPayload:  "socks5://192.168.1.1:1080",
			wantSubtitle: "SOCKS5 · 192.168.1.1:1080",
		},
		{
			name: "socks5 empty name omits fragment",
			proxy: config.Proxy{
				Name:    "",
				Type:    "socks5",
				Address: "192.168.1.1:1080",
			},
			wantPayload:  "socks5://192.168.1.1:1080",
			wantSubtitle: "SOCKS5 · 192.168.1.1:1080",
		},
		{
			name: "socks5 IPv6",
			proxy: config.Proxy{
				Name:    "IPv6 Server",
				Type:    "socks5",
				Address: "[2001:db8::1]:1080",
			},
			wantPayload:  "socks5://[2001:db8::1]:1080#IPv6%20Server",
			wantSubtitle: "SOCKS5 · [2001:db8::1]:1080",
		},
		{
			name: "socks5 IPv6 bracketed name matches host omits fragment",
			proxy: config.Proxy{
				Name:    "[2001:db8::1]",
				Type:    "socks5",
				Address: "[2001:db8::1]:1080",
			},
			wantPayload:  "socks5://[2001:db8::1]:1080",
			wantSubtitle: "SOCKS5 · [2001:db8::1]:1080",
		},
		{
			name: "socks5 special chars in user and pass use %20 not +",
			proxy: config.Proxy{
				Name:     "Special",
				Type:     "socks5",
				Address:  "proxy.org:1080",
				Username: "my@user name",
				Password: "p@ss:w#o/r%d ",
			},
			wantPayload:  "socks5://my%40user%20name:p%40ss%3Aw%23o%2Fr%25d%20@proxy.org:1080#Special",
			wantSubtitle: "SOCKS5 · proxy.org:1080",
		},
		{
			name: "socks5 cyrillic name",
			proxy: config.Proxy{
				Name:    "Мой сервер",
				Type:    "socks5",
				Address: "proxy.org:1080",
			},
			wantPayload:  "socks5://proxy.org:1080#%D0%9C%D0%BE%D0%B9%20%D1%81%D0%B5%D1%80%D0%B2%D0%B5%D1%80",
			wantSubtitle: "SOCKS5 · proxy.org:1080",
		},
		{
			name: "http with auth",
			proxy: config.Proxy{
				Name:     "Office",
				Type:     "http",
				Address:  "proxy.corp:8080",
				Username: "u",
				Password: "p",
			},
			wantPayload:  "http://u:p@proxy.corp:8080#Office",
			wantSubtitle: "HTTP · proxy.corp:8080",
		},
		{
			name: "http without auth",
			proxy: config.Proxy{
				Name:    "proxy.corp",
				Type:    "http",
				Address: "proxy.corp:3128",
			},
			wantPayload:  "http://proxy.corp:3128",
			wantSubtitle: "HTTP · proxy.corp:3128",
		},
		{
			name: "http IPv6 without auth or name",
			proxy: config.Proxy{
				Name:    "",
				Type:    "http",
				Address: "[2001:db8::1]:3128",
			},
			wantPayload:  "http://[2001:db8::1]:3128",
			wantSubtitle: "HTTP · [2001:db8::1]:3128",
		},
		{
			name: "http invalid port 0",
			proxy: config.Proxy{
				Name:    "Bad0",
				Type:    "http",
				Address: "proxy.corp:0",
			},
			wantErr: true,
		},
		{
			name: "http invalid port 65536",
			proxy: config.Proxy{
				Name:    "Bad65536",
				Type:    "http",
				Address: "proxy.corp:65536",
			},
			wantErr: true,
		},
		{
			name: "http missing port",
			proxy: config.Proxy{
				Name:    "NoPort",
				Type:    "http",
				Address: "proxy.corp",
			},
			wantErr: true,
		},
		{
			name: "socks5 empty host",
			proxy: config.Proxy{
				Name:    "NoHost",
				Type:    "socks5",
				Address: ":1080",
			},
			wantErr: true,
		},
		{
			name: "http host with slash rejected",
			proxy: config.Proxy{
				Name:    "BadSlash",
				Type:    "http",
				Address: "proxy.corp/sub:8080",
			},
			wantErr: true,
		},
		{
			name: "http host with query rejected",
			proxy: config.Proxy{
				Name:    "BadQuery",
				Type:    "http",
				Address: "proxy.corp?a=1:8080",
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := buildProxyQRPlan(tc.proxy, "", "", nil, 0)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got payload %q", plan.payload)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if plan.payload != tc.wantPayload {
				t.Fatalf("payload:\n got  %q\n want %q", plan.payload, tc.wantPayload)
			}
			if plan.subtitle != tc.wantSubtitle {
				t.Fatalf("subtitle: got %q want %q", plan.subtitle, tc.wantSubtitle)
			}
			if plan.warning != "" {
				t.Fatalf("unexpected warning: %q", plan.warning)
			}
			if tc.proxy.Type == "http" {
				// Strictly no path and no query before fragment so Android treats it as HTTP proxy.
				noScheme := strings.TrimPrefix(plan.payload, "http://")
				beforeFrag, _, _ := strings.Cut(noScheme, "#")
				if strings.ContainsAny(beforeFrag, "/?") {
					t.Fatalf("HTTP proxy URI contains path or query: %q", plan.payload)
				}
			}
		})
	}
}

func TestEncodeProxyQRVLESS(t *testing.T) {
	xhttpReality := "vless://" + qrTestUUID + "@203.0.113.10:443?encryption=none&security=reality&type=xhttp&path=%2Fxhttp&mode=auto&sni=www.microsoft.com&fp=chrome&pbk=" + qrTestPBK + "&sid=ab12#aeza-se"
	xhttpTLS := "vless://" + qrTestUUID + "@vless.example.com:443?encryption=none&security=tls&type=xhttp&path=%2Fapi&sni=vless.example.com#tls-srv"
	tcpReality := "vless://" + qrTestUUID + "@203.0.113.11:443?encryption=none&security=reality&type=tcp&flow=xtls-rprx-vision&sni=www.microsoft.com&pbk=" + qrTestPBK + "&sid=ab12#raw-srv"
	wsTLS := "vless://" + qrTestUUID + "@ws.example.com:443?encryption=none&security=tls&type=ws&path=%2Fws&sni=ws.example.com#ws-srv"
	grpcTLS := "vless://" + qrTestUUID + "@grpc.example.com:443?encryption=none&security=tls&type=grpc&serviceName=tun&sni=grpc.example.com#grpc-srv"
	xhttpNone := "vless://" + qrTestUUID + "@plain.example.com:80?encryption=none&security=none&type=xhttp&path=%2F#plain-srv"
	xhttpPlainDownload := "vless://" + qrTestUUID + "@dl.example.com:443?encryption=none&security=reality&type=xhttp&sni=www.microsoft.com&pbk=" + qrTestPBK + "&extra=%7B%22downloadSettings%22%3A%7B%22security%22%3A%22none%22%7D%7D#dl-plain"
	xhttpTLSDownload := "vless://" + qrTestUUID + "@dl-tls.example.com:443?encryption=none&security=reality&type=xhttp&sni=www.microsoft.com&pbk=" + qrTestPBK + "&extra=%7B%22downloadSettings%22%3A%7B%22security%22%3A%22tls%22%7D%7D#dl-tls"

	tests := []struct {
		name         string
		proxy        config.Proxy
		wantPayload  string
		wantSubtitle string
		wantWarn     bool
		wantErr      string
	}{
		{
			name:         "xhttp reality ok",
			proxy:        config.Proxy{Name: "SE", Type: "vless", Link: "  " + xhttpReality + "\n"},
			wantPayload:  xhttpReality,
			wantSubtitle: "VLESS · 203.0.113.10",
			wantWarn:     false,
		},
		{
			name:         "xhttp tls ok",
			proxy:        config.Proxy{Name: "TLS", Type: "vless", Link: xhttpTLS},
			wantPayload:  xhttpTLS,
			wantSubtitle: "VLESS · vless.example.com",
			wantWarn:     false,
		},
		{
			name:         "tcp raw warns",
			proxy:        config.Proxy{Name: "RAW", Type: "vless", Link: tcpReality},
			wantPayload:  tcpReality,
			wantSubtitle: "VLESS · 203.0.113.11",
			wantWarn:     true,
		},
		{
			name:         "ws warns",
			proxy:        config.Proxy{Name: "WS", Type: "vless", Link: wsTLS},
			wantPayload:  wsTLS,
			wantSubtitle: "VLESS · ws.example.com",
			wantWarn:     true,
		},
		{
			name:         "grpc warns",
			proxy:        config.Proxy{Name: "GRPC", Type: "vless", Link: grpcTLS},
			wantPayload:  grpcTLS,
			wantSubtitle: "VLESS · grpc.example.com",
			wantWarn:     true,
		},
		{
			name:         "security none warns",
			proxy:        config.Proxy{Name: "Plain", Type: "vless", Link: xhttpNone},
			wantPayload:  xhttpNone,
			wantSubtitle: "VLESS · plain.example.com",
			wantWarn:     true,
		},
		{
			name:         "xhttp unencrypted downloadSettings in link warns",
			proxy:        config.Proxy{Name: "DLPlain", Type: "vless", Link: xhttpPlainDownload},
			wantPayload:  xhttpPlainDownload,
			wantSubtitle: "VLESS · dl.example.com",
			wantWarn:     true,
		},
		{
			name: "xhttp unencrypted downloadSettings in VLESS params warns",
			proxy: config.Proxy{
				Name:    "DLStruct",
				Type:    "vless",
				Address: "dl2.example.com:443",
				Link:    xhttpPlainDownload,
				VLESS: &vless.Params{
					UUID:        qrTestUUID,
					Network:     "xhttp",
					Security:    "reality",
					SNI:         "www.microsoft.com",
					PublicKey:   qrTestPBK,
					Fingerprint: "firefox",
					SpiderX:     "/",
					Extra:       json.RawMessage(`{"downloadSettings":{"security":"none"}}`),
				},
			},
			wantPayload:  "vless://" + qrTestUUID + "@dl2.example.com:443?encryption=none&extra=%7B%22downloadSettings%22%3A%7B%22security%22%3A%22none%22%7D%7D&fp=firefox&pbk=" + qrTestPBK + "&security=reality&sni=www.microsoft.com&spx=%2F&type=xhttp#DLStruct",
			wantSubtitle: "VLESS · dl2.example.com",
			wantWarn:     true,
		},
		{
			name: "xhttp invalid extra JSON in VLESS params warns",
			proxy: config.Proxy{
				Name:    "DLBadJSON",
				Type:    "vless",
				Address: "dl3.example.com:443",
				Link:    xhttpReality,
				VLESS: &vless.Params{
					UUID:     qrTestUUID,
					Network:  "xhttp",
					Security: "reality",
					Extra:    json.RawMessage(`{invalid`),
				},
			},
			wantPayload:  "vless://" + qrTestUUID + "@dl3.example.com:443?encryption=none&extra=%7Binvalid&fp=firefox&security=reality&type=xhttp#DLBadJSON",
			wantSubtitle: "VLESS · dl3.example.com",
			wantWarn:     true,
		},
		{
			name: "edited VLESS params without Link synthesizes canonical vless URI",
			proxy: config.Proxy{
				Name:    "Manual",
				Type:    "vless",
				Address: "manual.example.com:443",
				VLESS: &vless.Params{
					UUID:        qrTestUUID,
					Network:     "xhttp",
					Security:    "reality",
					SNI:         "www.microsoft.com",
					PublicKey:   qrTestPBK,
					ShortID:     "ab12",
					Path:        "/xhttp",
					Fingerprint: "chrome",
					SpiderX:     "/",
				},
			},
			wantPayload:  "vless://" + qrTestUUID + "@manual.example.com:443?encryption=none&fp=chrome&path=%2Fxhttp&pbk=" + qrTestPBK + "&security=reality&sid=ab12&sni=www.microsoft.com&spx=%2F&type=xhttp#Manual",
			wantSubtitle: "VLESS · manual.example.com",
			wantWarn:     false,
		},
		{
			name:         "xhttp encrypted tls downloadSettings ok",
			proxy:        config.Proxy{Name: "DLTLS", Type: "vless", Link: xhttpTLSDownload},
			wantPayload:  xhttpTLSDownload,
			wantSubtitle: "VLESS · dl-tls.example.com",
			wantWarn:     false,
		},
		{
			name:    "empty link errors",
			proxy:   config.Proxy{Name: "Empty", Type: "vless", Address: "203.0.113.10:443"},
			wantErr: "у профиля нет ссылки vless://",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := buildProxyQRPlan(tc.proxy, "", "", nil, 0)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("got err %v want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if plan.payload != tc.wantPayload {
				t.Fatalf("payload mismatch:\n got  %q\n want %q", plan.payload, tc.wantPayload)
			}
			if plan.subtitle != tc.wantSubtitle {
				t.Fatalf("subtitle: got %q want %q", plan.subtitle, tc.wantSubtitle)
			}
			if strings.Contains(plan.subtitle, qrTestUUID) || strings.Contains(plan.subtitle, qrTestPBK) {
				t.Fatalf("subtitle leaked secret: %q", plan.subtitle)
			}
			if tc.wantWarn && plan.warning != vlessAndroidWarning {
				t.Fatalf("expected warning %q, got %q", vlessAndroidWarning, plan.warning)
			}
			if !tc.wantWarn && plan.warning != "" {
				t.Fatalf("unexpected warning: %q", plan.warning)
			}
		})
	}
}

func TestEncodeProxyQRSubscription(t *testing.T) {
	xhttpLink := "vless://" + qrTestUUID + "@xhttp.example.com:443?encryption=none&security=reality&type=xhttp&path=%2Fx&sni=www.microsoft.com&pbk=" + qrTestPBK + "&sid=ab12#Primary"
	tcpLink := "vless://" + qrTestUUID + "@tcp.example.com:443?encryption=none&security=reality&type=tcp&flow=xtls-rprx-vision&sni=www.microsoft.com&pbk=" + qrTestPBK + "&sid=ab12#Backup"
	entries := subs.Entries([]string{xhttpLink, tcpLink})
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	subProxy := config.Proxy{
		Name: "MySub",
		Type: "vless",
		Sub:  &config.Subscription{Sealed: "dummy", Host: "https://panel.example:2096/…", Count: 2},
	}

	t.Run("https subscription default mode", func(t *testing.T) {
		subURL := "https://panel.example:2096/sub/super-secret-token?flag=1"
		plan, err := buildProxyQRPlan(subProxy, "", subURL, entries, 0)
		if err != nil {
			t.Fatal(err)
		}
		if plan.payload != subURL {
			t.Fatalf("payload: got %q want %q", plan.payload, subURL)
		}
		if plan.subtitle != "Подписка · panel.example" {
			t.Fatalf("subtitle: got %q", plan.subtitle)
		}
		if strings.Contains(plan.subtitle, "super-secret-token") || strings.Contains(plan.subtitle, "flag=1") {
			t.Fatalf("subtitle leaked subscription path/query: %q", plan.subtitle)
		}
		if plan.warning != "" {
			t.Fatalf("unexpected warning: %q", plan.warning)
		}
		if plan.mode != "subscription" {
			t.Fatalf("mode: got %q", plan.mode)
		}
		if len(plan.modes) != 2 || plan.modes[0] != "subscription" || plan.modes[1] != "active" {
			t.Fatalf("modes: %+v", plan.modes)
		}
	})

	t.Run("http subscription warns", func(t *testing.T) {
		subURL := "http://panel.example:2096/sub/secret-token"
		plan, err := buildProxyQRPlan(subProxy, "subscription", subURL, entries, 0)
		if err != nil {
			t.Fatal(err)
		}
		if plan.warning != httpSubWarning {
			t.Fatalf("warning: got %q want %q", plan.warning, httpSubWarning)
		}
		if plan.subtitle != "Подписка · panel.example" {
			t.Fatalf("subtitle: got %q", plan.subtitle)
		}
	})

	t.Run("active mode primary xhttp ok", func(t *testing.T) {
		plan, err := buildProxyQRPlan(subProxy, "active", "https://panel.example/sub/tok", entries, 0)
		if err != nil {
			t.Fatal(err)
		}
		if plan.payload != xhttpLink {
			t.Fatalf("payload: got %q want %q", plan.payload, xhttpLink)
		}
		if plan.subtitle != "VLESS · xhttp.example.com" {
			t.Fatalf("subtitle: got %q", plan.subtitle)
		}
		if plan.warning != "" {
			t.Fatalf("unexpected warning: %q", plan.warning)
		}
		if plan.mode != "active" {
			t.Fatalf("mode: got %q", plan.mode)
		}
	})

	t.Run("active mode backup tcp warns", func(t *testing.T) {
		plan, err := buildProxyQRPlan(subProxy, "active", "https://panel.example/sub/tok", entries, 1)
		if err != nil {
			t.Fatal(err)
		}
		if plan.payload != tcpLink {
			t.Fatalf("payload: got %q want %q", plan.payload, tcpLink)
		}
		if plan.subtitle != "VLESS · tcp.example.com" {
			t.Fatalf("subtitle: got %q", plan.subtitle)
		}
		if plan.warning != vlessAndroidWarning {
			t.Fatalf("warning: got %q want %q", plan.warning, vlessAndroidWarning)
		}
	})

	t.Run("active mode out of range clamps to 0", func(t *testing.T) {
		plan, err := buildProxyQRPlan(subProxy, "active", "https://panel.example/sub/tok", entries, 99)
		if err != nil {
			t.Fatal(err)
		}
		if plan.payload != xhttpLink {
			t.Fatalf("expected index 0 entry, got %q", plan.payload)
		}
	})

	t.Run("no active entries", func(t *testing.T) {
		plan, err := buildProxyQRPlan(subProxy, "subscription", "https://panel.example/sub/tok", nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(plan.modes) != 1 || plan.modes[0] != "subscription" {
			t.Fatalf("modes: %+v", plan.modes)
		}
		if _, err := buildProxyQRPlan(subProxy, "active", "https://panel.example/sub/tok", nil, 0); err == nil || !strings.Contains(err.Error(), "в подписке нет рабочих серверов") {
			t.Fatalf("expected no active servers error, got %v", err)
		}
	})

	t.Run("unknown mode and undecrypted URL errors", func(t *testing.T) {
		if _, err := buildProxyQRPlan(subProxy, "bogus", "https://panel.example/sub/tok", entries, 0); err == nil || !strings.Contains(err.Error(), "неизвестный режим QR-кода") {
			t.Fatalf("expected unknown mode error, got %v", err)
		}
		if _, err := buildProxyQRPlan(subProxy, "subscription", "", entries, 0); err == nil || !strings.Contains(err.Error(), "не удалось расшифровать ссылку подписки") {
			t.Fatalf("expected undecrypted URL error, got %v", err)
		}
	})
}

func TestQRECLevelAndSVGQuietZone(t *testing.T) {
	if got := qrRecoveryLevel(strings.Repeat("a", 400)); got != qrcode.Medium {
		t.Fatalf("len 400: got %v want Medium", got)
	}
	if got := qrRecoveryLevel(strings.Repeat("a", 401)); got != qrcode.Low {
		t.Fatalf("len 401: got %v want Low", got)
	}

	payload := "socks5://alice:secret@192.168.1.1:1080#Home"
	qr, err := qrcode.New(payload, qrRecoveryLevel(payload))
	if err != nil {
		t.Fatal(err)
	}
	qr.DisableBorder = false
	bm := qr.Bitmap()
	n := len(bm)
	if n < 29 { // Version 1 is 21 + 8 quiet zone = 29
		t.Fatalf("bitmap too small: %d", n)
	}
	// Verify 4-module white quiet zone on all four sides.
	for y := 0; y < n; y++ {
		if len(bm[y]) != n {
			t.Fatalf("non-square bitmap row %d: %d != %d", y, len(bm[y]), n)
		}
		for x := 0; x < n; x++ {
			inBorder := y < 4 || y >= n-4 || x < 4 || x >= n-4
			if inBorder && bm[y][x] {
				t.Fatalf("dark module found inside 4-module quiet zone at (%d,%d)", x, y)
			}
		}
	}
	// Top-left finder pattern starts right at (4,4).
	if !bm[4][4] {
		t.Fatalf("expected dark module at finder pattern corner (4,4)")
	}

	dataURL, err := encodeQRDataURL(payload)
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "data:image/svg+xml;base64,"
	if !strings.HasPrefix(dataURL, prefix) {
		t.Fatalf("unexpected data URL prefix: %q", dataURL[:min(40, len(dataURL))])
	}
	rawSVG, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(dataURL, prefix))
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}
	svg := string(rawSVG)
	for _, want := range []string{
		`xmlns="http://www.w3.org/2000/svg"`,
		`shape-rendering="crispEdges"`,
		`fill="#ffffff"`,
		`<path fill="#000000" d="M4 4h7v1h-7z`,
		`</svg>`,
	} {
		if !strings.Contains(svg, want) {
			t.Fatalf("SVG missing %q: %s", want, svg[:min(200, len(svg))])
		}
	}
}

func TestProxyQRAPI(t *testing.T) {
	xhttpLink := "vless://" + qrTestUUID + "@203.0.113.10:443?encryption=none&security=reality&type=xhttp&path=%2Fxhttp&sni=www.microsoft.com&pbk=" + qrTestPBK + "&sid=ab12#SE"
	subSecretToken := "ultra-secret-sub-token-987654"
	subURL := "https://panel.example:2096/sub/" + subSecretToken

	sealed, err := subs.Seal(subs.Secret{URL: subURL, Links: []string{xhttpLink}})
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.Proxies = []config.Proxy{
		{
			Name:     "MySOCKS",
			Type:     "socks5",
			Address:  "127.0.0.1:1080",
			Username: "socksuser",
			Password: "supersecretpassword123",
		},
		{
			Name:     "MyHTTP",
			Type:     "http",
			Address:  "proxy.corp:8080",
			Username: "httpuser",
			Password: "httpsecretpassword456",
		},
		{
			Name: "MyVLESS",
			Type: "vless",
			Link: xhttpLink,
		},
		{
			Name: "MySub",
			Type: "vless",
			Sub: &config.Subscription{
				Sealed: sealed,
				Count:  1,
				Host:   subs.Mask(subURL),
			},
		},
	}

	c := newController(filepath.Join(t.TempDir(), "config.json"), cfg, nil, hooks{})
	t.Cleanup(c.shutdown)
	h := c.Handler()

	t.Run("auth and method checks", func(t *testing.T) {
		const host = "127.0.0.1:5000"
		cases := []struct {
			name, method, token, origin, ctype, body string
			want                                     int
		}{
			{"no token", http.MethodPost, "", "", "application/json", `{"name":"MySOCKS"}`, http.StatusForbidden},
			{"wrong token", http.MethodPost, "bad", "", "application/json", `{"name":"MySOCKS"}`, http.StatusForbidden},
			{"foreign origin", http.MethodPost, c.token, "https://evil.example", "application/json", `{"name":"MySOCKS"}`, http.StatusForbidden},
			{"GET rejected", http.MethodGet, c.token, "", "", "", http.StatusMethodNotAllowed},
			{"non-JSON rejected", http.MethodPost, c.token, "", "text/plain", `{"name":"MySOCKS"}`, http.StatusUnsupportedMediaType},
			{"unknown JSON field rejected", http.MethodPost, c.token, "", "application/json", `{"name":"MySOCKS","extra":1}`, http.StatusBadRequest},
		}
		for _, tc := range cases {
			req := httptest.NewRequest(tc.method, "/api/proxy/qr", strings.NewReader(tc.body))
			req.Host = host
			if tc.token != "" {
				req.Header.Set(tokenHeader, tc.token)
			}
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.ctype != "" {
				req.Header.Set("Content-Type", tc.ctype)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != tc.want {
				t.Errorf("%s: got %d want %d (%s)", tc.name, rr.Code, tc.want, strings.TrimSpace(rr.Body.String()))
			}
		}
	})

	callQR := func(t *testing.T, body string) (*httptest.ResponseRecorder, qrResponse) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/proxy/qr", strings.NewReader(body))
		req.Host = "127.0.0.1:5000"
		req.Header.Set(tokenHeader, c.token)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		var resp qrResponse
		_ = json.Unmarshal(rr.Body.Bytes(), &resp)
		return rr, resp
	}

	t.Run("unknown proxy returns 400", func(t *testing.T) {
		rr, _ := callQR(t, `{"name":"NoSuchProxy"}`)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("got %d want 400 (%s)", rr.Code, rr.Body.String())
		}
		if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
			t.Fatalf("Cache-Control: got %q want no-store", cc)
		}
		if !strings.Contains(rr.Body.String(), "прокси не найден") {
			t.Fatalf("unexpected error body: %s", rr.Body.String())
		}
	})

	t.Run("valid responses and no secret leakage", func(t *testing.T) {
		cases := []struct {
			body         string
			wantName     string
			wantSubtitle string
			wantMode     string
			wantModesLen int
			forbidden    []string
		}{
			{
				body:         `{"name":"MySOCKS"}`,
				wantName:     "MySOCKS",
				wantSubtitle: "SOCKS5 · 127.0.0.1:1080",
				forbidden:    []string{"socksuser", "supersecretpassword123", "socks5://"},
			},
			{
				body:         `{"name":"MyHTTP"}`,
				wantName:     "MyHTTP",
				wantSubtitle: "HTTP · proxy.corp:8080",
				forbidden:    []string{"httpuser", "httpsecretpassword456", "http://"},
			},
			{
				body:         `{"name":"MyVLESS"}`,
				wantName:     "MyVLESS",
				wantSubtitle: "VLESS · 203.0.113.10",
				forbidden:    []string{qrTestUUID, qrTestPBK, "vless://"},
			},
			{
				body:         `{"name":"MySub"}`,
				wantName:     "MySub",
				wantSubtitle: "Подписка · panel.example",
				wantMode:     "subscription",
				wantModesLen: 2,
				forbidden:    []string{subSecretToken, subURL, "https://panel.example"},
			},
			{
				body:         `{"name":"MySub","mode":"active"}`,
				wantName:     "MySub",
				wantSubtitle: "VLESS · 203.0.113.10",
				wantMode:     "active",
				wantModesLen: 2,
				forbidden:    []string{qrTestUUID, qrTestPBK, "vless://", subSecretToken},
			},
		}

		for _, tc := range cases {
			rr, resp := callQR(t, tc.body)
			if rr.Code != http.StatusOK {
				t.Fatalf("%s: got %d (%s)", tc.body, rr.Code, rr.Body.String())
			}
			if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
				t.Fatalf("%s: Cache-Control=%q", tc.body, cc)
			}
			if resp.Name != tc.wantName || resp.Subtitle != tc.wantSubtitle || resp.Mode != tc.wantMode || len(resp.Modes) != tc.wantModesLen {
				t.Fatalf("%s: unexpected metadata %+v", tc.body, resp)
			}
			if !strings.HasPrefix(resp.Image, "data:image/svg+xml;base64,") {
				t.Fatalf("%s: missing SVG data URL", tc.body)
			}
			rawBody := rr.Body.String()
			for _, secret := range tc.forbidden {
				if strings.Contains(rawBody, secret) {
					t.Fatalf("%s: response leaked secret %q", tc.body, secret)
				}
			}
		}
	})

	t.Run("subscription decrypted via subs.Open when absent from c.subs", func(t *testing.T) {
		c.mu.Lock()
		delete(c.subs, "MySub")
		c.mu.Unlock()

		rr, resp := callQR(t, `{"name":"MySub"}`)
		if rr.Code != http.StatusOK {
			t.Fatalf("got %d (%s)", rr.Code, rr.Body.String())
		}
		if resp.Subtitle != "Подписка · panel.example" || resp.Mode != "subscription" || len(resp.Modes) != 2 {
			t.Fatalf("unexpected fallback response: %+v", resp)
		}
		if strings.Contains(rr.Body.String(), subSecretToken) {
			t.Fatalf("response leaked subscription token")
		}
	})

	t.Run("subscription respects runtime failover active index", func(t *testing.T) {
		tcpLink := "vless://" + qrTestUUID + "@203.0.113.99:443?encryption=none&security=reality&type=tcp&flow=xtls-rprx-vision&sni=www.microsoft.com&pbk=" + qrTestPBK + "&sid=ab12#Backup"
		now := time.Now()
		fo := failover.New(2, now, failover.Defaults, func() float64 { return 0.5 })
		fo.Active = 1
		c.mu.Lock()
		c.subs["MySub"] = &subGroup{
			sealed:  sealed,
			url:     subURL,
			entries: subs.Entries([]string{xhttpLink, tcpLink}),
			fo:      fo,
		}
		c.mu.Unlock()

		rr, resp := callQR(t, `{"name":"MySub","mode":"active"}`)
		if rr.Code != http.StatusOK {
			t.Fatalf("got %d (%s)", rr.Code, rr.Body.String())
		}
		if resp.Subtitle != "VLESS · 203.0.113.99" {
			t.Fatalf("expected active backup host, got %q", resp.Subtitle)
		}
		if resp.Warning != vlessAndroidWarning {
			t.Fatalf("expected TCP warning for active backup, got %q", resp.Warning)
		}
	})
}
