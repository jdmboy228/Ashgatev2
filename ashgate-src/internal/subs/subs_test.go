package subs

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Fake values only.
const (
	uuid = "b7e2c1a0-4f3a-4c2b-9a11-111111111111"
	pbk  = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
)

func link(network, name string) string {
	extra := "&path=%2Fx&mode=auto"
	if network == "tcp" {
		extra = "&flow=xtls-rprx-vision"
	}
	if network == "grpc" {
		extra = "&serviceName=g"
	}
	return "vless://" + uuid + "@203.0.113.10:443?type=" + network + "&security=reality&pbk=" + pbk +
		"&fp=firefox&sni=example.com&sid=abcd" + extra + "#" + name
}

func names(entries []Entry) string {
	var out []string
	for _, e := range entries {
		out = append(out, e.Name)
	}
	return strings.Join(out, ",")
}

func TestParseFormats(t *testing.T) {
	plain := strings.Join([]string{
		link("tcp", "raw1"), "vmess://ignored", "", "garbage", link("xhttp", "x1"),
		"vless://not-a-link", link("grpc", "g1"),
	}, "\r\n")
	for name, body := range map[string]string{
		"plain":          plain,
		"base64":         base64.StdEncoding.EncodeToString([]byte(plain)),
		"base64 raw":     base64.RawStdEncoding.EncodeToString([]byte(plain)),
		"base64 url":     base64.URLEncoding.EncodeToString([]byte(plain)),
		"base64 wrapped": wrap(base64.StdEncoding.EncodeToString([]byte(plain)), 76),
	} {
		entries, skipped := Parse([]byte(body))
		if names(entries) != "raw1,x1,g1" || skipped != 3 {
			t.Errorf("%s: entries %q skipped %d", name, names(entries), skipped)
		}
	}
	if entries, _ := Parse([]byte("hello")); len(entries) != 0 {
		t.Fatal("parsed links from junk")
	}
}

func wrap(s string, n int) string {
	var b strings.Builder
	for len(s) > n {
		b.WriteString(s[:n] + "\n")
		s = s[n:]
	}
	return b.String() + s
}

// XHTTP first (primary), RAW second (backup), others after; the
// subscription order is kept within one transport.
func TestOrderPriority(t *testing.T) {
	entries, _ := Parse([]byte(strings.Join([]string{
		link("grpc", "g1"), link("tcp", "raw1"), link("xhttp", "x1"), link("ws", "w1"),
		link("tcp", "raw2"), link("xhttp", "x2"),
	}, "\n")))
	if got := names(Order(entries)); got != "x1,x2,raw1,raw2,g1,w1" {
		t.Fatalf("order %s", got)
	}
}

func TestApplyKeepsActiveLink(t *testing.T) {
	old, _ := Parse([]byte(link("xhttp", "x1") + "\n" + link("tcp", "raw1")))
	active := Order(old)[1].Link // on the RAW backup

	// The list changes but still has the active link: no reconnect, even
	// though its position moved.
	fresh, _ := Parse([]byte(strings.Join([]string{link("tcp", "raw0"), link("tcp", "raw1"), link("xhttp", "x9")}, "\n")))
	ordered, idx, reconnect := Apply(fresh, active)
	if reconnect || ordered[idx].Link != active || names(ordered) != "x9,raw0,raw1" {
		t.Fatalf("idx %d reconnect %v order %s", idx, reconnect, names(ordered))
	}

	// The active link disappeared: the best entry takes over.
	gone, _ := Parse([]byte(link("tcp", "raw5") + "\n" + link("xhttp", "x5")))
	ordered, idx, reconnect = Apply(gone, active)
	if !reconnect || idx != 0 || ordered[0].Name != "x5" {
		t.Fatalf("idx %d reconnect %v order %s", idx, reconnect, names(ordered))
	}
}

func TestFetchValidates(t *testing.T) {
	good := base64.StdEncoding.EncodeToString([]byte(link("tcp", "raw1") + "\n" + link("xhttp", "x1")))
	mux := http.NewServeMux()
	mux.HandleFunc("/sub/ok-token", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(good)) })
	mux.HandleFunc("/sub/empty-token", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(base64.StdEncoding.EncodeToString([]byte("vmess://x"))))
	})
	mux.HandleFunc("/sub/gone-token", func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) })
	mux.HandleFunc("/sub/slow-token", func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	entries, err := Fetch(context.Background(), srv.Client(), srv.URL+"/sub/ok-token")
	if err != nil || len(entries) != 2 {
		t.Fatalf("%v %d", err, len(entries))
	}
	for path, want := range map[string]string{"/sub/empty-token": "нет ни одной", "/sub/gone-token": "404", "/sub/slow-token": "вовремя"} {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		_, err := Fetch(ctx, srv.Client(), srv.URL+path)
		cancel()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", path, err, want)
		}
		if err != nil && strings.Contains(err.Error(), "token") {
			t.Errorf("%s: the error shows the URL: %v", path, err)
		}
	}
	if _, err := Fetch(context.Background(), srv.Client(), "http://127.0.0.1:1/sub/secret-token"); err == nil || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("unreachable: %v", err)
	}
}

func TestMaskAndSeal(t *testing.T) {
	if got := Mask("https://user:pw@sub.example.com:2096/sub/abcdef?token=x"); got != "https://sub.example.com:2096/…" {
		t.Fatal(got)
	}
	if CheckURL("ftp://x") == nil || CheckURL("https://sub.example.com/s/t") != nil {
		t.Fatal("CheckURL")
	}
	s := Secret{URL: "https://sub.example.com/sub/token", Links: []string{link("tcp", "raw1")}}
	sealed, err := Seal(s)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(sealed)
	if err != nil || got.URL != s.URL || len(got.Links) != 1 || got.Links[0] != s.Links[0] {
		t.Fatalf("%+v %v", got, err)
	}
	if e := Entries(got.Links); len(e) != 1 || e[0].Label() != "raw1 · RAW" {
		t.Fatalf("%+v", e)
	}
}
