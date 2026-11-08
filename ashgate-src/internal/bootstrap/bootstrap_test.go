package bootstrap

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeDoH answers A queries for vps.example.net with 203.0.113.7 and
// everything else with an empty answer.
func fakeDoH(t *testing.T, hits *atomic.Int32, down *atomic.Bool) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		hits.Add(1)
		if down.Load() || req.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		body, _ := io.ReadAll(req.Body)
		var q dnsmessage.Message
		if err := q.Unpack(body); err != nil || len(q.Questions) != 1 {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		resp := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: q.ID, Response: true, RecursionAvailable: true},
			Questions: q.Questions,
		}
		qq := q.Questions[0]
		if qq.Name.String() == "vps.example.net." && qq.Type == dnsmessage.TypeA {
			resp.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: qq.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
				Body:   &dnsmessage.AResource{A: [4]byte{203, 0, 113, 7}},
			}}
		}
		out, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/dns-query"
}

func TestLookupCachesAndServesStale(t *testing.T) {
	var hits atomic.Int32
	var down atomic.Bool
	url := fakeDoH(t, &hits, &down)
	r := New()
	r.SetServers([]string{url})
	now := time.Now()
	r.now = func() time.Time { return now }
	ctx := context.Background()

	ips, err := r.LookupIP(ctx, "VPS.example.net.")
	if err != nil || len(ips) != 1 || !ips[0].Equal(net.ParseIP("203.0.113.7")) {
		t.Fatalf("LookupIP = %v %v", ips, err)
	}
	if hits.Load() != 2 {
		t.Fatalf("%d DoH requests, want A and AAAA", hits.Load())
	}
	if _, err := r.LookupIP(ctx, "vps.example.net"); err != nil || hits.Load() != 2 {
		t.Fatalf("a fresh answer was asked again (%d requests, %v)", hits.Load(), err)
	}
	// TTL 60 s is raised to minTTL; past it, with the resolver down, the
	// old answer still serves.
	now = now.Add(minTTL + time.Second)
	down.Store(true)
	if ips, err := r.LookupIP(ctx, "vps.example.net"); err != nil || len(ips) != 1 {
		t.Fatalf("stale answer with the resolver down: %v %v", ips, err)
	}
	if _, err := r.LookupIP(ctx, "other.example.net"); err == nil {
		t.Fatal("an unknown name resolved with the resolver down")
	}
}

func TestLookupIPLiteralAndEmptyAnswer(t *testing.T) {
	var hits atomic.Int32
	var down atomic.Bool
	r := New()
	r.SetServers([]string{fakeDoH(t, &hits, &down)})
	if ips, err := r.LookupIP(context.Background(), "198.51.100.4"); err != nil || len(ips) != 1 || hits.Load() != 0 {
		t.Fatalf("IP literal: %v %v (%d requests)", ips, err, hits.Load())
	}
	if _, err := r.LookupIP(context.Background(), "nothing.example.net"); err == nil {
		t.Fatal("a name without addresses resolved")
	}
}

func TestCacheFileSurvivesRestart(t *testing.T) {
	var hits atomic.Int32
	var down atomic.Bool
	url := fakeDoH(t, &hits, &down)
	file := filepath.Join(t.TempDir(), "dnscache.json")
	a := New()
	a.SetServers([]string{url})
	a.SetFile(file)
	if _, err := a.LookupIP(context.Background(), "vps.example.net"); err != nil {
		t.Fatal(err)
	}
	down.Store(true)
	b := New()
	b.SetServers([]string{url})
	b.SetFile(file)
	b.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	if ips, err := b.LookupIP(context.Background(), "vps.example.net"); err != nil || len(ips) != 1 {
		t.Fatalf("after a restart with every resolver down: %v %v", ips, err)
	}
}
