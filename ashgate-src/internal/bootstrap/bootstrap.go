// Package bootstrap resolves the names Ashgate itself needs before a tunnel
// is up: proxy servers and the subscription host. It asks DNS over HTTPS
// resolvers addressed by IP, so the provider's DNS never sees these names
// (a VLESS server's domain is the clearest sign of it), and it does not use
// the Windows DNS client, whose lookups Ashgate sends through the tunnel.
package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"ashgate/internal/atomicfile"

	"golang.org/x/net/dns/dnsmessage"
)

// DefaultServers answer DoH on their own IP and are reachable from Russia.
var DefaultServers = []string{
	"https://1.1.1.1/dns-query",
	"https://8.8.8.8/dns-query",
	"https://9.9.9.9/dns-query",
	"https://94.140.14.14/dns-query",
}

const (
	perServer = 5 * time.Second
	minTTL    = 5 * time.Minute
	maxTTL    = 24 * time.Hour
	// staleFor is how long a cached answer still serves when every
	// resolver fails, so a server known yesterday is still reachable.
	staleFor = 30 * 24 * time.Hour
)

// Resolver looks up host names over DoH and caches the answers.
type Resolver struct {
	mu      sync.Mutex
	servers []string
	cache   map[string]entry
	file    string
	loaded  bool
	client  *http.Client
	now     func() time.Time
}

type entry struct {
	IPs   []net.IP  `json:"ips"`
	Until time.Time `json:"until"`
	At    time.Time `json:"at"`
}

// Default is the process-wide resolver.
var Default = New()

// CacheFile is where Default keeps its answers: next to the config.
func CacheFile(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "dnscache.json")
}

// New returns a resolver with the default servers and no cache file.
func New() *Resolver {
	return &Resolver{
		cache: map[string]entry{},
		client: &http.Client{Transport: &http.Transport{
			Proxy:               nil,
			ForceAttemptHTTP2:   true,
			DialContext:         (&net.Dialer{Timeout: perServer}).DialContext,
			TLSHandshakeTimeout: perServer,
			MaxIdleConns:        4,
			IdleConnTimeout:     30 * time.Second,
		}},
		now: time.Now,
	}
}

// SetServers replaces the DoH URLs; empty restores DefaultServers.
func (r *Resolver) SetServers(urls []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.servers = append([]string(nil), urls...)
}

// SetFile keeps the cache in file across restarts ("" for none). A stored
// answer lets Ashgate reach a known server when every resolver is blocked.
func (r *Resolver) SetFile(file string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if file != r.file {
		r.file, r.loaded = file, false
	}
}

// LookupIP returns the addresses of host. An IP literal is returned as is.
func (r *Resolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	if host == "" {
		return nil, errors.New("пустое имя")
	}
	if lanName(host) {
		// Only the LAN knows these; the engine lets such lookups go there.
		return net.DefaultResolver.LookupIP(ctx, "ip", host)
	}
	r.mu.Lock()
	r.loadLocked()
	cached, ok := r.cache[host]
	servers := r.servers
	r.mu.Unlock()
	now := r.now()
	if ok && now.Before(cached.Until) {
		return cached.IPs, nil
	}
	if len(servers) == 0 {
		servers = DefaultServers
	}
	var errs []string
	for _, url := range servers {
		ips, ttl, err := r.ask(ctx, url, host)
		if err != nil {
			errs = append(errs, err.Error())
			if ctx.Err() != nil {
				break
			}
			continue
		}
		r.store(host, ips, ttl)
		return ips, nil
	}
	if ok && now.Sub(cached.At) < staleFor {
		return cached.IPs, nil
	}
	return nil, fmt.Errorf("DoH не ответил: %s", strings.Join(errs, "; "))
}

// lanName reports localhost, dotless names and LAN suffixes.
func lanName(host string) bool {
	if !strings.Contains(host, ".") {
		return true
	}
	for _, s := range []string{"localhost", "local", "localdomain", "lan", "home.arpa", "internal"} {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

// ask queries one server for A and AAAA at once.
func (r *Resolver) ask(ctx context.Context, url, host string) ([]net.IP, time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, perServer)
	defer cancel()
	type res struct {
		ips []net.IP
		ttl time.Duration
		err error
	}
	out := make(chan res, 2)
	for _, t := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		go func(t dnsmessage.Type) {
			ips, ttl, err := r.query(ctx, url, host, t)
			out <- res{ips, ttl, err}
		}(t)
	}
	var ips []net.IP
	ttl := maxTTL
	var firstErr error
	answered := false
	for i := 0; i < 2; i++ {
		x := <-out
		if x.err != nil {
			if firstErr == nil {
				firstErr = x.err
			}
			continue
		}
		answered = true
		ips = append(ips, x.ips...)
		if len(x.ips) > 0 && x.ttl < ttl {
			ttl = x.ttl
		}
	}
	if !answered {
		return nil, 0, firstErr
	}
	if len(ips) == 0 {
		return nil, 0, fmt.Errorf("%s: нет адресов", host)
	}
	return ips, ttl, nil
}

func (r *Resolver) query(ctx context.Context, url, host string, t dnsmessage.Type) ([]net.IP, time.Duration, error) {
	name, err := dnsmessage.NewName(host + ".")
	if err != nil {
		return nil, 0, err
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: t, Class: dnsmessage.ClassINET}},
	}
	body, err := msg.Pack()
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("%s: HTTP %d", resp.Request.URL.Host, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, 0, err
	}
	return parseAnswer(raw, t)
}

// parseAnswer takes the addresses of type t from a DNS response. NXDOMAIN
// and an empty answer are answers too: no addresses, no error.
func parseAnswer(raw []byte, t dnsmessage.Type) ([]net.IP, time.Duration, error) {
	var p dnsmessage.Parser
	h, err := p.Start(raw)
	if err != nil {
		return nil, 0, err
	}
	if !h.Response {
		return nil, 0, errors.New("не ответ DNS")
	}
	switch h.RCode {
	case dnsmessage.RCodeSuccess, dnsmessage.RCodeNameError:
	default:
		return nil, 0, fmt.Errorf("DNS: %v", h.RCode)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, 0, err
	}
	var ips []net.IP
	ttl := maxTTL
	for {
		ah, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return nil, 0, err
		}
		if ah.Type != t {
			if err := p.SkipAnswer(); err != nil {
				return nil, 0, err
			}
			continue
		}
		switch t {
		case dnsmessage.TypeA:
			a, err := p.AResource()
			if err != nil {
				return nil, 0, err
			}
			ips = append(ips, net.IP(a.A[:]).To16())
		case dnsmessage.TypeAAAA:
			a, err := p.AAAAResource()
			if err != nil {
				return nil, 0, err
			}
			ips = append(ips, net.IP(a.AAAA[:]))
		}
		if d := time.Duration(ah.TTL) * time.Second; d < ttl {
			ttl = d
		}
	}
	return ips, ttl, nil
}

func (r *Resolver) store(host string, ips []net.IP, ttl time.Duration) {
	ttl = max(minTTL, min(ttl, maxTTL))
	now := r.now()
	r.mu.Lock()
	r.cache[host] = entry{IPs: ips, Until: now.Add(ttl), At: now}
	file := r.file
	raw, err := json.Marshal(r.cache)
	r.mu.Unlock()
	if file == "" || err != nil {
		return
	}
	_ = atomicfile.Write(file, raw)
}

// loadLocked reads the cache file once. Expired entries stay: they are
// the fallback when every resolver fails.
func (r *Resolver) loadLocked() {
	if r.loaded || r.file == "" {
		return
	}
	r.loaded = true
	raw, err := os.ReadFile(r.file)
	if err != nil {
		return
	}
	var stored map[string]entry
	if json.Unmarshal(raw, &stored) != nil {
		return
	}
	for k, v := range stored {
		if _, ok := r.cache[k]; !ok && len(v.IPs) > 0 {
			r.cache[k] = v
		}
	}
}

// Dial connects to addr ("host:port") from this process, finding a host
// name with Default instead of the system resolver.
func Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := Default.LookupIP(ctx, host)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	var last error
	for _, ip := range ips {
		c, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return c, nil
		}
		last = err
	}
	if last == nil {
		last = fmt.Errorf("%s: нет адресов", host)
	}
	return nil, last
}
