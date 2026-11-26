package vless

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

// Status is one bridge as Ashgate and the window see it.
type Status struct {
	// SOCKS, User and Pass are the private inbound Ashgate dials. They
	// change on every start and never leave the process.
	SOCKS string `json:"-"`
	User  string `json:"-"`
	Pass  string `json:"-"`
	// Published and HTTP are the fixed ports for other programs.
	Published string `json:"published,omitempty"`
	HTTP      string `json:"http,omitempty"`
	// PubUser and PubPass are set only when they were generated for this
	// start (no login in the config), so the window can show them.
	PubUser string `json:"user,omitempty"`
	PubPass string `json:"pass,omitempty"`
	Err     string `json:"error,omitempty"`
	Up      bool   `json:"up"`
	// Server is the VLESS server's host:port the bridge dials.
	Server string `json:"-"`
}

// Endpoint is one VLESS proxy the manager should keep running.
type Endpoint struct {
	Name    string
	Address string
	Params  Params
	Inbound Inbound
	Routing Routing
}

// Manager keeps one local SOCKS bridge per VLESS proxy.
// Unchanged proxies keep their port across Sync calls.
// Bridges follow the manager's lifetime, not the caller's context, so capture
// can stop without closing a port that other applications are using.
type Manager struct {
	mu     sync.Mutex
	by     map[string]*running
	ctx    context.Context
	cancel context.CancelFunc
}

type running struct {
	fp     string
	bridge *Bridge
}

// NewManager returns an empty manager.
func NewManager() *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{by: map[string]*running{}, ctx: ctx, cancel: cancel}
}

// Sync starts missing bridges, restarts changed ones, and stops removed ones.
// Unchanged proxies keep their port. A failure on one proxy does not stop
// the others; the returned error lists the proxies that did not come up.
func (m *Manager) Sync(ctx context.Context, items []Endpoint) (map[string]Status, error) {
	if m == nil {
		return nil, errors.New("VLESS: локальный мост не запущен")
	}
	if ctx != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ctx == nil || m.ctx.Err() != nil {
		return nil, errors.New("VLESS: локальный мост не запущен")
	}

	// Deduplicate by Name (first occurrence wins) so no started bridge is leaked.
	unique := make([]Endpoint, 0, len(items))
	want := make(map[string]string, len(items))
	for _, item := range items {
		if _, dup := want[item.Name]; dup {
			continue
		}
		want[item.Name] = fingerprint(item)
		unique = append(unique, item)
	}

	// Pass 1: stop all removed and changed bridges before starting any new ones
	// so fixed SOCKSPort renames, replacements, and port swaps do not conflict.
	for name, cur := range m.by {
		if fp, ok := want[name]; !ok || cur.fp != fp {
			cur.bridge.Close()
			delete(m.by, name)
		}
	}

	// Pass 2: keep unchanged bridges and start missing or changed ones.
	next := make(map[string]*running, len(unique))
	status := make(map[string]Status, len(unique))
	var errs []error
	for _, item := range unique {
		fp := want[item.Name]
		if cur, ok := m.by[item.Name]; ok {
			next[item.Name] = cur
			status[item.Name] = statusOf(cur.bridge)
			continue
		}
		br, err := ListenWith(m.ctx, item.Address, item.Params, item.Inbound, item.Routing)
		if err != nil {
			errs = append(errs, fmt.Errorf("прокси %s: %w", item.Name, err))
			status[item.Name] = Status{Err: err.Error()}
			continue
		}
		next[item.Name] = &running{fp: fp, bridge: br}
		status[item.Name] = statusOf(br)
	}
	m.by = next
	if len(errs) > 0 {
		return status, errors.Join(errs...)
	}
	return status, nil
}

// Close stops every bridge.
func (m *Manager) Close() {
	if m == nil {
		return
	}
	// Cancel before locking m.mu so in-flight ListenWith/DoH/waitPort calls
	// inside Sync abort immediately. m.cancel is immutable after NewManager.
	if m.cancel != nil {
		m.cancel()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for name, cur := range m.by {
		cur.bridge.Close()
		delete(m.by, name)
	}
}

func statusOf(b *Bridge) Status {
	if b == nil || b.Addr == "" {
		return Status{}
	}
	st := Status{SOCKS: b.Addr, User: b.User, Pass: b.Pass, Published: b.Published, HTTP: b.HTTP, Up: true, Server: b.server}
	if b.Generated {
		st.PubUser, st.PubPass = b.PubUser, b.PubPass
	}
	return st
}

func fingerprint(item Endpoint) string {
	raw, _ := json.Marshal(struct {
		Address string  `json:"address"`
		Params  Params  `json:"vless"`
		Inbound Inbound `json:"in"`
		Routing Routing `json:"routing"`
	}{item.Address, item.Params, item.Inbound, item.Routing})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
