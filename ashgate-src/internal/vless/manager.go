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

// Status is the published localhost address of one bridge.
type Status struct {
	SOCKS string `json:"socks,omitempty"`
	HTTP  string `json:"http,omitempty"`
	Err   string `json:"error,omitempty"`
	Up    bool   `json:"up"`
}

// Endpoint is one VLESS proxy the manager should keep running.
type Endpoint struct {
	Name    string
	Address string
	Params  Params
	Inbound Inbound
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

	next := make(map[string]*running, len(items))
	status := make(map[string]Status, len(items))
	var errs []error
	for _, item := range items {
		fp := fingerprint(item)
		if cur, ok := m.by[item.Name]; ok {
			if cur.fp == fp {
				next[item.Name] = cur
				status[item.Name] = statusOf(cur.bridge)
				continue
			}
			// Changed: stop the old bridge first. It is replaced either way,
			// and a fixed SOCKSPort it still held would make Listen fail.
			cur.bridge.Close()
			delete(m.by, item.Name)
		}
		br, err := Listen(m.ctx, item.Address, item.Params, item.Inbound)
		if err != nil {
			errs = append(errs, fmt.Errorf("прокси %s: %w", item.Name, err))
			status[item.Name] = Status{Err: err.Error()}
			continue
		}
		next[item.Name] = &running{fp: fp, bridge: br}
		status[item.Name] = statusOf(br)
	}
	for name, cur := range m.by {
		if next[name] != cur {
			cur.bridge.Close()
		}
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
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	for name, cur := range m.by {
		cur.bridge.Close()
		delete(m.by, name)
	}
}

func statusOf(b *Bridge) Status {
	if b == nil || b.Addr == "" {
		return Status{}
	}
	return Status{SOCKS: b.Addr, HTTP: b.HTTP, Up: true}
}

func fingerprint(item Endpoint) string {
	raw, _ := json.Marshal(struct {
		Address string  `json:"address"`
		Params  Params  `json:"vless"`
		Inbound Inbound `json:"in"`
	}{item.Address, item.Params, item.Inbound})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
