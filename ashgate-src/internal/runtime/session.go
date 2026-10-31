package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"ashgate/internal/config"
	"ashgate/internal/engine"
	"ashgate/internal/logbuf"
	"ashgate/internal/vless"
)

// Session is one running capture engine.
type Session struct {
	eng     *engine.Engine
	cancel  context.CancelFunc
	done    chan struct{}
	bridges *vless.Manager
	bctx    context.Context

	mu  sync.Mutex
	err error
}

// Apply installs a new configuration. Existing TCP flows keep their proxy.
func (s *Session) Apply(cfg *config.Config) error {
	if s == nil || s.eng == nil {
		return errors.New("движок не запущен")
	}
	cp, err := cloneConfig(cfg)
	if err != nil {
		return err
	}
	var syncErr error
	if s.bridges != nil {
		ctx := s.bctx
		if ctx == nil {
			ctx = context.Background()
		}
		_, syncErr = WireVLESS(ctx, s.bridges, cp)
	}
	applyErr := s.eng.Apply(cp)
	if applyErr == nil {
		// New or moved proxy servers must stay direct right away; the
		// periodic refresh is slow on purpose (see bypassEvery).
		ctx := s.bctx
		if ctx == nil {
			ctx = context.Background()
		}
		go s.eng.RefreshBypass(ctx)
	}
	if syncErr != nil {
		return syncErr
	}
	return applyErr
}

// Active is the number of proxied TCP and UDP flows.
func (s *Session) Active() int64 {
	if s == nil || s.eng == nil {
		return 0
	}
	return s.eng.Active()
}

// FlowCounts splits active proxied flows into TCP and UDP.
func (s *Session) FlowCounts() (tcp, udp int) {
	if s == nil || s.eng == nil {
		return 0, 0
	}
	return s.eng.FlowCounts()
}

// RuleStats returns per-rule counters, keyed by engine.RuleKey.
func (s *Session) RuleStats() map[string]engine.RuleStat {
	if s == nil || s.eng == nil {
		return nil
	}
	return s.eng.RuleStats()
}

// Traffic is bytes relayed by this session.
func (s *Session) Traffic() (up, down int64) {
	if s == nil || s.eng == nil {
		return 0, 0
	}
	return s.eng.Traffic()
}

// Stop asks the engine to exit. It is safe to call more than once.
func (s *Session) Stop() {
	if s != nil && s.cancel != nil {
		s.cancel()
	}
}

// Running reports whether the capture loop has not finished yet.
func (s *Session) Running() bool {
	if s == nil || s.done == nil {
		return false
	}
	select {
	case <-s.done:
		return false
	default:
		return true
	}
}

// Done is closed after the driver handles have been released.
func (s *Session) Done() <-chan struct{} {
	if s == nil || s.done == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return s.done
}

// Err is the first background failure, if the capture loop stopped by itself.
func (s *Session) Err() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *Session) setErr(err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.mu.Unlock()
}

// WireVLESS starts or updates the local bridges for every VLESS proxy and
// writes each SOCKS address into Proxy.Local. Proxies that fail to start
// get an empty Local; their error is in the status map and the returned error.
func WireVLESS(ctx context.Context, m *vless.Manager, cfg *config.Config) (map[string]vless.Status, error) {
	if m == nil || cfg == nil {
		return nil, errors.New("VLESS: локальный мост не запущен")
	}
	items := make([]vless.Endpoint, 0)
	for i := range cfg.Proxies {
		p := &cfg.Proxies[i]
		if p.Type != "vless" {
			continue
		}
		if err := p.Prepare(); err != nil {
			return nil, fmt.Errorf("прокси %s: %w", p.Name, err)
		}
		items = append(items, vless.Endpoint{
			Name: p.Name, Address: p.Address, Params: *p.VLESS,
			Inbound: vless.Inbound{Port: p.SOCKSPort, User: p.LocalUser, Pass: p.LocalPass},
		})
	}
	status, err := m.Sync(ctx, items)
	if status == nil {
		status = map[string]vless.Status{}
	}
	for i := range cfg.Proxies {
		st, ok := status[cfg.Proxies[i].Name]
		if ok && st.SOCKS != "" {
			cfg.Proxies[i].Local = st.SOCKS
		} else if cfg.Proxies[i].Type == "vless" {
			cfg.Proxies[i].Local = ""
		}
	}
	return status, err
}

// LogBridges writes one Russian line per bridge that is up or failed.
func LogBridges(logs *logbuf.Buffer, status map[string]vless.Status) {
	if logs == nil {
		return
	}
	for name, st := range status {
		if st.Err != "" {
			logs.Add(logbuf.Event{Process: "ashgate", Proto: "TCP", Via: name, Status: "error", Error: st.Err})
			continue
		}
		if st.SOCKS != "" {
			logs.Add(logbuf.Event{Process: "ashgate", Proto: "TCP", Dest: st.SOCKS, Via: name, Status: "open"})
		}
	}
}

func cloneConfig(cfg *config.Config) (*config.Config, error) {
	if cfg == nil {
		return nil, errors.New("пустая конфигурация")
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var out config.Config
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	out.ApplyDefaults()
	if err := out.Validate(); err != nil {
		return nil, err
	}
	return &out, nil
}
