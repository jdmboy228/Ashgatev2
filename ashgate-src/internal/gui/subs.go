package gui

import (
	"bufio"
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ashgate/internal/config"
	"ashgate/internal/failover"
	"ashgate/internal/logbuf"
	"ashgate/internal/socks5"
	"ashgate/internal/subs"
	"ashgate/internal/vless"
)

// Subscription timings.
const (
	subEvery         = 24 * time.Hour   // automatic update, ±10 %
	subJitter        = 0.1              //
	subRetry         = 30 * time.Minute // one retry after a failed update
	subFirst         = time.Minute      // first update after start, when due
	subDirectTimeout = 15 * time.Second // fetch without a tunnel: one try
	subTunnelTimeout = 30 * time.Second
	subTick          = 5 * time.Second
)

// freezeAfter: a tunnel that took the request but answered nothing for
// this long is frozen. Tests shorten it.
var freezeAfter = 15 * time.Second

// healthHost answers generate_204; the check reaches it only through the
// tunnel (the VLESS server makes the request), never directly.
var healthHost, healthPort = "www.gstatic.com", uint16(80)

// browserUA is sent with the health check, like a browser would.
const browserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"

// subRand is the jitter source; tests replace it.
var subRand = rand.Float64

// subGroup is one subscription at run time: its servers in priority order
// and the failover state. url is decrypted and never logged or sent to the
// window.
type subGroup struct {
	sealed    string
	url       string
	entries   []subs.Entry
	fo        *failover.Group
	openErr   string
	nextFetch time.Time
	retried   bool
	checking  bool
	probing   bool
}

// subView is what the window shows for a subscription besides the stored
// count, update time and error.
type subView struct {
	Servers    int       `json:"servers"`
	Active     string    `json:"active,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	SwitchedAt time.Time `json:"switchedAt,omitempty"`
	Fetching   bool      `json:"fetching,omitempty"`
	Error      string    `json:"error,omitempty"`
}

func nextUpdate(from time.Time) time.Time {
	return from.Add(failover.Jitter(subEvery, subJitter, subRand()))
}

// openSub decrypts a stored subscription.
func openSub(p config.Proxy, now time.Time) *subGroup {
	g := &subGroup{sealed: p.Sub.Sealed}
	sec, err := subs.Open(p.Sub.Sealed)
	if err != nil {
		g.openErr = "Подписка: " + err.Error()
		g.fo = failover.New(0, now, failover.Defaults, subRand)
		g.nextFetch = now.Add(100 * 365 * 24 * time.Hour)
		return g
	}
	g.url = sec.URL
	g.entries = subs.Entries(sec.Links)
	g.fo = failover.New(len(g.entries), now, failover.Defaults, subRand)
	g.nextFetch = nextUpdate(p.Sub.UpdatedAt)
	if p.Sub.UpdatedAt.IsZero() || g.nextFetch.Before(now.Add(subFirst)) {
		// Due: give the tunnel a minute to come up, so the update can go
		// through it.
		g.nextFetch = now.Add(subFirst)
	}
	return g
}

// syncSubsLocked matches the run-time groups to cfg: new or re-sealed
// subscriptions are opened, removed ones dropped. Callers hold c.mu.
func (c *controller) syncSubsLocked(cfg *config.Config, now time.Time) {
	if c.subs == nil {
		c.subs = map[string]*subGroup{}
	}
	seen := map[string]bool{}
	for _, p := range cfg.Proxies {
		if p.Sub == nil {
			continue
		}
		seen[p.Name] = true
		if g := c.subs[p.Name]; g != nil && g.sealed == p.Sub.Sealed {
			continue
		}
		c.subs[p.Name] = openSub(p, now)
	}
	for name := range c.subs {
		if !seen[name] {
			delete(c.subs, name)
		}
	}
}

// materializeLocked fills each subscription proxy of cfg (a copy) with its
// active server. One without servers stays empty: it gets no bridge, and
// its apps are refused, never sent direct. Callers hold c.mu.
func (c *controller) materializeLocked(cfg *config.Config) *config.Config {
	for i, p := range cfg.Proxies {
		if p.Sub == nil {
			continue
		}
		cfg.Proxies[i].VLESS, cfg.Proxies[i].Address = nil, ""
		if g := c.subs[p.Name]; g != nil && len(g.entries) > 0 {
			e := g.entries[g.fo.Active]
			params := e.Params
			cfg.Proxies[i].VLESS, cfg.Proxies[i].Address = &params, e.Address
		}
	}
	return cfg
}

// runtimeCfg is the config the engine and bridges get.
func (c *controller) runtimeCfg() *config.Config {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.materializeLocked(cloneCfg(c.cfg))
}

// keepSubs copies the server's own subscription state into a config the
// window sent: the window's copy may predate an update.
func keepSubs(next, old *config.Config) {
	if next == nil || old == nil {
		return
	}
	for i, p := range next.Proxies {
		if p.Sub == nil {
			continue
		}
		if o, ok := old.ProxyByName(p.Name); ok && o.Sub != nil {
			s := *o.Sub
			next.Proxies[i].Sub = &s
		}
	}
}

// applySubs moves bridges and capture to the current active servers.
// Existing connections on a replaced server end; new ones use the new
// server. Nothing goes direct meanwhile.
func (c *controller) applySubs() {
	cfg := c.runtimeCfg()
	c.mu.Lock()
	sess := c.sess
	running := sess != nil && sess.Running()
	c.mu.Unlock()
	_ = c.syncBridges(cfg)
	if running {
		_ = sess.Apply(cfg)
	}
}

func (c *controller) subLog(name, status, msg string) {
	if c.logs != nil {
		c.logs.Add(logbuf.Event{Process: "ashgate", Via: name, Status: status, Error: msg})
	}
}

// subsLoop runs updates, health checks and primary probes when due.
func (c *controller) subsLoop() {
	t := time.NewTicker(subTick)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			c.subsTick(time.Now())
		}
	}
}

func (c *controller) subsTick(now time.Time) {
	var fetch string
	var checks, probes []string
	c.mu.Lock()
	running := c.sess != nil && c.sess.Running()
	for name, g := range c.subs {
		if fetch == "" && !c.subFetching && g.url != "" && !now.Before(g.nextFetch) {
			fetch = name
			c.subFetching, c.subFetchName = true, name
		}
		// Health checks only while capture runs: otherwise nothing uses
		// the tunnel and the checks would be a pattern of their own.
		if !running || len(g.entries) == 0 {
			continue
		}
		if !g.checking && g.fo.CheckDue(now) {
			g.checking = true
			checks = append(checks, name)
		}
		if !g.probing && g.fo.ProbeDue(now) {
			g.probing = true
			probes = append(probes, name)
		}
	}
	c.mu.Unlock()
	if fetch != "" {
		go func() { _ = c.fetchSub(fetch) }()
	}
	for _, name := range checks {
		go c.healthCheck(name)
	}
	for _, name := range probes {
		go c.probePrimary(name)
	}
}

// refreshSub is the «Обновить» button.
func (c *controller) refreshSub(name string) error {
	c.mu.Lock()
	if c.subFetching {
		c.mu.Unlock()
		return errors.New("Подписка уже обновляется, подождите минуту")
	}
	if c.subs[name] == nil {
		c.mu.Unlock()
		return errors.New("подписка не найдена")
	}
	c.subFetching, c.subFetchName = true, name
	c.mu.Unlock()
	return c.fetchSub(name)
}

// fetchSub updates one subscription. The caller has set subFetching.
// Through the tunnel when it is up, otherwise directly, once, with a 15 s
// limit. A failure keeps the old list.
func (c *controller) fetchSub(name string) error {
	defer func() {
		c.mu.Lock()
		c.subFetching = false
		c.mu.Unlock()
	}()
	c.mu.Lock()
	g := c.subs[name]
	if g == nil || g.url == "" {
		c.mu.Unlock()
		return errors.New("подписка не найдена")
	}
	url := g.url
	st := c.bridgeSt[name]
	// "Up" means proven: capture runs and the last check through this
	// tunnel answered. Otherwise one direct try.
	running := c.sess != nil && c.sess.Running()
	viaTunnel := running && st.Up && st.SOCKS != "" && g.fo.Verified()
	c.mu.Unlock()

	client, timeout := directClient(), subDirectTimeout
	if viaTunnel {
		client, timeout = tunnelClient(st), subTunnelTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	entries, err := subs.Fetch(ctx, client, url)
	now := time.Now()
	if err != nil {
		c.subFailed(name, err, now)
		return errors.New("Подписка не обновилась: " + err.Error())
	}
	return c.subApply(name, url, entries, now)
}

func directClient() *http.Client {
	return &http.Client{Transport: &http.Transport{Proxy: nil, ForceAttemptHTTP2: true}}
}

// tunnelClient sends requests through a bridge's private inbound. Host
// names travel to the VLESS server, so nothing is resolved locally.
func tunnelClient(st vless.Status) *http.Client {
	via := config.Proxy{Address: st.SOCKS, Username: st.User, Password: st.Pass}
	return &http.Client{Transport: &http.Transport{
		Proxy:             nil,
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			host, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			port, _ := strconv.Atoi(portStr)
			return socks5.Dial(ctx, via, host, uint16(port))
		},
	}}
}

// subApply adopts a fetched list. The active server stays while its link
// is in the list; otherwise the best server by priority takes over.
func (c *controller) subApply(name, url string, fresh []subs.Entry, now time.Time) error {
	sealed, err := subs.Seal(subs.Secret{URL: url, Links: subs.Links(subs.Order(fresh))})
	if err != nil {
		c.subFailed(name, err, now)
		return err
	}
	c.saveMu.Lock()
	defer c.saveMu.Unlock()
	c.mu.Lock()
	g := c.subs[name]
	idx := -1
	for i, p := range c.cfg.Proxies {
		if p.Name == name && p.Sub != nil {
			idx = i
		}
	}
	if g == nil || idx < 0 {
		c.mu.Unlock()
		return nil // removed meanwhile
	}
	activeLink := ""
	if len(g.entries) > 0 {
		activeLink = g.entries[g.fo.Active].Link
	}
	ordered, active, reconnect := subs.Apply(fresh, activeLink)
	reason := ""
	if reconnect && activeLink != "" {
		reason = "Подписка обновлена, прежнего сервера в ней нет → " + ordered[active].Label()
	}
	g.entries, g.sealed, g.retried = ordered, sealed, false
	g.fo.Reset(len(ordered), active, now, reason != "", reason)
	g.nextFetch = nextUpdate(now)
	cfg := cloneCfg(c.cfg)
	s := *cfg.Proxies[idx].Sub
	s.Sealed, s.Count, s.UpdatedAt, s.CheckedAt, s.Error = sealed, len(ordered), now, now, ""
	cfg.Proxies[idx].Sub = &s
	c.mu.Unlock()
	if err := config.Save(c.path, cfg); err != nil {
		return err
	}
	c.mu.Lock()
	c.cfg = cfg
	c.mu.Unlock()
	c.subLog(name, "info", "Подписка обновлена: серверов "+strconv.Itoa(len(ordered)))
	if reconnect {
		c.applySubs()
	}
	return nil
}

// subFailed records a failed update: one retry after 30 minutes, then the
// next scheduled update. The old list stays.
func (c *controller) subFailed(name string, err error, now time.Time) {
	c.saveMu.Lock()
	defer c.saveMu.Unlock()
	c.mu.Lock()
	g := c.subs[name]
	idx := -1
	for i, p := range c.cfg.Proxies {
		if p.Name == name && p.Sub != nil {
			idx = i
		}
	}
	if g == nil || idx < 0 {
		c.mu.Unlock()
		return
	}
	if !g.retried {
		g.nextFetch, g.retried = now.Add(subRetry), true
	} else {
		g.nextFetch, g.retried = nextUpdate(now), false
	}
	cfg := cloneCfg(c.cfg)
	s := *cfg.Proxies[idx].Sub
	s.CheckedAt, s.Error = now, err.Error()
	cfg.Proxies[idx].Sub = &s
	c.mu.Unlock()
	if config.Save(c.path, cfg) == nil {
		c.mu.Lock()
		c.cfg = cfg
		c.mu.Unlock()
	}
	c.subLog(name, "error", "Подписка не обновилась: "+err.Error()+". Остаётся прежний список")
}

// healthCheck asks generate_204 through the active server's tunnel and
// switches servers when the failover rules say so.
func (c *controller) healthCheck(name string) {
	c.mu.Lock()
	g := c.subs[name]
	st := c.bridgeSt[name]
	c.mu.Unlock()
	res := failover.Failed
	if st.Up && st.SOCKS != "" {
		res = checkTunnel(context.Background(), st.SOCKS, st.User, st.Pass)
	}
	c.mu.Lock()
	if g == nil || c.subs[name] != g {
		c.mu.Unlock()
		return
	}
	g.checking = false
	switched := g.fo.Check(time.Now(), res, g.label)
	reason := g.fo.Reason
	c.mu.Unlock()
	if switched {
		c.subLog(name, "error", "Переключение сервера: "+reason)
		c.applySubs()
	}
}

// probePrimary checks the primary server through a short-lived tunnel of
// its own while a backup carries traffic. The fingerprint and SNI are the
// primary's own, as always.
func (c *controller) probePrimary(name string) {
	c.mu.Lock()
	g := c.subs[name]
	var e subs.Entry
	if g != nil && len(g.entries) > 0 {
		e = g.entries[0]
	}
	c.mu.Unlock()
	ok := false
	if e.Link != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 2*freezeAfter)
		if br, err := vless.Listen(ctx, e.Address, e.Params, vless.Inbound{}); err == nil {
			ok = checkTunnel(ctx, br.Addr, br.User, br.Pass) == failover.OK
			br.Close()
		}
		cancel()
	}
	c.mu.Lock()
	if g == nil || c.subs[name] != g {
		c.mu.Unlock()
		return
	}
	g.probing = false
	back := g.fo.Probe(time.Now(), ok, g.label)
	reason := g.fo.Reason
	c.mu.Unlock()
	if back {
		c.subLog(name, "info", "Переключение сервера: "+reason)
		c.applySubs()
	}
}

func (g *subGroup) label(i int) string {
	if i < 0 || i >= len(g.entries) {
		return "сервер"
	}
	return g.entries[i].Label()
}

// checkTunnel requests generate_204 through a bridge's private inbound.
// The request reaches the target only through the VLESS server. No answer
// within freezeAfter of sending it is a freeze.
func checkTunnel(ctx context.Context, addr, user, pass string) failover.Result {
	ctx, cancel := context.WithTimeout(ctx, freezeAfter+5*time.Second)
	defer cancel()
	conn, err := socks5.Dial(ctx, config.Proxy{Address: addr, Username: user, Password: pass}, healthHost, healthPort)
	if err != nil {
		return failover.Failed
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(freezeAfter))
	req := "GET /generate_204 HTTP/1.1\r\nHost: " + healthHost + "\r\nUser-Agent: " + browserUA +
		"\r\nAccept: */*\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return failover.Failed
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return failover.Frozen
		}
		return failover.Failed
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return failover.Failed
	}
	return failover.OK
}

// addSub fetches a new subscription (directly: it has no tunnel yet) and
// adds it as a proxy. Nothing is added when the fetch fails.
func (c *controller) addSub(name, rawURL string) error {
	name, rawURL = strings.TrimSpace(name), strings.TrimSpace(rawURL)
	if err := subs.CheckURL(rawURL); err != nil {
		return err
	}
	c.mu.Lock()
	if _, ok := c.cfg.ProxyByName(name); ok {
		c.mu.Unlock()
		return errors.New("Имя прокси уже занято.")
	}
	if c.subFetching {
		c.mu.Unlock()
		return errors.New("Подписка уже обновляется, подождите минуту")
	}
	c.subFetching, c.subFetchName = true, name
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.subFetching = false
		c.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), subDirectTimeout)
	defer cancel()
	entries, err := subs.Fetch(ctx, directClient(), rawURL)
	if err != nil {
		return errors.New("Подписка не загрузилась: " + err.Error())
	}
	ordered := subs.Order(entries)
	sealed, err := subs.Seal(subs.Secret{URL: rawURL, Links: subs.Links(ordered)})
	if err != nil {
		return err
	}
	now := time.Now()
	cfg := cloneCfg(c.cfg)
	cfg.Proxies = append(cfg.Proxies, config.Proxy{
		Name: name, Type: "vless",
		Sub: &config.Subscription{Sealed: sealed, Count: len(ordered), Host: subs.Mask(rawURL), UpdatedAt: now, CheckedAt: now},
	})
	if err := c.replace(cfg); err != nil {
		return err
	}
	c.subLog(name, "info", "Подписка добавлена: серверов "+strconv.Itoa(len(ordered)))
	return nil
}

// subViewsLocked describes every subscription for the window.
func (c *controller) subViewsLocked() map[string]subView {
	out := map[string]subView{}
	for name, g := range c.subs {
		v := subView{Servers: len(g.entries), Reason: g.fo.Reason, SwitchedAt: g.fo.SwitchedAt, Error: g.openErr}
		if len(g.entries) > 0 {
			v.Active = g.label(g.fo.Active)
		}
		out[name] = v
	}
	if v, ok := out[c.subFetchName]; ok && c.subFetching {
		v.Fetching = true
		out[c.subFetchName] = v
	}
	return out
}
