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

	"ashgate/internal/bootstrap"
	"ashgate/internal/config"
	"ashgate/internal/engine"
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
	// subTick is how often the loop looks at the traffic through the
	// active servers. It bounds how late a stall is noticed.
	subTick = 250 * time.Millisecond
	// probeTimeout bounds one probe of the primary: its own tunnel (the
	// server's name may need a DoH lookup) and one check through it.
	probeTimeout = 15 * time.Second
)

// checkTimeout is how long a check waits for its answer. With traffic
// already unanswered for failover.Config.SuspectAfter, a check that also
// gets nothing in this time means the server is gone. Tests shorten it.
var checkTimeout = 3500 * time.Millisecond

// healthHost answers generate_204; the check reaches it only through the
// tunnel (the VLESS server makes the request), never directly.
var healthHost, healthPort = "www.gstatic.com", uint16(80)

// browserUA is sent with the health check, like a browser would.
const browserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"

// subRand is the jitter source; tests replace it.
var subRand = rand.Float64

// tunnelSession is what the subscription loop reads from the capture
// session.
type tunnelSession interface {
	Running() bool
	RelayHealth(proxy string, since time.Time) engine.RelayHealth
	RuleStats() map[string]engine.RuleStat
}

// foHooks replaces, per controller, what the failover loop reads and runs.
// Only tests set them, before the first round they drive; nil fields mean
// the real thing. They are fields, not package variables: controllers of
// other tests keep running their loops.
type foHooks struct {
	session func() tunnelSession
	check   func(vless.Status) failover.Result
	probe   func(subs.Entry) bool
	route   func(addr string) bool
}

// tunnel is c's capture session or nil. Callers hold c.mu.
func (c *controller) tunnel() tunnelSession {
	if c.fo.session != nil {
		return c.fo.session()
	}
	if c.sess == nil {
		return nil
	}
	return c.sess
}

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
	// applying is set from a switch until the new server's tunnel is up.
	// Nothing is judged meanwhile.
	applying bool
	// sess is the capture session the group last saw running: a new one
	// counts its bytes from zero.
	sess tunnelSession
	// The byte counters of the rules that use this subscription, as last
	// seen, and what they show: silentSince and silentLast are the first
	// and the latest time bytes went up with none coming down since, and
	// silentBytes how many did; lastUp is when bytes last went up. counted
	// is false until the first reading of a session.
	counted                 bool
	up, down                int64
	silentSince, silentLast time.Time
	silentBytes             int64
	lastUp                  time.Time
}

// silentLimit is the most bytes sent into silence that still count as a
// sign of a dead server. A dead server takes what the buffers on the way
// hold and then nothing; megabytes that keep going up are an upload the
// server is reading, whose answer comes when it ends.
const silentLimit = 256 << 10

// forget drops what the byte counters showed: capture restarted, or
// another server took over.
func (g *subGroup) forget() {
	g.counted = false
	g.silentSince, g.silentLast, g.silentBytes = time.Time{}, time.Time{}, 0
}

// traffic takes a reading of the byte counters.
func (g *subGroup) traffic(now time.Time, up, down int64) {
	if !g.counted || up < g.up || down < g.down {
		g.counted, g.up, g.down = true, up, down
		g.silentSince, g.silentLast, g.silentBytes = time.Time{}, time.Time{}, 0
		return
	}
	switch {
	case down > g.down:
		g.silentSince, g.silentLast, g.silentBytes = time.Time{}, time.Time{}, 0
	case up > g.up:
		if g.silentSince.IsZero() {
			g.silentSince = now
		}
		g.silentLast = now
		g.silentBytes += up - g.up
	}
	if up > g.up {
		g.lastUp = now
	}
	g.up, g.down = up, down
}

// evidence is what the traffic through the active server shows at now: the
// engine's TCP relays (h) and the byte counters of the subscription's
// rules, which also cover UDP and requests on connections already open.
func (g *subGroup) evidence(now time.Time, h engine.RelayHealth, up, down int64) failover.Evidence {
	g.traffic(now, up, down)
	ev := failover.Evidence{LastDead: h.LastDead, LastGood: h.LastGood, LastUse: h.LastAsk}
	if g.silentBytes <= silentLimit {
		ev.SilentSince, ev.SilentLast = g.silentSince, g.silentLast
	}
	if h.Waiting > 0 {
		ev.WaitingSince = h.WaitingSince
	}
	if g.lastUp.After(ev.LastUse) {
		ev.LastUse = g.lastUp
	}
	return ev
}

// ruleBytes sums the bytes of the enabled rules that send programs through
// the proxy named name.
func ruleBytes(cfg *config.Config, name string, stats map[string]engine.RuleStat) (up, down int64) {
	for _, r := range cfg.EffectiveRules() {
		if !r.IsEnabled() || r.Action != "proxy" || r.Proxy != name {
			continue
		}
		s := stats[engine.RuleKey(r.Process)]
		up += s.Up
		down += s.Down
	}
	return up, down
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

// subsLoop runs updates, and watches the traffic through the active
// servers for the checks and probes it calls for.
func (c *controller) subsLoop() {
	defer close(c.loopDone)
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
	sess := c.tunnel()
	running := sess != nil && sess.Running()
	var stats map[string]engine.RuleStat
	for name, g := range c.subs {
		if fetch == "" && !c.subFetching && g.url != "" && !now.Before(g.nextFetch) {
			fetch = name
			c.subFetching, c.subFetchName = true, name
		}
		// Only while capture runs: otherwise nothing uses the tunnel, and
		// there is no traffic to judge the server by.
		if !running || len(g.entries) == 0 {
			g.sess = nil
			continue
		}
		if g.sess != sess {
			// A new capture session counts its bytes from zero.
			g.sess = sess
			g.forget()
		}
		if g.applying {
			continue
		}
		if stats == nil {
			stats = sess.RuleStats()
		}
		up, down := ruleBytes(c.cfg, name, stats)
		ev := g.evidence(now, sess.RelayHealth(name, g.fo.Since()), up, down)
		if !g.checking && g.fo.Observe(now, ev) {
			g.checking = true
			g.fo.Begin(now)
			checks = append(checks, name)
		}
		if !g.checking && !g.probing && g.fo.ProbeDue(now) {
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
	c.mu.Unlock()
	// Through the tunnel when it is proven to work, otherwise one direct
	// try.
	st, viaTunnel := c.provenTunnel(name, g)

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

// provenTunnel reports whether the subscription's tunnel is known to work
// right now, and its bridge: capture runs and the active server answered
// a moment ago. An idle tunnel has no such answer, so it gets one check
// first; a check or a switch already under way is waited for.
func (c *controller) provenTunnel(name string, g *subGroup) (vless.Status, bool) {
	deadline := time.Now().Add(2*checkTimeout + 2*time.Second)
	checked := false
	for {
		c.mu.Lock()
		st := c.bridgeSt[name]
		running := c.sess != nil && c.sess.Running()
		if c.subs[name] != g || !running || len(g.entries) == 0 {
			c.mu.Unlock()
			return st, false
		}
		up := st.Up && st.SOCKS != ""
		busy := g.checking || g.applying
		switch {
		case busy:
			c.mu.Unlock()
			if time.Now().After(deadline) {
				return st, false
			}
			time.Sleep(50 * time.Millisecond)
		case up && g.fo.Proven(time.Now()):
			c.mu.Unlock()
			return st, true
		case !up || checked:
			c.mu.Unlock()
			return st, false
		default:
			checked = true
			g.checking = true
			g.fo.BeginOwn(time.Now())
			c.mu.Unlock()
			c.healthCheck(name)
		}
	}
}

// directClient is the one direct try. The host is looked up with DoH, not
// the provider's DNS (the TLS name still shows it; the tunnel hides both).
func directClient() *http.Client {
	return &http.Client{Transport: &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, DialContext: bootstrap.Dial}}
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
		c.mu.Lock()
		g.applying = true
		c.mu.Unlock()
		c.switched(g)
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
// switches servers when the failover rules say so. The caller has set
// checking and told the group that the check begins.
func (c *controller) healthCheck(name string) {
	c.mu.Lock()
	g := c.subs[name]
	st := c.bridgeSt[name]
	server := ""
	if g != nil && g.fo.Active < len(g.entries) {
		server = g.entries[g.fo.Active].Address
	}
	c.mu.Unlock()
	check, route := checkBridge, hasRoute
	if c.fo.check != nil {
		check = c.fo.check
	}
	if c.fo.route != nil {
		route = c.fo.route
	}
	res := check(st)
	if res != failover.OK && !route(server) {
		res = failover.NoNetwork
	}
	c.mu.Lock()
	if g == nil || c.subs[name] != g {
		c.mu.Unlock()
		return
	}
	// Real traffic answered while the check ran outweighs the check.
	var good time.Time
	if sess := c.tunnel(); sess != nil && sess.Running() {
		good = sess.RelayHealth(name, g.fo.Since()).LastGood
	}
	switched := g.fo.Check(time.Now(), res, good, g.label)
	reason := g.fo.Reason
	g.checking, g.applying = false, switched
	c.mu.Unlock()
	if switched {
		c.subLog(name, "error", "Переключение сервера: "+reason)
		c.switched(g)
	}
}

// checkBridge checks the active server through its bridge; one that is not
// up has failed.
func checkBridge(st vless.Status) failover.Result {
	if !st.Up || st.SOCKS == "" {
		return failover.Failed
	}
	return checkTunnel(context.Background(), st.SOCKS, st.User, st.Pass)
}

// hasRoute reports whether this machine has a route to the server at addr
// (IP:port). It sends nothing: connecting a UDP socket only asks the
// routing table. With no route, a failed check means the machine's own
// network is down. An address that is a name, or anything else that
// cannot be asked, counts as reachable.
func hasRoute(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || net.ParseIP(host) == nil {
		return true
	}
	c, err := net.Dial("udp", addr)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// probeServer checks a server that carries no traffic through a tunnel of
// its own, made for this one check.
func probeServer(e subs.Entry) bool {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	br, err := vless.Listen(ctx, e.Address, e.Params, vless.Inbound{})
	if err != nil {
		return false
	}
	defer br.Close()
	return checkTunnel(ctx, br.Addr, br.User, br.Pass) == failover.OK
}

// switched moves bridges and capture to g's new active server, then lets
// the group judge it: what the traffic showed until now was the old
// server's, or the moment without a tunnel.
func (c *controller) switched(g *subGroup) {
	c.applySubs()
	c.mu.Lock()
	g.applying = false
	g.forget()
	g.fo.Ready(time.Now())
	c.mu.Unlock()
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
	probe := probeServer
	if c.fo.probe != nil {
		probe = c.fo.probe
	}
	ok := e.Link != "" && probe(e)
	c.mu.Lock()
	if g == nil || c.subs[name] != g {
		c.mu.Unlock()
		return
	}
	g.probing = false
	// While a check of the backup runs or a switch is under way, a good
	// probe does not count: the return waits for a calmer moment. A group
	// that is on the primary by now has nothing to return to.
	back := false
	if g.fo.Active != 0 {
		back = g.fo.Probe(time.Now(), ok && !g.checking && !g.applying, g.label)
	}
	reason := g.fo.Reason
	g.applying = g.applying || back
	c.mu.Unlock()
	if back {
		c.subLog(name, "info", "Переключение сервера: "+reason)
		c.switched(g)
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
// within checkTimeout is a freeze; an answer that is not the 204, or a
// connection that ends without one, is a failure. A header of random
// length keeps two checks from having the same size on the wire.
func checkTunnel(ctx context.Context, addr, user, pass string) failover.Result {
	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	// bad tells a check that ran out of time from one that was refused.
	bad := func(err error) failover.Result {
		var ne net.Error
		if ctx.Err() != nil || (errors.As(err, &ne) && ne.Timeout()) {
			return failover.Frozen
		}
		return failover.Failed
	}
	conn, err := socks5.Dial(ctx, config.Proxy{Address: addr, Username: user, Password: pass}, healthHost, healthPort)
	if err != nil {
		return bad(err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	pad := make([]byte, 4+rand.IntN(44))
	for i := range pad {
		pad[i] = "0123456789abcdef"[rand.IntN(16)]
	}
	req := "GET /generate_204 HTTP/1.1\r\nHost: " + healthHost + "\r\nUser-Agent: " + browserUA +
		"\r\nAccept: */*\r\nX-Request-Id: " + string(pad) + "\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return bad(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return bad(err)
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
	// Copy the config after the fetch and save it under saveMu: a copy
	// taken earlier, or a save in between, would undo what the window
	// saved meanwhile.
	c.saveMu.Lock()
	c.mu.Lock()
	if _, ok := c.cfg.ProxyByName(name); ok {
		c.mu.Unlock()
		c.saveMu.Unlock()
		return errors.New("Имя прокси уже занято.")
	}
	cfg := cloneCfg(c.cfg)
	c.mu.Unlock()
	cfg.Proxies = append(cfg.Proxies, config.Proxy{
		Name: name, Type: "vless",
		Sub: &config.Subscription{Sealed: sealed, Count: len(ordered), Host: subs.Mask(rawURL), UpdatedAt: now, CheckedAt: now},
	})
	err = c.replaceLocked(cfg)
	c.saveMu.Unlock()
	if err != nil {
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
