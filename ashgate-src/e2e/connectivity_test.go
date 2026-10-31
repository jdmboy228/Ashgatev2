//go:build windows && e2e

package e2e

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"ashgate/e2e/harness"
	"ashgate/internal/config"
)

// activeLog records every change of the subscription's active server.
type activeLog struct {
	mu   sync.Mutex
	hist []activeChange
	stop chan struct{}
	done chan struct{}
}

type activeChange struct {
	At     time.Time
	Active string
	Reason string
}

func watchActive(a *harness.App) *activeLog {
	l := &activeLog{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(l.done)
		last := ""
		for {
			if s, err := a.State(); err == nil {
				v := s.Subs[harness.SubName]
				if v.Active != last {
					l.mu.Lock()
					l.hist = append(l.hist, activeChange{time.Now(), v.Active, v.Reason})
					l.mu.Unlock()
					last = v.Active
				}
			}
			select {
			case <-l.stop:
				return
			case <-time.After(time.Second):
			}
		}
	}()
	return l
}

func (l *activeLog) Stop() []activeChange {
	close(l.stop)
	<-l.done
	return l.History()
}

func (l *activeLog) History() []activeChange {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]activeChange(nil), l.hist...)
}

func (l *activeLog) waitFor(transport string, timeout time.Duration) (time.Time, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		h := l.History()
		if len(h) > 0 && strings.Contains(h[len(h)-1].Active, transport) {
			return h[len(h)-1].At, nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return time.Time{}, fmt.Errorf("active server never became %s within %s: %v", transport, timeout, l.History())
}

// transfer runs the throughput set through whatever server is active and
// checks the test server saw it on inbound.
func transfer(t *testing.T, env *harness.Env, s *harness.Session, label, inbound string) {
	t.Helper()
	since := time.Now()
	url := harness.URL(harness.TargetTCP)
	down := harness.RunClient(s.Client, "get", "-url", url, "-n", fmt.Sprint(16<<20), "-seed", label+"-down", "-stall", "10s")
	up := harness.RunClient(s.Client, "put", "-url", url, "-n", fmt.Sprint(16<<20), "-seed", label+"-up")
	par := harness.RunClient(s.Client, "par", "-url", url, "-n", fmt.Sprint(4<<20), "-streams", "8", "-seed", label+"-par", "-stall", "10s")
	for name, r := range map[string]harness.ClientResult{"16 MB download": down, "16 MB upload": up, "8×4 MB parallel": par} {
		if !r.OK {
			t.Errorf("%s %s: %s", label, name, r)
		}
		if r.Stalls > 0 {
			t.Errorf("%s %s stalled (longest gap %.1fs)", label, name, r.MaxGapS)
		}
	}
	env.Metric("throughput."+label+".down_MBps", down.MBps, "MB/s", "higher")
	env.Metric("throughput."+label+".up_MBps", up.MBps, "MB/s", "higher")
	env.Metric("throughput."+label+".parallel_MBps", par.MBps, "MB/s", "higher")
	var on []string
	for _, a := range s.Fx.AccessSince(since, harness.TargetTCP) {
		on = append(on, a.Inbound)
	}
	if len(on) == 0 {
		t.Errorf("%s: the test server saw no connection", label)
	}
	for _, in := range on {
		if in != inbound {
			t.Errorf("%s: traffic went through %s, want %s", label, in, inbound)
			break
		}
	}
}

// TestConnectivity is the connectivity job: subscription import, XHTTP as
// primary and RAW as backup, throughput, failover, SOCKS5 and HTTP.
func TestConnectivity(t *testing.T) {
	env := harness.LoadEnv(t)
	harness.EnsureQuit(env.Exe)
	socksApp := env.ClientExe(t, harness.ClientSOCKS)
	httpApp := env.ClientExe(t, harness.ClientHTTP)
	s := harness.NewSession(t, harness.SessionOpts{})
	a := s.App
	act := watchActive(a)
	defer act.Stop()

	t.Run("SubscriptionImport", func(t *testing.T) {
		st := a.MustState()
		v := st.Subs[harness.SubName]
		if v.Servers != 2 {
			t.Errorf("subscription lists %d servers, want 2", v.Servers)
		}
		if !strings.Contains(v.Active, "XHTTP") {
			t.Errorf("active server %q, want the XHTTP one as primary (the subscription lists RAW first)", v.Active)
		}
		if v.Error != "" {
			t.Errorf("subscription error: %s", v.Error)
		}
		var p *config.Proxy
		for i := range st.Config.Proxies {
			if st.Config.Proxies[i].Name == harness.SubName {
				p = &st.Config.Proxies[i]
			}
		}
		if p == nil || p.Sub == nil || p.Sub.Count != 2 {
			t.Errorf("config proxy for the subscription: %+v", p)
		}
	})

	t.Run("ThroughputXHTTP", func(t *testing.T) { transfer(t, env, s, "xhttp", "in-xhttp") })

	t.Run("FailoverToRAW", func(t *testing.T) {
		c, err := harness.StartCapture(env, "failover")
		if err != nil {
			t.Fatal(err)
		}
		// A censor: the XHTTP port accepts but nothing comes back.
		s.Fx.XHTTP.Set(harness.GateBlackhole)
		blocked := time.Now()
		stopProbe := make(chan struct{})
		var probes []harness.ClientResult
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopProbe:
					return
				case <-time.After(5 * time.Second):
				}
				probes = append(probes, harness.RunClient(s.Client, "tcp", "-addr", harness.TargetTCP, "-timeout", "3s"))
			}
		}()
		at, err := act.waitFor("RAW", 150*time.Second)
		close(stopProbe)
		wg.Wait()
		pkts, _ := c.Stop()
		if err != nil {
			t.Fatalf("no failover: %v", err)
		}
		d := at.Sub(blocked)
		env.Metric("failover.to_raw_seconds", d.Seconds(), "s", "lower")
		if d > 120*time.Second {
			t.Errorf("switched to RAW after %s, want ≤ 120 s (check every 60 s ±20 %% + 15 s freeze)", d.Round(time.Second))
		}
		if leak := harness.Filter(pkts, harness.ToTestNet()); len(leak) > 0 {
			t.Errorf("direct packets during the failover:%s", harness.Brief(leak, 10))
		}
		t.Logf("%d connection attempts during the outage", len(probes))
	})

	t.Run("ThroughputRAW", func(t *testing.T) { transfer(t, env, s, "raw", "in-raw") })

	if env.Long {
		t.Run("ReturnToXHTTP", func(t *testing.T) {
			s.Fx.XHTTP.Set(harness.GatePass)
			open := time.Now()
			at, err := act.waitFor("XHTTP", 22*time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			env.Metric("failover.return_seconds", at.Sub(open).Seconds(), "s", "lower")
			if r := harness.RunClient(s.Client, "get", "-url", harness.URL(harness.TargetTCP), "-n", "2000000"); !r.OK {
				t.Errorf("after returning to XHTTP: %s", r)
			}
		})
		t.Run("NoFlapping", func(t *testing.T) {
			h := act.History()
			env.WriteJSON("connectivity/active-history.json", h)
			// XHTTP at start, RAW after the block, XHTTP after two good probes.
			if len(h) != 3 {
				t.Errorf("active server changed %d times, want exactly 2 switches: %+v", len(h)-1, h)
			}
		})
	} else {
		env.Note("skipped", "connectivity: return to XHTTP after 2 good probes (≈20 min): nightly and workflow_dispatch only")
		s.Fx.XHTTP.Set(harness.GatePass)
	}

	t.Run("RefusedPortSwitches", func(t *testing.T) {
		// Whichever is active now gets its port refused (RST): two failed
		// checks in a row must move to the other one.
		from, to, gate := "RAW", "XHTTP", s.Fx.RAW
		if strings.Contains(harness.ActiveServer(a), "XHTTP") {
			from, to, gate = "XHTTP", "RAW", s.Fx.XHTTP
		}
		gate.Set(harness.GateRefuse)
		defer gate.Set(harness.GatePass)
		refused := time.Now()
		at, err := act.waitFor(to, 180*time.Second)
		if err != nil {
			t.Fatalf("refused %s port: %v", from, err)
		}
		env.Metric("failover.refused_seconds", at.Sub(refused).Seconds(), "s", "lower")
		if r := harness.RunClient(s.Client, "get", "-url", harness.URL(harness.TargetTCP), "-n", "2000000"); !r.OK {
			t.Errorf("after switching to %s: %s", to, r)
		}
	})

	t.Run("SOCKS5AndHTTPPerApp", func(t *testing.T) {
		err := a.UpdateConfig(func(c *config.Config) {
			c.Proxies = append(c.Proxies,
				config.Proxy{Name: "e2e-socks", Type: "socks5", Address: s.Fx.SOCKS.Addr, Username: s.Fx.ProxyUser, Password: s.Fx.ProxyPass},
				config.Proxy{Name: "e2e-http", Type: "http", Address: s.Fx.HTTP.Addr, Username: s.Fx.ProxyUser, Password: s.Fx.ProxyPass})
			on := true
			c.Rules = append(c.Rules,
				config.Rule{Enabled: &on, Process: socksApp, Action: "proxy", Proxy: "e2e-socks"},
				config.Rule{Enabled: &on, Process: httpApp, Action: "proxy", Proxy: "e2e-http"})
		})
		if err != nil {
			t.Fatalf("add SOCKS5/HTTP proxies: %v", err)
		}
		time.Sleep(2 * time.Second)
		c, err := harness.StartCapture(env, "socks-http")
		if err != nil {
			t.Fatal(err)
		}
		url := harness.URL(harness.TargetTCP)
		res := map[string]harness.ClientResult{
			"socks get":  harness.RunClient(socksApp, "get", "-url", url, "-n", fmt.Sprint(4<<20), "-seed", "socks"),
			"socks put":  harness.RunClient(socksApp, "put", "-url", url, "-n", fmt.Sprint(4<<20), "-seed", "socks-up"),
			"socks udp":  harness.RunClient(socksApp, "udp", "-addr", harness.TargetUDP),
			"http get":   harness.RunClient(httpApp, "get", "-url", url, "-n", fmt.Sprint(4<<20), "-seed", "http"),
			"http put":   harness.RunClient(httpApp, "put", "-url", url, "-n", fmt.Sprint(4<<20), "-seed", "http-up"),
			"http dnstc": harness.RunClient(httpApp, "dns", "-server", "1.1.1.1:53", "-name", "x.e2e-http.example"),
		}
		httpUDP := harness.RunClient(httpApp, "udp", "-addr", harness.TargetUDP, "-timeout", "4s")
		pkts, _ := c.Stop()
		for name, r := range res {
			if !r.OK {
				t.Errorf("%s: %s", name, r)
			}
		}
		if httpUDP.OK {
			t.Errorf("UDP of an app on an HTTP proxy got an answer: it must be blocked (udpUnsupported: block)")
		}
		if leak := harness.Filter(pkts, harness.ToTestNet()); len(leak) > 0 {
			t.Errorf("direct packets of SOCKS5/HTTP apps:%s", harness.Brief(leak, 10))
		}
		ev := a.MustState().Events
		for _, e := range ev {
			if strings.HasPrefix(e.Process, harness.ClientSOCKS) && e.Via != "" && e.Via != "e2e-socks" {
				t.Errorf("%s went via %s", e.Process, e.Via)
			}
			if strings.HasPrefix(e.Process, harness.ClientHTTP) && e.Via != "" && e.Via != "e2e-http" {
				t.Errorf("%s went via %s", e.Process, e.Via)
			}
		}
	})

	if h := act.History(); len(h) > 0 {
		env.WriteJSON("connectivity/active-history.json", h)
	}
}
