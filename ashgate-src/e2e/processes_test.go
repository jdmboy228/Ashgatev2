//go:build windows && e2e

package e2e

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ashgate/e2e/harness"
)

// TestProcesses is the processes job: what runs when, what is left after
// stop, quit and a crash.
func TestProcesses(t *testing.T) {
	env := harness.LoadEnv(t)
	harness.EnsureQuit(env.Exe)
	testStart := time.Now()

	t.Run("NoRemoteDebuggingByDefault", func(t *testing.T) {
		harness.WithoutDebugPolicy(func() { noRemoteDebugging(t, env) })
	})
	testProcessesSession(t, env, testStart)
}

func noRemoteDebugging(t *testing.T, env *harness.Env) {
	if harness.DebugPolicySet() {
		t.Fatalf("the WebView2 debugging policy is set during a normal launch")
	}
	a := harness.Launch(t, env, env.Exe, harness.LaunchOpts{NoDebug: true})
	defer a.Quit()
	var wv []harness.Proc
	err := harness.Eventually(45*time.Second, 500*time.Millisecond, func() error {
		if _, ok := harness.MainWindow(uint32(a.PID)); !ok {
			return errors.New("window not visible yet")
		}
		wv = webviews(uint32(a.PID))
		if len(wv) == 0 {
			return errors.New("no WebView2 processes yet")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Second)
	wv = webviews(uint32(a.PID))
	var pids []uint32
	for _, p := range wv {
		pids = append(pids, p.PID)
	}
	for _, s := range harness.SocketsOf(pids...) {
		if s.Proto == "tcp" && s.State == harness.TCPListen {
			t.Errorf("WebView2 process %d listens on %s:%d in a normal launch", s.PID, s.Local, s.LPort)
		}
	}
	lines, _ := harness.PS(`Get-CimInstance Win32_Process -Filter "Name='msedgewebview2.exe'" | ForEach-Object { $_.CommandLine }`)
	if strings.Contains(lines, "remote-debugging") {
		t.Errorf("a WebView2 process has remote debugging on its command line in a normal launch")
	}
	c := http.Client{Timeout: 2 * time.Second}
	if resp, err := c.Get(fmt.Sprintf("http://127.0.0.1:%d/json/version", harness.DebugPort)); err == nil {
		resp.Body.Close()
		t.Errorf("remote debugging answers on port %d in a normal launch", harness.DebugPort)
	}
}

func testProcessesSession(t *testing.T, env *harness.Env, testStart time.Time) {
	s := harness.NewSession(t, harness.SessionOpts{NoCapture: true})
	a := s.App
	pid := uint32(a.PID)

	t.Run("Launch", func(t *testing.T) {
		if _, ok := harness.MainWindow(pid); !ok {
			t.Errorf("no visible Ashgate window")
		}
		for _, sk := range harness.SocketsOf(pid) {
			if sk.State == harness.TCPListen && !sk.Local.IsLoopback() {
				t.Errorf("ashgate.exe listens on %s:%d (not loopback)", sk.Local, sk.LPort)
			}
		}
		if st := harness.ServiceState("WinDivert"); st == "RUNNING" {
			t.Errorf("WinDivert is loaded before Start")
		}
		st := a.MustState()
		if b, ok := st.Bridges[harness.SubName]; !ok || !b.Up {
			t.Errorf("subscription bridge not up: %+v", b)
		}
	})

	t.Run("Start", func(t *testing.T) {
		if err := a.StartCapture(); err != nil {
			t.Fatalf("start: %v (WinDivert on this runner: %s)", err, harness.ServiceState("WinDivert"))
		}
		if st := harness.ServiceState("WinDivert"); st != "RUNNING" {
			t.Errorf("WinDivert service %q after Start", st)
		}
		want := map[string]bool{"127.0.0.1:34010": false, "[::1]:34010": false}
		for _, sk := range harness.SocketsOf(pid) {
			if sk.Proto == "tcp" && sk.State == harness.TCPListen && sk.LPort == 34010 {
				want[net.JoinHostPort(sk.Local.String(), "34010")] = true
			}
		}
		for k, ok := range want {
			if !ok {
				t.Errorf("relay %s not listening", k)
			}
		}
		if g := guards(pid); len(g) != 1 {
			t.Errorf("%d kill-switch guard processes, want 1", len(g))
		}
		hit := harness.WaitTunnelHealthy(t, s.Fx, a.Started, 150*time.Second)
		if hit.Origin != harness.OriginTunnel {
			t.Errorf("health check came from %s, want the tunnel", hit.Origin)
		}
	})

	t.Run("OnlyMatchingApps", func(t *testing.T) {
		c, err := harness.StartCapture(env, "only-matching")
		if err != nil {
			t.Fatalf("pktmon: %v", err)
		}
		since := time.Now()
		r := harness.RunClient(s.Client, "get", "-url", harness.URL(harness.TargetTCP), "-n", "2000000")
		d := harness.RunClient(s.Direct, "tcp", "-addr", harness.ControlIP, "-timeout", "4s")
		pkts, err := c.Stop()
		if err != nil {
			t.Fatal(err)
		}
		if !r.OK {
			t.Errorf("proxied client: %s", r)
		}
		if d.OK {
			t.Errorf("the app without a rule reached %s: it must have been proxied", harness.ControlIP)
		}
		ctl := harness.Filter(pkts, func(p harness.Packet) bool { return p.Dst == strings.Split(harness.ControlIP, ":")[0] && p.SYN })
		if len(ctl) == 0 {
			t.Fatalf("pktmon did not see the direct app's SYN to %s: packet capture cannot prove leaks on this runner", harness.ControlIP)
		}
		if leak := harness.Filter(pkts, harness.ToTestNet(strings.Split(harness.ControlIP, ":")[0])); len(leak) > 0 {
			t.Errorf("proxied traffic on the network card:%s", harness.Brief(leak, 10))
		}
		if len(s.Fx.AccessSince(since, harness.TargetTCP)) == 0 {
			t.Errorf("the test server saw no tunnel connection to %s", harness.TargetTCP)
		}
		ev := a.MustState().Events
		if !hasEvent(ev, harness.ClientProxied) {
			t.Errorf("connection log has no %s row", harness.ClientProxied)
		}
		if hasEvent(ev, harness.ClientDirect) {
			t.Errorf("connection log lists %s although it has no rule", harness.ClientDirect)
		}
	})

	t.Run("Stop", func(t *testing.T) {
		if err := a.StopCapture(); err != nil {
			t.Fatal(err)
		}
		if err := waitDriverGone(15 * time.Second); err != nil {
			t.Errorf("after Stop: %v", err)
		}
		if !harness.PortFree("tcp4", "127.0.0.1:34010") || !harness.PortFree("tcp6", "[::1]:34010") {
			t.Errorf("relay port 34010 still held after Stop")
		}
		if err := waitKillRules(s.Client, 20*time.Second); err != nil {
			t.Errorf("kill switch after Stop: %v", err)
		}
		if g := guards(pid); len(g) != 0 {
			t.Errorf("guard still running after Stop: %v", g)
		}
	})

	t.Run("CrashRecovery", func(t *testing.T) {
		if err := a.StartCapture(); err != nil {
			t.Fatal(err)
		}
		if r := harness.RunClient(s.Client, "get", "-url", harness.URL(harness.TargetTCP), "-n", "500000"); !r.OK {
			t.Fatalf("before the crash: %s", r)
		}
		c, err := harness.StartCapture(env, "crash")
		if err != nil {
			t.Fatal(err)
		}
		a.Kill()
		crashAt := time.Now()
		ruleErr := waitKillRules(s.Client, 10*time.Second)
		ruleIn := time.Since(crashAt)
		var tries []harness.ClientResult
		for i := 0; i < 3; i++ {
			tries = append(tries, harness.RunClient(s.Client, "tcp", "-addr", harness.TargetTCP, "-timeout", "3s"))
		}
		pkts, _ := c.Stop()
		if ruleErr != nil {
			t.Errorf("after the crash the guard did not restore the firewall rules: %v", ruleErr)
		} else {
			env.Metric("crash.killswitch_restore_seconds", ruleIn.Seconds(), "s", "lower")
			if ruleIn > 5*time.Second {
				t.Errorf("firewall rules came back after %s, want ≤ 5 s", ruleIn.Round(100*time.Millisecond))
			}
		}
		for _, r := range tries {
			if r.OK {
				t.Errorf("the proxied app connected while Ashgate was dead")
			}
		}
		if leak := harness.Filter(pkts, harness.ToTestNet()); len(leak) > 0 {
			t.Errorf("packets left after the crash:%s", harness.Brief(leak, 10))
		}
		if err := waitDriverGone(20 * time.Second); err != nil {
			env.Note("finding", "after ashgate.exe was killed: "+err.Error())
			t.Errorf("after the crash: %v", err)
		}
		// Restart: capture comes back with Start, traffic flows.
		a = harness.Launch(t, env, env.Exe, harness.LaunchOpts{})
		s.App = a
		pid = uint32(a.PID)
		if err := a.StartCapture(); err != nil {
			t.Fatalf("restart after crash: %v", err)
		}
		if r := harness.RunClient(s.Client, "get", "-url", harness.URL(harness.TargetTCP), "-n", "500000"); !r.OK {
			t.Errorf("after restart: %s", r)
		}
	})

	t.Run("ServerStall", func(t *testing.T) {
		// Xray runs inside ashgate.exe, so there is no xray.exe to kill.
		// What the app can lose is the server: cut both off.
		env.Note("info", "kill xray.exe: not applicable, Xray-core runs inside ashgate.exe; tested by killing ashgate.exe and by cutting the servers")
		before := a.MustState().Subs[harness.SubName]
		c, err := harness.StartCapture(env, "server-stall")
		if err != nil {
			t.Fatal(err)
		}
		s.Fx.XHTTP.Set(harness.GateBlackhole)
		s.Fx.RAW.Set(harness.GateBlackhole)
		stallAt := time.Now()
		r := harness.RunClient(s.Client, "get", "-url", harness.URL(harness.TargetTCP), "-n", "200000", "-stall", "8s")
		noticed := harness.Eventually(150*time.Second, time.Second, func() error {
			v := a.MustState().Subs[harness.SubName]
			if v.SwitchedAt.After(before.SwitchedAt) || (v.Reason != "" && v.Reason != before.Reason) {
				return nil
			}
			return errors.New("no switch or reason yet")
		})
		pkts, _ := c.Stop()
		if r.OK {
			t.Errorf("the client got data with both servers cut off")
		}
		if noticed != nil {
			t.Errorf("the health check did not notice the dead servers within 150 s")
		} else {
			env.Metric("stall.detect_seconds", time.Since(stallAt).Seconds(), "s", "lower")
		}
		if leak := harness.Filter(pkts, harness.ToTestNet()); len(leak) > 0 {
			t.Errorf("direct packets while the servers were down:%s", harness.Brief(leak, 10))
		}
		s.Fx.XHTTP.Set(harness.GatePass)
		s.Fx.RAW.Set(harness.GatePass)
		back := time.Now()
		err = harness.Eventually(5*time.Minute, 5*time.Second, func() error {
			if r := harness.RunClient(s.Client, "get", "-url", harness.URL(harness.TargetTCP), "-n", "200000", "-stall", "8s"); !r.OK {
				return errors.New(r.Error)
			}
			return nil
		})
		if err != nil {
			t.Errorf("traffic did not resume after the servers came back: %v", err)
		} else {
			env.Metric("stall.recover_seconds", time.Since(back).Seconds(), "s", "lower")
		}
	})

	t.Run("SafeNetworkChange", func(t *testing.T) {
		nic, err := harness.MainNIC()
		if err != nil {
			t.Fatal(err)
		}
		c, err := harness.StartCapture(env, "net-change")
		if err != nil {
			t.Fatal(err)
		}
		undo, err := harness.AddTestRoute(nic)
		if err != nil {
			t.Log(err)
		}
		time.Sleep(3 * time.Second)
		r1 := harness.RunClient(s.Client, "get", "-url", harness.URL(harness.TargetTCP), "-n", "500000")
		undo()
		undo6, err := harness.SetupFakeIPv6(nic)
		if err != nil {
			t.Log(err)
		}
		time.Sleep(2 * time.Second)
		r2 := harness.RunClient(s.Client, "get", "-url", harness.URL(harness.TargetTCP), "-n", "500000")
		undo6()
		time.Sleep(2 * time.Second)
		r3 := harness.RunClient(s.Client, "get", "-url", harness.URL(harness.TargetTCP), "-n", "500000")
		pkts, _ := c.Stop()
		for i, r := range []harness.ClientResult{r1, r2, r3} {
			if !r.OK {
				t.Errorf("after network change %d: %s", i+1, r)
			}
		}
		if !a.MustState().Running {
			t.Errorf("capture stopped after the network changes")
		}
		if leak := harness.Filter(pkts, harness.ToTestNet()); len(leak) > 0 {
			t.Errorf("leak during network changes:%s", harness.Brief(leak, 10))
		}
	})

	t.Run("Quit", func(t *testing.T) {
		var ports []harness.Sock
		for _, sk := range harness.SocketsOf(pid) {
			if sk.State == harness.TCPListen || sk.Proto == "udp" {
				ports = append(ports, sk)
			}
		}
		wv := webviews(pid)
		d := a.Quit()
		env.Metric("quit.seconds", d.Seconds(), "s", "lower")
		if d > 10*time.Second {
			t.Errorf("quit took %s, want ≤ 10 s", d.Round(100*time.Millisecond))
		}
		if pids := harness.PIDsByName("ashgate.exe"); len(pids) > 0 {
			t.Errorf("orphan ashgate.exe after quit: %v", pids)
		}
		err := harness.Eventually(15*time.Second, 500*time.Millisecond, func() error {
			for _, p := range wv {
				if harness.Alive(p.PID) {
					return fmt.Errorf("WebView2 process %d still alive", p.PID)
				}
			}
			return nil
		})
		if err != nil {
			t.Errorf("after quit: %v", err)
		}
		for _, sk := range ports {
			network := sk.Proto + "4"
			if sk.Local.To4() == nil {
				network = sk.Proto + "6"
			}
			if !harness.PortFree(network, net.JoinHostPort(sk.Local.String(), fmt.Sprint(sk.LPort))) {
				t.Errorf("%s %s:%d still taken after quit", sk.Proto, sk.Local, sk.LPort)
			}
		}
		if err := waitDriverGone(15 * time.Second); err != nil {
			t.Errorf("after quit: %v", err)
		}
		// Closed with a kill-switch rule: the firewall keeps the app off the net.
		if err := waitKillRules(s.Client, 5*time.Second); err != nil {
			t.Errorf("after quit: %v", err)
		}
	})

	t.Run("NoCrashes", func(t *testing.T) {
		logs := harness.AppLog()
		if errs, _ := filepath.Glob(env.Path("app", "stderr-*.log")); len(errs) > 0 {
			for _, f := range errs {
				b, _ := os.ReadFile(f)
				logs += string(b)
			}
		}
		for _, bad := range []string{"panic:", "fatal error:", "[signal "} {
			if strings.Contains(logs, bad) {
				t.Errorf("ashgate.log or the app's stderr contains %q", bad)
			}
		}
		ev, _ := harness.PS(fmt.Sprintf(`Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=[datetime]'%s'} -ErrorAction SilentlyContinue |`+
			` Where-Object { $_.ProviderName -in 'Application Error','Windows Error Reporting','.NET Runtime' -and $_.Message -match 'ashgate|msedgewebview2' } |`+
			` ForEach-Object { "$($_.TimeCreated) $($_.ProviderName) $($_.Id): $($_.Message -replace '\s+',' ')" }`, testStart.Format("2006-01-02T15:04:05")))
		if strings.TrimSpace(ev) != "" {
			_ = os.WriteFile(env.Path("processes", "app-errors.txt"), []byte(ev), 0o644)
			t.Errorf("Windows logged application errors:\n%s", ev)
		}
		if dumps, _ := filepath.Glob(filepath.Join(harness.DumpDir, "*.dmp")); len(dumps) > 0 {
			t.Errorf("crash dumps written: %v", dumps)
		}
	})
}

func webviews(pid uint32) []harness.Proc {
	var out []harness.Proc
	for _, p := range harness.Descendants(pid) {
		if strings.EqualFold(p.Name, "msedgewebview2.exe") {
			out = append(out, p)
		}
	}
	return out
}

func guards(pid uint32) []harness.Proc {
	var out []harness.Proc
	for _, p := range harness.Descendants(pid) {
		if strings.EqualFold(p.Name, "ashgate.exe") {
			out = append(out, p)
		}
	}
	return out
}

func hasEvent(ev []harness.Event, name string) bool {
	for _, e := range ev {
		if strings.EqualFold(strings.TrimSuffix(e.Process, ".exe"), name) {
			return true
		}
	}
	return false
}

func waitDriverGone(timeout time.Duration) error {
	return harness.Eventually(timeout, 500*time.Millisecond, func() error {
		if st := harness.ServiceState("WinDivert"); st != "" && st != "STOPPED" {
			return fmt.Errorf("WinDivert driver still %s (sc query WinDivert)", st)
		}
		if harness.DriverLoaded("WinDivert") {
			return errors.New("WinDivert driver still loaded")
		}
		return nil
	})
}

func waitKillRules(program string, timeout time.Duration) error {
	return harness.Eventually(timeout, 250*time.Millisecond, func() error {
		rules, err := harness.FirewallRules("Ashgate kill switch")
		if err != nil {
			return err
		}
		in, out := false, false
		for _, r := range rules {
			if strings.EqualFold(r.Program, program) && strings.EqualFold(r.Action, "Block") {
				in = in || strings.EqualFold(r.Direction, "Inbound")
				out = out || strings.EqualFold(r.Direction, "Outbound")
			}
		}
		if !in || !out {
			return fmt.Errorf("no inbound+outbound kill-switch block rule for %s (%d rules)", program, len(rules))
		}
		return nil
	})
}
