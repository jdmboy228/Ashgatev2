//go:build windows && e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ashgate/e2e/harness"
	"ashgate/internal/config"
)

// footprint sums ashgate.exe and its WebView2 processes.
type footprint struct {
	CPU        time.Duration
	WorkingSet uint64
	Private    uint64
	Handles    uint32
	Threads    uint32
}

func measure(pid uint32) (app harness.Usage, total footprint) {
	app, _ = harness.Sample(pid)
	total = footprint{app.CPU, app.WorkingSet, app.Private, app.Handles, app.Threads}
	for _, p := range webviews(pid) {
		if u, err := harness.Sample(p.PID); err == nil {
			total.CPU += u.CPU
			total.WorkingSet += u.WorkingSet
			total.Private += u.Private
			total.Handles += u.Handles
			total.Threads += u.Threads
		}
	}
	return app, total
}

// idle samples CPU and memory for d and counts UI polling and re-renders.
func idle(t *testing.T, env *harness.Env, a *harness.App, label string, d time.Duration) {
	t.Helper()
	pid := uint32(a.PID)
	var polls atomic.Int64
	page, err := harness.AppPage(harness.DebugPort)
	var cdp *harness.CDP
	if err == nil {
		cdp, err = harness.DialCDP(page, func(method string, params json.RawMessage) {
			if method == "Network.requestWillBeSent" && strings.Contains(string(params), "/api/state") {
				polls.Add(1)
			}
		})
	}
	var m0 map[string]float64
	if err == nil {
		_ = cdp.Call("Network.enable", nil, nil)
		_ = cdp.Call("Performance.enable", nil, nil)
		m0, _ = cdp.Metrics()
	} else {
		t.Logf("cdp: %v", err)
	}
	appStart, totStart := measure(pid)
	start := time.Now()
	time.Sleep(d)
	appEnd, totEnd := measure(pid)
	el := time.Since(start)
	cores := float64(numCPU())
	appCPU := float64(appEnd.CPU-appStart.CPU) / float64(el) * 100 / cores
	totCPU := float64(totEnd.CPU-totStart.CPU) / float64(el) * 100 / cores
	env.Metric("idle."+label+".cpu_percent_ashgate", appCPU, "%", "lower")
	env.Metric("idle."+label+".cpu_percent_total", totCPU, "%", "lower")
	env.Metric("idle."+label+".working_set_MB", float64(totEnd.WorkingSet)/1e6, "MB", "lower")
	env.Metric("idle."+label+".private_MB", float64(totEnd.Private)/1e6, "MB", "lower")
	env.Metric("idle."+label+".ashgate_private_MB", float64(appEnd.Private)/1e6, "MB", "lower")
	if cdp != nil {
		m1, _ := cdp.Metrics()
		perMin := func(k string) float64 { return (m1[k] - m0[k]) / el.Minutes() }
		env.Metric("ui."+label+".state_polls_per_min", float64(polls.Load())/el.Minutes(), "/min", "lower")
		env.Metric("ui."+label+".layouts_per_min", perMin("LayoutCount"), "/min", "lower")
		env.Metric("ui."+label+".style_recalcs_per_min", perMin("RecalcStyleCount"), "/min", "lower")
		env.Metric("ui."+label+".script_ms_per_min", perMin("ScriptDuration")*1000, "ms/min", "lower")
		if label == "tray" && polls.Load() > 0 {
			env.Note("finding", fmt.Sprintf("the hidden page keeps polling /api/state in the tray: %.0f requests/min", float64(polls.Load())/el.Minutes()))
		}
		if l := perMin("LayoutCount"); l > 30 {
			env.Note("finding", fmt.Sprintf("%s idle: %.0f layouts/min with nothing changing on screen", label, l))
		}
		cdp.Close()
	}
	if totCPU > 5 {
		t.Errorf("%s idle CPU %.1f%% of the machine (ashgate %.1f%%), want ≤ 5%%", label, totCPU, appCPU)
	}
}

func numCPU() int {
	if n := os.Getenv("NUMBER_OF_PROCESSORS"); n != "" {
		var k int
		fmt.Sscan(n, &k)
		if k > 0 {
			return k
		}
	}
	return 1
}

// TestPerf is the perf job.
func TestPerf(t *testing.T) {
	env := harness.LoadEnv(t)
	harness.EnsureQuit(env.Exe)

	t.Run("Startup", func(t *testing.T) {
		var vis, ready []float64
		for i := 0; i < 3; i++ {
			a := harness.Launch(t, env, env.Exe, harness.LaunchOpts{})
			if err := harness.Eventually(30*time.Second, 50*time.Millisecond, func() error {
				if _, ok := harness.MainWindow(uint32(a.PID)); !ok {
					return fmt.Errorf("no window")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			v := time.Since(a.Started)
			// UI ready: the page drew its first screen.
			page, _ := harness.AppPage(harness.DebugPort)
			c, err := harness.DialCDP(page, nil)
			if err == nil {
				_ = harness.Eventually(20*time.Second, 50*time.Millisecond, func() error {
					var ok bool
					_ = c.Eval(`document.readyState === 'complete' && !!document.querySelector('#page') && document.querySelector('#page').children.length > 0`, &ok)
					if !ok {
						return fmt.Errorf("page not drawn")
					}
					return nil
				})
				c.Close()
			}
			r := time.Since(a.Started)
			vis = append(vis, v.Seconds())
			ready = append(ready, r.Seconds())
			env.Metric(fmt.Sprintf("startup.run%d.ready_seconds", i+1), r.Seconds(), "s", "lower")
			a.Quit()
		}
		env.Metric("startup.cold_ready_seconds", ready[0], "s", "lower")
		env.Metric("startup.window_visible_seconds", median(vis), "s", "lower")
		env.Metric("startup.ready_seconds", median(ready), "s", "lower")
		if median(ready) > 10 {
			t.Errorf("median startup to a drawn UI %.1fs, want ≤ 10 s", median(ready))
		}
	})

	fx, err := harness.StartFixture(env)
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	a := harness.Launch(t, env, env.Exe, harness.LaunchOpts{})
	defer func() {
		if ok, _ := a.Exited(); !ok {
			a.Quit()
		}
	}()
	pid := uint32(a.PID)
	xApp := env.ClientExe(t, harness.ClientProxied)
	rApp := env.ClientExe(t, harness.ClientPlain)
	err = a.UpdateConfig(func(c *config.Config) {
		c.Proxies = append(c.Proxies,
			config.Proxy{Name: "perf-xhttp", Type: "vless", Address: fx.XHTTP.Addr, Link: fx.XHTTPLink},
			config.Proxy{Name: "perf-raw", Type: "vless", Address: fx.RAW.Addr, Link: fx.RAWLink})
		on := true
		c.Rules = []config.Rule{
			{Enabled: &on, Process: xApp, Action: "proxy", Proxy: "perf-xhttp"},
			{Enabled: &on, Process: rApp, Action: "proxy", Proxy: "perf-raw"},
		}
	})
	if err != nil {
		t.Fatalf("perf proxies: %v", err)
	}

	t.Run("IdleWindowOpen", func(t *testing.T) { idle(t, env, a, "window", 2*time.Minute) })

	t.Run("IdleTray", func(t *testing.T) {
		if err := a.Post("/api/window", map[string]string{"op": "close"}, nil); err != nil {
			t.Fatal(err)
		}
		time.Sleep(3 * time.Second)
		if w, ok := harness.MainWindow(pid); ok && w.Visible {
			t.Errorf("window still visible after close (should hide to the tray)")
		}
		idle(t, env, a, "tray", 2*time.Minute)
		// A second launch brings the hidden window back.
		_, _ = harness.Run(env.Exe)
		time.Sleep(2 * time.Second)
	})

	if err := a.StartCapture(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Run("IdleCapturing", func(t *testing.T) { idle(t, env, a, "capturing", time.Minute) })

	t.Run("Load", func(t *testing.T) {
		for _, c := range []struct{ label, exe string }{{"xhttp", xApp}, {"raw", rApp}} {
			before, _ := harness.Sample(pid)
			start := time.Now()
			r := harness.RunClient(c.exe, "par", "-url", harness.URL(harness.TargetTCP), "-n", fmt.Sprint(25<<20),
				"-streams", "8", "-seed", "load-"+c.label, "-stall", "15s")
			el := time.Since(start)
			after, _ := harness.Sample(pid)
			if !r.OK {
				t.Errorf("%s load: %s", c.label, r)
				continue
			}
			mb := float64(r.Bytes) / 1e6
			cpu := (after.CPU - before.CPU).Seconds()
			env.Metric("load."+c.label+".MBps", mb/el.Seconds(), "MB/s", "higher")
			env.Metric("load."+c.label+".cpu_seconds_per_100MB", cpu/mb*100, "s", "lower")
			env.Metric("load."+c.label+".cpu_percent", cpu/el.Seconds()*100/float64(numCPU()), "%", "lower")
		}
	})

	t.Run("Spawns", func(t *testing.T) {
		_, _ = harness.Run("auditpol", "/set", "/subcategory:Process Creation", "/success:enable")
		since := time.Now()
		time.Sleep(2 * time.Minute)
		out, err := harness.PS(fmt.Sprintf(`Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=[datetime]'%s'} -ErrorAction SilentlyContinue |`+
			` ForEach-Object { $x=[xml]$_.ToXml(); $d=@{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name]=$_.'#text' };`+
			` if ($d.ParentProcessName -like '*\ashgate.exe') { Split-Path -Leaf $d.NewProcessName } } | Group-Object | ForEach-Object { "$($_.Name)=$($_.Count)" }`,
			since.Format("2006-01-02T15:04:05")))
		if err != nil {
			t.Logf("audit: %v", err)
			return
		}
		out = strings.TrimSpace(out)
		total := 0
		for _, l := range strings.Fields(out) {
			var n int
			if i := strings.LastIndexByte(l, '='); i > 0 {
				fmt.Sscan(l[i+1:], &n)
			}
			total += n
		}
		env.Metric("idle.child_processes_per_10min", float64(total)*5, "/10min", "lower")
		if total > 0 {
			env.Note("finding", "while capturing and idle, ashgate.exe started child processes in 2 min: "+out)
		}
	})

	t.Run("Growth", func(t *testing.T) {
		d := 2 * time.Minute
		if env.Long {
			d = 10 * time.Minute
		} else {
			env.Note("skipped", "perf: the 10-minute growth and long-session run is nightly/dispatch only; push runs 2 minutes")
		}
		stop := make(chan struct{})
		var wg sync.WaitGroup
		var churnFail atomic.Int64
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				case <-time.After(5 * time.Second):
				}
				if r := harness.RunClient(xApp, "churn", "-url", harness.URL(harness.TargetTCP), "-count", "10"); !r.OK {
					churnFail.Add(1)
				}
			}
		}()
		holdSecs := int(d.Seconds()) + 30
		var hold harness.ClientResult
		wg.Add(1)
		go func() {
			defer wg.Done()
			hold = harness.RunClient(rApp, "hold", "-url", harness.URL(harness.TargetTCP),
				"-secs", fmt.Sprint(holdSecs), "-rate", fmt.Sprint(128<<10), "-seed", "hold", "-stall", "10s")
		}()
		type sample struct {
			At         float64 `json:"t"`
			Handles    uint32  `json:"handles"`
			Threads    uint32  `json:"threads"`
			PrivateMB  float64 `json:"privateMB"`
			Goroutines int     `json:"goroutines"`
		}
		var samples []sample
		start := time.Now()
		for time.Since(start) < d {
			u, _ := harness.Sample(pid)
			g := -1
			if st, err := a.State(); err == nil {
				g = st.Goroutines
			}
			samples = append(samples, sample{time.Since(start).Seconds(), u.Handles, u.Threads, float64(u.Private) / 1e6, g})
			time.Sleep(10 * time.Second)
		}
		close(stop)
		wg.Wait()
		env.WriteJSON("perf/growth.json", samples)
		if !hold.OK {
			t.Errorf("long session stream: %s", hold)
		}
		if hold.MaxGapS > 10 {
			t.Errorf("long session stalled %.1fs", hold.MaxGapS)
		}
		if n := churnFail.Load(); n > 0 {
			t.Errorf("%d rounds of short connections failed during the run", n)
		}
		warm := len(samples) / 5
		if len(samples)-warm < 4 {
			return
		}
		rest := samples[warm:]
		xs := make([]float64, len(rest))
		col := func(f func(sample) float64) []float64 {
			ys := make([]float64, len(rest))
			for i, s := range rest {
				xs[i] = s.At / 60
				ys[i] = f(s)
			}
			return ys
		}
		hSlope := slope(xs, col(func(s sample) float64 { return float64(s.Handles) }))
		tSlope := slope(xs, col(func(s sample) float64 { return float64(s.Threads) }))
		pSlope := slope(xs, col(func(s sample) float64 { return s.PrivateMB }))
		gSlope := slope(xs, col(func(s sample) float64 { return float64(s.Goroutines) }))
		env.Metric("growth.handles_per_min", hSlope, "/min", "lower")
		env.Metric("growth.threads_per_min", tSlope, "/min", "lower")
		env.Metric("growth.private_MB_per_min", pSlope, "MB/min", "lower")
		first, last := rest[0], rest[len(rest)-1]
		if first.Goroutines >= 0 {
			env.Metric("growth.goroutines_per_min", gSlope, "/min", "lower")
			env.Metric("run.goroutines_end", float64(last.Goroutines), "", "lower")
		} else {
			env.Note("info", "the app does not report goroutines in /api/state")
		}
		env.Metric("run.handles_end", float64(last.Handles), "", "lower")
		env.Metric("run.private_MB_end", last.PrivateMB, "MB", "lower")
		mins := (last.At - first.At) / 60
		if hSlope > 10 && float64(last.Handles)-float64(first.Handles) > 10*mins {
			t.Errorf("handles keep growing: %.1f/min (%d → %d)", hSlope, first.Handles, last.Handles)
		}
		if first.Goroutines >= 0 && gSlope > 5 && float64(last.Goroutines-first.Goroutines) > 5*mins {
			t.Errorf("goroutines keep growing: %.1f/min (%d → %d)", gSlope, first.Goroutines, last.Goroutines)
		}
		if pSlope > 3 && last.PrivateMB-first.PrivateMB > 3*mins {
			t.Errorf("private memory keeps growing: %.1f MB/min (%.0f → %.0f MB)", pSlope, first.PrivateMB, last.PrivateMB)
		}
	})
}

func median(v []float64) float64 {
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	if len(s) == 0 {
		return math.NaN()
	}
	return s[len(s)/2]
}

// slope is the least-squares slope of ys over xs.
func slope(xs, ys []float64) float64 {
	n := float64(len(xs))
	var sx, sy, sxx, sxy float64
	for i := range xs {
		sx += xs[i]
		sy += ys[i]
		sxx += xs[i] * xs[i]
		sxy += xs[i] * ys[i]
	}
	den := n*sxx - sx*sx
	if den == 0 {
		return 0
	}
	return (n*sxy - sx*sy) / den
}
