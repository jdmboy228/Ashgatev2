//go:build windows && e2e

package harness

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// trafficGiveUp is how long one request of Traffic waits before its
// program gives up and closes the connection, as a browser's user would.
const trafficGiveUp = 4 * time.Second

// Request is one request of Traffic.
type Request struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
	OK    bool      `json:"ok"`
	Error string    `json:"error,omitempty"`
}

// Traffic is a program in use: a client asks the TCP target for a small
// page every interval until Stop. Requests overlap while they wait for an
// answer. Failover judges a server by traffic like this; a tunnel nobody
// uses is not checked at all.
type Traffic struct {
	stop chan struct{}
	wg   sync.WaitGroup
	mu   sync.Mutex
	reqs []Request
}

// StartTraffic starts the requests of the client exe.
func StartTraffic(exe string, every time.Duration) *Traffic {
	t := &Traffic{stop: make(chan struct{})}
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		tick := time.NewTicker(every)
		defer tick.Stop()
		for {
			t.wg.Add(1)
			go func() {
				defer t.wg.Done()
				t.one(exe)
			}()
			select {
			case <-t.stop:
				return
			case <-tick.C:
			}
		}
	}()
	return t
}

func (t *Traffic) one(exe string) {
	r := Request{Start: time.Now()}
	ctx, cancel := context.WithTimeout(context.Background(), trafficGiveUp)
	defer cancel()
	out, err := exec.CommandContext(ctx, exe, "get", "-url", URL(TargetTCP), "-n", "20000", "-stall", "3s").Output()
	r.End = time.Now()
	var res ClientResult
	switch jerr := json.Unmarshal(lastLine(out), &res); {
	case ctx.Err() != nil:
		r.Error = "no answer, gave up"
	case jerr != nil:
		r.Error = fmt.Sprintf("client output %q: %v", strings.TrimSpace(string(out)), err)
	default:
		r.OK, r.Error = res.OK, res.Error
	}
	t.mu.Lock()
	t.reqs = append(t.reqs, r)
	t.mu.Unlock()
}

// Requests are the requests that ended so far.
func (t *Traffic) Requests() []Request {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]Request(nil), t.reqs...)
}

// Stop ends the traffic, waits for the open requests and returns them all.
func (t *Traffic) Stop() []Request {
	close(t.stop)
	t.wg.Wait()
	return t.Requests()
}

// FirstOK is when the first request that started at from or later got its
// page.
func (t *Traffic) FirstOK(from time.Time) (time.Time, bool) {
	var at time.Time
	for _, r := range t.Requests() {
		if r.OK && !r.Start.Before(from) && (at.IsZero() || r.End.Before(at)) {
			at = r.End
		}
	}
	return at, !at.IsZero()
}

// Failed counts the requests that started in [from, to) and got no page.
func Failed(reqs []Request, from, to time.Time) (failed, all int) {
	for _, r := range reqs {
		if r.Start.Before(from) || !r.Start.Before(to) {
			continue
		}
		all++
		if !r.OK {
			failed++
		}
	}
	return failed, all
}

// WaitActive keeps the tunnel in use (a request a second) until the
// subscription's active server is the one whose label contains want, and
// returns when the app says it switched to it. The primary is probed only
// while programs use the tunnel, so waiting without traffic would wait
// forever.
func WaitActive(a *App, client, want string, timeout time.Duration) (time.Time, error) {
	if strings.Contains(ActiveServer(a), want) {
		return time.Now(), nil
	}
	tr := StartTraffic(client, time.Second)
	defer tr.Stop()
	var at time.Time
	err := Eventually(timeout, 500*time.Millisecond, func() error {
		s, err := a.State()
		if err != nil {
			return err
		}
		v := s.Subs[SubName]
		if !strings.Contains(v.Active, want) {
			return fmt.Errorf("active server is %q (%s), want %s", v.Active, v.Reason, want)
		}
		at = v.SwitchedAt
		return nil
	})
	return at, err
}
