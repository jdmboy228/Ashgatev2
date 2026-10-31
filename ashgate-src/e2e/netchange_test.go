//go:build windows && e2e

package e2e

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"ashgate/e2e/harness"
)

// TestNetworkChange is the netchange job: the runner's network card goes
// down and up while capture runs. It is its own job because the runner can
// lose its connection to GitHub while the card is off.
func TestNetworkChange(t *testing.T) {
	env := harness.LoadEnv(t)
	harness.EnsureQuit(env.Exe)
	s := harness.NewSession(t, harness.SessionOpts{})
	a := s.App
	nic, err := harness.MainNIC()
	if err != nil {
		t.Fatal(err)
	}
	if r := harness.RunClient(s.Client, "get", "-url", harness.URL(harness.TargetTCP), "-n", "1000000"); !r.OK {
		t.Fatalf("before the change: %s", r)
	}
	// Safety net: a SYSTEM task turns the card back on after 20 s even if
	// this process or the runner's session is gone.
	task := "ashgate-e2e-nic"
	tr := fmt.Sprintf("powershell -NoProfile -Command Start-Sleep 20; Get-NetAdapter -InterfaceIndex %d | Enable-NetAdapter -Confirm:$false", nic.Index)
	if out, err := harness.Run("schtasks", "/Create", "/TN", task, "/SC", "ONCE", "/ST", "23:59", "/RU", "SYSTEM", "/TR", tr, "/F"); err != nil {
		t.Fatalf("safety task: %v: %s", err, out)
	}
	defer harness.Run("schtasks", "/Delete", "/TN", task, "/F")

	c, err := harness.StartCapture(env, "adapter-flap")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := harness.Run("schtasks", "/Run", "/TN", task); err != nil {
		t.Fatalf("safety task run: %v: %s", err, out)
	}
	if out, err := harness.PS(fmt.Sprintf(`Get-NetAdapter -InterfaceIndex %d | Disable-NetAdapter -Confirm:$false`, nic.Index)); err != nil {
		t.Fatalf("disable adapter: %v: %s", err, out)
	}
	downAt := time.Now()
	// While the card is off: the proxied app must not get anywhere.
	during := harness.RunClient(s.Client, "tcp", "-addr", harness.TargetTCP, "-timeout", "3s")
	time.Sleep(7 * time.Second)
	_, _ = harness.PS(fmt.Sprintf(`Get-NetAdapter -InterfaceIndex %d | Enable-NetAdapter -Confirm:$false`, nic.Index))
	err = harness.Eventually(60*time.Second, time.Second, func() error {
		out, _ := harness.PS(fmt.Sprintf(`(Get-NetAdapter -InterfaceIndex %d).Status`, nic.Index))
		if !strings.EqualFold(strings.TrimSpace(out), "Up") {
			return errors.New("adapter " + out)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("adapter did not come back: %v", err)
	}
	upAt := time.Now()
	t.Logf("card off for %s; proxied attempt while off: %s", upAt.Sub(downAt).Round(time.Second), during)
	err = harness.Eventually(60*time.Second, 2*time.Second, func() error {
		if r := harness.RunClient(s.Client, "get", "-url", harness.URL(harness.TargetTCP), "-n", "1000000", "-stall", "8s"); !r.OK {
			return errors.New(r.Error)
		}
		return nil
	})
	pkts, _ := c.Stop()
	if err != nil {
		t.Errorf("proxied app did not recover within 60 s of the card coming back: %v", err)
	} else {
		env.Metric("netchange.recover_seconds", time.Since(upAt).Seconds(), "s", "lower")
	}
	if !a.MustState().Running {
		t.Errorf("capture stopped after the card went down and up")
	}
	if leak := harness.Filter(pkts, harness.ToTestNet()); len(leak) > 0 {
		t.Errorf("leak around the network change:%s", harness.Brief(leak, 10))
	}
}
