package gui

import (
	"errors"
	"strings"
	"time"

	"ashgate/internal/config"
	"ashgate/internal/killswitch"
	"ashgate/internal/process"
	"ashgate/internal/rules"
)

// ksView is the kill switch as the window shows it.
type ksView struct {
	On      bool     `json:"on"`
	Blocked []string `json:"blocked"`
	Missing []string `json:"missing,omitempty"`
	Error   string   `json:"error,omitempty"`
}

const ksEvery = 15 * time.Second

// ksLoop keeps the firewall rules in step with the config and with the
// processes that start while capture is stopped.
func (c *controller) ksLoop() {
	for {
		c.syncKill()
		time.Sleep(ksEvery)
	}
}

// killTargets lists the programs that proxy rules with the kill switch
// cover: exact path rules, running and installed images that a name or
// mask rule matches, and running processes that inherit such a rule from
// a parent. missing lists rules with no known executable.
func killTargets(cfg *config.Config) (paths, missing []string) {
	eff := cfg.EffectiveRules()
	set := rules.Compile(eff)
	seen := map[string]bool{}
	add := func(p string) {
		if k := strings.ToLower(p); p != "" && !seen[k] {
			seen[k] = true
			paths = append(paths, p)
		}
	}
	running := process.Snapshot()
	for _, p := range running {
		if d := set.Match(p); d.Action == "proxy" && d.KillSwitch {
			add(p.Path)
		}
	}
	var installed []process.Installed
	for _, r := range eff {
		if !r.IsEnabled() || r.Action != "proxy" || !r.RuleKillSwitch() {
			continue
		}
		raw := strings.Trim(strings.TrimSpace(r.Process), `"`)
		if rules.IsPath(raw) && !strings.ContainsAny(raw, "*?") {
			add(strings.TrimPrefix(raw, `\\?\`))
			continue
		}
		one := rules.Compile([]config.Rule{r})
		found := false
		for _, p := range running {
			if one.Match(rules.Process{Name: p.Name, Path: p.Path}).Action != "" {
				found = true
				break
			}
		}
		if installed == nil {
			installed = process.InstalledApps()
		}
		for _, a := range installed {
			if one.Match(rules.Process{Name: rules.Base(a.Path), Path: a.Path}).Action != "" {
				add(a.Path)
				found = true
			}
		}
		if !found {
			missing = append(missing, raw)
		}
	}
	return paths, missing
}

// killWanted reports whether any enabled proxy rule has the kill switch.
func killWanted(cfg *config.Config) bool {
	for _, r := range cfg.EffectiveRules() {
		if r.IsEnabled() && r.Action == "proxy" && r.RuleKillSwitch() {
			return true
		}
	}
	return false
}

// syncKill applies the kill switch for the current state: rules absent
// while capture runs (they would block the proxy too), present otherwise.
func (c *controller) syncKill() {
	fw := c.hooks.firewall
	if fw == nil {
		return
	}
	c.ksMu.Lock()
	defer c.ksMu.Unlock()
	c.mu.Lock()
	cfg := cloneCfg(c.cfg)
	running := c.sess != nil && c.sess.Running() && !c.stopping
	c.mu.Unlock()

	var err error
	var missing []string
	switch {
	case !killWanted(cfg):
		if len(fw.Blocked()) > 0 {
			err = fw.Unblock()
		}
		c.stopGuardLocked()
	case running:
		var paths []string
		paths, missing = killTargets(cfg)
		// The guard blocks these if Ashgate dies while capturing.
		err = killswitch.SaveTargets(c.ksState(), paths)
		if c.guardStop == nil && err == nil {
			c.guardStop, err = c.hooks.guard(c.ksState())
		}
		if len(fw.Blocked()) > 0 {
			err = errors.Join(err, fw.Unblock())
		}
	default:
		var paths []string
		paths, missing = killTargets(cfg)
		err = fw.Block(paths)
		c.stopGuardLocked()
	}
	c.mu.Lock()
	c.ksMissing = missing
	c.ksErr = ""
	if err != nil && !errors.Is(err, killswitch.ErrUnsupported) {
		c.ksErr = err.Error()
	}
	c.mu.Unlock()
}

func (c *controller) stopGuardLocked() {
	if c.guardStop != nil {
		c.guardStop()
		c.guardStop = nil
	}
}

func (c *controller) ksState() string {
	return killswitch.StatePath(c.path)
}

func (c *controller) ksSnapshot(on bool) ksView {
	v := ksView{On: on, Blocked: []string{}}
	if c.hooks.firewall != nil {
		v.Blocked = c.hooks.firewall.Blocked()
	}
	v.Missing = append(v.Missing, c.ksMissing...)
	v.Error = c.ksErr
	return v
}

// kickKill schedules a kill-switch sync. Saves come in bursts (each click
// on the Apps tab saves); one worker runs the sync once more after the
// burst instead of a full process scan per click.
func (c *controller) kickKill() {
	if c.hooks.firewall == nil {
		return
	}
	c.mu.Lock()
	c.ksPending = true
	start := !c.ksRunning
	c.ksRunning = true
	c.mu.Unlock()
	if !start {
		return
	}
	go func() {
		for {
			c.mu.Lock()
			if !c.ksPending {
				c.ksRunning = false
				c.mu.Unlock()
				return
			}
			c.ksPending = false
			c.mu.Unlock()
			c.syncKill()
		}
	}()
}
