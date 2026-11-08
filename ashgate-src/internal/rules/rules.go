// Package rules matches a process against the configured proxy rules.
package rules

import (
	"strings"

	"ashgate/internal/config"
)

// Process is the application that owns a socket.
type Process struct {
	PID  uint32
	Name string
	Path string
	// PPID and Started (creation time, Unix nanoseconds) identify the
	// parent. Zero means unknown.
	PPID    uint32
	Started int64
	// Parents is the ancestor chain, nearest first. Each element has no
	// Parents of its own.
	Parents []Process
}

// Decision is the first matching rule, or Action == "" when nothing matched.
type Decision struct {
	Action    string
	Proxy     string
	RuleIndex int
	// Parent names the ancestor whose rule was inherited; empty when the
	// process matched a rule itself.
	Parent string
	// KillSwitch and TCPOnly are the matched rule's settings.
	KillSwitch bool
	TCPOnly    bool
}

// Set is an immutable list of enabled rules in config order.
type Set struct {
	rules []compiled
}

type compiled struct {
	path     bool
	match    string
	action   string
	proxy    string
	index    int
	children bool
	ks       bool
	tcpOnly  bool
	// glob is set when match contains '*' or '?'.
	glob bool
}

// Compile keeps enabled rules in order. Disabled rules are skipped. Pass
// Config.EffectiveRules so groups and the kill-switch default apply.
// A '*' in a rule matches any run of characters, '\' included, so
// `*\Discord\app-*\Discord.exe` survives Discord's versioned folders.
func Compile(rules []config.Rule) *Set {
	out := &Set{rules: make([]compiled, 0, len(rules))}
	for i, r := range rules {
		if !r.IsEnabled() {
			continue
		}
		raw := strings.TrimSpace(r.Process)
		raw = strings.Trim(raw, `"`)
		c := compiled{action: r.Action, proxy: r.Proxy, index: i, children: r.CoversChildren(),
			ks: r.RuleKillSwitch(), tcpOnly: r.TCPOnly}
		if IsPath(raw) {
			c.path = true
			c.match = NormalizePath(raw)
		} else {
			c.match = NormalizeName(raw)
			// "chrome" means chrome.exe; every process image has an extension.
			if c.match != "" && !strings.Contains(c.match, ".") && !strings.HasSuffix(c.match, "*") {
				c.match += ".exe"
			}
		}
		c.glob = strings.ContainsAny(c.match, "*?")
		out.rules = append(out.rules, c)
	}
	return out
}

// Match returns the first enabled rule for p. When no rule names p itself,
// the nearest ancestor whose first matching rule covers children decides,
// so helpers an application starts (updaters, Electron and browser helpers,
// games started by a launcher) follow the application's rule. The climb
// stops at shell and system processes; otherwise a rule could spread to
// everything started from the desktop.
func (s *Set) Match(p Process) Decision {
	if s == nil {
		return Decision{RuleIndex: -1}
	}
	if r, ok := s.first(p); ok {
		return r.decision("")
	}
	for _, a := range p.Parents {
		if IsShellOrSystem(a) {
			break
		}
		if r, ok := s.first(a); ok && r.children {
			parent := Base(a.Name)
			if parent == "" {
				parent = Base(a.Path)
			}
			return r.decision(parent)
		}
	}
	return Decision{RuleIndex: -1}
}

func (r compiled) decision(parent string) Decision {
	return Decision{Action: r.action, Proxy: r.proxy, RuleIndex: r.index, Parent: parent, KillSwitch: r.ks, TCPOnly: r.tcpOnly}
}

func (r compiled) matches(name, path string) bool {
	want := name
	if r.path {
		want = path
	}
	if want == "" {
		return false
	}
	if r.glob {
		return Glob(r.match, want)
	}
	return want == r.match
}

// Glob matches s against pattern, where '*' is any run of characters and
// '?' is one character. Both are already lower-case.
func Glob(pattern, s string) bool {
	px, sx := 0, 0
	star, mark := -1, 0
	for sx < len(s) {
		switch {
		case px < len(pattern) && (pattern[px] == '?' || pattern[px] == s[sx]):
			px++
			sx++
		case px < len(pattern) && pattern[px] == '*':
			star, mark = px, sx
			px++
		case star >= 0:
			px = star + 1
			mark++
			sx = mark
		default:
			return false
		}
	}
	for px < len(pattern) && pattern[px] == '*' {
		px++
	}
	return px == len(pattern)
}

func (s *Set) first(p Process) (compiled, bool) {
	name := NormalizeName(p.Name)
	if name == "" {
		name = Base(p.Path)
	}
	path := NormalizePath(p.Path)
	for _, r := range s.rules {
		// A mask never takes the Windows service host: svchost carries
		// system traffic for every program (see dns.systemResolver).
		if r.glob && name == "svchost.exe" {
			continue
		}
		if r.matches(name, path) {
			return r, true
		}
	}
	return compiled{}, false
}

// shellOrSystem are processes that start unrelated programs. Rules are
// never inherited through them.
var shellOrSystem = map[string]bool{
	"explorer.exe": true, "svchost.exe": true, "services.exe": true, "wininit.exe": true,
	"winlogon.exe": true, "userinit.exe": true, "smss.exe": true, "csrss.exe": true,
	"lsass.exe": true, "system": true, "sihost.exe": true, "taskhostw.exe": true,
	"runtimebroker.exe": true, "dllhost.exe": true, "wmiprvse.exe": true, "taskeng.exe": true,
	"startmenuexperiencehost.exe": true, "shellexperiencehost.exe": true,
	"searchhost.exe": true, "applicationframehost.exe": true, "ashgate.exe": true,
}

// IsShellOrSystem reports a process whose children must not inherit rules.
func IsShellOrSystem(p Process) bool {
	name := Base(p.Name)
	if name == "" {
		name = Base(p.Path)
	}
	return shellOrSystem[name]
}

// IsPath reports whether the rule field is a filesystem path rather than a bare exe name.
func IsPath(p string) bool {
	p = strings.TrimSpace(p)
	if strings.ContainsAny(p, `\/`) {
		return true
	}
	return len(p) >= 2 && p[1] == ':'
}

// NormalizePath lower-cases a Windows path and strips the extended-length prefix.
func NormalizePath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.Trim(p, `"`)
	p = strings.ReplaceAll(p, "/", `\`)
	p = strings.ToLower(p)
	p = strings.TrimPrefix(p, `\??\`)
	p = strings.TrimPrefix(p, `\\?\`)
	return p
}

// NormalizeName returns the lower-case file name.
func NormalizeName(p string) string {
	return Base(p)
}

// Base returns the lower-case file name of a Windows path.
func Base(p string) string {
	p = NormalizePath(p)
	if i := strings.LastIndex(p, `\`); i >= 0 {
		p = p[i+1:]
	}
	return p
}

// IsSystemDNS reports the Windows DNS Client host process.
func IsSystemDNS(name string) bool {
	return Base(name) == "svchost.exe"
}
