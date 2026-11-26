// Package rules matches a process against the configured proxy rules.
package rules

import (
	"strings"
	"unicode/utf8"

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
	// dir is the application's install folder, "" when the rule names no
	// folder of its own. A process started from it or a subfolder inherits
	// the rule, so a program launched by a service (LDPlayer's
	// Ld9BoxHeadless.exe, started by Ld9BoxSVC.exe) still follows it.
	dir string
	// family groups the executables of one emulator or launcher; "" when
	// the rule names no such program.
	family string
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
		c.dir = companionDir(c.match)
		c.family = Family(c.match)
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
//
// When there is no ancestor to inherit from, a companion decides: a process
// that lives in the rule's install folder (or a subfolder of it), or one
// that belongs to the same emulator or launcher family. That covers a
// program a service started, which has no ancestor in the app's tree.
func (s *Set) Match(p Process) Decision {
	if s == nil {
		return Decision{RuleIndex: -1}
	}
	if r, ok := s.first(p); ok {
		return r.decision("")
	}
	if IsShellOrSystem(p) {
		return Decision{RuleIndex: -1}
	}
	for _, a := range p.Parents {
		if IsShellOrSystem(a) {
			break
		}
		if r, ok := s.first(a); ok && r.children {
			return r.decision(appName(a))
		}
	}
	return s.companion(p)
}

// companion returns the first rule whose install folder or family holds p.
// Only rules that cover children take part, so the existing "proxy child
// processes" switch controls this too.
func (s *Set) companion(p Process) Decision {
	name := NormalizeName(p.Name)
	if name == "" {
		name = Base(p.Path)
	}
	// System traffic is never caught by a folder or family: svchost carries
	// other programs' traffic and services host unrelated programs.
	if name == "svchost.exe" || shellOrSystem[name] {
		return Decision{RuleIndex: -1}
	}
	path := NormalizePath(p.Path)
	for _, r := range s.rules {
		if !r.children {
			continue
		}
		if r.family != "" && r.family == Family(name) {
			return r.decision(appName(Process{Name: r.match}))
		}
		if r.dir != "" && inDir(path, r.dir) {
			return r.decision(appName(Process{Name: r.match}))
		}
	}
	return Decision{RuleIndex: -1}
}

// inDir reports that path lies in dir or below it. Both are normalized.
func inDir(path, dir string) bool {
	if path == "" || dir == "" || !strings.HasPrefix(path, dir) {
		return false
	}
	rest := path[len(dir):]
	return strings.HasPrefix(rest, `\`)
}

// appName is the name of the rule's application, shown as the parent of a
// process that inherited its rule.
func appName(p Process) string {
	if n := Base(p.Name); n != "" {
		return n
	}
	return Base(p.Path)
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
// '?' is one character (UTF-8 rune). Both are already lower-case.
func Glob(pattern, s string) bool {
	px, sx := 0, 0
	star, mark := -1, 0
	for sx < len(s) {
		if px < len(pattern) && pattern[px] == '*' {
			star, mark = px, sx
			px++
			continue
		}
		if px < len(pattern) && pattern[px] == '?' {
			_, sz := utf8.DecodeRuneInString(s[sx:])
			px++
			sx += sz
			continue
		}
		if px < len(pattern) {
			pr, psz := utf8.DecodeRuneInString(pattern[px:])
			sr, ssz := utf8.DecodeRuneInString(s[sx:])
			if pr == sr {
				px += psz
				sx += ssz
				continue
			}
		}
		if star >= 0 {
			_, sz := utf8.DecodeRuneInString(s[mark:])
			mark += sz
			px = star + 1
			sx = mark
			continue
		}
		return false
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
	// Never match the Windows service host: svchost carries system traffic
	// for every program (see dns.systemResolver).
	if name == "svchost.exe" {
		return compiled{}, false
	}
	path := NormalizePath(p.Path)
	for _, r := range s.rules {
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

// versionSeg reports a Squirrel version folder such as app-1.0.9187, which
// Discord, Slack and Teams put their executables in. Every update adds a
// folder and leaves the old one, so a rule naming one of them stops
// matching.
func versionSeg(seg string) bool {
	low := strings.ToLower(seg)
	if !strings.HasPrefix(low, "app-") || len(low) == 4 {
		return false
	}
	return low[4] >= '0' && low[4] <= '9'
}

// VersionMask turns a path with Squirrel version folders into a mask that
// survives updates, keeping everything else as typed:
// `C:\Users\u\AppData\Local\Discord\app-1.0.9187\Discord.exe` becomes
// `C:\Users\u\AppData\Local\Discord\app-*\Discord.exe`. ok is false when
// the path has no such folder, is already a mask, or is not a path.
func VersionMask(p string) (mask string, ok bool) {
	p = strings.Trim(strings.TrimSpace(p), `"`)
	if p == "" || strings.ContainsAny(p, "*?") || !IsPath(p) {
		return "", false
	}
	sep := `\`
	if !strings.Contains(p, `\`) {
		sep = "/"
	}
	segs := strings.Split(p, sep)
	changed := false
	for i, seg := range segs {
		if versionSeg(seg) {
			segs[i] = seg[:len("app-")] + "*"
			changed = true
		}
	}
	if !changed {
		return "", false
	}
	return strings.Join(segs, sep), true
}

// sharedRoots are folders that hold unrelated programs. A rule naming one
// of them never covers a companion by folder: the sibling would be another
// application.
var sharedRoots = map[string]bool{
	`c:`:               true,
	`c:\program files`: true, `c:\program files (x86)`: true,
	`c:\program files\common files`: true, `c:\program files (x86)\common files`: true,
	`c:\programdata`: true, `c:\programdata\microsoft`: true,
	`c:\users`: true, `c:\windows`: true, `c:\windows\system32`: true,
	`c:\windows\syswow64`: true, `c:\windows\installer`: true,
}

// sharedUserDirs are the per-user folders people drop portable programs
// into; a rule for one exe there must not cover its neighbours.
var sharedUserDirs = []string{`\desktop`, `\downloads`, `\documents`}

// companionDir returns the install folder of a rule's executable, or "" when
// the rule names no folder of its own: a bare name, a folder too shallow to
// mean one application, or a shared root such as Program Files.
func companionDir(match string) string {
	if match == "" || !IsPath(match) {
		return ""
	}
	if i := strings.IndexAny(match, "*?"); i >= 0 {
		// A mask names the folder before its first wildcard, and the
		// version segment there is the app's own (…\Discord\app-*\…).
		match = match[:i]
		if j := strings.LastIndex(match, `\`); j >= 0 {
			match = match[:j]
		}
	} else if j := strings.LastIndex(match, `\`); j >= 0 {
		match = match[:j]
	}
	match = strings.TrimSuffix(match, `\`)
	if len(match) <= 3 || sharedRoots[match] {
		return ""
	}
	if u := userHomeDir(match); u != "" {
		rest := strings.ToLower(match[len(u):])
		if rest == "" || rest == `\appdata` || rest == `\appdata\local` || rest == `\appdata\roaming` {
			return ""
		}
		for _, d := range sharedUserDirs {
			if rest == d {
				return ""
			}
		}
	}
	// A folder directly on a drive (D:\Games) holds unrelated programs.
	if len(strings.Split(match, `\`)) < 3 {
		return ""
	}
	return match
}

// userHomeDir returns the `c:\users\<name>` prefix of a normalized path, or
// "" when it is not under a user profile.
func userHomeDir(p string) string {
	const root = `c:\users\`
	if !strings.HasPrefix(p, root) {
		return ""
	}
	rest := p[len(root):]
	if i := strings.Index(rest, `\`); i >= 0 {
		return root + rest[:i]
	}
	return root + rest
}

// families groups the executables of one emulator or launcher. A program a
// service starts (LDPlayer's Ld9BoxHeadless.exe runs under Ld9BoxSVC.exe)
// has no ancestor in the app's tree, so the name is what ties it to the
// rule.
var families = map[string][]string{
	"ldplayer":   {"dnplayer.exe", "ldplayer.exe", "ld9boxheadless.exe", "ld9boxsvc.exe", "ld9boxs.exe", "ld9boxvmm.exe"},
	"bluestacks": {"bluestacks.exe", "hd-player.exe", "bstksvc.exe", "bstkvm.exe", "bstkgb.exe"},
	"nox":        {"nox.exe", "noxplayer.exe", "noxvmhandle.exe", "noxservice.exe", "noxconsole.exe"},
	"memu":       {"memu.exe", "memuheadless.exe", "memuconsole.exe", "memusvc.exe"},
}

// familyOf maps an executable name to its family; built once from families.
var familyOf = func() map[string]string {
	out := make(map[string]string)
	for fam, names := range families {
		for _, n := range names {
			out[n] = fam
		}
	}
	return out
}()

// Family returns the emulator or launcher family of an executable name or
// path, or "" when it belongs to none.
func Family(p string) string {
	name := Base(p)
	if name == "" {
		name = strings.ToLower(strings.TrimSpace(p))
	}
	return familyOf[name]
}
