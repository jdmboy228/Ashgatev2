// Package rules matches a process against the configured proxy rules.
package rules

import (
	"sort"
	"strings"
	"unicode"
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
	// MatchKind says how the rule was matched: MatchExact when the process
	// itself named the rule, MatchCompanion when one of the rule's companions
	// did, MatchChild when an ancestor's rule was inherited, MatchFolder when
	// the process lives in the install folder of the rule or a companion.
	MatchKind string
	// Parent names the ancestor whose rule was inherited; empty when the
	// process matched a rule itself.
	Parent string
	// KillSwitch and TCPOnly are the matched rule's settings.
	KillSwitch bool
	TCPOnly    bool
}

// MatchKind values; see Decision.MatchKind.
const (
	MatchExact     = "exact"
	MatchCompanion = "companion"
	MatchChild     = "child"
	MatchFolder    = "folder"
)

// Set is an immutable list of enabled rules in config order.
type Set struct {
	rules []compiled
}

// matcher is one compiled process name, path, or glob mask.
type matcher struct {
	path  bool
	match string
	glob  bool
	// dir is the install folder of the executable, "" when the mask names no
	// folder of its own (or one too shallow or shared to mean an application).
	dir string
}

type compiled struct {
	// primary is the rule's own process; companions are extra executables,
	// paths, or masks attached to the same rule.
	primary    matcher
	companions []matcher
	action     string
	proxy      string
	index      int
	children   bool
	ks         bool
	tcpOnly    bool
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
		c := compiled{action: r.Action, proxy: r.Proxy, index: i, children: r.CoversChildren(),
			ks: r.RuleKillSwitch(), tcpOnly: r.TCPOnly}
		c.primary = compileMatcher(r.Process)
		for _, raw := range r.Companions {
			if strings.Trim(strings.TrimSpace(raw), `"`) == "" {
				continue
			}
			c.companions = append(c.companions, compileMatcher(raw))
		}
		out.rules = append(out.rules, c)
	}
	return out
}

// compileMatcher compiles one process name, path, or glob mask.
func compileMatcher(raw string) matcher {
	raw = strings.Trim(strings.TrimSpace(raw), `"`)
	var m matcher
	if IsPath(raw) {
		m.path = true
		m.match = NormalizePath(raw)
	} else {
		m.match = NormalizeName(raw)
		// "chrome" means chrome.exe; every process image has an extension.
		if m.match != "" && !strings.Contains(m.match, ".") && !strings.HasSuffix(m.match, "*") {
			m.match += ".exe"
		}
	}
	m.glob = strings.ContainsAny(m.match, "*?")
	m.dir = companionDir(m.match)
	return m
}

// Match returns the first enabled rule for p. When no rule names p itself,
// the nearest ancestor whose first matching rule covers children decides,
// so helpers an application starts (updaters, Electron and browser helpers,
// games started by a launcher) follow the application's rule. The climb
// stops at shell and system processes; otherwise a rule could spread to
// everything started from the desktop.
//
// When there is no ancestor to inherit from, a companion decides: a process
// that lives in the rule's install folder (or a subfolder of it), or one in
// the install folder of a companion such as a service-started VM process.
func (s *Set) Match(p Process) Decision {
	if s == nil {
		return Decision{RuleIndex: -1}
	}
	if r, kind, ok := s.first(p); ok {
		return r.decision("", kind)
	}
	if IsShellOrSystem(p) {
		return Decision{RuleIndex: -1}
	}
	for _, a := range p.Parents {
		if IsShellOrSystem(a) {
			break
		}
		if r, _, ok := s.first(a); ok && r.children {
			return r.decision(appName(a), MatchChild)
		}
	}
	return s.companion(p)
}

// companion returns the first rule whose install folder holds p, or whose
// companion's install folder holds it. Only rules that cover children take
// part, so the existing "proxy child processes" switch controls this too.
func (s *Set) companion(p Process) Decision {
	name := NormalizeName(p.Name)
	if name == "" {
		name = Base(p.Path)
	}
	// System traffic is never caught by a folder: svchost carries other
	// programs' traffic and services host unrelated programs.
	if name == "svchost.exe" || shellOrSystem[name] {
		return Decision{RuleIndex: -1}
	}
	path := NormalizePath(p.Path)
	for _, r := range s.rules {
		if !r.children {
			continue
		}
		if r.primary.dir != "" && inDir(path, r.primary.dir) {
			return r.decision(appName(Process{Name: r.primary.match}), MatchFolder)
		}
		for _, c := range r.companions {
			if c.dir != "" && inDir(path, c.dir) {
				return r.decision(appName(Process{Name: r.primary.match}), MatchFolder)
			}
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

func (r compiled) decision(parent, kind string) Decision {
	return Decision{Action: r.action, Proxy: r.proxy, RuleIndex: r.index, MatchKind: kind, Parent: parent, KillSwitch: r.ks, TCPOnly: r.tcpOnly}
}

func (m matcher) matches(name, path string) bool {
	want := name
	if m.path {
		want = path
	}
	if want == "" {
		return false
	}
	if m.glob {
		return Glob(m.match, want)
	}
	return want == m.match
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

// first returns the first rule naming p, by its primary process (MatchExact)
// or by one of its companions (MatchCompanion), and in rules order.
func (s *Set) first(p Process) (compiled, string, bool) {
	name := NormalizeName(p.Name)
	if name == "" {
		name = Base(p.Path)
	}
	// Never match the Windows service host: svchost carries system traffic
	// for every program (see dns.systemResolver).
	if name == "svchost.exe" {
		return compiled{}, "", false
	}
	path := NormalizePath(p.Path)
	for _, r := range s.rules {
		if r.primary.matches(name, path) {
			return r, MatchExact, true
		}
		for _, c := range r.companions {
			if c.matches(name, path) {
				return r, MatchCompanion, true
			}
		}
	}
	return compiled{}, "", false
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

// sharedRootSuffixes are drive-agnostic folders that hold unrelated programs.
// A rule naming one of them never covers a companion by folder: the sibling
// would be another application.
var sharedRootSuffixes = map[string]bool{
	``:                             true,
	`\program files`:               true,
	`\program files (x86)`:         true,
	`\program files\common files`:  true,
	`\program files (x86)\common files`: true,
	`\programdata`:                 true,
	`\programdata\microsoft`:       true,
	`\users`:                       true,
	`\users\public`:                true,
	`\windows`:                     true,
	`\windows\system32`:            true,
	`\windows\syswow64`:            true,
	`\windows\installer`:           true,
}

// sharedUserDirs are per-user folders that hold unrelated programs; a rule
// for one exe there must not cover its neighbours.
var sharedUserDirs = map[string]bool{
	``:                           true,
	`\desktop`:                   true,
	`\downloads`:                 true,
	`\documents`:                 true,
	`\onedrive`:                  true,
	`\onedrive\desktop`:          true,
	`\onedrive\downloads`:        true,
	`\onedrive\documents`:        true,
	`\appdata`:                   true,
	`\appdata\local`:             true,
	`\appdata\roaming`:           true,
	`\appdata\local\programs`:    true,
	`\appdata\local\temp`:        true,
	`\appdata\local\microsoft`:   true,
	`\appdata\local\packages`:    true,
	`\appdata\roaming\microsoft`: true,
}

// CompanionDir returns the normalized install folder of a rule's executable
// path or mask, or "" when it names no application-specific folder (bare name,
// shared system/user root, UNC share root, or too shallow).
func CompanionDir(raw string) string {
	return companionDir(NormalizePath(raw))
}

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
	if len(match) <= 3 {
		return ""
	}
	// UNC paths (\\server\share) need at least a subdirectory under the share.
	if strings.HasPrefix(match, `\\`) {
		parts := strings.Split(strings.TrimPrefix(match, `\\`), `\`)
		if len(parts) < 3 || parts[0] == "" || parts[1] == "" {
			return ""
		}
		return match
	}
	// Drive-agnostic shared root check (handles Windows/Program Files on D:, etc.).
	noDrive := match
	if len(noDrive) >= 2 && noDrive[1] == ':' {
		noDrive = noDrive[2:]
	}
	if sharedRootSuffixes[noDrive] {
		return ""
	}
	if u := userHomeDir(noDrive); u != "" {
		rest := noDrive[len(u):]
		if sharedUserDirs[rest] {
			return ""
		}
	}
	// A folder directly on a drive (D:\Games) holds unrelated programs.
	if len(strings.Split(match, `\`)) < 3 {
		return ""
	}
	return match
}

// userHomeDir returns the `\users\<name>` prefix of a drive-stripped
// normalized path, or "" when it is not under a user profile.
func userHomeDir(p string) string {
	const root = `\users\`
	if !strings.HasPrefix(p, root) {
		return ""
	}
	rest := p[len(root):]
	if i := strings.Index(rest, `\`); i >= 0 {
		return root + rest[:i]
	}
	return root + rest
}

// pathTokenStop are words too common in paths and program names to tell one
// application family from another.
var pathTokenStop = map[string]bool{
	"program": true, "files": true, "x86": true, "x64": true, "bin": true,
	"app": true, "apps": true, "appdata": true, "local": true, "roaming": true,
	"users": true, "windows": true, "system32": true, "syswow64": true,
	"common": true, "client": true, "server": true, "helper": true,
	"service": true, "svc": true, "headless": true, "player": true,
	"launcher": true, "updater": true, "update": true, "exe": true,
	"win": true, "win64": true, "win32": true, "game": true, "games": true,
	"data": true, "cache": true, "temp": true, "tmp": true, "runtime": true,
	"core": true, "host": true, "agent": true, "daemon": true, "tray": true,
	"web": true, "view": true, "webview": true, "browser": true,
	"electron": true, "portable": true, "release": true, "debug": true,
	"build": true, "dist": true, "lib": true, "src": true, "box": true,
}

// PathTokens returns the meaningful words of a path or program name: the
// path is split on separators, letter/digit boundaries and camelCase, then
// lower-cased, with short, numeric and stop words dropped. Two programs of
// one product share a token even when they live in different folders and
// have unrelated names, such as C:\LDPlayer\...\dnmultiplayerex.exe and
// C:\Program Files\ldplayer9box\Ld9BoxHeadless.exe ("ldplayer").
func PathTokens(path string) []string {
	s := strings.Trim(strings.TrimSpace(path), `"`)
	s = strings.ReplaceAll(s, "/", `\`)
	s = strings.TrimPrefix(s, `\??\`)
	s = strings.TrimPrefix(s, `\\?\`)

	var b strings.Builder
	var prev rune
	for i, r := range s {
		if i > 0 {
			alnum := unicode.IsLetter(prev) || unicode.IsDigit(prev)
			switch {
			case alnum && (unicode.IsLetter(r) || unicode.IsDigit(r)) && unicode.IsDigit(prev) != unicode.IsDigit(r):
				b.WriteByte(' ')
			case unicode.IsLower(prev) && unicode.IsUpper(r):
				b.WriteByte(' ')
			}
		}
		b.WriteRune(r)
		prev = r
	}
	fields := strings.FieldsFunc(b.String(), func(r rune) bool {
		return r == '\\' || r == '/' || r == '_' || r == '-' || r == '.' || unicode.IsSpace(r)
	})

	seen := make(map[string]bool, len(fields))
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		t := strings.ToLower(f)
		if utf8.RuneCountInString(t) < 3 || pathTokenStop[t] || allDigits(t) || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// allDigits reports that s has at least one rune and every one is a digit.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}
