// Package rules matches a process against the configured proxy rules.
package rules

import (
	"regexp"
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

// Decision is the winning rule, or Action == "" when nothing matched. The
// winner is chosen by how specifically it names the process, never by its
// position in the configuration; see Set.
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
	MatchAuto      = "auto"
)

// Set is an immutable collection of enabled rules. Matching is decided by
// specificity: the rule that names the process most precisely wins, so the
// order of the rules passed to Compile never changes Action, Proxy, MatchKind,
// KillSwitch or TCPOnly. RuleIndex still reports the winner's original
// position in that slice.
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
	// literals, fixedSegs and wildcards measure how specific the mask is;
	// see rank.
	literals  int
	fixedSegs int
	wildcards int
}

type compiled struct {
	// primary is the rule's own process; companions are extra executables,
	// paths, or masks attached to the same rule.
	primary    matcher
	companions []matcher
	// excludes are companions that must not be picked up by this rule's
	// install folder.
	excludes []matcher
	action   string
	proxy    string
	index    int
	children bool
	ks       bool
	tcpOnly  bool
	// canon orders rules independently of the order they were compiled in;
	// it breaks ties between equally specific rules.
	canon canonical
}

// Compile compiles the enabled rules; disabled rules are skipped. The order
// of the slice is kept only so Decision.RuleIndex points at the caller's
// rule — matching itself is independent of it. Pass Config.EffectiveRules so
// groups and the kill-switch default apply.
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
		for _, raw := range r.ExcludeCompanions {
			if strings.Trim(strings.TrimSpace(raw), `"`) == "" {
				continue
			}
			c.excludes = append(c.excludes, compileMatcher(raw))
		}
		c.canon = c.canonical()
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
	m.literals, m.fixedSegs, m.wildcards = measureMask(m.match)
	return m
}

// measureMask counts the literal (non-wildcard) runes, the path segments
// without a wildcard, and the wildcards of a compiled mask. A mask with more
// literals and more fixed segments, and fewer wildcards, is more specific.
func measureMask(match string) (literals, fixedSegs, wildcards int) {
	segments := strings.Split(match, `\`)
	for _, seg := range segments {
		fixed := true
		for _, r := range seg {
			switch r {
			case '*', '?':
				wildcards++
				fixed = false
			default:
				literals++
			}
		}
		if fixed && seg != "" {
			fixedSegs++
		}
	}
	return literals, fixedSegs, wildcards
}

// Match returns the most specific enabled rule for p, regardless of the order
// of the rules. A rule naming p's exact path beats one naming a path mask,
// which beats one naming the exe name, which beats one naming a name mask,
// which beats one naming p as a companion; ties go to the mask with more
// literal text and fixed segments, then to the canonical order (block, then
// direct, then proxy).
//
// When no rule names p itself, the nearest ancestor whose most specific rule
// covers children decides, so helpers an application starts (updaters,
// Electron and browser helpers, games started by a launcher) follow the
// application's rule. The climb stops at shell and system processes;
// otherwise a rule could spread to everything started from the desktop.
//
// When there is no ancestor to inherit from, a companion decides: a process
// that lives in the rule's install folder (or a subfolder of it), or one in
// the install folder of a companion such as a service-started VM process.
// The deepest matching folder wins.
func (s *Set) Match(p Process) Decision {
	if s == nil {
		return Decision{RuleIndex: -1}
	}
	if r, kind, ok := s.best(p); ok {
		return r.decision("", kind)
	}
	if IsShellOrSystem(p) {
		return Decision{RuleIndex: -1}
	}
	for _, a := range p.Parents {
		if IsShellOrSystem(a) {
			break
		}
		if r, _, ok := s.best(a); ok && r.children {
			return r.decision(appName(a), MatchChild)
		}
	}
	return s.companion(p)
}

// IsExcluded reports whether the rule at ruleIndex (an index into the slice
// passed to Compile) excludes p: p matches one of the rule's
// ExcludeCompanions. Only the install-folder companion match consults it;
// explicit MatchExact and MatchCompanion matches are unaffected.
func (s *Set) IsExcluded(ruleIndex int, p Process) bool {
	if s == nil {
		return false
	}
	name := NormalizeName(p.Name)
	if name == "" {
		name = Base(p.Path)
	}
	path := NormalizePath(p.Path)
	for _, r := range s.rules {
		if r.index == ruleIndex {
			return r.isExcluded(name, path)
		}
	}
	return false
}

// isExcluded reports that name or path matches one of the rule's excludes.
func (r compiled) isExcluded(name, path string) bool {
	for _, m := range r.excludes {
		if m.matches(name, path) {
			return true
		}
	}
	return false
}

// companion returns the rule whose install folder holds p, or whose
// companion's install folder holds it. Only rules that cover children take
// part, so the existing "proxy child processes" switch controls this too.
//
// Every rule is considered, and the deepest (longest) matching folder wins,
// so a rule for `C:\Apps\Suite\Tool` beats one for `C:\Apps\Suite`. On equal
// depth a rule's own folder beats a companion's, and remaining ties use the
// same canonical order as best, so the result never depends on rule order.
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
	var (
		win    compiled
		winDir string
		winOwn bool
		found  bool
	)
	consider := func(r compiled, dir string, own bool) {
		if dir == "" || !inDir(path, dir) {
			return
		}
		if !found ||
			len(dir) > len(winDir) ||
			(len(dir) == len(winDir) && own && !winOwn) ||
			(len(dir) == len(winDir) && own == winOwn && r.canon.less(win.canon)) {
			win, winDir, winOwn, found = r, dir, own, true
		}
	}
	for _, r := range s.rules {
		if !r.children {
			continue
		}
		if r.isExcluded(name, path) {
			continue
		}
		consider(r, r.primary.dir, true)
		for _, c := range r.companions {
			consider(r, c.dir, false)
		}
	}
	if !found {
		return Decision{RuleIndex: -1}
	}
	return win.decision(appName(Process{Name: win.primary.match}), MatchFolder)
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

// best returns the most specific rule naming p, by its primary process
// (MatchExact) or by one of its companions (MatchCompanion). Every rule is
// considered; see rank for how candidates are compared.
func (s *Set) best(p Process) (compiled, string, bool) {
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
	var (
		win   compiled
		kind  string
		top   rank
		found bool
	)
	consider := func(r compiled, m matcher, tier int, k string) {
		rk := m.rank(tier)
		if !found || rk.better(top) || (rk == top && r.canon.less(win.canon)) {
			win, kind, top, found = r, k, rk, true
		}
	}
	for _, r := range s.rules {
		if r.primary.matches(name, path) {
			consider(r, r.primary, r.primary.tier(true), MatchExact)
		}
		for _, c := range r.companions {
			if c.matches(name, path) {
				consider(r, c, c.tier(false), MatchCompanion)
			}
		}
	}
	return win, kind, found
}

// tier ranks a matcher by how precisely it names a process: 8 is an exact
// full path and 1 a companion's name mask. Primary matchers outrank
// companions at the same shape.
func (m matcher) tier(primary bool) int {
	switch {
	case primary && m.path && !m.glob:
		return 8
	case primary && m.path:
		return 7
	case primary && !m.glob:
		return 6
	case primary:
		return 5
	case m.path && !m.glob:
		return 4
	case m.path:
		return 3
	case !m.glob:
		return 2
	default:
		return 1
	}
}

// rank is the specificity of one matching candidate; a higher rank wins.
type rank struct {
	tier      int
	literals  int
	fixedSegs int
	wildcards int
}

// rank returns the specificity of m at tier.
func (m matcher) rank(tier int) rank {
	return rank{tier: tier, literals: m.literals, fixedSegs: m.fixedSegs, wildcards: m.wildcards}
}

// better reports that r is more specific than o: a higher tier, then more
// literal text, then more fixed path segments, then fewer wildcards.
func (r rank) better(o rank) bool {
	switch {
	case r.tier != o.tier:
		return r.tier > o.tier
	case r.literals != o.literals:
		return r.literals > o.literals
	case r.fixedSegs != o.fixedSegs:
		return r.fixedSegs > o.fixedSegs
	default:
		return r.wildcards < o.wildcards
	}
}

// canonical orders rules independently of the order they were compiled in.
type canonical struct {
	action     int
	primary    string
	proxy      string
	ks         bool
	tcpOnly    bool
	children   bool
	companions string
	excludes   string
}

// canonical returns the tie-breaking key of r. The first three fields are the
// documented tie-breakers; the rest only order rules that are otherwise
// identical, so even duplicate definitions resolve the same way in any order.
func (r compiled) canonical() canonical {
	return canonical{
		action:     actionRank(r.action),
		primary:    r.primary.match,
		proxy:      r.proxy,
		ks:         r.ks,
		tcpOnly:    r.tcpOnly,
		children:   r.children,
		companions: matcherKey(r.companions),
		excludes:   matcherKey(r.excludes),
	}
}

// less reports that c comes before o in the canonical order.
func (c canonical) less(o canonical) bool {
	switch {
	case c.action != o.action:
		return c.action > o.action
	case c.primary != o.primary:
		return c.primary < o.primary
	case c.proxy != o.proxy:
		return c.proxy < o.proxy
	case c.ks != o.ks:
		return c.ks
	case c.tcpOnly != o.tcpOnly:
		return c.tcpOnly
	case c.children != o.children:
		return c.children
	case c.companions != o.companions:
		return c.companions < o.companions
	default:
		return c.excludes < o.excludes
	}
}

// actionRank orders actions for tie-breaking: block beats direct beats proxy.
func actionRank(action string) int {
	switch action {
	case "block":
		return 2
	case "direct":
		return 1
	default:
		return 0
	}
}

// matcherKey renders a matcher list as a canonical string.
func matcherKey(ms []matcher) string {
	if len(ms) == 0 {
		return ""
	}
	keys := make([]string, len(ms))
	for i, m := range ms {
		keys[i] = m.match
	}
	sort.Strings(keys)
	return strings.Join(keys, "\x00")
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
	``:                                  true,
	`\program files`:                    true,
	`\program files (x86)`:              true,
	`\program files\common files`:       true,
	`\program files (x86)\common files`: true,
	`\program files\windowsapps`:        true,
	`\programdata`:                      true,
	`\programdata\microsoft`:            true,
	`\programdata\package cache`:        true,
	`\users`:                            true,
	`\users\public`:                     true,
	`\windows`:                          true,
	`\windows\system32`:                 true,
	`\windows\syswow64`:                 true,
	`\windows\installer`:                true,
	`\windows\winsxs`:                   true,
	`\windows\servicing`:                true,
	`\windows\inf`:                      true,
}

// sharedUserDirs are per-user folders that hold unrelated programs; a rule
// for one exe there must not cover its neighbours.
var sharedUserDirs = map[string]bool{
	``:                               true,
	`\desktop`:                       true,
	`\downloads`:                     true,
	`\documents`:                     true,
	`\onedrive`:                      true,
	`\onedrive\desktop`:              true,
	`\onedrive\downloads`:            true,
	`\onedrive\documents`:            true,
	`\appdata`:                       true,
	`\appdata\local`:                 true,
	`\appdata\roaming`:               true,
	`\appdata\locallow`:              true,
	`\appdata\local\programs`:        true,
	`\appdata\local\programs\common`: true,
	`\appdata\local\temp`:            true,
	`\appdata\local\microsoft`:       true,
	`\appdata\local\packages`:        true,
	`\appdata\roaming\microsoft`:     true,
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

// stripUserProfileName removes the `<username>` segment from paths under
// `<drive>:\users\<username>\...` (or `\users\<username>\...`) while keeping
// the original casing of the remaining path for camelCase splitting.
func stripUserProfileName(s string) string {
	const root = `\users\`
	low := strings.ToLower(s)
	off := 0
	if len(low) >= 2 && low[1] == ':' {
		off = 2
	}
	if !strings.HasPrefix(low[off:], root) {
		return s
	}
	userStart := off + len(root)
	if i := strings.IndexByte(s[userStart:], '\\'); i >= 0 {
		return s[:userStart] + s[userStart+i+1:]
	}
	return s[:userStart]
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
	// System and user folders that hold unrelated programs.
	"programs": true, "programdata": true, "desktop": true, "downloads": true,
	"documents": true, "public": true, "default": true, "windowsapps": true,
	"packages": true, "resources": true, "current": true,
	"application": true, "applications": true,
	"system": true, "low": true, "log": true, "logs": true, "doc": true,
	"docs": true, "help": true, "asar": true, "unpacked": true,
	"locales": true, "locale": true, "assets": true, "binaries": true,
	"plugins": true, "plugin": true, "modules": true, "config": true,
	"settings": true, "profile": true, "profiles": true, "userdata": true,
	"store": true, "library": true, "installer": true, "installed": true,
	"setup": true, "install": true, "dev": true, "beta": true, "stable": true,
	"software": true, "canary": true, "nightly": true, "preview": true,
	"alpha": true, "insiders": true, "crashpad": true, "handler": true,
	"worker": true, "monitor": true, "manager": true, "console": true,
	"steamapps": true, "vendor": true, "third": true, "party": true,
	"redist": true, "studio": true,
	// Corporate suffixes of publisher names in install folders.
	"corporation": true, "incorporated": true, "limited": true, "company": true,
	"gmbh": true, "sarl": true, "inc": true, "ltd": true, "llc": true,
	"technologies": true, "solutions": true, "international": true, "group": true,
	"digital": true, "entertainment": true,
}

// guidBlock matches a GUID in braces, such as the installer package folder
// name `{02bd05cf-...}v10.1` under ProgramData\Package Cache.
var guidBlock = regexp.MustCompile(`\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}`)

// storeFamilyTail matches the version tail of a Store package-family folder:
// `_1.6.19.0_x64__8wekyb3d8bbwe`. The tail holds the publisher hash that
// would otherwise leak into the tokens as "wekyb" and "bbwe".
var storeFamilyTail = regexp.MustCompile(`_[0-9].*__[0-9A-Za-z]{8,}`)

// stripStoreFamilyTail cuts the version tail of a Store package-family
// folder name, keeping the product part before it.
func stripStoreFamilyTail(seg string) string {
	if loc := storeFamilyTail.FindStringIndex(seg); loc != nil {
		return seg[:loc[0]]
	}
	return seg
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
	s = stripUserProfileName(s)
	// Installer package folders and Store package families carry a GUID or a
	// publisher hash that means nothing about the product.
	s = guidBlock.ReplaceAllString(s, " ")
	segs := strings.Split(s, `\`)
	for i, seg := range segs {
		segs[i] = stripStoreFamilyTail(seg)
	}
	s = strings.Join(segs, `\`)

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
	// Split on every rune that is not a letter or a digit: separators,
	// punctuation such as "(x86)" and any stray brace or bracket disappear.
	fields := strings.FieldsFunc(b.String(), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
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

// ProductTokens returns the meaningful words of a path without the tokens
// that name a large software vendor. Two unrelated products of one vendor,
// such as Yandex Browser and Yandex Music, share the vendor token but are not
// the same product, so a product match must ignore it.
func ProductTokens(path string) []string {
	tokens := PathTokens(path)
	out := make([]string, 0, len(tokens))
	for _, t := range tokens {
		if commonVendorTokens[t] {
			continue
		}
		out = append(out, t)
	}
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

// commonVendorTokens name a large software vendor on their own. A match is by
// whole token, so "Samd LLC" does not name AMD and "Intelligent Systems" does
// not name Intel.
var commonVendorTokens = map[string]bool{
	"microsoft": true, "google": true, "apple": true, "oracle": true,
	"nvidia": true, "intel": true, "amd": true, "valve": true,
	"adobe": true, "jetbrains": true, "ubisoft": true, "mozilla": true,
	"amazon": true, "opera": true, "blizzard": true, "activision": true,
	"yandex": true, "logitech": true, "realtek": true, "samsung": true,
	"unity": true, "msi": true, "tencent": true, "netease": true,
	"mihoyo": true, "hoyoverse": true, "qualcomm": true, "broadcom": true,
	"dell": true, "hp": true, "lenovo": true, "asus": true, "acer": true,
	"gigabyte": true, "razer": true, "corsair": true, "sony": true, "lg": true,
	"canon": true, "epson": true, "citrix": true, "vmware": true, "sap": true,
	"ibm": true, "autodesk": true, "corel": true, "kaspersky": true,
	"avast": true, "avg": true, "eset": true, "bitdefender": true,
	"malwarebytes": true, "norton": true, "mcafee": true, "sophos": true,
	"avira": true, "comodo": true, "rockstar": true, "bethesda": true,
	"capcom": true, "sega": true,
}

// commonVendorPhrases are multi-word vendor names; their tokens must appear
// next to each other.
var commonVendorPhrases = [][]string{
	{"advanced", "micro", "devices"},
	{"electronic", "arts"},
	{"riot", "games"},
	{"epic", "games"},
	{"meta", "platforms"},
	{"mail", "ru"},
	{"square", "enix"},
	{"take", "two"},
}

// IsCommonVendor reports that name looks like a large, well-known software
// vendor ("NVIDIA Corporation", "Advanced Micro Devices, Inc."). Tokens are
// compared whole, never as substrings.
func IsCommonVendor(name string) bool {
	tokens := vendorTokens(name)
	for _, t := range tokens {
		if commonVendorTokens[t] {
			return true
		}
	}
	for _, phrase := range commonVendorPhrases {
		if hasTokenSeq(tokens, phrase) {
			return true
		}
	}
	return false
}

// vendorTokens lower-cases name and splits it on every non-letter, non-digit
// rune, keeping short words so multi-word vendor phrases match exactly.
func vendorTokens(name string) []string {
	return strings.FieldsFunc(strings.ToLower(name), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

// hasTokenSeq reports that seq appears as consecutive tokens of tokens.
func hasTokenSeq(tokens, seq []string) bool {
	if len(seq) == 0 || len(seq) > len(tokens) {
		return false
	}
	for i := 0; i+len(seq) <= len(tokens); i++ {
		ok := true
		for j, s := range seq {
			if tokens[i+j] != s {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// IsSystemPath reports that path lies inside a Windows folder (x:\windows or
// below it). Program Files and WindowsApps are not system paths.
func IsSystemPath(path string) bool {
	p := NormalizePath(path)
	if len(p) < 2 || p[1] != ':' {
		return false
	}
	rest := p[2:]
	return rest == `\windows` || strings.HasPrefix(rest, `\windows\`)
}

// CommandLineMatches reports that cmd names one of the directories, or one of
// the executables, with a path or word boundary. The command line is normally
// read from Windows as typed, so it is lower-cased and its slashes are turned
// into backslashes here; dirs and exes are already normalized.
func CommandLineMatches(cmd string, dirs, exes []string) bool {
	cmd = strings.ReplaceAll(strings.ToLower(cmd), "/", `\`)
	if cmd == "" {
		return false
	}
	for _, d := range dirs {
		if d == "" {
			continue
		}
		for off := 0; ; {
			i := strings.Index(cmd[off:], d)
			if i < 0 {
				break
			}
			i += off
			end := i + len(d)
			if (i == 0 || cmdWordBoundary(cmd[i-1])) && (end == len(cmd) || cmdPathBoundary(cmd[end])) {
				return true
			}
			off = i + 1
		}
	}
	for _, e := range exes {
		if e == "" {
			continue
		}
		for off := 0; ; {
			i := strings.Index(cmd[off:], e)
			if i < 0 {
				break
			}
			i += off
			end := i + len(e)
			if (i == 0 || cmdWordBoundary(cmd[i-1])) && (end == len(cmd) || cmdWordBoundary(cmd[end])) {
				return true
			}
			off = i + 1
		}
	}
	return false
}

// cmdPathBoundary reports a character that ends a directory on a command
// line: the folder is complete and something follows, not a longer name.
func cmdPathBoundary(b byte) bool {
	switch b {
	case '\\', '/', '"', '\'', ' ', '\t', '\r', '\n':
		return true
	}
	return false
}

// cmdWordBoundary reports a character that ends an executable name.
func cmdWordBoundary(b byte) bool {
	switch b {
	case '\\', '/', '"', '\'', ' ', '\t', '\r', '\n', '=', ',', ';', '(', ')':
		return true
	}
	return false
}

// serviceOrCOMAncestors start programs on behalf of the system, the task
// scheduler, or a COM server. explorer.exe is deliberately absent: a program
// started from the desktop is not a service's companion.
var serviceOrCOMAncestors = map[string]bool{
	"svchost.exe": true, "services.exe": true, "dllhost.exe": true,
	"taskeng.exe": true, "taskhostw.exe": true, "wmiprvse.exe": true,
}

// IsServiceOrCOMAncestor reports that p was started by a service host, the
// task scheduler, or a COM server rather than by an application.
func IsServiceOrCOMAncestor(p Process) bool {
	for _, a := range p.Parents {
		name := NormalizeName(a.Name)
		if name == "" {
			name = NormalizeName(a.Path)
		}
		if serviceOrCOMAncestors[name] {
			return true
		}
	}
	return false
}

// NonVendorTokens returns path's tokens without the ones that also appear in
// signer, so a product token can be told from a vendor token.
func NonVendorTokens(path, signer string) []string {
	tokens := PathTokens(path)
	if signer == "" {
		return tokens
	}
	vendor := make(map[string]bool)
	for _, t := range PathTokens(signer) {
		vendor[t] = true
	}
	out := make([]string, 0, len(tokens))
	for _, t := range tokens {
		if !vendor[t] {
			out = append(out, t)
		}
	}
	return out
}
