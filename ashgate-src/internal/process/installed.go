package process

import (
	"sort"
	"strings"
	"sync"
	"time"

	"ashgate/internal/rules"
)

// Installed is an application found on disk, for the rule dialog's search.
// Mask is the path generalized for versioned (Squirrel) folders, and Family
// names the emulator or launcher it belongs to; both are empty when they do
// not apply, so the dialog can offer them without asking the engine again.
type Installed struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Mask   string `json:"mask,omitempty"`
	Family string `json:"family,omitempty"`
}

const installedTTL = 2 * time.Minute

var installed struct {
	mu   sync.Mutex
	at   time.Time
	list []Installed
}

// InstalledApps lists applications from the Start menu and the registry,
// one row per executable. The scan is cached for two minutes.
func InstalledApps() []Installed {
	installed.mu.Lock()
	defer installed.mu.Unlock()
	if installed.list == nil || time.Since(installed.at) > installedTTL {
		installed.list = mergeInstalled(scanInstalled())
		installed.at = time.Now()
	}
	return append([]Installed(nil), installed.list...)
}

// mergeInstalled drops unusable targets and duplicate paths. The first name
// wins, so scanners list Start menu shortcuts (the names people know) first.
func mergeInstalled(in []Installed) []Installed {
	seen := map[string]bool{}
	out := make([]Installed, 0, len(in))
	for _, it := range in {
		it.Path = cleanTarget(it.Path)
		it.Name = strings.TrimSpace(it.Name)
		if !usableTarget(it.Path) {
			continue
		}
		key := strings.ToLower(it.Path)
		if seen[key] {
			continue
		}
		seen[key] = true
		if it.Name == "" {
			it.Name = strings.TrimSuffix(baseOf(it.Path), ".exe")
		}
		it.Mask, _ = rules.VersionMask(it.Path)
		it.Family = rules.Family(it.Path)
		out = append(out, it)
	}
	sort.SliceStable(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

// cleanTarget turns a registry or shortcut value such as
// `"%ProgramFiles%\App\app.exe",0` into a plain path.
func cleanTarget(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, `"`) {
		if j := strings.Index(s[1:], `"`); j >= 0 {
			s = s[1 : 1+j]
		}
	}
	if i := strings.LastIndex(strings.ToLower(s), ".exe,"); i >= 0 {
		s = s[:i+4]
	}
	return expandEnv(strings.Trim(s, `"`))
}

func usableTarget(path string) bool {
	low := strings.ToLower(path)
	if !strings.HasSuffix(low, ".exe") || len(low) < 3 || low[0] < 'a' || low[0] > 'z' || low[1] != ':' || low[2] != '\\' {
		return false
	}
	name := baseOf(low)
	for _, bad := range []string{"unins", "uninst", "setup", "install", "update", "crashpad", "crashhandler", "helper"} {
		if strings.Contains(name, bad) {
			return false
		}
	}
	return !strings.HasPrefix(low, strings.ToLower(windowsDir())+`\installer\`) && fileExists(path)
}

func baseOf(p string) string {
	p = strings.ReplaceAll(p, "/", `\`)
	if i := strings.LastIndex(p, `\`); i >= 0 {
		return p[i+1:]
	}
	return p
}
