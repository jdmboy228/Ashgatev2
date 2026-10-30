// Package killswitch blocks proxied applications in Windows Firewall while
// Ashgate is not capturing, so they cannot reach the network directly.
//
// While capture runs the rules must be absent: Windows checks the firewall
// when the application connects, before Ashgate redirects the packet, so a
// block rule would also stop proxied traffic.
package killswitch

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// RuleName names every firewall rule Ashgate adds.
const RuleName = "Ashgate kill switch"

// ErrUnsupported is returned outside Windows.
var ErrUnsupported = errors.New("kill switch: доступен только в Windows")

// Firewall keeps one inbound and one outbound block rule per program. The
// installed set is saved next to the config so a later run can remove
// exactly those rules, even after a crash.
type Firewall struct {
	mu    sync.Mutex
	state string
	cur   map[string]string // lower-case path -> path
	// view is a copy of cur for Blocked, which the window polls; it must
	// not wait for netsh commands running under mu.
	view atomic.Pointer[[]string]
	// run executes one netsh command line (without "netsh").
	run func(cmdline string) error
}

// New loads the saved state. state is the JSON file that records the
// installed rules.
func New(state string) *Firewall {
	f := &Firewall{state: state, cur: map[string]string{}, run: runNetsh}
	if data, err := os.ReadFile(state); err == nil {
		var list []string
		if json.Unmarshal(data, &list) == nil {
			for _, p := range list {
				// The file is outside this process's control; a quote in
				// a path would inject arguments into the netsh command line.
				if valid(p) {
					f.cur[strings.ToLower(p)] = p
				}
			}
		}
	}
	f.publishLocked()
	return f
}

func (f *Firewall) publishLocked() {
	list := f.listLocked()
	f.view.Store(&list)
}

// Blocked returns the programs currently blocked, sorted.
func (f *Firewall) Blocked() []string {
	if v := f.view.Load(); v != nil {
		return append([]string(nil), (*v)...)
	}
	return nil
}

// Block makes the blocked set equal to paths. New rules are added before
// stale ones are removed, so there is no moment without protection.
func (f *Firewall) Block(paths []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	want := map[string]string{}
	for _, p := range paths {
		if valid(p) {
			want[strings.ToLower(p)] = p
		}
	}
	var errs []error
	for k, p := range want {
		if _, ok := f.cur[k]; ok {
			continue
		}
		if err := f.add(p); err != nil {
			errs = append(errs, err)
			continue
		}
		f.cur[k] = p
	}
	for k, p := range f.cur {
		if _, ok := want[k]; ok {
			continue
		}
		f.del(p)
		delete(f.cur, k)
	}
	if err := f.saveLocked(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Unblock removes every Ashgate kill-switch rule.
func (f *Firewall) Unblock() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Deleting by name also removes rules a lost state file forgot.
	err := f.run(`advfirewall firewall delete rule name="` + RuleName + `"`)
	if errors.Is(err, ErrUnsupported) {
		return err
	}
	clear(f.cur)
	return f.saveLocked()
}

func (f *Firewall) add(path string) error {
	for _, dir := range []string{"out", "in"} {
		line := `advfirewall firewall add rule name="` + RuleName + `" dir=` + dir +
			` action=block enable=yes profile=any program="` + path + `"`
		if err := f.run(line); err != nil {
			f.del(path)
			return err
		}
	}
	return nil
}

func (f *Firewall) del(path string) {
	// netsh fails when nothing matches; that is the wanted end state.
	_ = f.run(`advfirewall firewall delete rule name="` + RuleName + `" program="` + path + `"`)
}

func (f *Firewall) listLocked() []string {
	out := make([]string, 0, len(f.cur))
	for _, p := range f.cur {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func (f *Firewall) saveLocked() error {
	f.publishLocked()
	if f.state == "" {
		return nil
	}
	data, _ := json.Marshal(f.listLocked())
	if err := os.MkdirAll(filepath.Dir(f.state), 0o755); err != nil {
		return err
	}
	tmp := f.state + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.state)
}

// valid accepts absolute Windows paths to an .exe. A quote would break the
// netsh command line, and Windows paths cannot contain one.
func valid(p string) bool {
	low := strings.ToLower(p)
	return strings.HasSuffix(low, ".exe") && len(p) > 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') &&
		!strings.ContainsAny(p, "\"\r\n")
}

// NewWithRunner is New with a custom netsh runner. Tests use it.
func NewWithRunner(state string, run func(cmdline string) error) *Firewall {
	f := New(state)
	f.run = run
	return f
}
