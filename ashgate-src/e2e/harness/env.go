//go:build windows && e2e

// Package harness drives an installed Ashgate on a Windows runner for the
// end-to-end tests in ashgate/e2e. Nothing here is built by `go test ./...`:
// every file needs the e2e build tag. See .github/workflows/windows-e2e.yml.
package harness

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// Env is what the workflow tells a test job.
type Env struct {
	InstallDir string // %ProgramFiles%\Ashgate
	Exe        string // InstallDir\ashgate.exe
	Bin        string // helper exes: ashgate-e2e-client.exe, ...
	Out        string // this job's artifact folder
	Setup      string // Setup.exe of this commit
	SetupPrev  string // Setup.exe of the previous release, may be empty
	Dist       string // the build's dist folder (expected file hashes)
	Long       bool   // nightly / workflow_dispatch: run the long tests
	Secrets    *Secrets
}

var (
	envOnce sync.Once
	envVal  *Env
)

// LoadEnv reads the E2E_* variables set by the workflow.
func LoadEnv(t testing.TB) *Env {
	t.Helper()
	envOnce.Do(func() {
		pf := os.Getenv("ProgramFiles")
		if pf == "" {
			pf = `C:\Program Files`
		}
		out := os.Getenv("E2E_OUT")
		if out == "" {
			out = filepath.Join(os.TempDir(), "ashgate-e2e-out")
		}
		_ = os.MkdirAll(out, 0o755)
		e := &Env{
			InstallDir: filepath.Join(pf, "Ashgate"),
			Bin:        os.Getenv("E2E_BIN"),
			Out:        out,
			Setup:      os.Getenv("E2E_SETUP"),
			SetupPrev:  os.Getenv("E2E_SETUP_PREV"),
			Dist:       os.Getenv("E2E_DIST"),
			Long:       os.Getenv("E2E_LONG") == "1",
		}
		e.Exe = filepath.Join(e.InstallDir, "ashgate.exe")
		e.Secrets = NewSecrets(filepath.Join(out, "secrets.json"))
		envVal = e
	})
	return envVal
}

// NeedLong skips t unless the long tests were asked for.
func (e *Env) NeedLong(t testing.TB) {
	t.Helper()
	if !e.Long {
		e.Note("skipped", t.Name()+": long test: nightly and workflow_dispatch only")
		t.Skip("long test: nightly and workflow_dispatch only")
	}
}

// Path joins elem under the artifact folder and creates its parent.
func (e *Env) Path(elem ...string) string {
	p := filepath.Join(append([]string{e.Out}, elem...)...)
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	return p
}

var notesMu sync.Mutex

// Note appends one line to notes.md under a heading (skipped, finding,
// info). The report job puts these lines into the run summary.
func (e *Env) Note(kind, text string) {
	notesMu.Lock()
	defer notesMu.Unlock()
	f, err := os.OpenFile(e.Path("notes.md"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "- **%s** %s\n", kind, strings.ReplaceAll(text, "\n", " "))
}

// Metric is one measured number for perf.json.
type Metric struct {
	Value float64 `json:"value"`
	Unit  string  `json:"unit"`
	// Better is "lower" or "higher"; the report compares runs with it.
	Better string `json:"better,omitempty"`
}

var metricsMu sync.Mutex

// Metric records name = value in metrics.json of this job.
func (e *Env) Metric(name string, value float64, unit, better string) {
	metricsMu.Lock()
	defer metricsMu.Unlock()
	path := e.Path("metrics.json")
	all := map[string]Metric{}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &all)
	}
	all[name] = Metric{Value: value, Unit: unit, Better: better}
	keys := make([]string, 0, len(all))
	for k := range all {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	b, _ := json.MarshalIndent(all, "", "  ")
	_ = os.WriteFile(path, b, 0o644)
}

// WriteJSON stores v as an artifact.
func (e *Env) WriteJSON(name string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(e.Path(name), b, 0o644)
}

// Stop wraps an error that ends Eventually at once (no point waiting).
type Stop struct{ Err error }

func (s Stop) Error() string { return s.Err.Error() }

// Eventually polls fn until it returns nil or the timeout passes. A Stop
// error ends it early.
func Eventually(timeout, every time.Duration, fn func() error) error {
	deadline := time.Now().Add(timeout)
	var err error
	for {
		if err = fn(); err == nil {
			return nil
		}
		var stop Stop
		if errors.As(err, &stop) {
			return stop.Err
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(every)
	}
}
