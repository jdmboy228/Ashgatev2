package killswitch

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func fake(f *Firewall) *[]string {
	var log []string
	f.run = func(line string) error {
		log = append(log, line)
		if strings.Contains(line, "bad.exe") && strings.Contains(line, " add ") {
			return errors.New("denied")
		}
		return nil
	}
	return &log
}

func TestBlockSyncsAndPersists(t *testing.T) {
	state := filepath.Join(t.TempDir(), "killswitch.json")
	f := New(state)
	log := fake(f)
	if err := f.Block([]string{`C:\Program Files\App\app.exe`, `C:\Tools\curl.exe`, "relative.exe"}); err != nil {
		t.Fatal(err)
	}
	if got := f.Blocked(); len(got) != 2 {
		t.Fatalf("blocked %v", got)
	}
	if !strings.Contains((*log)[0], `program="C:\`) || !strings.Contains(strings.Join(*log, "\n"), "dir=in") {
		t.Fatalf("netsh lines %v", *log)
	}
	*log = nil
	if err := f.Block([]string{`C:\Tools\curl.exe`, `C:\New\new.exe`}); err != nil {
		t.Fatal(err)
	}
	if len(*log) != 3 || !strings.Contains((*log)[2], `delete rule name="Ashgate kill switch" program="C:\Program Files\App\app.exe"`) {
		t.Fatalf("expected two adds then one delete: %v", *log)
	}
	// A new process reads the saved set.
	g := New(state)
	if got := g.Blocked(); len(got) != 2 {
		t.Fatalf("state not saved: %v", got)
	}
	fake(g)
	if err := g.Unblock(); err != nil || len(g.Blocked()) != 0 {
		t.Fatalf("unblock: %v %v", err, g.Blocked())
	}
}

func TestFailedAddIsNotRecorded(t *testing.T) {
	f := New("")
	fake(f)
	if err := f.Block([]string{`C:\x\bad.exe`}); err == nil {
		t.Fatal("error lost")
	}
	if len(f.Blocked()) != 0 {
		t.Fatal("failed rule recorded as blocked")
	}
}

func TestTargetsRoundTrip(t *testing.T) {
	state := filepath.Join(t.TempDir(), "killswitch.json")
	if got := LoadTargets(state); len(got) != 0 {
		t.Fatalf("no file: %v", got)
	}
	want := []string{`C:\Apps\a.exe`, `C:\Apps\b.exe`}
	if err := SaveTargets(state, want); err != nil {
		t.Fatal(err)
	}
	if got := LoadTargets(state); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %v", got)
	}
}

func TestUnblockKeepsStateOnNetshErrorAndClearsOnNoRules(t *testing.T) {
	state := filepath.Join(t.TempDir(), "killswitch.json")
	var failErr error
	f := NewWithRunner(state, func(line string) error {
		if strings.Contains(line, "delete rule") && failErr != nil {
			return failErr
		}
		return nil
	})
	if err := f.Block([]string{`C:\Apps\app.exe`}); err != nil {
		t.Fatal(err)
	}

	// A real netsh error must preserve f.cur and killswitch.json.
	failErr = errors.New("netsh: exit status 1: access denied")
	if err := f.Unblock(); err == nil {
		t.Fatal("expected error from Unblock")
	}
	if got := f.Blocked(); len(got) != 1 || got[0] != `C:\Apps\app.exe` {
		t.Fatalf("Unblock error cleared memory state: %v", got)
	}
	if reloaded := New(state).Blocked(); len(reloaded) != 1 || reloaded[0] != `C:\Apps\app.exe` {
		t.Fatalf("Unblock error cleared persisted state: %v", reloaded)
	}

	// "No rules match" (English and Russian) means rules are already gone.
	failErr = errors.New("netsh: exit status 1: No rules match the specified criteria.")
	if err := f.Unblock(); err != nil {
		t.Fatalf("English no-rules error failed Unblock: %v", err)
	}
	if got := f.Blocked(); len(got) != 0 {
		t.Fatalf("blocked after English no-rules: %v", got)
	}
	if reloaded := New(state).Blocked(); len(reloaded) != 0 {
		t.Fatalf("persisted state after English no-rules: %v", reloaded)
	}

	if err := f.Block([]string{`C:\Apps\app.exe`}); err != nil {
		t.Fatal(err)
	}
	failErr = errors.New("netsh: exit status 1: Нет правил, соответствующих указанным критериям.")
	if err := f.Unblock(); err != nil {
		t.Fatalf("Russian no-rules error failed Unblock: %v", err)
	}
	if got := f.Blocked(); len(got) != 0 {
		t.Fatalf("blocked after Russian no-rules: %v", got)
	}
}
