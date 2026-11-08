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
