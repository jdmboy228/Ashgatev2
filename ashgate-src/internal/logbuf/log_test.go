package logbuf

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileRotatesBySize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ashgate.log")
	b, err := New(4, path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	big := strings.Repeat("x", 64<<10)
	for i := 0; i < maxLogBytes/len(big)+1; i++ {
		b.Add(Event{Process: "curl.exe", Error: big})
	}
	b.Add(Event{Process: "after.exe"})
	b.Flush()
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("no rotated file: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, utf8BOM) || !bytes.Contains(data, []byte("after.exe")) {
		t.Fatalf("fresh log: %.200q", data)
	}
	if b.w.size != int64(len(data)) {
		t.Fatalf("tracked size %d, file %d", b.w.size, len(data))
	}
}

// readLog parses the JSON lines of a log file.
func readLog(t *testing.T, path string) []Event {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.TrimPrefix(data, utf8BOM)
	var out []Event
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("line %q: %v", sc.Text(), err)
		}
		out = append(out, e)
	}
	return out
}

func TestFileKeepsOrderAndFlushes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ashgate.log")
	b, err := New(16, path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	for round := 0; round < 3; round++ {
		for i := 0; i < 1000; i++ {
			b.Add(Event{Process: "curl.exe", Dest: fmt.Sprint(round*1000 + i)})
		}
		b.Flush()
		got := readLog(t, path)
		if len(got) != (round+1)*1000 {
			t.Fatalf("round %d: %d lines after Flush", round, len(got))
		}
		for i, e := range got {
			if e.Dest != fmt.Sprint(i) {
				t.Fatalf("line %d is %q", i, e.Dest)
			}
		}
	}
	if n := len(b.Snapshot()); n != 16 {
		t.Fatalf("ring holds %d", n)
	}
}

func TestCloseDrains(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ashgate.log")
	b, err := New(8, path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 500; i++ {
		b.Add(Event{Dest: fmt.Sprint(i)})
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if got := readLog(t, path); len(got) != 500 || got[499].Dest != "499" {
		t.Fatalf("%d lines after Close", len(got))
	}
	// After Close only the window sees new events.
	b.Add(Event{Dest: "late"})
	b.Flush()
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if got := b.Snapshot(); got[len(got)-1].Dest != "late" {
		t.Fatal("event after Close missing from the ring")
	}
	if got := readLog(t, path); len(got) != 500 {
		t.Fatalf("%d lines: written after Close", len(got))
	}
}

// stoppedBuffer is New with a queue of n and the writer not started yet.
func stoppedBuffer(t *testing.T, path string, n int) (*Buffer, func()) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	b := &Buffer{ev: make([]Event, 32), cap: 32, w: newFileWriter(path, f), lines: make(chan Event, n)}
	return b, func() { go b.w.run(b.lines, &b.skipped) }
}

func TestSkippedLinesAreCounted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ashgate.log")
	b, start := stoppedBuffer(t, path, 3)
	defer b.Close()
	// A stuck writer never holds Add up: the file loses lines, the ring none.
	for i := 0; i < 10; i++ {
		b.Add(Event{Dest: fmt.Sprint(i)})
	}
	if n := len(b.Snapshot()); n != 10 {
		t.Fatalf("ring holds %d", n)
	}
	start()
	b.Flush()
	got := readLog(t, path)
	if len(got) != 4 || got[0].Dest != "0" || got[2].Dest != "2" {
		t.Fatalf("log %+v", got)
	}
	if !strings.Contains(got[3].Error, "пропущено строк журнала: 7") {
		t.Fatalf("summary %+v", got[3])
	}
	b.Add(Event{Dest: "next"})
	b.Flush()
	if got := readLog(t, path); len(got) != 5 || got[4].Dest != "next" {
		t.Fatalf("log after drain %+v", got)
	}
}

func TestNoFileNoWriter(t *testing.T) {
	b, err := New(4, "")
	if err != nil {
		t.Fatal(err)
	}
	b.Add(Event{Dest: "x"})
	b.Flush()
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	var nilBuf *Buffer
	nilBuf.Flush()
}

// A rotation that cannot open the new file must not end the file log: the
// writer tries again, but not for every event.
func TestFileReopensAfterFailedRotation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ashgate.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(1000, 0)
	w := newFileWriter(path, f)
	w.now = func() time.Time { return clock }
	if err := os.RemoveAll(dir); err != nil { // the new file cannot be created
		t.Fatal(err)
	}
	w.rotate()
	if w.file != nil {
		t.Fatal("rotation opened a file in a missing directory")
	}
	w.write(Event{Process: "lost.exe"})
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(reopenEvery - time.Second)
	w.write(Event{Process: "too-soon.exe"})
	if w.file != nil {
		t.Fatal("reopened before reopenEvery")
	}
	clock = clock.Add(time.Second)
	w.write(Event{Process: "back.exe"})
	if w.file == nil {
		t.Fatal("log not reopened")
	}
	_ = w.buf.Flush()
	got := readLog(t, path)
	if len(got) != 1 || got[0].Process != "back.exe" {
		t.Fatalf("log after reopening: %+v", got)
	}
	// A failed try waits another reopenEvery.
	_ = w.file.Close()
	w.file = nil
	_ = os.RemoveAll(dir)
	w.write(Event{Process: "x"})
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	w.write(Event{Process: "y"})
	if w.file != nil {
		t.Fatal("retried at once after a failed try")
	}
}
