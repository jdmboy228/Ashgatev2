// Package logbuf is a bounded connection log shared by the engine and the GUI.
package logbuf

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxLogBytes = 5 << 20
	logKeep     = 2
	// reopenEvery spaces the tries to open the log again after a rotation
	// could not (a full disk, a file another program holds).
	reopenEvery = 5 * time.Second
)

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// Event is one connection-log line.
type Event struct {
	Time      time.Time `json:"time"`
	Process   string    `json:"process"`
	PID       uint32    `json:"pid"`
	Proto     string    `json:"proto"`
	Dest      string    `json:"dest"`
	Via       string    `json:"via"`
	Status    string    `json:"status"`
	BytesUp   int64     `json:"bytesUp"`
	BytesDown int64     `json:"bytesDown"`
	Error     string    `json:"error,omitempty"`
	// Parent is the application whose rule a child process inherited.
	Parent string `json:"parent,omitempty"`
}

// Buffer keeps the newest events and optionally mirrors them to a JSON-lines
// file. One goroutine writes the file, so Add never waits for the disk: the
// engine logs while holding its packet lock.
type Buffer struct {
	mu   sync.Mutex
	ev   []Event
	cap  int
	pos  int
	full bool
	gen  uint64
	// File output, nil without a file. queued counts the events handed to
	// lines; skipped those a full lines dropped, not yet reported.
	lines   chan Event
	closed  bool
	queued  uint64
	skipped atomic.Int64
	w       *fileWriter
}

const (
	// fileQueue is how many events wait for the writer. A slow disk drops
	// lines from the file beyond it, never from the window.
	fileQueue = 4096
	// flushEvery bounds how long a written line stays in the writer's
	// buffer while events keep coming.
	flushEvery = 100 * time.Millisecond
)

// New returns an in-memory buffer. file may be empty.
func New(capacity int, file string) (*Buffer, error) {
	if capacity < 1 {
		capacity = 2000
	}
	b := &Buffer{ev: make([]Event, capacity), cap: capacity}
	if file == "" {
		return b, nil
	}
	f, err := os.OpenFile(file, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	b.w = newFileWriter(file, f)
	b.lines = make(chan Event, fileQueue)
	go b.w.run(b.lines, &b.skipped)
	return b, nil
}

// Close writes the queued events and closes the log file.
func (b *Buffer) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	if b.lines == nil || b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	close(b.lines)
	b.mu.Unlock()
	return b.w.wait()
}

// Flush waits until the events added so far are in the log file.
func (b *Buffer) Flush() {
	if b == nil {
		return
	}
	b.mu.Lock()
	target, w := b.queued, b.w
	b.mu.Unlock()
	if w != nil {
		w.waitFor(target)
	}
}

// Add appends an event. A zero time is replaced with the current local time.
func (b *Buffer) Add(e Event) {
	if b == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	b.mu.Lock()
	b.ev[b.pos] = e
	b.pos = (b.pos + 1) % b.cap
	if b.pos == 0 {
		b.full = true
	}
	b.gen++
	if b.lines != nil && !b.closed {
		select {
		case b.lines <- e:
			b.queued++
		default:
			b.skipped.Add(1)
		}
	}
	b.mu.Unlock()
}

// fileWriter owns the log file. Only its run goroutine writes; Flush and
// Close wait on mu.
type fileWriter struct {
	path string
	file *os.File
	buf  *bufio.Writer
	enc  *json.Encoder
	// size is the file length plus what buf holds, so writing does not
	// stat the file for every event.
	size int64
	// retryAt is when write may try to open a missing file again; now is the
	// clock (tests replace it).
	retryAt time.Time
	now     func() time.Time

	mu      sync.Mutex
	cond    sync.Cond
	written uint64
	stopped bool
	err     error
}

// sizeWriter counts bytes written to the log file.
type sizeWriter struct {
	w io.Writer
	n *int64
}

func (w sizeWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	*w.n += int64(n)
	return n, err
}

func newFileWriter(path string, f *os.File) *fileWriter {
	w := &fileWriter{path: path, buf: bufio.NewWriterSize(f, 64<<10), now: time.Now}
	w.cond.L = &w.mu
	w.attach(f)
	return w
}

// attach makes f the live log file, writing a BOM to a new file.
func (w *fileWriter) attach(f *os.File) {
	w.size = 0
	if st, err := f.Stat(); err == nil {
		w.size = st.Size()
	}
	w.file = f
	w.buf.Reset(f)
	sw := sizeWriter{w: w.buf, n: &w.size}
	if w.size == 0 {
		_, _ = sw.Write(utf8BOM)
	}
	w.enc = json.NewEncoder(sw)
	w.enc.SetEscapeHTML(false)
}

// run writes events until lines closes. It flushes when no event is
// waiting, and at least every flushEvery, then tells Flush how far it got.
// Lines skipped while lines was full are reported once it drains.
func (w *fileWriter) run(lines <-chan Event, skipped *atomic.Int64) {
	var done uint64
	last := time.Now()
	for e := range lines {
		w.write(e)
		done++
		idle := len(lines) == 0
		if !idle && time.Since(last) < flushEvery {
			continue
		}
		if idle {
			w.reportSkipped(skipped)
		}
		_ = w.buf.Flush()
		last = time.Now()
		w.mu.Lock()
		w.written += done
		w.mu.Unlock()
		w.cond.Broadcast()
		done = 0
	}
	w.reportSkipped(skipped)
	_ = w.buf.Flush()
	var err error
	if w.file != nil {
		err = w.file.Close()
		w.file = nil
	}
	w.mu.Lock()
	w.written += done
	w.stopped = true
	w.err = err
	w.mu.Unlock()
	w.cond.Broadcast()
}

func (w *fileWriter) reportSkipped(skipped *atomic.Int64) {
	if n := skipped.Swap(0); n > 0 {
		w.write(Event{Time: time.Now(), Process: "ashgate", Status: "error", Error: fmt.Sprintf("пропущено строк журнала: %d (запись на диск не успевала)", n)})
	}
}

func (w *fileWriter) write(e Event) {
	if w.file == nil && !w.reopen() {
		return
	}
	if w.size >= maxLogBytes {
		w.rotate()
	}
	if w.enc != nil {
		_ = w.enc.Encode(e)
	}
}

// waitFor blocks until n events are written or the writer stopped.
func (w *fileWriter) waitFor(n uint64) {
	w.mu.Lock()
	for w.written < n && !w.stopped {
		w.cond.Wait()
	}
	w.mu.Unlock()
}

// wait blocks until the writer stopped and returns the file's close error.
func (w *fileWriter) wait() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	for !w.stopped {
		w.cond.Wait()
	}
	return w.err
}

// reopen opens the log again after a rotation left it closed, at most once
// per reopenEvery. Without it one failed rotation would end the file log
// until restart. It reports that the file is open.
func (w *fileWriter) reopen() bool {
	if w.path == "" {
		return false
	}
	now := w.now()
	if now.Before(w.retryAt) {
		return false
	}
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		w.retryAt = now.Add(reopenEvery)
		return false
	}
	w.attach(f)
	return true
}

func (w *fileWriter) rotate() {
	if w.path == "" || w.file == nil {
		return
	}
	_ = w.buf.Flush()
	_ = w.file.Close()
	w.file = nil
	w.enc = nil
	_ = os.Remove(w.path + ".2")
	if logKeep < 2 {
		_ = os.Remove(w.path + ".1")
	} else {
		_ = os.Rename(w.path+".1", w.path+".2")
	}
	renamed := os.Rename(w.path, w.path+".1") == nil
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		// write tries again in reopenEvery.
		w.retryAt = w.now().Add(reopenEvery)
		return
	}
	w.attach(f)
	if !renamed {
		// Another program holds the file open, so it could not be renamed.
		// Try again after another maxLogBytes instead of on every event.
		w.size = 0
	}
}

// Clear drops the in-memory events. A log file, if any, is left as history.
func (b *Buffer) Clear() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := range b.ev {
		b.ev[i] = Event{}
	}
	b.pos = 0
	b.full = false
	b.gen++
}

// Generation changes every time an event is added.
func (b *Buffer) Generation() uint64 {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.gen
}

// Snapshot returns events from oldest to newest.
func (b *Buffer) Snapshot() []Event {
	return b.Recent(0)
}

// Recent returns the newest n events (all of them when n < 1), oldest
// first. The window asks for a few hundred on every poll; copying only
// those keeps the poll cheap.
func (b *Buffer) Recent(n int) []Event {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	size := b.pos
	if b.full {
		size = b.cap
	}
	if size == 0 {
		return nil
	}
	if n < 1 || n > size {
		n = size
	}
	out := make([]Event, n)
	// The newest event is at pos-1; the oldest wanted one is n before pos.
	start := b.pos - n
	if start >= 0 {
		copy(out, b.ev[start:b.pos])
		return out
	}
	k := copy(out, b.ev[b.cap+start:])
	copy(out[k:], b.ev[:b.pos])
	return out
}
