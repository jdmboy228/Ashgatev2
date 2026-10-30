// Package logbuf is a bounded connection log shared by the engine and the GUI.
package logbuf

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

const (
	maxLogBytes = 5 << 20
	logKeep     = 2
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

// Buffer keeps the newest events and optionally mirrors them to a JSON-lines file.
type Buffer struct {
	mu   sync.Mutex
	ev   []Event
	cap  int
	pos  int
	full bool
	gen  uint64
	enc  *json.Encoder
	file *os.File
	path string
	// size tracks the log file length so Add does not stat the file for
	// every event. The engine logs while holding its packet lock.
	size int64
}

// sizeWriter counts bytes written to the log file.
type sizeWriter struct {
	f *os.File
	n *int64
}

func (w sizeWriter) Write(p []byte) (int, error) {
	n, err := w.f.Write(p)
	*w.n += int64(n)
	return n, err
}

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
	b.path = file
	b.attach(f)
	return b, nil
}

// attach makes f the live log file, writing a BOM to a new file.
func (b *Buffer) attach(f *os.File) {
	b.size = 0
	if st, err := f.Stat(); err == nil {
		b.size = st.Size()
	}
	b.file = f
	w := sizeWriter{f: f, n: &b.size}
	if b.size == 0 {
		_, _ = w.Write(utf8BOM)
	}
	b.enc = json.NewEncoder(w)
	b.enc.SetEscapeHTML(false)
}

// Close closes the optional log file.
func (b *Buffer) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.file == nil {
		return nil
	}
	err := b.file.Close()
	b.file = nil
	b.enc = nil
	return err
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
	b.writeLocked(e)
	b.mu.Unlock()
}

func (b *Buffer) writeLocked(e Event) {
	if b.file == nil || b.enc == nil {
		return
	}
	if b.size >= maxLogBytes {
		b.rotateLocked()
	}
	if b.enc != nil {
		_ = b.enc.Encode(e)
	}
}

func (b *Buffer) rotateLocked() {
	if b.path == "" || b.file == nil {
		return
	}
	_ = b.file.Close()
	b.file = nil
	b.enc = nil
	_ = os.Remove(b.path + ".2")
	if logKeep < 2 {
		_ = os.Remove(b.path + ".1")
	} else {
		_ = os.Rename(b.path+".1", b.path+".2")
	}
	renamed := os.Rename(b.path, b.path+".1") == nil
	f, err := os.OpenFile(b.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	b.attach(f)
	if !renamed {
		// Another program holds the file open, so it could not be renamed.
		// Try again after another maxLogBytes instead of on every event.
		b.size = 0
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
