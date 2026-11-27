package engine

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"ashgate/internal/logbuf"
	"ashgate/internal/rules"
)

// DirectProcs help the window show which programs bypass the rules. A
// program whose traffic goes direct is remembered until its flow is cached
// (see directTCP/directUDP) or it is bound to a rule, so the user can add it
// as a companion of an existing application.

// ageMap is ageSet with a value per key: rotate drops entries not used since
// the previous rotate, so the map stays bounded by the traffic of the last
// two intervals.
type ageMap[K comparable, V any] struct {
	cur map[K]V
	old map[K]V
}

func newAgeMap[K comparable, V any]() ageMap[K, V] {
	return ageMap[K, V]{cur: map[K]V{}, old: map[K]V{}}
}

// get returns k's value and keeps it alive for another generation.
func (m *ageMap[K, V]) get(k K) (V, bool) {
	if v, ok := m.cur[k]; ok {
		return v, true
	}
	if v, ok := m.old[k]; ok {
		delete(m.old, k)
		if m.cur == nil {
			m.cur = map[K]V{}
		}
		m.cur[k] = v
		return v, true
	}
	var zero V
	return zero, false
}

func (m *ageMap[K, V]) set(k K, v V) {
	if m.cur == nil {
		m.cur = map[K]V{}
	}
	m.cur[k] = v
}

func (m *ageMap[K, V]) del(k K) {
	delete(m.cur, k)
	delete(m.old, k)
}

func (m *ageMap[K, V]) rotate() {
	m.old = m.cur
	m.cur = map[K]V{}
}

func (m *ageMap[K, V]) clear() {
	m.cur = map[K]V{}
	m.old = map[K]V{}
}

func (m *ageMap[K, V]) len() int { return len(m.cur) + len(m.old) }

// DirectProc is the snapshot of one program whose traffic went direct
// without a matching rule.
type DirectProc struct {
	Name        string   `json:"name"`
	Path        string   `json:"path"`
	PID         uint32   `json:"pid"`
	Started     int64    `json:"started"`
	Conns       int64    `json:"conns"`
	Bytes       int64    `json:"bytes"`
	FirstSeen   int64    `json:"firstSeen"` // Unix ms
	LastSeen    int64    `json:"lastSeen"`  // Unix ms
	SampleDests []string `json:"sampleDests,omitempty"`
	System      bool     `json:"system,omitempty"`
}

const (
	// maxDirectProcs bounds the unmatched programs kept. A machine with a
	// large program churn must not grow the list forever.
	maxDirectProcs = 256
	// maxDirectDests is how many destinations one program remembers.
	maxDirectDests = 4
	// maxDirectEvents is the size of the unmatched-traffic feed.
	maxDirectEvents = 200
	// directEventEvery throttles identical (program, destination) events.
	directEventEvery = 2 * time.Second
	// maxDirectEvKeys bounds the throttle map; it is cleared when full.
	maxDirectEvKeys = 512
	// directIdle drops a program that sent nothing for this long.
	directIdle = 5 * time.Minute
)

// directProcEntry is one unmatched program's counters. The atomic fields are
// read and written without locks (the packet path); the rest is guarded by
// directTracker.mu.
type directProcEntry struct {
	name        string
	path        string
	pid         uint32
	started     int64
	firstSeen   int64
	sampleDests []string
	system      bool
	evicted     atomic.Bool
	conns       atomic.Int64
	bytes       atomic.Int64
	lastSeen    atomic.Int64
}

// addBytes counts another packet of this program, without taking a lock.
func (e *directProcEntry) addBytes(n, nowMs int64) {
	e.bytes.Add(n)
	e.lastSeen.Store(nowMs)
}

// addDest keeps dest among the newest unique destinations.
func (e *directProcEntry) addDest(dest string) {
	if dest == "" {
		return
	}
	for i, d := range e.sampleDests {
		if d == dest {
			e.sampleDests = append(e.sampleDests[:i], e.sampleDests[i+1:]...)
			break
		}
	}
	e.sampleDests = append(e.sampleDests, dest)
	if len(e.sampleDests) > maxDirectDests {
		e.sampleDests = append(e.sampleDests[:0], e.sampleDests[len(e.sampleDests)-maxDirectDests:]...)
	}
}

// directEvKey identifies one throttle slot.
type directEvKey struct {
	proc, dest string
}

// directTracker remembers the programs whose traffic went direct without a
// rule, and a bounded feed of their destinations.
type directTracker struct {
	mu    sync.Mutex
	procs map[string]*directProcEntry
	// events is a ring of the newest unmatched-traffic events.
	events []logbuf.Event
	pos    int
	full   bool
	gen    uint64
	// lastEv throttles the feed: the same (program, destination) pair is
	// logged at most once per directEventEvery.
	lastEv map[directEvKey]int64
}

func (t *directTracker) init() {
	t.procs = map[string]*directProcEntry{}
	t.events = make([]logbuf.Event, maxDirectEvents)
	t.lastEv = map[directEvKey]int64{}
}

// record credits one packet of proc that was not matched by any rule. It
// returns the entry so the address can cache it; nil when proc is unknown.
func (t *directTracker) record(proc rules.Process, proto, dest string, pktBytes int, now time.Time) *directProcEntry {
	if proc.PID == 0 && proc.Name == "" && proc.Path == "" {
		return nil
	}
	key := rules.NormalizePath(proc.Path)
	if key == "" {
		key = rules.NormalizeName(proc.Name)
	}
	if key == "" {
		return nil
	}
	nowMs := now.UnixMilli()
	system := rules.IsShellOrSystem(proc) || rules.IsSystemDNS(proc.Name)

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.procs == nil {
		t.init()
	}
	e := t.procs[key]
	if e == nil {
		if len(t.procs) >= maxDirectProcs {
			t.evictOldestLocked()
		}
		e = &directProcEntry{firstSeen: nowMs}
		t.procs[key] = e
	}
	if name := display(proc); name != "" {
		e.name = name
	}
	if proc.Path != "" {
		e.path = proc.Path
	}
	e.pid = proc.PID
	e.started = proc.Started
	e.system = e.system || system
	e.conns.Add(1)
	e.bytes.Add(int64(pktBytes))
	e.lastSeen.Store(nowMs)
	e.addDest(dest)

	if !e.system {
		evKey := directEvKey{proc: key, dest: dest}
		prev, seen := t.lastEv[evKey]
		if !seen || nowMs-prev >= directEventEvery.Milliseconds() {
			if !seen && len(t.lastEv) >= maxDirectEvKeys {
				clear(t.lastEv)
			}
			t.lastEv[evKey] = nowMs
			t.pushEventLocked(logbuf.Event{
				Time:    now,
				Process: display(proc),
				Path:    proc.Path,
				PID:     proc.PID,
				Proto:   proto,
				Dest:    dest,
				Via:     "direct",
				Status:  "unmatched",
			})
		}
	}
	return e
}

// evictOldestLocked drops the program that sent nothing for the longest.
// Callers hold t.mu.
func (t *directTracker) evictOldestLocked() {
	oldKey := ""
	var oldest int64
	for k, e := range t.procs {
		ls := e.lastSeen.Load()
		if oldKey == "" || ls < oldest {
			oldest, oldKey = ls, k
		}
	}
	if oldKey != "" {
		if old := t.procs[oldKey]; old != nil {
			old.evicted.Store(true)
		}
		delete(t.procs, oldKey)
	}
}

// pushEventLocked appends to the event ring. Callers hold t.mu.
func (t *directTracker) pushEventLocked(ev logbuf.Event) {
	if len(t.events) == 0 {
		t.events = make([]logbuf.Event, maxDirectEvents)
	}
	t.events[t.pos] = ev
	t.pos = (t.pos + 1) % len(t.events)
	if t.pos == 0 {
		t.full = true
	}
	t.gen++
}

// pruneMatched forgets the programs a rule now names. Apply calls it, so a
// program just added as a companion disappears from the list at once.
func (t *directTracker) pruneMatched(rs *rules.Set) {
	if t == nil || rs == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, e := range t.procs {
		if rs.Match(rules.Process{Name: e.name, Path: e.path}).Action != "" {
			e.evicted.Store(true)
			delete(t.procs, k)
		}
	}
}

// pruneKey forgets one program by key, when an auto match attributes it to a
// rule. It marks the entry evicted so a cached direct address stops using it.
func (t *directTracker) pruneKey(key string) {
	if t == nil || key == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if e := t.procs[key]; e != nil {
		e.evicted.Store(true)
		delete(t.procs, key)
		t.gen++
	}
}

// sweep drops programs that sent nothing for directIdle.
func (t *directTracker) sweep(now time.Time) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, e := range t.procs {
		last := time.UnixMilli(e.lastSeen.Load())
		if now.Sub(last) > directIdle {
			e.evicted.Store(true)
			delete(t.procs, k)
		}
	}
}

// countRecent counts non-system unmatched programs active within window,
// without allocating or copying the event ring.
func (t *directTracker) countRecent(now time.Time, window time.Duration) int {
	if t == nil {
		return 0
	}
	nowMs := now.UnixMilli()
	winMs := window.Milliseconds()
	t.mu.Lock()
	n := 0
	for _, e := range t.procs {
		if e.system {
			continue
		}
		ls := e.lastSeen.Load()
		if ls <= 0 {
			continue
		}
		if age := nowMs - ls; age >= 0 && age <= winMs {
			n++
		}
	}
	t.mu.Unlock()
	return n
}

// snapshot returns the programs (newest first, then by traffic), the events
// oldest first, and the event generation.
func (t *directTracker) snapshot() ([]DirectProc, []logbuf.Event, uint64) {
	if t == nil {
		return nil, nil, 0
	}
	t.mu.Lock()
	var procs []DirectProc
	if len(t.procs) > 0 {
		procs = make([]DirectProc, 0, len(t.procs))
		for _, e := range t.procs {
			procs = append(procs, DirectProc{
				Name:        e.name,
				Path:        e.path,
				PID:         e.pid,
				Started:     e.started,
				Conns:       e.conns.Load(),
				Bytes:       e.bytes.Load(),
				FirstSeen:   e.firstSeen,
				LastSeen:    e.lastSeen.Load(),
				SampleDests: append([]string(nil), e.sampleDests...),
				System:      e.system,
			})
		}
	}
	evs := t.recentEventsLocked()
	gen := t.gen
	t.mu.Unlock()
	if len(procs) > 1 {
		sort.Slice(procs, func(i, j int) bool {
			if procs[i].LastSeen != procs[j].LastSeen {
				return procs[i].LastSeen > procs[j].LastSeen
			}
			if procs[i].Bytes != procs[j].Bytes {
				return procs[i].Bytes > procs[j].Bytes
			}
			return procs[i].Name < procs[j].Name
		})
	}
	return procs, evs, gen
}

// recentEventsLocked copies the ring oldest first. Callers hold t.mu.
func (t *directTracker) recentEventsLocked() []logbuf.Event {
	size := t.pos
	if t.full {
		size = len(t.events)
	}
	if size == 0 {
		return nil
	}
	out := make([]logbuf.Event, size)
	start := t.pos - size
	if start >= 0 {
		copy(out, t.events[start:t.pos])
		return out
	}
	n := copy(out, t.events[len(t.events)+start:])
	copy(out[n:], t.events[:t.pos])
	return out
}

// clearEvents empties the feed, resets its throttle map, and bumps its generation.
func (t *directTracker) clearEvents() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := range t.events {
		t.events[i] = logbuf.Event{}
	}
	t.pos = 0
	t.full = false
	clear(t.lastEv)
	t.gen++
}

// DirectSnapshot returns the unmatched programs and their event feed.
func (e *Engine) DirectSnapshot() ([]DirectProc, []logbuf.Event, uint64) {
	if e == nil {
		return nil, nil, 0
	}
	return e.direct.snapshot()
}

// DirectCount returns the number of non-system unmatched programs active within window.
func (e *Engine) DirectCount(now time.Time, window time.Duration) int {
	if e == nil {
		return 0
	}
	return e.direct.countRecent(now, window)
}

// ClearDirectEvents empties the unmatched-traffic feed.
func (e *Engine) ClearDirectEvents() {
	if e == nil {
		return
	}
	e.direct.clearEvents()
}
