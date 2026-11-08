package process

import (
	"sync"
	"time"

	"ashgate/internal/packet"
	"ashgate/internal/rules"
)

const (
	closeGrace = 15 * time.Second
	helperGap  = 50 * time.Millisecond
	// pruneEvery bounds how often Observe drops expired entries. Without it
	// every socket the machine ever closed would stay in memory.
	pruneEvery = 30 * time.Second
	// maxImages caps the PID cache when the platform cannot tell whether a
	// process has exited.
	maxImages = 4096
	// maxParents bounds the ancestor chain.
	maxParents = 8
	// maxMisses bounds missAt; a full map is cleared.
	maxMisses = 4096
	// missKeep is how long a miss is remembered. Held packets are decided
	// within 50 ms; older entries are of packets decided elsewhere.
	missKeep = 10 * time.Second
	// systemPID is the kernel ("System"). It has no image to read, and its
	// sockets (SMB, NetBIOS) belong to no program a rule can name.
	systemPID = 4
)

type exactKey struct {
	proto uint8
	addr  packet.Addr
}

type wildKey struct {
	proto uint8
	port  uint16
}

type entry struct {
	proc  rules.Process
	until time.Time
	// closed is when the socket closed; zero while it is open.
	closed time.Time
}

// Resolver remembers SOCKET/FLOW events and falls back to the IP Helper tables.
// A socket event wins over the helper table so a stale table cannot replace it.
type Resolver struct {
	mu         sync.Mutex
	exact      map[exactKey]entry
	wild       map[wildKey]entry
	helper     map[exactKey]uint32
	helperWild map[wildKey]uint32
	images     map[uint32]rules.Process
	// helperAt is when the tables in helper were read (the read's start);
	// triedAt is when the last read started, failed ones included. loading
	// is closed when the read in progress ends; nil when none runs.
	helperAt time.Time
	triedAt  time.Time
	loading  chan struct{}
	// missAt is when a lookup of a socket first came back empty. Its packet
	// is held from then, so only tables read after it can list its socket.
	missAt     map[exactKey]time.Time
	pruneAt    time.Time
	now        func() time.Time
	image      func(pid uint32) rules.Process
	loadHelper func() ([]Endpoint, error)
	// present reports that a process with pid runs, even one whose image
	// cannot be read (a protected process). Nil means it does.
	present func(pid uint32) bool
	// exited reports that pid no longer names the process cached for it.
	// Windows reuses PIDs, so a cached name must be checked before reuse.
	// Nil means the platform cannot tell; the cache is then only size-capped.
	exited func(pid uint32) bool
	// release frees platform resources, such as held process handles.
	release func()
}

// Close releases process handles held for the PID cache.
func (r *Resolver) Close() {
	if r != nil && r.release != nil {
		r.release()
	}
}

// New returns an empty resolver. On Windows it also queries IP Helper.
func New() *Resolver {
	r := &Resolver{
		exact:      map[exactKey]entry{},
		wild:       map[wildKey]entry{},
		helper:     map[exactKey]uint32{},
		helperWild: map[wildKey]uint32{},
		images:     map[uint32]rules.Process{},
		missAt:     map[exactKey]time.Time{},
		now:        time.Now,
		image: func(pid uint32) rules.Process {
			return rules.Process{PID: pid}
		},
	}
	configure(r)
	return r
}

// Observe records a SOCKET or FLOW event. closing keeps the entry for closeGrace.
func (r *Resolver) Observe(proto uint8, local packet.Addr, pid uint32, closing bool) {
	if r == nil || pid == 0 || local.Port == 0 || (proto != packet.ProtoTCP && proto != packet.ProtoUDP) {
		return
	}
	now := r.now()
	proc := r.resolve(pid)
	e := entry{proc: proc}
	if closing {
		e.closed = now
		e.until = now.Add(closeGrace)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if unspecified(local) {
		r.wild[wildKey{proto, local.Port}] = e
	} else {
		r.exact[exactKey{proto, local}] = e
	}
	if r.pruneAt.IsZero() {
		r.pruneAt = now
	} else if now.Sub(r.pruneAt) >= pruneEvery {
		r.pruneLocked(now)
	}
}

// pruneLocked drops closed sockets past their grace period, sockets of
// processes that have exited (their CLOSE event may have been lost), and
// cached images of exited processes.
func (r *Resolver) pruneLocked(now time.Time) {
	r.pruneAt = now
	gone := map[uint32]bool{}
	dead := func(pid uint32) bool {
		if r.exited == nil {
			return false
		}
		d, ok := gone[pid]
		if !ok {
			d = r.exited(pid)
			gone[pid] = d
		}
		return d
	}
	for k, e := range r.exact {
		if !alive(e, now) || dead(e.proc.PID) {
			delete(r.exact, k)
		}
	}
	for k, e := range r.wild {
		if !alive(e, now) || dead(e.proc.PID) {
			delete(r.wild, k)
		}
	}
	for pid := range r.images {
		if dead(pid) {
			delete(r.images, pid)
		}
	}
	for k, at := range r.missAt {
		if now.Sub(at) > missKeep {
			delete(r.missAt, k)
		}
	}
	if len(r.images) > maxImages {
		clear(r.images)
	}
}

// Lookup implements engine.Resolver. It is a last try: it may read the
// IP Helper tables before it answers.
func (r *Resolver) Lookup(proto uint8, src packet.Addr) (rules.Process, bool) {
	return r.Owner(proto, src, false, true)
}

// LookupLive is Lookup without sockets that already closed; see Owner.
func (r *Resolver) LookupLive(proto uint8, src packet.Addr) (rules.Process, bool) {
	return r.Owner(proto, src, true, true)
}

// Owner finds the program of the local socket src.
//
// live is for a packet that starts a flow (a TCP SYN, any UDP): a closed
// socket's entry stays for closeGrace so a connection's last packets keep
// their owner, but its port may already be another program's whose event
// is still on the way. Live, such an entry does not count, and neither
// does a table read before that socket closed: the table may still list
// it. Unknown, the packet waits for the event or a newer table.
//
// final is the last try for a held packet. Before it, a lookup never waits
// for the tables (four table reads on the packet goroutine stall every
// packet): a missing or outdated table starts a read in the background
// and the answer is "unknown", so the capture loop holds the packet and
// asks again. The last try waits for a read when none since the packet
// came has finished, at most one per helperGap.
func (r *Resolver) Owner(proto uint8, src packet.Addr, live, final bool) (rules.Process, bool) {
	if r == nil || src.Port == 0 {
		return rules.Process{}, false
	}
	key := exactKey{proto, src}
	now := r.now()
	r.mu.Lock()
	p, ok, closed := r.socketLocked(proto, src, now, live)
	if ok {
		delete(r.missAt, key)
		r.mu.Unlock()
		return r.finish(p)
	}
	since := r.sinceLocked(key, now, closed, live)
	if !final {
		if r.tableFromLocked(since) {
			if p, ok := r.helperLocked(proto, src); ok {
				delete(r.missAt, key)
				r.mu.Unlock()
				return r.finish(p)
			}
		}
		if _, seen := r.missAt[key]; !seen {
			if len(r.missAt) >= maxMisses {
				clear(r.missAt)
			}
			r.missAt[key] = now
		}
		if !r.tableFromLocked(since) {
			r.startLoadLocked(now)
		}
		r.mu.Unlock()
		return rules.Process{}, false
	}
	delete(r.missAt, key)
	for try := 0; try < 2 && !r.tableFromLocked(since); try++ {
		ch := r.loading
		if ch == nil {
			if ch = r.startLoadLocked(r.now()); ch == nil {
				break // read too recently; use what there is
			}
		}
		r.mu.Unlock()
		<-ch
		r.mu.Lock()
	}
	// The socket's event may have come while the tables were read.
	p, ok, closed = r.socketLocked(proto, src, r.now(), live)
	if !ok && r.tableFromLocked(closed) {
		p, ok = r.helperLocked(proto, src)
	}
	r.mu.Unlock()
	if !ok {
		return rules.Process{}, false
	}
	return r.finish(p)
}

// sinceLocked is the oldest table read that can answer for key. For a new
// flow it must be read after the packet came (the socket existed by then)
// and after the socket closed; otherwise a read within helperGap will do,
// or after the first miss, since an older one already had no answer.
func (r *Resolver) sinceLocked(key exactKey, now, closed time.Time, live bool) time.Time {
	since, seen := r.missAt[key]
	switch {
	case seen:
	case live:
		since = now
	default:
		since = now.Add(-helperGap).Add(time.Nanosecond)
	}
	if closed.After(since) {
		since = closed
	}
	return since
}

// tableFromLocked reports a table read at or after since. A zero since
// takes any table.
func (r *Resolver) tableFromLocked(since time.Time) bool {
	return !r.helperAt.IsZero() && !r.helperAt.Before(since)
}

// startLoadLocked starts a table read on its own goroutine unless one
// runs or the last one started less than helperGap ago. It returns the
// channel closed when the read ends, or nil when none was started.
func (r *Resolver) startLoadLocked(now time.Time) chan struct{} {
	if r.loadHelper == nil || r.loading != nil {
		return nil
	}
	if !r.triedAt.IsZero() && now.Sub(r.triedAt) < helperGap {
		return nil
	}
	ch := make(chan struct{})
	r.loading, r.triedAt = ch, now
	go func() {
		rows, err := r.loadHelper()
		r.mu.Lock()
		if err == nil {
			r.storeHelper(rows, now)
		}
		r.loading = nil
		r.mu.Unlock()
		close(ch)
	}()
	return ch
}

func (r *Resolver) finish(p rules.Process) (rules.Process, bool) {
	if p.Name == "" && p.Path == "" {
		p = r.resolve(p.PID)
	}
	if p.Name != "" || p.Path != "" {
		return p, true
	}
	switch {
	case p.PID == systemPID:
		return rules.Process{PID: systemPID, Name: "System"}, true
	case p.PID == 0, r.present != nil && !r.present(p.PID):
		// The program is gone: its packets are a dead socket's last ones,
		// which the engine decides as having no program.
		return rules.Process{}, false
	}
	// Running, but its image cannot be read (a protected process): it is
	// known, and no rule names it.
	return rules.Process{PID: p.PID}, true
}

// socketLocked finds a socket event for src. live skips closed sockets
// and reports the latest close among them.
func (r *Resolver) socketLocked(proto uint8, src packet.Addr, now time.Time, live bool) (p rules.Process, ok bool, closed time.Time) {
	if e, ok := r.exact[exactKey{proto, src}]; ok {
		switch {
		case !alive(e, now):
			delete(r.exact, exactKey{proto, src})
		case !live || e.until.IsZero():
			return e.proc, true, time.Time{}
		default:
			closed = e.closed
		}
	}
	wk := wildKey{proto, src.Port}
	if e, ok := r.wild[wk]; ok {
		switch {
		case !alive(e, now):
			delete(r.wild, wk)
		case !live || e.until.IsZero():
			return e.proc, true, time.Time{}
		case e.closed.After(closed):
			closed = e.closed
		}
	}
	return rules.Process{}, false, closed
}

// helperLocked returns only the PID. finish resolves the name through
// resolve, which checks that the cached image still belongs to that PID.
func (r *Resolver) helperLocked(proto uint8, src packet.Addr) (rules.Process, bool) {
	if pid, ok := r.helper[exactKey{proto, src}]; ok {
		return rules.Process{PID: pid}, true
	}
	if pid, ok := r.helperWild[wildKey{proto, src.Port}]; ok {
		return rules.Process{PID: pid}, true
	}
	return rules.Process{}, false
}

func (r *Resolver) storeHelper(rows []Endpoint, now time.Time) {
	h := make(map[exactKey]uint32, len(rows))
	w := map[wildKey]uint32{}
	for _, row := range rows {
		if row.PID == 0 || row.Addr.Port == 0 {
			continue
		}
		if row.Unspecified {
			w[wildKey{row.Proto, row.Addr.Port}] = row.PID
			continue
		}
		h[exactKey{row.Proto, row.Addr}] = row.PID
	}
	r.helper = h
	r.helperWild = w
	r.helperAt = now
}

func (r *Resolver) resolve(pid uint32) rules.Process {
	return r.resolveAt(pid, 0)
}

// resolveAt resolves pid and, below maxParents, its ancestor chain. The
// chain is computed once, when the PID is first cached: a parent never
// changes, and it may exit later.
func (r *Resolver) resolveAt(pid uint32, depth int) rules.Process {
	r.mu.Lock()
	p, ok := r.images[pid]
	r.mu.Unlock()
	if ok && (p.Name != "" || p.Path != "") {
		if r.exited == nil || !r.exited(pid) {
			return p
		}
		// The process is gone and the PID may now belong to another one.
		r.mu.Lock()
		if cur, ok := r.images[pid]; ok && cur.Started == p.Started && cur.Path == p.Path {
			delete(r.images, pid)
		}
		r.mu.Unlock()
	}
	if r.image == nil {
		return rules.Process{PID: pid}
	}
	got := r.image(pid)
	got.PID = pid
	if got.Name == "" && got.Path != "" {
		got.Name = rules.Base(got.Path)
	}
	if got.Name == "" && got.Path == "" {
		return got
	}
	if depth < maxParents {
		got.Parents = r.parents(got, depth)
	}
	r.mu.Lock()
	r.images[pid] = got
	r.mu.Unlock()
	return got
}

// parents returns child's ancestors, nearest first. A parent that started
// after the child holds a reused PID and ends the chain, as does one that
// has exited or cannot be opened.
func (r *Resolver) parents(child rules.Process, depth int) []rules.Process {
	if child.PPID == 0 || child.PPID == child.PID {
		return nil
	}
	par := r.resolveAt(child.PPID, depth+1)
	if par.Name == "" && par.Path == "" {
		return nil
	}
	if par.Started != 0 && child.Started != 0 && par.Started > child.Started {
		return nil
	}
	out := make([]rules.Process, 0, 1+len(par.Parents))
	flat := par
	flat.Parents = nil
	out = append(out, flat)
	for _, a := range par.Parents {
		if len(out) >= maxParents || a.PID == child.PID {
			break
		}
		out = append(out, a)
	}
	return out
}

func alive(e entry, now time.Time) bool {
	return e.until.IsZero() || now.Before(e.until)
}

func unspecified(a packet.Addr) bool {
	for i := uint8(0); i < a.Len; i++ {
		if a.IP[i] != 0 {
			return false
		}
	}
	return a.Len == 4 || a.Len == 16
}

// SetClock overrides the clock. Tests use it.
func (r *Resolver) SetClock(now func() time.Time) {
	if now != nil {
		r.now = now
	}
}

// SetImage overrides process-image lookup. Tests use it.
func (r *Resolver) SetImage(fn func(pid uint32) rules.Process) {
	r.image = fn
}

// SetExited overrides the process-exit check. Tests use it.
func (r *Resolver) SetExited(fn func(pid uint32) bool) {
	r.exited = fn
}

// SetHelper overrides the IP Helper refresh. Tests use it.
func (r *Resolver) SetHelper(fn func() ([]Endpoint, error)) {
	r.loadHelper = fn
}

// SetPresent overrides the check that a process runs. Tests use it.
func (r *Resolver) SetPresent(fn func(pid uint32) bool) {
	r.present = fn
}
