package runtime

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"ashgate/internal/engine"
	"ashgate/internal/logbuf"
	"ashgate/internal/packet"
)

const (
	udpShards     = 4
	udpShardDepth = 1024
)

// udpQueue hands proxied UDP datagrams to a few workers. A flow always goes
// to the same worker, so its datagrams leave in the order they came. When a
// worker's queue is full the datagram is dropped, as the network would, and
// the drops are logged as one line a second at most.
type udpQueue struct {
	shards  []chan engine.UDPDatagram
	forward func(engine.UDPDatagram)
	logs    *logbuf.Buffer
	every   time.Duration
	dropped atomic.Int64
	armed   atomic.Bool
	wg      sync.WaitGroup
}

// newUDPQueue starts one worker per shard. Each calls forward for its
// datagrams one at a time.
func newUDPQueue(shards, depth int, logs *logbuf.Buffer, forward func(engine.UDPDatagram)) *udpQueue {
	q := &udpQueue{forward: forward, logs: logs, every: time.Second}
	q.shards = make([]chan engine.UDPDatagram, shards)
	for i := range q.shards {
		ch := make(chan engine.UDPDatagram, depth)
		q.shards[i] = ch
		q.wg.Add(1)
		go func() {
			defer q.wg.Done()
			for d := range ch {
				q.forward(d)
			}
		}()
	}
	return q
}

// push queues d without waiting. It reports false when d was dropped.
func (q *udpQueue) push(d engine.UDPDatagram) bool {
	select {
	case q.shards[shardOf(d, len(q.shards))] <- d:
		return true
	default:
		q.drop()
		return false
	}
}

// close lets the workers finish what is queued and waits for them. push
// must not be called after close.
func (q *udpQueue) close() {
	for _, ch := range q.shards {
		close(ch)
	}
	q.wg.Wait()
}

// drop counts a dropped datagram. The first drop after a report arms a
// timer; the report then logs every drop counted until it runs.
func (q *udpQueue) drop() {
	q.dropped.Add(1)
	if q.armed.CompareAndSwap(false, true) {
		time.AfterFunc(q.every, q.report)
	}
}

func (q *udpQueue) report() {
	// Disarm first: a drop counted after the swap arms the next report.
	q.armed.Store(false)
	n := q.dropped.Swap(0)
	if n > 0 && q.logs != nil {
		q.logs.Add(logbuf.Event{Process: "ashgate", Proto: "UDP", Status: "blocked", Error: fmt.Sprintf("очередь UDP переполнена: отброшено %d", n)})
	}
}

// shardOf picks the shard of d's flow: FNV-1a over its source and
// destination addresses and ports. The low bits of FNV-1a depend only on
// the low bits of each byte, so the high half is folded in first.
func shardOf(d engine.UDPDatagram, n int) int {
	h := uint32(2166136261)
	h = hashAddr(h, d.Key.Src)
	h = hashAddr(h, d.Key.Dst)
	h ^= h >> 16
	return int(h % uint32(n))
}

func hashAddr(h uint32, a packet.Addr) uint32 {
	const prime = 16777619
	n := min(int(a.Len), len(a.IP))
	for _, b := range a.IP[:n] {
		h ^= uint32(b)
		h *= prime
	}
	h ^= uint32(a.Port >> 8)
	h *= prime
	h ^= uint32(a.Port & 0xff)
	h *= prime
	return h
}
