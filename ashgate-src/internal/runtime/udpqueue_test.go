package runtime

import (
	"encoding/binary"
	goruntime "runtime"
	"sync"
	"testing"
	"time"

	"ashgate/internal/engine"
	"ashgate/internal/logbuf"
	"ashgate/internal/packet"
)

func datagramOf(flow, seq int) engine.UDPDatagram {
	var d engine.UDPDatagram
	d.Key.Src = packet.V4(10, 0, byte(flow>>8), byte(flow), uint16(40000+flow))
	d.Key.Dst = packet.V4(1, 1, 1, 1, 443)
	d.Payload = binary.BigEndian.AppendUint32(nil, uint32(seq))
	return d
}

func TestUDPQueueKeepsFlowOrder(t *testing.T) {
	const flows, per = 40, 300
	var mu sync.Mutex
	got := map[packet.Addr][]uint32{}
	q := newUDPQueue(udpShards, 16, nil, func(d engine.UDPDatagram) {
		mu.Lock()
		got[d.Key.Src] = append(got[d.Key.Src], binary.BigEndian.Uint32(d.Payload))
		mu.Unlock()
	})
	for seq := 0; seq < per; seq++ {
		for f := 0; f < flows; f++ {
			// Retrying the same datagram until it fits keeps the order.
			for !q.push(datagramOf(f, seq)) {
				goruntime.Gosched()
			}
		}
	}
	q.close()
	if len(got) != flows {
		t.Fatalf("%d flows arrived", len(got))
	}
	for src, seqs := range got {
		if len(seqs) != per {
			t.Fatalf("%s: %d datagrams", src, len(seqs))
		}
		for i, s := range seqs {
			if s != uint32(i) {
				t.Fatalf("%s: datagram %d arrived as %d", src, s, i)
			}
		}
	}
}

func TestUDPQueueSpreadsFlows(t *testing.T) {
	used := map[int]int{}
	for f := 0; f < 400; f++ {
		d := datagramOf(f, 0)
		s := shardOf(d, udpShards)
		if s != shardOf(datagramOf(f, 99), udpShards) {
			t.Fatal("one flow on two shards")
		}
		used[s]++
	}
	for s := 0; s < udpShards; s++ {
		if used[s] < 50 {
			t.Fatalf("shard use %v", used)
		}
	}
	var bad engine.UDPDatagram
	bad.Key.Src = packet.Addr{Len: 200, Port: 1}
	_ = shardOf(bad, udpShards) // a bad length must not panic
}

func TestUDPQueueCountsDrops(t *testing.T) {
	logs, _ := logbuf.New(10, "")
	started := make(chan struct{}, 1)
	gate := make(chan struct{})
	q := newUDPQueue(1, 2, logs, func(engine.UDPDatagram) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-gate
	})
	q.every = 30 * time.Millisecond
	if !q.push(datagramOf(1, 0)) {
		t.Fatal("first datagram dropped")
	}
	<-started // the worker holds it; the queue is empty again
	for i := 1; i <= 2; i++ {
		if !q.push(datagramOf(1, i)) {
			t.Fatalf("datagram %d dropped with room left", i)
		}
	}
	for i := 0; i < 5; i++ {
		if q.push(datagramOf(1, 10+i)) {
			t.Fatal("pushed past a full queue")
		}
	}
	want := "очередь UDP переполнена: отброшено 5"
	deadline := time.Now().Add(3 * time.Second)
	for len(logs.Snapshot()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(3 * q.every) // no second line for the same drops
	ev := logs.Snapshot()
	if len(ev) != 1 || ev[0].Error != want || ev[0].Proto != "UDP" {
		t.Fatalf("log %+v", ev)
	}
	// A later burst is reported on its own.
	q.push(datagramOf(1, 20))
	for len(logs.Snapshot()) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if ev := logs.Snapshot(); len(ev) != 2 || ev[1].Error != "очередь UDP переполнена: отброшено 1" {
		t.Fatalf("log %+v", ev)
	}
	close(gate)
	q.close()
}
