package runtime

import (
	"context"
	"time"

	"ashgate/internal/engine"
	"ashgate/internal/windivert"
)

const (
	holdFor    = 50 * time.Millisecond
	holdTick   = 15 * time.Millisecond
	maxPending = 2048
	// recvBatch is the most packets one WinDivertRecvEx returns.
	recvBatch = 64
)

// classifier is the engine as the capture loop uses it.
type classifier interface {
	HandlePacket(pkt []byte, meta engine.Meta, final bool) engine.Result
}

// reinjector hands packets back to WinDivert.
type reinjector interface {
	send(pkt []byte, addr *windivert.Address) error
	sendBatch(b *windivert.Batch) error
}

// netBatch is the packets of one WinDivertRecvEx and their addresses.
type netBatch struct {
	pkts  [][]byte
	addrs []windivert.Address
}

// held is a packet waiting for its socket's event.
type held struct {
	pkt  []byte
	addr windivert.Address
	at   time.Time
}

// capture decides captured packets and reinjects them with one SendBatch
// per received batch and per hold tick. Only the consume goroutine uses it.
type capture struct {
	eng     classifier
	out     reinjector
	udp     *udpQueue
	limit   int
	now     func() time.Time
	pending []held
	batch   windivert.Batch
}

func newCapture(eng classifier, out reinjector, udp *udpQueue) *capture {
	return &capture{eng: eng, out: out, udp: udp, limit: maxPending, now: time.Now}
}

// consume decides the packets from in until it closes or ctx ends. Held
// packets are retried every holdTick.
func consume(ctx context.Context, c *capture, in <-chan netBatch) {
	tick := time.NewTicker(holdTick)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			c.release(true)
			return
		case b, ok := <-in:
			if !ok {
				c.release(true)
				return
			}
			c.handle(b)
		case <-tick.C:
			c.release(false)
		}
	}
}

// handle decides a received batch in order and reinjects what goes on.
func (c *capture) handle(b netBatch) {
	for i, pkt := range b.pkts {
		c.queue(pkt, b.addrs[i])
	}
	c.flush()
}

// queue decides a new packet, or holds it while its program is unknown. A
// full hold queue makes room by deciding its oldest packet as final.
func (c *capture) queue(pkt []byte, addr windivert.Address) {
	res := c.eng.HandlePacket(pkt, metaOf(&addr), false)
	if res.Action != engine.ActionUnknown {
		c.apply(pkt, addr, res)
		return
	}
	if len(c.pending) > 0 && len(c.pending) >= c.limit {
		old := c.pending[0]
		c.pending[0] = held{}
		c.pending = c.pending[1:]
		c.decideFinal(old.pkt, old.addr)
	}
	// A copy: a slice of the batch would keep all of it in memory.
	c.pending = append(c.pending, held{pkt: append([]byte(nil), pkt...), addr: addr, at: c.now()})
}

// release retries the held packets in order. Those held for holdFor, or
// all of them when force is set, are decided as final.
func (c *capture) release(force bool) {
	if len(c.pending) == 0 {
		return
	}
	now := c.now()
	keep := c.pending[:0]
	for _, h := range c.pending {
		if force || now.Sub(h.at) >= holdFor {
			c.decideFinal(h.pkt, h.addr)
			continue
		}
		// The owning socket's event has often arrived by now. Decide
		// on this tick instead of always waiting the full holdFor.
		res := c.eng.HandlePacket(h.pkt, metaOf(&h.addr), false)
		if res.Action == engine.ActionUnknown {
			keep = append(keep, h)
			continue
		}
		c.apply(h.pkt, h.addr, res)
	}
	clear(c.pending[len(keep):])
	c.pending = keep
	c.flush()
}

func (c *capture) decideFinal(pkt []byte, addr windivert.Address) {
	res := c.eng.HandlePacket(pkt, metaOf(&addr), true)
	if res.Action == engine.ActionUnknown {
		res.Action = engine.ActionPass
	}
	c.apply(pkt, addr, res)
}

// apply carries out the engine's decision. A packet to reinject joins the
// send batch; flush sends it.
func (c *capture) apply(pkt []byte, addr windivert.Address, res engine.Result) {
	switch res.Action {
	case engine.ActionDrop:
		return
	case engine.ActionUDP:
		if res.UDP != nil && c.udp != nil {
			c.udp.push(*res.UDP)
		}
		return
	case engine.ActionModified:
		// Impostor stops this handle from taking the packet again.
		// WinDivert decrements TTL on impostor packets; that is acceptable
		// because the packet was rewritten. Unmodified packets keep the
		// address WinDivertRecv returned, so their TTL and checksum offload
		// flags stay as they were.
		addr.SetImpostor(true)
		if res.Inbound {
			addr.SetOutbound(false)
			addr.SetIfIdx(res.IfIdx)
			addr.SetSubIfIdx(res.SubIfIdx)
		}
		windivert.MarkValidChecksums(&addr, pkt)
	}
	c.send(pkt, &addr)
}

func (c *capture) send(pkt []byte, addr *windivert.Address) {
	if c.batch.Add(pkt, addr) {
		return
	}
	c.flush()
	if !c.batch.Add(pkt, addr) {
		// Its IP length is not its size, so the driver could not cut it
		// out of a batch. It goes alone, after the packets before it.
		_ = c.out.send(pkt, addr)
	}
}

// flush sends the batch. Errors are ignored as for single packets; a failed
// batch is not resent packet by packet, which could send some twice.
func (c *capture) flush() {
	if c.batch.Len() == 0 {
		return
	}
	_ = c.out.sendBatch(&c.batch)
	c.batch.Reset()
}

func metaOf(a *windivert.Address) engine.Meta {
	return engine.Meta{IfIdx: a.IfIdx(), SubIfIdx: a.SubIfIdx()}
}
