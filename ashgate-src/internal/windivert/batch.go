package windivert

import "encoding/binary"

// Batch limits from windivert.h 2.2.2.
const (
	BatchMax = 255
	MTUMax   = 40 + 0xFFFF
)

// Queue limits from windivert.h 2.2.2.
const (
	QueueLengthMax = 16384
	QueueSizeMax   = 32 << 20
)

// SplitBatch cuts the packets of one WinDivertRecvEx buffer and appends them
// to out. The driver packs packets back to back, so each one ends where its
// IP length field says. At most limit packets are cut: the last one, and a
// packet whose length is zero, too short for its header or past the end of
// buf, takes the rest. No bytes are lost that way: the engine passes a
// packet it cannot parse.
//
// Each packet's capacity ends with it, so an append to one cannot overwrite
// the next.
func SplitBatch(buf []byte, limit int, out [][]byte) [][]byte {
	for i := 0; i < limit && len(buf) > 0; i++ {
		n := ipLen(buf)
		if n == 0 || n > len(buf) || i == limit-1 {
			n = len(buf)
		}
		out = append(out, buf[:n:n])
		buf = buf[n:]
	}
	return out
}

// ipLen is the length the IPv4 or IPv6 header at the start of b gives, or 0
// when there is no usable header. IPv6 without payload is not usable: the
// network handle only takes TCP and UDP, which have headers of their own.
func ipLen(b []byte) int {
	if len(b) < 1 {
		return 0
	}
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return 0
		}
		ihl := int(b[0]&0x0f) * 4
		n := int(binary.BigEndian.Uint16(b[2:4]))
		if ihl < 20 || n < ihl {
			return 0
		}
		return n
	case 6:
		if len(b) < 40 {
			return 0
		}
		payload := int(binary.BigEndian.Uint16(b[4:6]))
		if payload == 0 {
			return 0
		}
		return 40 + payload
	}
	return 0
}

// batchBytes bounds a send batch, so its reused buffer stays the size of
// a received batch of 64 even when large packets are released together.
const batchBytes = 64 * MTUMax

// Batch collects packets for one SendBatch. The zero value is empty.
type Batch struct {
	Buf   []byte
	Addrs []Address
}

// Add appends pkt and its address. It adds nothing and reports false when
// the batch is full, or when pkt's IP length is not its size: the driver
// splits a batch by that length, so such a packet must be sent alone.
func (b *Batch) Add(pkt []byte, addr *Address) bool {
	if len(b.Addrs) >= BatchMax || len(pkt) == 0 || ipLen(pkt) != len(pkt) {
		return false
	}
	if len(b.Buf) > 0 && len(b.Buf)+len(pkt) > batchBytes {
		return false
	}
	b.Buf = append(b.Buf, pkt...)
	b.Addrs = append(b.Addrs, *addr)
	return true
}

// Len is the number of packets in the batch.
func (b *Batch) Len() int { return len(b.Addrs) }

// Reset empties the batch and keeps its memory.
func (b *Batch) Reset() {
	b.Buf = b.Buf[:0]
	b.Addrs = b.Addrs[:0]
}

// Skip drops from the front the packets that SendBatch has dealt with:
// those sent whole, and the one the send stopped in. sent is the byte count
// SendBatch returned with its error. The packets left are the ones never
// tried; the caller sends them as a new batch, so no packet goes out twice.
func (b *Batch) Skip(sent int) {
	if sent < 0 {
		sent = 0
	}
	off, n := 0, 0
	for n < len(b.Addrs) && off <= sent {
		l := ipLen(b.Buf[off:])
		if l == 0 || off+l > len(b.Buf) {
			// Cannot happen for packets that Add took; give up on the rest.
			off, n = len(b.Buf), len(b.Addrs)
			break
		}
		off += l
		n++
	}
	b.Buf = b.Buf[:copy(b.Buf, b.Buf[off:])]
	b.Addrs = b.Addrs[:copy(b.Addrs, b.Addrs[n:])]
}
