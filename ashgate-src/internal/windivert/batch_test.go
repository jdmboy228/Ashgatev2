package windivert

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"ashgate/internal/packet"
)

func udp4(t *testing.T, n int) []byte {
	t.Helper()
	pkt, err := packet.BuildUDP(packet.V4(10, 0, 0, 1, 1000), packet.V4(1, 2, 3, 4, 53), bytes.Repeat([]byte{4}, n))
	if err != nil {
		t.Fatal(err)
	}
	return pkt
}

func tcp6(t *testing.T) []byte {
	t.Helper()
	pkt, err := packet.BuildTCP(packet.FromIP(net.ParseIP("2001:db8::1"), 1000), packet.FromIP(net.ParseIP("2001:db8::2"), 443), 0x02)
	if err != nil {
		t.Fatal(err)
	}
	return pkt
}

func udp6(t *testing.T, n int) []byte {
	t.Helper()
	pkt, err := packet.BuildUDP(packet.FromIP(net.ParseIP("2001:db8::1"), 1000), packet.FromIP(net.ParseIP("2001:db8::2"), 53), bytes.Repeat([]byte{6}, n))
	if err != nil {
		t.Fatal(err)
	}
	return pkt
}

func join(pkts ...[]byte) []byte {
	var b []byte
	for _, p := range pkts {
		b = append(b, p...)
	}
	return b
}

func sameSplit(t *testing.T, got [][]byte, want ...[]byte) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%d packets, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("packet %d: %d bytes %x, want %d bytes", i, len(got[i]), got[i][:min(len(got[i]), 8)], len(want[i]))
		}
		if cap(got[i]) != len(got[i]) {
			t.Fatalf("packet %d: capacity %d runs into the next packet", i, cap(got[i]))
		}
	}
}

func TestSplitBatchIPv4(t *testing.T) {
	a, b, c := udp4(t, 0), udp4(t, 1), udp4(t, 1400)
	sameSplit(t, SplitBatch(join(a, b, c), 64, nil), a, b, c)
}

func TestSplitBatchIPv6(t *testing.T) {
	a, b := tcp6(t), udp6(t, 999)
	sameSplit(t, SplitBatch(join(a, b), 64, nil), a, b)
}

func TestSplitBatchMixed(t *testing.T) {
	a, b, c, d := udp4(t, 10), tcp6(t), udp4(t, 3), udp6(t, 0)
	out := make([][]byte, 0, 4)
	sameSplit(t, SplitBatch(join(a, b, c, d), 64, out), a, b, c, d)
}

func TestSplitBatchLimit(t *testing.T) {
	a, b, c := udp4(t, 1), udp4(t, 2), udp4(t, 3)
	// More packets than addresses: the last one takes the rest.
	sameSplit(t, SplitBatch(join(a, b, c), 2, nil), a, join(b, c))
	if got := SplitBatch(join(a, b), 0, nil); len(got) != 0 {
		t.Fatalf("limit 0 gave %d packets", len(got))
	}
}

func TestSplitBatchTruncated(t *testing.T) {
	a, b := udp4(t, 20), udp6(t, 20)
	whole := join(a, b)
	// The second packet's length runs past the end.
	cut := whole[:len(whole)-5]
	sameSplit(t, SplitBatch(cut, 64, nil), a, b[:len(b)-5])
	// Shorter than a header.
	sameSplit(t, SplitBatch(join(a, b[:30]), 64, nil), a, b[:30])
	sameSplit(t, SplitBatch(a[:10], 64, nil), a[:10])
	if got := SplitBatch(nil, 64, nil); len(got) != 0 {
		t.Fatalf("empty buffer gave %d packets", len(got))
	}
}

func TestSplitBatchGarbage(t *testing.T) {
	a := udp4(t, 8)
	zero4 := append([]byte(nil), a...)
	binary.BigEndian.PutUint16(zero4[2:4], 0)
	short4 := append([]byte(nil), a...)
	binary.BigEndian.PutUint16(short4[2:4], 19)
	badIHL := append([]byte(nil), a...)
	badIHL[0] = 0x44
	zero6 := udp6(t, 8)
	binary.BigEndian.PutUint16(zero6[4:6], 0)
	huge6 := udp6(t, 8)
	binary.BigEndian.PutUint16(huge6[4:6], 0xFFFF)
	version := append([]byte(nil), a...)
	version[0] = 0x55
	for name, bad := range map[string][]byte{"zero4": zero4, "short4": short4, "ihl": badIHL, "zero6": zero6, "huge6": huge6, "version": version} {
		t.Run(name, func(t *testing.T) {
			sameSplit(t, SplitBatch(join(a, bad, a), 64, nil), a, join(bad, a))
		})
	}
}

func TestBatchAddKeepsSplitOrder(t *testing.T) {
	pkts := [][]byte{udp4(t, 5), tcp6(t), udp6(t, 70), udp4(t, 1300)}
	var b Batch
	for i, p := range pkts {
		var addr Address
		addr.SetIfIdx(uint32(i))
		if !b.Add(p, &addr) {
			t.Fatalf("packet %d refused", i)
		}
	}
	if b.Len() != len(pkts) {
		t.Fatalf("len %d", b.Len())
	}
	sameSplit(t, SplitBatch(b.Buf, b.Len(), nil), pkts...)
	for i := range pkts {
		if b.Addrs[i].IfIdx() != uint32(i) {
			t.Fatalf("address %d out of order", i)
		}
	}
	b.Reset()
	if b.Len() != 0 || len(b.Buf) != 0 {
		t.Fatal("reset kept packets")
	}
}

func TestBatchRefusesMislabelledAndFull(t *testing.T) {
	var b Batch
	var addr Address
	p := udp4(t, 4)
	if b.Add(p[:len(p)-1], &addr) || b.Add(nil, &addr) || b.Add(append(p, 0), &addr) {
		t.Fatal("a packet whose length field is off was batched")
	}
	for i := 0; i < BatchMax; i++ {
		if !b.Add(p, &addr) {
			t.Fatalf("refused at %d", i)
		}
	}
	if b.Add(p, &addr) {
		t.Fatal("batch grew past BatchMax")
	}
}

func TestBatchBoundsBytes(t *testing.T) {
	var b Batch
	var addr Address
	big := udp4(t, 64000)
	n := 0
	for b.Add(big, &addr) {
		n++
	}
	if n == 0 || len(b.Buf) > batchBytes || len(b.Buf)+len(big) <= batchBytes {
		t.Fatalf("%d packets, %d bytes", n, len(b.Buf))
	}
	b.Reset()
	if !b.Add(big, &addr) {
		t.Fatal("empty batch refused a packet")
	}
}
