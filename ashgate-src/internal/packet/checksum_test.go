package packet

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"testing"
)

// addBytes16 is addBytes before 0.9.3, two bytes at a time.
func addBytes16(sum uint32, b []byte) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

func TestAddBytesMatchesWordSum(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	var lengths []int
	for n := 0; n <= 2000; n++ {
		lengths = append(lengths, n)
	}
	lengths = append(lengths, 65535, 65534, 65533)
	fill := []func(b []byte){
		func(b []byte) {
			for i := range b {
				b[i] = byte(r.Uint32())
			}
		},
		func(b []byte) {
			for i := range b {
				b[i] = 0xFF // every 64-bit add carries
			}
		},
		func(b []byte) { clear(b) },
	}
	buf := make([]byte, 65535+7)
	for _, n := range lengths {
		for k, f := range fill {
			// An odd start offset too: packets are not aligned in a batch.
			off := r.IntN(8)
			b := buf[off : off+n]
			f(b)
			starts := []uint32{0, 1, 0xFFFF, uint32(r.IntN(1 << 16)), uint32(r.IntN(1 << 31))}
			for _, start := range starts {
				// Starts stay below 2^31: callers pass small sums, and the
				// old loop wraps at 2^32 for the longest packets.
				want, got := addBytes16(start, b), addBytes(start, b)
				if fold(got) != fold(want) {
					t.Fatalf("len %d fill %d start %#x: fold %#x, want %#x", n, k, start, fold(got), fold(want))
				}
				// Callers add the pseudo-header's protocol and length.
				for _, extra := range []uint32{0, 17, 65535 + 6} {
					if fold(got+extra) != fold(want+extra) {
						t.Fatalf("len %d start %#x extra %d: fold differs", n, start, extra)
					}
				}
			}
		}
	}
}

func TestChecksumKnownValues(t *testing.T) {
	// RFC 1071's example words 0001 f203 f4f5 f6f7 sum to ddf2.
	if got := checksum([]byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}); got != ^uint16(0xddf2) {
		t.Fatalf("checksum %#x", got)
	}
	if got := checksum(nil); got != 0xFFFF {
		t.Fatalf("empty checksum %#x", got)
	}
	if got := checksum(bytes.Repeat([]byte{0xFF}, 64)); got != 0 {
		t.Fatalf("all-ones checksum %#x", got)
	}
}

func benchSum(b *testing.B, f func(uint32, []byte) uint32, n int) {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = byte(i * 7)
	}
	b.SetBytes(int64(n))
	var sink uint32
	for b.Loop() {
		sink += f(0, buf)
	}
	_ = sink
}

func BenchmarkAddBytes1500(b *testing.B)    { benchSum(b, addBytes, 1500) }
func BenchmarkAddBytes16_1500(b *testing.B) { benchSum(b, addBytes16, 1500) }
func BenchmarkAddBytes64K(b *testing.B)     { benchSum(b, addBytes, 65535) }
func BenchmarkAddBytes16_64K(b *testing.B)  { benchSum(b, addBytes16, 65535) }
