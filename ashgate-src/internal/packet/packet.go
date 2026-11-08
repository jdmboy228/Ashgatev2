// Package packet parses and rewrites IPv4/IPv6 TCP and UDP headers.
// Checksums are computed in process so the rewriter can be tested without WinDivert.
package packet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"net"
)

const (
	ProtoTCP = 6
	ProtoUDP = 17
)

// Addr is an IPv4 or IPv6 address and a port. IPv4 occupies IP[:4].
type Addr struct {
	IP   [16]byte
	Len  uint8
	Port uint16
}

// V4 builds an IPv4 address.
func V4(a, b, c, d byte, port uint16) Addr {
	return Addr{IP: [16]byte{a, b, c, d}, Len: 4, Port: port}
}

// V6 builds an IPv6 address from a 16-byte network-order address.
func V6(ip net.IP, port uint16) Addr {
	var a Addr
	a.Len = 16
	a.Port = port
	copy(a.IP[:], ip.To16())
	return a
}

// FromIP converts a net.IP. IPv4 is stored in 4 bytes.
func FromIP(ip net.IP, port uint16) Addr {
	if ip == nil {
		return Addr{}
	}
	if v4 := ip.To4(); v4 != nil {
		return Addr{IP: [16]byte{v4[0], v4[1], v4[2], v4[3]}, Len: 4, Port: port}
	}
	return V6(ip, port)
}

// NetIP allocates a net.IP. The fast path should avoid calling it.
func (a Addr) NetIP() net.IP {
	if a.Len == 4 {
		return net.IPv4(a.IP[0], a.IP[1], a.IP[2], a.IP[3]).To4()
	}
	ip := make(net.IP, 16)
	copy(ip, a.IP[:])
	return ip
}

// String is host:port.
func (a Addr) String() string {
	return net.JoinHostPort(a.NetIP().String(), itoa(a.Port))
}

// IsZero reports an unset address.
func (a Addr) IsZero() bool { return a.Len == 0 }

// Equal compares family, address, and port.
func (a Addr) Equal(b Addr) bool {
	if a.Len != b.Len || a.Port != b.Port {
		return false
	}
	for i := uint8(0); i < a.Len; i++ {
		if a.IP[i] != b.IP[i] {
			return false
		}
	}
	return true
}

// Header is a parsed TCP or UDP packet. The address arrays do not alias the packet.
type Header struct {
	Ver        int
	Src        Addr
	Dst        Addr
	Proto      uint8
	IHL        int
	L4Off      int
	IPEnd      int
	PayloadOff int
	PayloadLen int
	Frag       bool
	// FragID is the IPv4 identification or the IPv6 fragment header's
	// identification. It is set only when Frag is.
	FragID uint32
	// Ack is the TCP acknowledgment number.
	Ack uint32
	SYN bool
	ACK bool
	FIN bool
	RST bool
}

// Parse fills h from a full IP packet. It does not allocate.
func Parse(pkt []byte, h *Header) error {
	*h = Header{}
	if len(pkt) < 1 {
		return errors.New("packet: empty")
	}
	ver := pkt[0] >> 4
	switch ver {
	case 4:
		return parse4(pkt, h)
	case 6:
		return parse6(pkt, h)
	default:
		return fmt.Errorf("packet: unsupported ip version %d", ver)
	}
}

func parse4(pkt []byte, h *Header) error {
	if len(pkt) < 20 {
		return errors.New("packet: short ipv4 header")
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return errors.New("packet: bad ipv4 header length")
	}
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if total < ihl || total > len(pkt) {
		return errors.New("packet: bad ipv4 total length")
	}
	frag := binary.BigEndian.Uint16(pkt[6:8])
	offset := frag & 0x1FFF
	mf := frag&0x2000 != 0
	if offset != 0 || mf {
		h.FragID = uint32(binary.BigEndian.Uint16(pkt[4:6]))
	}
	h.Ver = 4
	h.IHL = ihl
	h.IPEnd = total
	h.Proto = pkt[9]
	copy(h.Src.IP[:4], pkt[12:16])
	h.Src.Len = 4
	copy(h.Dst.IP[:4], pkt[16:20])
	h.Dst.Len = 4
	if offset != 0 {
		h.Frag = true
		return nil
	}
	if mf {
		h.Frag = true
	}
	return parseL4(pkt, h, ihl, total)
}

func parse6(pkt []byte, h *Header) error {
	if len(pkt) < 40 {
		return errors.New("packet: short ipv6 header")
	}
	payloadLen := int(binary.BigEndian.Uint16(pkt[4:6]))
	end := 40 + payloadLen
	if payloadLen == 0 {
		end = len(pkt)
	}
	if end > len(pkt) || end < 40 {
		return errors.New("packet: bad ipv6 payload length")
	}
	h.Ver = 6
	h.IHL = 40
	h.IPEnd = end
	copy(h.Src.IP[:], pkt[8:24])
	h.Src.Len = 16
	copy(h.Dst.IP[:], pkt[24:40])
	h.Dst.Len = 16
	next := pkt[6]
	off := 40
	for i := 0; i < 8; i++ {
		switch next {
		case ProtoTCP, ProtoUDP:
			h.Proto = next
			return parseL4(pkt, h, off, end)
		case 0, 43, 60: // hop-by-hop, routing, destination options
			if off+2 > end {
				return errors.New("packet: truncated ipv6 extension")
			}
			hdrLen := (int(pkt[off+1]) + 1) * 8
			if off+hdrLen > end {
				return errors.New("packet: truncated ipv6 extension")
			}
			next = pkt[off]
			off += hdrLen
		case 44: // fragment
			if off+8 > end {
				return errors.New("packet: truncated ipv6 fragment header")
			}
			foff := binary.BigEndian.Uint16(pkt[off+2 : off+4])
			offset := foff >> 3
			h.FragID = binary.BigEndian.Uint32(pkt[off+4 : off+8])
			next = pkt[off]
			off += 8
			if offset != 0 {
				h.Frag = true
				h.Proto = next
				return nil
			}
			h.Frag = true
		case 51: // AH
			if off+2 > end {
				return errors.New("packet: truncated ah header")
			}
			hdrLen := (int(pkt[off+1]) + 2) * 4
			if off+hdrLen > end {
				return errors.New("packet: truncated ah header")
			}
			next = pkt[off]
			off += hdrLen
		default:
			return fmt.Errorf("packet: unsupported ipv6 next header %d", next)
		}
	}
	return errors.New("packet: too many ipv6 extension headers")
}

func parseL4(pkt []byte, h *Header, off, end int) error {
	h.L4Off = off
	switch h.Proto {
	case ProtoTCP:
		if off+20 > end {
			return errors.New("packet: short tcp header")
		}
		doff := int(pkt[off+12]>>4) * 4
		if doff < 20 || off+doff > end {
			return errors.New("packet: bad tcp data offset")
		}
		flags := pkt[off+13]
		h.FIN = flags&0x01 != 0
		h.SYN = flags&0x02 != 0
		h.RST = flags&0x04 != 0
		h.ACK = flags&0x10 != 0
		h.Ack = binary.BigEndian.Uint32(pkt[off+8 : off+12])
		h.Src.Port = binary.BigEndian.Uint16(pkt[off : off+2])
		h.Dst.Port = binary.BigEndian.Uint16(pkt[off+2 : off+4])
		h.PayloadOff = off + doff
		h.PayloadLen = end - h.PayloadOff
		return nil
	case ProtoUDP:
		if off+8 > end {
			return errors.New("packet: short udp header")
		}
		h.Src.Port = binary.BigEndian.Uint16(pkt[off : off+2])
		h.Dst.Port = binary.BigEndian.Uint16(pkt[off+2 : off+4])
		h.PayloadOff = off + 8
		h.PayloadLen = end - h.PayloadOff
		if h.PayloadLen < 0 {
			return errors.New("packet: bad udp length")
		}
		return nil
	default:
		return fmt.Errorf("packet: unsupported protocol %d", h.Proto)
	}
}

// Rewrite replaces the source and destination and recomputes checksums.
// Both addresses must match the packet's IP version.
func Rewrite(pkt []byte, h *Header, src, dst Addr) error {
	if h.Frag && h.L4Off == 0 {
		return errors.New("packet: cannot rewrite a fragment without a transport header")
	}
	if h.Ver == 4 {
		if src.Len != 4 || dst.Len != 4 {
			return errors.New("packet: ipv4 rewrite requires ipv4 addresses")
		}
		copy(pkt[12:16], src.IP[:4])
		copy(pkt[16:20], dst.IP[:4])
	} else if h.Ver == 6 {
		if src.Len != 16 || dst.Len != 16 {
			return errors.New("packet: ipv6 rewrite requires ipv6 addresses")
		}
		copy(pkt[8:24], src.IP[:])
		copy(pkt[24:40], dst.IP[:])
	} else {
		return errors.New("packet: rewrite of an unparsed packet")
	}
	if h.L4Off+4 > len(pkt) {
		return errors.New("packet: short transport header")
	}
	binary.BigEndian.PutUint16(pkt[h.L4Off:], src.Port)
	binary.BigEndian.PutUint16(pkt[h.L4Off+2:], dst.Port)
	h.Src = src
	h.Dst = dst
	if h.Ver == 4 {
		if err := setIPv4Checksum(pkt, h.IHL); err != nil {
			return err
		}
	}
	return setTransportChecksum(pkt, h)
}

// BuildUDP builds a UDP/IP packet with valid checksums.
func BuildUDP(src, dst Addr, payload []byte) ([]byte, error) {
	if src.Len == 0 || src.Len != dst.Len {
		return nil, errors.New("packet: udp addresses must share a family")
	}
	if len(payload) > 65000 {
		return nil, errors.New("packet: udp payload too large")
	}
	if src.Len == 4 {
		return build4(src, dst, payload)
	}
	return build6(src, dst, payload)
}

func build4(src, dst Addr, payload []byte) ([]byte, error) {
	n := 20 + 8 + len(payload)
	pkt := make([]byte, n)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(n))
	binary.BigEndian.PutUint16(pkt[4:], 1)
	binary.BigEndian.PutUint16(pkt[6:], 0x4000)
	pkt[8] = 64
	pkt[9] = ProtoUDP
	copy(pkt[12:16], src.IP[:4])
	copy(pkt[16:20], dst.IP[:4])
	binary.BigEndian.PutUint16(pkt[20:], src.Port)
	binary.BigEndian.PutUint16(pkt[22:], dst.Port)
	binary.BigEndian.PutUint16(pkt[24:], uint16(8+len(payload)))
	copy(pkt[28:], payload)
	var h Header
	if err := Parse(pkt, &h); err != nil {
		return nil, err
	}
	if err := setIPv4Checksum(pkt, h.IHL); err != nil {
		return nil, err
	}
	if err := setTransportChecksum(pkt, &h); err != nil {
		return nil, err
	}
	return pkt, nil
}

func build6(src, dst Addr, payload []byte) ([]byte, error) {
	n := 40 + 8 + len(payload)
	pkt := make([]byte, n)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:], uint16(8+len(payload)))
	pkt[6] = ProtoUDP
	pkt[7] = 64
	copy(pkt[8:24], src.IP[:])
	copy(pkt[24:40], dst.IP[:])
	binary.BigEndian.PutUint16(pkt[40:], src.Port)
	binary.BigEndian.PutUint16(pkt[42:], dst.Port)
	binary.BigEndian.PutUint16(pkt[44:], uint16(8+len(payload)))
	copy(pkt[48:], payload)
	var h Header
	if err := Parse(pkt, &h); err != nil {
		return nil, err
	}
	if err := setTransportChecksum(pkt, &h); err != nil {
		return nil, err
	}
	return pkt, nil
}

// BuildRST builds a reset from src to dst. seq must be the sequence number
// dst expects next (the ACK number dst last sent), or dst ignores it.
func BuildRST(src, dst Addr, seq uint32) ([]byte, error) {
	pkt, err := BuildTCP(src, dst, 0x04)
	if err != nil {
		return nil, err
	}
	var h Header
	if err := Parse(pkt, &h); err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint32(pkt[h.L4Off+4:], seq)
	binary.BigEndian.PutUint16(pkt[h.L4Off+14:], 0)
	if err := setTransportChecksum(pkt, &h); err != nil {
		return nil, err
	}
	return pkt, nil
}

// BuildTCP builds a TCP/IP packet with no payload and the given flags.
func BuildTCP(src, dst Addr, flags byte) ([]byte, error) {
	if src.Len == 4 && dst.Len == 4 {
		return buildTCP4(src, dst, flags)
	}
	if src.Len == 16 && dst.Len == 16 {
		return buildTCP6(src, dst, flags)
	}
	return nil, errors.New("packet: tcp addresses must share a family")
}

func buildTCP4(src, dst Addr, flags byte) ([]byte, error) {
	n := 40
	pkt := make([]byte, n)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(n))
	binary.BigEndian.PutUint16(pkt[6:], 0x4000)
	pkt[8] = 64
	pkt[9] = ProtoTCP
	copy(pkt[12:16], src.IP[:4])
	copy(pkt[16:20], dst.IP[:4])
	fillTCP(pkt[20:], src.Port, dst.Port, flags)
	var h Header
	if err := Parse(pkt, &h); err != nil {
		return nil, err
	}
	if err := setIPv4Checksum(pkt, h.IHL); err != nil {
		return nil, err
	}
	if err := setTransportChecksum(pkt, &h); err != nil {
		return nil, err
	}
	return pkt, nil
}

func buildTCP6(src, dst Addr, flags byte) ([]byte, error) {
	pkt := make([]byte, 60)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:], 20)
	pkt[6] = ProtoTCP
	pkt[7] = 64
	copy(pkt[8:24], src.IP[:])
	copy(pkt[24:40], dst.IP[:])
	fillTCP(pkt[40:], src.Port, dst.Port, flags)
	var h Header
	if err := Parse(pkt, &h); err != nil {
		return nil, err
	}
	if err := setTransportChecksum(pkt, &h); err != nil {
		return nil, err
	}
	return pkt, nil
}

func fillTCP(h []byte, src, dst uint16, flags byte) {
	binary.BigEndian.PutUint16(h[0:], src)
	binary.BigEndian.PutUint16(h[2:], dst)
	binary.BigEndian.PutUint32(h[4:], 1)
	h[12] = (5 << 4)
	h[13] = flags
	binary.BigEndian.PutUint16(h[14:], 65535)
}

// ValidChecksums checks the IPv4 header checksum and the TCP/UDP checksum.
func ValidChecksums(pkt []byte) error {
	var h Header
	if err := Parse(pkt, &h); err != nil {
		return err
	}
	if h.L4Off == 0 {
		return errors.New("packet: no transport header")
	}
	if h.Ver == 4 {
		got := binary.BigEndian.Uint16(pkt[10:12])
		pkt[10], pkt[11] = 0, 0
		want := checksum(pkt[:h.IHL])
		binary.BigEndian.PutUint16(pkt[10:12], got)
		if got != want {
			return fmt.Errorf("packet: ipv4 checksum %04x want %04x", got, want)
		}
	}
	csumOff := h.L4Off + 16
	if h.Proto == ProtoUDP {
		csumOff = h.L4Off + 6
	}
	got := binary.BigEndian.Uint16(pkt[csumOff : csumOff+2])
	pkt[csumOff], pkt[csumOff+1] = 0, 0
	want := transportChecksum(pkt, &h)
	binary.BigEndian.PutUint16(pkt[csumOff:], got)
	if h.Proto == ProtoUDP && want == 0 {
		want = 0xFFFF
	}
	if got != want {
		return fmt.Errorf("packet: transport checksum %04x want %04x", got, want)
	}
	return nil
}

func setIPv4Checksum(pkt []byte, ihl int) error {
	if ihl < 20 || len(pkt) < ihl {
		return errors.New("packet: short ipv4 header")
	}
	pkt[10], pkt[11] = 0, 0
	binary.BigEndian.PutUint16(pkt[10:12], checksum(pkt[:ihl]))
	return nil
}

func setTransportChecksum(pkt []byte, h *Header) error {
	if h.L4Off <= 0 || h.IPEnd < h.L4Off || h.IPEnd > len(pkt) {
		return errors.New("packet: bad transport range")
	}
	csumOff := h.L4Off + 16
	if h.Proto == ProtoUDP {
		csumOff = h.L4Off + 6
	}
	if csumOff+2 > h.IPEnd {
		return errors.New("packet: checksum field out of range")
	}
	pkt[csumOff], pkt[csumOff+1] = 0, 0
	c := transportChecksum(pkt, h)
	if h.Proto == ProtoUDP && c == 0 {
		c = 0xFFFF
	}
	binary.BigEndian.PutUint16(pkt[csumOff:], c)
	return nil
}

func transportChecksum(pkt []byte, h *Header) uint16 {
	seg := pkt[h.L4Off:h.IPEnd]
	var sum uint32
	if h.Ver == 4 {
		sum = addBytes(sum, pkt[12:16])
		sum = addBytes(sum, pkt[16:20])
		sum += uint32(h.Proto)
		sum += uint32(len(seg))
	} else {
		sum = addBytes(sum, pkt[8:24])
		sum = addBytes(sum, pkt[24:40])
		l := uint32(len(seg))
		sum += l >> 16
		sum += l & 0xFFFF
		sum += uint32(h.Proto)
	}
	sum = addBytes(sum, seg)
	return fold(sum)
}

func checksum(b []byte) uint16 {
	return fold(addBytes(0, b))
}

// addBytes adds b as big-endian 16-bit words to the one's complement sum.
// It reads 8 bytes at a time: 2^16 is 1 modulo 0xFFFF, so a 64-bit word
// sums like its four 16-bit words, and a carry out of bit 63 is added back
// in. The result is folded to 16 bits (zero only when everything was), so
// callers can still add small values before fold.
func addBytes(sum uint32, b []byte) uint32 {
	acc := uint64(sum)
	var c uint64
	for len(b) >= 32 {
		acc, c = bits.Add64(acc, binary.BigEndian.Uint64(b), 0)
		acc, c = bits.Add64(acc, binary.BigEndian.Uint64(b[8:]), c)
		acc, c = bits.Add64(acc, binary.BigEndian.Uint64(b[16:]), c)
		acc, c = bits.Add64(acc, binary.BigEndian.Uint64(b[24:]), c)
		acc, c = bits.Add64(acc, 0, c)
		acc += c
		b = b[32:]
	}
	for len(b) >= 8 {
		acc, c = bits.Add64(acc, binary.BigEndian.Uint64(b), 0)
		acc += c
		b = b[8:]
	}
	acc = acc&0xFFFFFFFF + acc>>32
	for len(b) >= 2 {
		acc += uint64(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		acc += uint64(b[0]) << 8
	}
	for acc > 0xFFFF {
		acc = acc&0xFFFF + acc>>16
	}
	return uint32(acc)
}

func fold(sum uint32) uint16 {
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func itoa(p uint16) string {
	if p == 0 {
		return "0"
	}
	var b [5]byte
	i := len(b)
	for p > 0 {
		i--
		b[i] = byte('0' + p%10)
		p /= 10
	}
	return string(b[i:])
}

// Loopback reports 127.0.0.0/8 or ::1.
func Loopback(a Addr) bool {
	if a.Len == 4 {
		return a.IP[0] == 127
	}
	if a.Len != 16 {
		return false
	}
	for i := 0; i < 15; i++ {
		if a.IP[i] != 0 {
			return false
		}
	}
	return a.IP[15] == 1
}

// MulticastOrBroadcast reports addresses that cannot be proxied meaningfully.
func MulticastOrBroadcast(a Addr) bool {
	if a.Len == 4 {
		if a.IP[0] >= 224 {
			return true
		}
		return a.IP[0] == 255 && a.IP[1] == 255 && a.IP[2] == 255 && a.IP[3] == 255
	}
	if a.Len == 16 {
		return a.IP[0] == 0xff
	}
	return false
}

// LinkLocal reports 169.254.0.0/16 or fe80::/10.
func LinkLocal(a Addr) bool {
	if a.Len == 4 {
		return a.IP[0] == 169 && a.IP[1] == 254
	}
	if a.Len == 16 {
		return a.IP[0] == 0xfe && a.IP[1]&0xc0 == 0x80
	}
	return false
}

// Private reports RFC1918 and unique-local IPv6.
func Private(a Addr) bool {
	if a.Len == 4 {
		if a.IP[0] == 10 {
			return true
		}
		if a.IP[0] == 172 && a.IP[1] >= 16 && a.IP[1] <= 31 {
			return true
		}
		if a.IP[0] == 192 && a.IP[1] == 168 {
			return true
		}
		return false
	}
	if a.Len == 16 {
		return a.IP[0]&0xfe == 0xfc
	}
	return false
}
