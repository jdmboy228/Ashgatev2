// Package windivert describes the WinDivert 2.2 address block and the
// user-mode API used by the Windows capture path.
//
// The 80-byte layout matches the MSVC packing of WINDIVERT_ADDRESS in
// WinDivert 2.2 (little-endian). SOCKET and FLOW addresses are stored in
// WinDivert host order; packet.Addr is network order.
package windivert

import (
	"encoding/binary"
	"math/bits"

	"ashgate/internal/packet"
)

// Address is one WINDIVERT_ADDRESS.
type Address [80]byte

const AddressSize = 80

// Layers and events from windivert.h 2.2.2.
const (
	LayerNetwork uint8 = 0
	LayerFlow    uint8 = 2
	LayerSocket  uint8 = 3

	EventNetworkPacket   uint8 = 0
	EventFlowEstablished uint8 = 1
	EventFlowDeleted     uint8 = 2
	EventSocketBind      uint8 = 3
	EventSocketConnect   uint8 = 4
	EventSocketListen    uint8 = 5
	EventSocketAccept    uint8 = 6
	EventSocketClose     uint8 = 7

	FlagSniff    uint64 = 0x1
	FlagRecvOnly uint64 = 0x4

	ParamQueueLength = 0
	ParamQueueTime   = 1
	ParamQueueSize   = 2

	ShutdownRecv uint32 = 0x1
	ShutdownSend uint32 = 0x2
	ShutdownBoth uint32 = 0x3
)

const (
	bitSniffed  = 16
	bitOutbound = 17
	bitLoopback = 18
	bitImpostor = 19
	bitIPv6     = 20
	bitIPSum    = 21
	bitTCPSum   = 22
	bitUDPSum   = 23
)

func (a *Address) flags() uint32 {
	return binary.LittleEndian.Uint32(a[8:12])
}

func (a *Address) setFlags(v uint32) {
	binary.LittleEndian.PutUint32(a[8:12], v)
}

func (a *Address) bit(n int) bool {
	return a.flags()&(1<<uint(n)) != 0
}

func (a *Address) setBit(n int, on bool) {
	f := a.flags()
	if on {
		f |= 1 << uint(n)
	} else {
		f &^= 1 << uint(n)
	}
	a.setFlags(f)
}

// Layer is the low 8 bits of the flag word.
func (a *Address) Layer() uint8 { return uint8(a.flags()) }

// SetLayer writes the layer without touching the other flag bits.
func (a *Address) SetLayer(layer uint8) {
	a.setFlags(a.flags()&^0xff | uint32(layer))
}

// Event is bits 8–15 of the flag word.
func (a *Address) Event() uint8 { return uint8(a.flags() >> 8) }

// SetEvent writes the event without touching the other flag bits.
func (a *Address) SetEvent(ev uint8) {
	a.setFlags(a.flags()&^0xff00 | uint32(ev)<<8)
}

// Outbound reports the outbound bit.
func (a *Address) Outbound() bool { return a.bit(bitOutbound) }

// Impostor reports the impostor bit.
func (a *Address) Impostor() bool { return a.bit(bitImpostor) }

// SetOutbound sets the outbound bit.
func (a *Address) SetOutbound(on bool) { a.setBit(bitOutbound, on) }

// SetLoopback sets the loopback bit.
func (a *Address) SetLoopback(on bool) { a.setBit(bitLoopback, on) }

// SetImpostor sets the impostor bit so a reinjected packet misses "!impostor".
func (a *Address) SetImpostor(on bool) { a.setBit(bitImpostor, on) }

// SetIPv6 sets the IPv6 bit.
func (a *Address) SetIPv6(on bool) { a.setBit(bitIPv6, on) }

// SetChecksums marks which checksums are already valid.
func (a *Address) SetChecksums(ip, tcp, udp bool) {
	a.setBit(bitIPSum, ip)
	a.setBit(bitTCPSum, tcp)
	a.setBit(bitUDPSum, udp)
}

// IfIdx is the interface index at offset 16.
func (a *Address) IfIdx() uint32 { return binary.LittleEndian.Uint32(a[16:20]) }

// SetIfIdx writes the interface index.
func (a *Address) SetIfIdx(v uint32) { binary.LittleEndian.PutUint32(a[16:20], v) }

// SubIfIdx is the sub-interface index at offset 20.
func (a *Address) SubIfIdx() uint32 { return binary.LittleEndian.Uint32(a[20:24]) }

// SetSubIfIdx writes the sub-interface index.
func (a *Address) SetSubIfIdx(v uint32) { binary.LittleEndian.PutUint32(a[20:24], v) }

// ProcessID is the SOCKET/FLOW process id at offset 32.
func (a *Address) ProcessID() uint32 { return binary.LittleEndian.Uint32(a[32:36]) }

// SetProcessID writes the SOCKET/FLOW process id.
func (a *Address) SetProcessID(pid uint32) { binary.LittleEndian.PutUint32(a[32:36], pid) }

// Protocol is the SOCKET/FLOW IP protocol at offset 72.
func (a *Address) Protocol() uint8 { return a[72] }

// SetProtocol writes the SOCKET/FLOW IP protocol.
func (a *Address) SetProtocol(p uint8) { a[72] = p }

// Local is the SOCKET/FLOW local endpoint.
func (a *Address) Local() packet.Addr { return endpointAt(a, 36, 68) }

// Remote is the SOCKET/FLOW remote endpoint.
func (a *Address) Remote() packet.Addr { return endpointAt(a, 52, 70) }

// endpointAt converts WinDivert host-order address words directly to packet.Addr.
// IPv4-mapped 1.2.3.4 is stored as [0x01020304, 0x0000FFFF, 0, 0].
// 2001:db8::1 is stored as [0x00000001, 0, 0, 0x20010db8].
func endpointAt(a *Address, ipOff, portOff int) packet.Addr {
	var b [16]byte
	for i := 0; i < 4; i++ {
		w := binary.LittleEndian.Uint32(a[ipOff+4*i : ipOff+4*i+4])
		binary.LittleEndian.PutUint32(b[(3-i)*4:], bits.ReverseBytes32(w))
	}
	port := binary.LittleEndian.Uint16(a[portOff : portOff+2])
	if isV4Mapped(b) {
		return packet.V4(b[12], b[13], b[14], b[15], port)
	}
	return packet.Addr{IP: b, Len: 16, Port: port}
}

func isV4Mapped(b [16]byte) bool {
	for i := 0; i < 10; i++ {
		if b[i] != 0 {
			return false
		}
	}
	return b[10] == 0xff && b[11] == 0xff
}

// MarkValidChecksums sets the checksum-valid bits to match a parsed packet.
func MarkValidChecksums(addr *Address, pkt []byte) {
	if len(pkt) < 1 || addr == nil {
		return
	}
	ver := pkt[0] >> 4
	var proto byte
	switch ver {
	case 4:
		if len(pkt) >= 20 {
			proto = pkt[9]
		}
		addr.SetChecksums(true, proto == packet.ProtoTCP, proto == packet.ProtoUDP)
	case 6:
		addr.SetIPv6(true)
		proto = ipv6Proto(pkt)
		addr.SetChecksums(false, proto == packet.ProtoTCP, proto == packet.ProtoUDP)
	}
}

func ipv6Proto(pkt []byte) byte {
	if len(pkt) < 40 {
		return 0
	}
	next := pkt[6]
	off := 40
	for i := 0; i < 8; i++ {
		switch next {
		case packet.ProtoTCP, packet.ProtoUDP:
			return next
		case 0, 43, 60: // hop-by-hop, routing, destination options
			if off+2 > len(pkt) {
				return next
			}
			hdrLen := (int(pkt[off+1]) + 1) * 8
			if hdrLen < 8 || off+hdrLen > len(pkt) {
				return next
			}
			next = pkt[off]
			off += hdrLen
		case 44: // fragment
			if off+8 > len(pkt) {
				return next
			}
			next = pkt[off]
			off += 8
		case 51: // AH
			if off+2 > len(pkt) {
				return next
			}
			hdrLen := (int(pkt[off+1]) + 2) * 4
			if hdrLen < 8 || off+hdrLen > len(pkt) {
				return next
			}
			next = pkt[off]
			off += hdrLen
		default:
			return next
		}
	}
	return next
}
