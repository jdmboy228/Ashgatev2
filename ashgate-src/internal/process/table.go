// Package process maps a local socket to the Windows process that owns it.
package process

import (
	"encoding/binary"
	"fmt"

	"ashgate/internal/packet"
)

// TableKind selects an IP Helper owner table.
type TableKind int

const (
	// TableTCP4 is MIB_TCPTABLE_OWNER_PID.
	TableTCP4 TableKind = iota
	// TableTCP6 is MIB_TCP6TABLE_OWNER_PID.
	TableTCP6
	// TableUDP4 is MIB_UDPTABLE_OWNER_PID.
	TableUDP4
	// TableUDP6 is MIB_UDP6TABLE_OWNER_PID.
	TableUDP6
)

// Endpoint is one local socket from an IP Helper table.
type Endpoint struct {
	Proto       uint8
	Addr        packet.Addr
	PID         uint32
	State       uint32
	Unspecified bool
}

// ParseOwnerTable decodes a GetExtendedTcpTable or GetExtendedUdpTable buffer.
// The first DWORD is the row count. Rows are packed on a 4-byte boundary.
// Ports occupy the first two bytes of their DWORD in network order.
func ParseOwnerTable(buf []byte, kind TableKind) ([]Endpoint, error) {
	if len(buf) < 4 {
		return nil, fmt.Errorf("ip helper table is shorter than 4 bytes")
	}
	count := binary.LittleEndian.Uint32(buf[:4])
	rowSize, proto, parse := rowLayout(kind)
	if rowSize == 0 {
		return nil, fmt.Errorf("unknown ip helper table kind %d", kind)
	}
	need := 4 + int(count)*rowSize
	if count > 1_000_000 || need < 0 || need > len(buf) {
		return nil, fmt.Errorf("ip helper table count %d does not fit %d bytes", count, len(buf))
	}
	out := make([]Endpoint, 0, count)
	for i := 0; i < int(count); i++ {
		row := buf[4+i*rowSize : 4+(i+1)*rowSize]
		ep := parse(row)
		ep.Proto = proto
		if ep.PID == 0 || ep.Addr.Port == 0 {
			continue
		}
		out = append(out, ep)
	}
	return out, nil
}

func rowLayout(kind TableKind) (int, uint8, func([]byte) Endpoint) {
	switch kind {
	case TableTCP4:
		return 24, packet.ProtoTCP, parseTCP4
	case TableTCP6:
		return 56, packet.ProtoTCP, parseTCP6
	case TableUDP4:
		return 12, packet.ProtoUDP, parseUDP4
	case TableUDP6:
		return 28, packet.ProtoUDP, parseUDP6
	default:
		return 0, 0, func([]byte) Endpoint { return Endpoint{} }
	}
}

func parseTCP4(row []byte) Endpoint {
	ep := v4row(binary.LittleEndian.Uint32(row[4:8]), binary.LittleEndian.Uint32(row[8:12]), binary.LittleEndian.Uint32(row[20:24]))
	ep.State = binary.LittleEndian.Uint32(row[0:4])
	return ep
}

func parseUDP4(row []byte) Endpoint {
	return v4row(binary.LittleEndian.Uint32(row[0:4]), binary.LittleEndian.Uint32(row[4:8]), binary.LittleEndian.Uint32(row[8:12]))
}

func parseTCP6(row []byte) Endpoint {
	ep := v6row(row[0:16], binary.LittleEndian.Uint32(row[20:24]), binary.LittleEndian.Uint32(row[52:56]))
	ep.State = binary.LittleEndian.Uint32(row[48:52])
	return ep
}

func parseUDP6(row []byte) Endpoint {
	return v6row(row[0:16], binary.LittleEndian.Uint32(row[20:24]), binary.LittleEndian.Uint32(row[24:28]))
}

func v4row(addr, portDWORD, pid uint32) Endpoint {
	ip := [4]byte{byte(addr), byte(addr >> 8), byte(addr >> 16), byte(addr >> 24)}
	ep := Endpoint{
		Addr: packet.V4(ip[0], ip[1], ip[2], ip[3], portFromDWORD(portDWORD)),
		PID:  pid,
	}
	ep.Unspecified = ip == [4]byte{}
	return ep
}

func v6row(addr []byte, portDWORD, pid uint32) Endpoint {
	var ip [16]byte
	copy(ip[:], addr)
	ep := Endpoint{
		Addr: packet.Addr{IP: ip, Len: 16, Port: portFromDWORD(portDWORD)},
		PID:  pid,
	}
	ep.Unspecified = ip == [16]byte{}
	return ep
}

// portFromDWORD reads a TCP/UDP port stored in network order in the low bytes
// of a little-endian DWORD.
func portFromDWORD(v uint32) uint16 {
	return binary.BigEndian.Uint16([]byte{byte(v), byte(v >> 8)})
}
