package runtime

import (
	"fmt"
	"net"
)

// netFilter is the WinDivert filter of the network handle. It leaves out
// loopback traffic except the relay's replies (TCP from a relay port). The
// engine passes every packet to a loopback address unchanged
// (destinationBypass), and the only loopback packets it rewrites are those
// replies (tcpReturn). Leaving the rest out keeps local connections, such
// as the VLESS SOCKS ports, from crossing user mode with every packet.
func netFilter(relay4, relay6 uint16) string {
	relay := fmt.Sprintf("(tcp and tcp.SrcPort == %d)", relay4)
	if relay6 != relay4 {
		relay += fmt.Sprintf(" or (tcp and tcp.SrcPort == %d)", relay6)
	}
	return "outbound and !impostor and (tcp or udp) and (!loopback or " + relay + ")"
}

// relayPort is the port of a relay address such as 127.0.0.1:34010, read
// as the config and the engine read it.
func relayPort(addr string) (uint16, error) {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, err
	}
	n, err := net.LookupPort("tcp", p)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("неверный порт приёмника %q", addr)
	}
	return uint16(n), nil
}
