//go:build windows

package process

import "ashgate/internal/packet"

// TCPOwner reports the process that has a TCP socket bound to port.
// Listeners on loopback or on every address are preferred.
func TCPOwner(port int) (name string, pid uint32, ok bool) {
	if port < 1 || port > 65535 {
		return "", 0, false
	}
	eps, err := loadTables()
	if err != nil {
		return "", 0, false
	}
	const tcpStateListen = 2 // MIB_TCP_STATE_LISTEN
	var fallback uint32
	for _, ep := range eps {
		if ep.Proto != packet.ProtoTCP || ep.State != tcpStateListen || int(ep.Addr.Port) != port || ep.PID == 0 {
			continue
		}
		if fallback == 0 {
			fallback = ep.PID
		}
		ip := ep.Addr.NetIP()
		if ep.Unspecified || (ip != nil && (ip.IsLoopback() || ip.IsUnspecified())) {
			pid = ep.PID
			break
		}
	}
	if pid == 0 {
		pid = fallback
	}
	if pid == 0 {
		return "", 0, false
	}
	img := queryImage(pid)
	return img.Name, pid, true
}
