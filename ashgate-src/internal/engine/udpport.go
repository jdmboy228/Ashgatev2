package engine

// Direct UDP decisions are cached by source and destination. When the
// socket behind a source port closes, Windows may give the port to another
// program next, and a routed program sending to the same destination would
// inherit "direct" from the cache without its owner being looked up. The
// socket's CLOSE event therefore drops the port's cached decisions; the
// next packet from the port is decided again.

// addDirectUDP caches a direct decision and indexes it by source port.
// Callers hold e.mu.
func (e *Engine) addDirectUDP(k udpKey) {
	e.directUDP.add(k)
	if e.directPorts == nil {
		e.directPorts = map[uint16]map[udpKey]struct{}{}
	}
	m := e.directPorts[k.Src.Port]
	if m == nil {
		m = map[udpKey]struct{}{}
		e.directPorts[k.Src.Port] = m
	}
	m[k] = struct{}{}
}

// ForgetUDPPort drops the cached direct decisions of UDP sources on port.
// The capture loop calls it when a UDP socket on that port closes. The port
// alone is enough: a socket bound to 0.0.0.0 closes with that address, and
// forgetting too much only means one more lookup.
func (e *Engine) ForgetUDPPort(port uint16) {
	if e == nil || port == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for k := range e.directPorts[port] {
		e.directUDP.del(k)
	}
	delete(e.directPorts, port)
}

// reindexDirectUDP rebuilds the port index from the cache after it aged,
// so the index does not keep keys the cache dropped. Callers hold e.mu.
func (e *Engine) reindexDirectUDP() {
	idx := map[uint16]map[udpKey]struct{}{}
	for _, gen := range []map[udpKey]struct{}{e.directUDP.cur, e.directUDP.old} {
		for k := range gen {
			m := idx[k.Src.Port]
			if m == nil {
				m = map[udpKey]struct{}{}
				idx[k.Src.Port] = m
			}
			m[k] = struct{}{}
		}
	}
	e.directPorts = idx
}
