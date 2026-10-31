//go:build windows && e2e

package harness

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// Packet is one captured packet, reduced to what the leak checks need.
type Packet struct {
	Time    time.Time `json:"time"`
	Proto   string    `json:"proto"` // tcp, udp, icmp, other
	Src     string    `json:"src"`
	Dst     string    `json:"dst"`
	SrcPort int       `json:"sport,omitempty"`
	DstPort int       `json:"dport,omitempty"`
	SYN     bool      `json:"syn,omitempty"`
	DNS     []string  `json:"dns,omitempty"` // query names
}

// DstIP parses Dst.
func (p Packet) DstIP() net.IP { return net.ParseIP(p.Dst) }

func (p Packet) String() string {
	s := fmt.Sprintf("%s %s %s:%d -> %s:%d", p.Time.Format("15:04:05.000"), p.Proto, p.Src, p.SrcPort, p.Dst, p.DstPort)
	if p.SYN {
		s += " SYN"
	}
	if len(p.DNS) > 0 {
		s += " dns=" + strings.Join(p.DNS, ",")
	}
	return s
}

var pktmonMu sync.Mutex

// Capture is one pktmon session: everything every network component of
// the runner sends and receives. Loopback never reaches a network card,
// so the tunnel itself (127.0.0.1) is not in it.
type Capture struct {
	etl  string
	Name string
	env  *Env
}

// StartCapture starts pktmon for one test phase.
func StartCapture(env *Env, name string) (*Capture, error) {
	pktmonMu.Lock()
	c := &Capture{etl: env.Path("pcap", name+".etl"), Name: name, env: env}
	_, _ = Run("pktmon", "stop")
	_, _ = Run("pktmon", "filter", "remove")
	out, err := Run("pktmon", "start", "--capture", "--pkt-size", "0", "--file-name", c.etl, "--file-size", "256")
	if err != nil {
		pktmonMu.Unlock()
		return nil, fmt.Errorf("pktmon start: %v: %s", err, out)
	}
	// pktmon needs a moment before the first packet is logged.
	time.Sleep(1500 * time.Millisecond)
	return c, nil
}

// Stop ends the capture and returns its packets.
func (c *Capture) Stop() ([]Packet, error) {
	defer pktmonMu.Unlock()
	time.Sleep(1500 * time.Millisecond)
	if out, err := Run("pktmon", "stop"); err != nil {
		return nil, fmt.Errorf("pktmon stop: %v: %s", err, out)
	}
	pcap := strings.TrimSuffix(c.etl, ".etl") + ".pcapng"
	out, err := Run("pktmon", "etl2pcap", c.etl, "--out", pcap)
	if err != nil {
		// Older builds call the command pcapng.
		out2, err2 := Run("pktmon", "pcapng", c.etl, "-o", pcap)
		if err2 != nil {
			return nil, fmt.Errorf("pktmon etl2pcap: %v: %s / %s", err, out, out2)
		}
	}
	pkts, err := ReadPcapng(pcap)
	// The raw capture holds the runner's own traffic; keep only the
	// summary as an artifact.
	_ = os.Remove(c.etl)
	_ = os.Remove(pcap)
	if err != nil {
		return nil, err
	}
	c.env.WriteJSON(filepath.Join("pcap", c.Name+".json"), interesting(pkts))
	return pkts, nil
}

// interesting keeps the packets a reader of the artifact cares about.
func interesting(pkts []Packet) []Packet {
	var out []Packet
	for _, p := range pkts {
		ip := p.DstIP()
		if ip != nil && (TestNet4.Contains(ip) || TestNet6.Contains(ip)) || len(p.DNS) > 0 || p.DstPort == 3478 {
			out = append(out, p)
		}
	}
	return out
}

// ReadPcapng parses a pcapng file.
func ReadPcapng(path string) ([]Packet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		return nil, err
	}
	var out []Packet
	for {
		data, ci, err := r.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// A truncated last block is normal when pktmon stops.
			break
		}
		lt := layers.LinkTypeEthernet
		if intf, err := r.Interface(ci.InterfaceIndex); err == nil {
			lt = layers.LinkType(intf.LinkType)
		}
		if p, ok := decode(data, lt); ok {
			p.Time = ci.Timestamp
			out = append(out, p)
		}
	}
	return out, nil
}

func decode(data []byte, lt layers.LinkType) (Packet, bool) {
	var first gopacket.Decoder = lt
	if lt == layers.LinkTypeRaw || lt == 101 {
		if len(data) > 0 && data[0]>>4 == 6 {
			first = layers.LayerTypeIPv6
		} else {
			first = layers.LayerTypeIPv4
		}
	}
	pk := gopacket.NewPacket(data, first, gopacket.Lazy)
	var p Packet
	switch {
	case pk.Layer(layers.LayerTypeIPv4) != nil:
		ip := pk.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		p.Src, p.Dst = ip.SrcIP.String(), ip.DstIP.String()
	case pk.Layer(layers.LayerTypeIPv6) != nil:
		ip := pk.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		p.Src, p.Dst = ip.SrcIP.String(), ip.DstIP.String()
	default:
		return p, false
	}
	p.Proto = "other"
	if l := pk.Layer(layers.LayerTypeTCP); l != nil {
		t := l.(*layers.TCP)
		p.Proto, p.SrcPort, p.DstPort = "tcp", int(t.SrcPort), int(t.DstPort)
		p.SYN = t.SYN && !t.ACK
	} else if l := pk.Layer(layers.LayerTypeUDP); l != nil {
		u := l.(*layers.UDP)
		p.Proto, p.SrcPort, p.DstPort = "udp", int(u.SrcPort), int(u.DstPort)
	} else if pk.Layer(layers.LayerTypeICMPv4) != nil || pk.Layer(layers.LayerTypeICMPv6) != nil {
		p.Proto = "icmp"
	}
	if p.SrcPort == 53 || p.DstPort == 53 {
		if l := pk.Layer(layers.LayerTypeDNS); l != nil {
			for _, q := range l.(*layers.DNS).Questions {
				p.DNS = append(p.DNS, strings.ToLower(string(q.Name)))
			}
		} else if p.Proto == "tcp" {
			// DNS over TCP: a 2-byte length, then the message.
			if app := pk.ApplicationLayer(); app != nil && len(app.Payload()) > 2 {
				var d layers.DNS
				if d.DecodeFromBytes(app.Payload()[2:], gopacket.NilDecodeFeedback) == nil {
					for _, q := range d.Questions {
						p.DNS = append(p.DNS, strings.ToLower(string(q.Name)))
					}
				}
			}
		}
	}
	return p, true
}

// Filter returns the packets that match fn.
func Filter(pkts []Packet, fn func(Packet) bool) []Packet {
	var out []Packet
	for _, p := range pkts {
		if fn(p) {
			out = append(out, p)
		}
	}
	return out
}

// ToTestNet matches packets sent to the documentation ranges, except the
// given addresses (for example the control app's own direct target).
func ToTestNet(except ...string) func(Packet) bool {
	skip := map[string]bool{}
	for _, e := range except {
		skip[e] = true
	}
	return func(p Packet) bool {
		ip := p.DstIP()
		if ip == nil || skip[ip.String()] {
			return false
		}
		return TestNet4.Contains(ip) || TestNet6.Contains(ip)
	}
}

// DNSFor matches DNS packets that ask for a name containing marker.
func DNSFor(marker string) func(Packet) bool {
	marker = strings.ToLower(marker)
	return func(p Packet) bool {
		for _, n := range p.DNS {
			if strings.Contains(n, marker) {
				return true
			}
		}
		return false
	}
}

// Brief formats at most n packets for an error message.
func Brief(pkts []Packet, n int) string {
	var b strings.Builder
	for i, p := range pkts {
		if i == n {
			fmt.Fprintf(&b, "\n  … and %d more", len(pkts)-n)
			break
		}
		b.WriteString("\n  " + p.String())
	}
	return b.String()
}

// SockWatch polls the sockets of some processes while a phase runs, so a
// short direct connection of ashgate.exe is still seen.
type SockWatch struct {
	stop chan struct{}
	done chan struct{}
	mu   sync.Mutex
	seen map[string]Sock
}

// WatchSockets starts polling the sockets of pids every 100 ms.
func WatchSockets(pids ...uint32) *SockWatch {
	w := &SockWatch{stop: make(chan struct{}), done: make(chan struct{}), seen: map[string]Sock{}}
	go func() {
		defer close(w.done)
		t := time.NewTicker(100 * time.Millisecond)
		defer t.Stop()
		for {
			for _, s := range SocketsOf(pids...) {
				if s.Proto != "tcp" || s.State == TCPListen || s.Remote == nil || s.Remote.IsUnspecified() {
					continue
				}
				k := fmt.Sprintf("%s:%d", s.Remote, s.RPort)
				w.mu.Lock()
				w.seen[k] = s
				w.mu.Unlock()
			}
			select {
			case <-w.stop:
				return
			case <-t.C:
			}
		}
	}()
	return w
}

// Stop ends the watch and returns every remote endpoint seen.
func (w *SockWatch) Stop() []Sock {
	close(w.stop)
	<-w.done
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]Sock, 0, len(w.seen))
	for _, s := range w.seen {
		out = append(out, s)
	}
	return out
}
