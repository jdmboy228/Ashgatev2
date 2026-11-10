package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type packetSummary struct {
	Time  string   `json:"time"`
	Proto string   `json:"proto"`
	Src   string   `json:"src"`
	Dst   string   `json:"dst"`
	Sport int      `json:"sport,omitempty"`
	Dport int      `json:"dport,omitempty"`
	DNS   []string `json:"dns,omitempty"`
}

func writePcapSummary(in, out string, names, nets []string) error {
	pkts, err := readCapture(in)
	if err != nil {
		return err
	}
	var cidrs []*net.IPNet
	for _, n := range nets {
		_, ipn, err := net.ParseCIDR(n)
		if err != nil {
			return fmt.Errorf("net %s: %w", n, err)
		}
		cidrs = append(cidrs, ipn)
	}
	var kept []packetSummary
	for _, p := range pkts {
		if packetInteresting(p, names, cidrs) {
			kept = append(kept, p)
		}
	}
	if kept == nil {
		kept = []packetSummary{}
	}
	raw, err := json.MarshalIndent(map[string]any{"packets": kept, "total": len(pkts)}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(out, raw, 0o644)
}

func packetInteresting(p packetSummary, names []string, nets []*net.IPNet) bool {
	if len(names) == 0 && len(nets) == 0 {
		return true
	}
	for _, q := range p.DNS {
		if nameWanted(q, names) {
			return true
		}
	}
	for _, ip := range []net.IP{net.ParseIP(p.Src), net.ParseIP(p.Dst)} {
		if ip == nil {
			continue
		}
		for _, n := range nets {
			if n.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func nameWanted(q string, names []string) bool {
	q = strings.TrimSuffix(strings.ToLower(q), ".")
	for _, w := range names {
		w = strings.TrimSuffix(strings.ToLower(w), ".")
		if w != "" && (q == w || strings.HasSuffix(q, "."+w)) {
			return true
		}
	}
	return false
}

func readCapture(path string) ([]packetSummary, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	ng, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		if _, seekErr := f.Seek(0, io.SeekStart); seekErr != nil {
			return nil, err
		}
		r, err2 := pcapgo.NewReader(f)
		if err2 != nil {
			return nil, fmt.Errorf("pcap: %v / %v", err, err2)
		}
		return readLoop(func() ([]byte, gopacket.CaptureInfo, layers.LinkType, error) {
			data, ci, e := r.ReadPacketData()
			return data, ci, r.LinkType(), e
		})
	}
	return readLoop(func() ([]byte, gopacket.CaptureInfo, layers.LinkType, error) {
		data, ci, e := ng.ReadPacketData()
		lt := layers.LinkTypeEthernet
		if intf, ierr := ng.Interface(ci.InterfaceIndex); ierr == nil {
			lt = layers.LinkType(intf.LinkType)
		}
		return data, ci, lt, e
	})
}

func readLoop(next func() ([]byte, gopacket.CaptureInfo, layers.LinkType, error)) ([]packetSummary, error) {
	var out []packetSummary
	seen := map[string]time.Time{}
	for {
		data, ci, lt, err := next()
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			break
		}
		p, ok := decodePacket(data, lt)
		if !ok {
			continue
		}
		p.Time = ci.Timestamp.UTC().Format(time.RFC3339Nano)
		key := fmt.Sprintf("%s|%s|%s|%d|%d|%v", p.Proto, p.Src, p.Dst, p.Sport, p.Dport, p.DNS)
		if t, ok := seen[key]; ok && ci.Timestamp.Sub(t) < 50*time.Millisecond {
			continue
		}
		seen[key] = ci.Timestamp
		out = append(out, p)
	}
	return out, nil
}

func decodePacket(data []byte, lt layers.LinkType) (packetSummary, bool) {
	var first gopacket.Decoder = lt
	if lt == layers.LinkTypeRaw || lt == layers.LinkTypeNull || lt == 101 {
		if len(data) > 0 && data[0]>>4 == 6 {
			first = layers.LayerTypeIPv6
		} else {
			first = layers.LayerTypeIPv4
		}
	}
	pkt := gopacket.NewPacket(data, first, gopacket.Lazy)
	var p packetSummary
	switch {
	case pkt.Layer(layers.LayerTypeIPv4) != nil:
		ip := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		p.Src, p.Dst = ip.SrcIP.String(), ip.DstIP.String()
	case pkt.Layer(layers.LayerTypeIPv6) != nil:
		ip := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		p.Src, p.Dst = ip.SrcIP.String(), ip.DstIP.String()
	default:
		return p, false
	}
	if tcp := pkt.Layer(layers.LayerTypeTCP); tcp != nil {
		t := tcp.(*layers.TCP)
		p.Proto = "tcp"
		p.Sport, p.Dport = int(t.SrcPort), int(t.DstPort)
		if t.SrcPort == 53 || t.DstPort == 53 {
			p.DNS = dnsNames(t.Payload, true)
		}
	} else if udp := pkt.Layer(layers.LayerTypeUDP); udp != nil {
		u := udp.(*layers.UDP)
		p.Proto = "udp"
		p.Sport, p.Dport = int(u.SrcPort), int(u.DstPort)
		if u.SrcPort == 53 || u.DstPort == 53 {
			p.DNS = dnsNames(u.Payload, false)
		}
	} else {
		p.Proto = "other"
	}
	return p, true
}

func dnsNames(payload []byte, tcp bool) []string {
	raw := payload
	if tcp && len(payload) > 2 {
		raw = payload[2:]
	}
	pkt := gopacket.NewPacket(raw, layers.LayerTypeDNS, gopacket.Lazy)
	layer := pkt.Layer(layers.LayerTypeDNS)
	if layer == nil {
		return nil
	}
	dns, ok := layer.(*layers.DNS)
	if !ok || dns == nil {
		return nil
	}
	var names []string
	for _, q := range dns.Questions {
		if q.Name != nil {
			names = append(names, string(q.Name))
		}
	}
	return names
}
