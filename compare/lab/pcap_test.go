package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestPcapKeepsDNSNameAndTestNet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "t.pcapng")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w, err := pcapgo.NewNgWriter(f, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	write := func(pkt []byte) {
		ci := gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(pkt), Length: len(pkt)}
		if err := w.WritePacket(ci, pkt); err != nil {
			t.Fatal(err)
		}
	}
	write(serialize(t, dnsPacket("a1.probe.example")...))
	write(serialize(t, ipPacket(net.IPv4(198, 51, 100, 10))...))
	write(serialize(t, ipPacket(net.IPv4(1, 2, 3, 4))...))
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	out := filepath.Join(dir, "out.json")
	if err := writePcapSummary(path, out, []string{"a1.probe.example"}, []string{"198.51.100.0/24"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !contains([]byte(text), []byte("a1.probe.example")) || !contains([]byte(text), []byte("198.51.100.10")) {
		t.Fatalf("summary missing matches: %s", text)
	}
	if contains([]byte(text), []byte("1.2.3.4")) {
		t.Fatalf("unrelated packet kept: %s", text)
	}
}

func serialize(t *testing.T, layersToSend ...gopacket.SerializableLayer) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, layersToSend...); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func dnsPacket(name string) []gopacket.SerializableLayer {
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{1, 1, 1, 1, 1, 1}, DstMAC: net.HardwareAddr{2, 2, 2, 2, 2, 2}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IPv4(10, 0, 0, 2), DstIP: net.IPv4(1, 1, 1, 1)}
	udp := &layers.UDP{SrcPort: 53000, DstPort: 53}
	_ = udp.SetNetworkLayerForChecksum(ip)
	q := layers.DNSQuestion{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN}
	dns := &layers.DNS{ID: 1, QR: false, QDCount: 1, Questions: []layers.DNSQuestion{q}, OpCode: layers.DNSOpCodeQuery}
	return []gopacket.SerializableLayer{eth, ip, udp, dns}
}

func ipPacket(dst net.IP) []gopacket.SerializableLayer {
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{1, 1, 1, 1, 1, 1}, DstMAC: net.HardwareAddr{2, 2, 2, 2, 2, 2}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.IPv4(10, 0, 0, 2), DstIP: dst}
	tcp := &layers.TCP{SrcPort: 40000, DstPort: 18080, SYN: true}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	return []gopacket.SerializableLayer{eth, ip, tcp}
}

func TestServerConfigUsesBothTransports(t *testing.T) {
	cfg := serverConfig("priv", "abcd", "u1", "u2", "127.0.0.1:1", 2, 3, "raw", "a", "e")
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{`"network":"xhttp"`, `"network":"raw"`, "198.51.100.0/24", "www.gstatic.com", "xtls-rprx-vision"} {
		if !contains([]byte(text), []byte(want)) {
			t.Fatalf("config missing %s\n%s", want, text)
		}
	}
}
