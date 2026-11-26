package windivert

import (
	"encoding/binary"
	"testing"
)

func TestAddressSizeAndFlags(t *testing.T) {
	var a Address
	if len(a) != AddressSize {
		t.Fatalf("size %d", len(a))
	}
	a.SetLayer(LayerSocket)
	a.SetEvent(EventSocketConnect)
	a.SetOutbound(true)
	a.SetImpostor(true)
	a.SetIfIdx(7)
	a.SetSubIfIdx(9)
	a.SetProcessID(4242)
	a.SetProtocol(6)
	if a.Layer() != LayerSocket || a.Event() != EventSocketConnect {
		t.Fatalf("layer/event %d/%d", a.Layer(), a.Event())
	}
	if !a.Outbound() || !a.Impostor() || a.bit(bitLoopback) {
		t.Fatalf("flags %x", a.flags())
	}
	if a.IfIdx() != 7 || a.SubIfIdx() != 9 || a.ProcessID() != 4242 || a.Protocol() != 6 {
		t.Fatalf("meta if=%d sub=%d pid=%d proto=%d", a.IfIdx(), a.SubIfIdx(), a.ProcessID(), a.Protocol())
	}
	a.SetOutbound(false)
	if a.Outbound() || a.Layer() != LayerSocket {
		t.Fatal("clearing outbound clobbered the layer")
	}
}

func TestHostOrderIPv4(t *testing.T) {
	var a Address
	// 1.2.3.4 mapped, port 443. Words are WinDivert host order.
	binary.LittleEndian.PutUint32(a[36:40], 0x01020304)
	binary.LittleEndian.PutUint32(a[40:44], 0x0000FFFF)
	binary.LittleEndian.PutUint16(a[68:70], 443)
	got := a.Local()
	if got.String() != "1.2.3.4:443" || got.Len != 4 {
		t.Fatalf("local %s len %d", got, got.Len)
	}
}

func TestHostOrderIPv6(t *testing.T) {
	var a Address
	// 2001:db8::1 port 53 at the remote endpoint.
	binary.LittleEndian.PutUint32(a[52:56], 0x00000001)
	binary.LittleEndian.PutUint32(a[64:68], 0x20010db8)
	binary.LittleEndian.PutUint16(a[70:72], 53)
	got := a.Remote()
	if got.String() != "[2001:db8::1]:53" || got.Len != 16 {
		t.Fatalf("remote %s len %d", got, got.Len)
	}
}

func TestMarkValidChecksums(t *testing.T) {
	var a Address
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	pkt[9] = 6
	MarkValidChecksums(&a, pkt)
	if !a.bit(bitIPSum) || !a.bit(bitTCPSum) || a.bit(bitUDPSum) || a.bit(bitIPv6) {
		t.Fatalf("v4 flags %x", a.flags())
	}
	var b Address
	v6 := make([]byte, 48)
	v6[0] = 0x60
	v6[6] = 17
	MarkValidChecksums(&b, v6)
	if b.bit(bitIPSum) || b.bit(bitTCPSum) || !b.bit(bitUDPSum) || !b.bit(bitIPv6) {
		t.Fatalf("v6 flags %x", b.flags())
	}
	// Extension header length 255 must not overflow uint8 to 0.
	v6Ext := make([]byte, 48)
	v6Ext[0] = 0x60
	v6Ext[6] = 0 // hop-by-hop
	v6Ext[40] = 17
	v6Ext[41] = 255
	if got := ipv6Proto(v6Ext); got != 0 {
		t.Fatalf("ipv6Proto with len=255 returned %d, want 0", got)
	}
}
