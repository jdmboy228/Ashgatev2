package runtime

import "testing"

func TestNetFilterOnePort(t *testing.T) {
	got := netFilter(34010, 34010)
	want := "outbound and !impostor and (tcp or udp) and (!loopback or (tcp and tcp.SrcPort == 34010))"
	if got != want {
		t.Fatalf("filter\n%s\nwant\n%s", got, want)
	}
}

func TestNetFilterTwoPorts(t *testing.T) {
	got := netFilter(34010, 34011)
	want := "outbound and !impostor and (tcp or udp) and (!loopback or (tcp and tcp.SrcPort == 34010) or (tcp and tcp.SrcPort == 34011))"
	if got != want {
		t.Fatalf("filter\n%s\nwant\n%s", got, want)
	}
}

func TestRelayPort(t *testing.T) {
	for addr, want := range map[string]uint16{"127.0.0.1:34010": 34010, "[::1]:34011": 34011, "127.0.0.2:1": 1} {
		got, err := relayPort(addr)
		if err != nil || got != want {
			t.Fatalf("%s: %d, %v", addr, got, err)
		}
	}
	for _, addr := range []string{"", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:65536", "[::1]:-1"} {
		if _, err := relayPort(addr); err == nil {
			t.Fatalf("%q accepted", addr)
		}
	}
}
