package vless

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
)

func outboundByTag(t *testing.T, raw []byte, tag string) map[string]any {
	t.Helper()
	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, o := range doc.Outbounds {
		if o["tag"] == tag {
			return o
		}
	}
	t.Fatalf("no outbound %q in %s", tag, raw)
	return nil
}

// A and AAAA go to Xray's DNS; any other type goes as it is to the raw
// server through the tunnel, never to the server the program asked.
func TestDNSOutboundSendsOtherTypesThroughTheTunnel(t *testing.T) {
	p := Params{UUID: "b7e2c1a0-4f3a-4c2b-9a11-111111111111", Network: "tcp", Security: "none"}
	raw, err := ClientJSON(ClientConfig{Server: "203.0.113.10", ServerPort: 443, Params: p, Port: 1080, User: "u", Pass: "p",
		Routing: Routing{Direct: []string{"ru"}, DNS: []string{"https://1.1.1.1/dns-query"}, Raw: "1.1.1.1:53"}})
	if err != nil {
		t.Fatal(err)
	}
	out := outboundByTag(t, raw, tagDNS)
	set, _ := out["settings"].(map[string]any)
	if set["rewriteNetwork"] != "tcp" || set["rewriteAddress"] != "1.1.1.1" || set["rewritePort"] != float64(53) {
		t.Fatalf("dns-out settings %v", set)
	}
	rules, _ := json.Marshal(set["rules"])
	if string(rules) != `[{"action":"hijack","qType":"1,28"},{"action":"direct"}]` {
		t.Fatalf("dns-out rules %s", rules)
	}
	stream, _ := json.Marshal(out["streamSettings"])
	if string(stream) != `{"sockopt":{"dialerProxy":"proxy"}}` {
		t.Fatalf("dns-out goes %s, want through the proxy outbound", stream)
	}

	raw, err = ClientJSON(ClientConfig{Server: "203.0.113.10", ServerPort: 443, Params: p, Port: 1080, User: "u", Pass: "p",
		Routing: Routing{DNS: []string{"https://1.1.1.1/dns-query"}}})
	if err != nil {
		t.Fatal(err)
	}
	if set, _ := outboundByTag(t, raw, tagDNS)["settings"].(map[string]any); set["nonIPQuery"] != "reject" {
		t.Fatalf("without a raw server other types must be refused: %v", set)
	}
}

func TestByAddressKeepsTheHandshake(t *testing.T) {
	for _, tc := range []struct {
		in   Params
		want Params
	}{
		{Params{Security: "tls", Network: "ws"}, Params{Security: "tls", Network: "ws", SNI: "vps.example.net"}},
		{Params{Security: "reality", Network: "xhttp", SNI: "www.microsoft.com"}, Params{Security: "reality", Network: "xhttp", SNI: "www.microsoft.com"}},
		{Params{Security: "none", Network: "ws"}, Params{Security: "none", Network: "ws", Host: "vps.example.net"}},
		{Params{Security: "none", Network: "xhttp", Host: "cdn.example.org"}, Params{Security: "none", Network: "xhttp", Host: "cdn.example.org"}},
		{Params{Security: "none", Network: "grpc"}, Params{Security: "none", Network: "grpc", Authority: "vps.example.net"}},
		{Params{Security: "none", Network: "tcp"}, Params{Security: "none", Network: "tcp"}},
	} {
		if got := byAddress(tc.in, "vps.example.net"); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("byAddress(%+v) = %+v, want %+v", tc.in, got, tc.want)
		}
	}
}

func TestDialTargetUsesResolveServer(t *testing.T) {
	defer func(old func(context.Context, string) ([]net.IP, error)) { ResolveServer = old }(ResolveServer)
	var asked []string
	ResolveServer = func(_ context.Context, host string) ([]net.IP, error) {
		asked = append(asked, host)
		if host == "gone.example.net" {
			return nil, errors.New("no answer")
		}
		return []net.IP{net.ParseIP("2001:db8::7"), net.ParseIP("203.0.113.7")}, nil
	}
	p := Params{Security: "tls", Network: "tcp"}
	host, got, err := dialTarget(context.Background(), "vps.example.net", p)
	if err != nil || host != "203.0.113.7" || got.SNI != "vps.example.net" {
		t.Fatalf("dialTarget = %q %+v %v", host, got, err)
	}
	if host, _, _ := dialTarget(context.Background(), "198.51.100.1", p); host != "198.51.100.1" || len(asked) != 1 {
		t.Fatalf("an IP was looked up: %q %v", host, asked)
	}
	if _, _, err := dialTarget(context.Background(), "gone.example.net", p); err == nil || !strings.Contains(err.Error(), "IP-адрес") {
		t.Fatalf("failed lookup: %v", err)
	}
}
