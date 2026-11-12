package mobilecfg

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// Fake servers only: documentation addresses and made-up keys.
const (
	fakeUUID  = "11111111-2222-4333-8444-555555555555"
	fakeKey   = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	xhttpLink = "vless://" + fakeUUID + "@server.example:8443?type=xhttp&security=reality&pbk=" + fakeKey +
		"&sid=ab12&sni=www.example.org&fp=chrome&path=%2Fapi&host=cdn.example.org&mode=packet-up#Test%20XHTTP"
	rawLink = "vless://" + fakeUUID + "@server.example:443?type=tcp&security=reality&pbk=" + fakeKey +
		"&sid=ab12&sni=www.example.org&flow=xtls-rprx-vision#Test%20RAW"
)

func TestFromLinkXHTTP(t *testing.T) {
	p, err := FromLink("  " + xhttpLink + "\n")
	if err != nil {
		t.Fatal(err)
	}
	want := Profile{Name: "Test XHTTP", Kind: KindVLESS, Link: xhttpLink, Host: "server.example", Port: 8443}
	if p != want {
		t.Fatalf("got %+v, want %+v", p, want)
	}
	out := outbounds(t, p)[0]
	if out["tag"] != TagProxy || out["protocol"] != "vless" {
		t.Fatalf("first outbound is %v/%v", out["tag"], out["protocol"])
	}
	stream := out["streamSettings"].(map[string]any)
	if stream["network"] != "xhttp" || stream["security"] != "reality" {
		t.Fatalf("stream is %v/%v", stream["network"], stream["security"])
	}
	wantX := map[string]any{"path": "/api", "host": "cdn.example.org", "mode": "packet-up"}
	if got := stream["xhttpSettings"]; !reflect.DeepEqual(got, wantX) {
		t.Fatalf("xhttpSettings = %v, want %v", got, wantX)
	}
	reality := stream["realitySettings"].(map[string]any)
	if reality["serverName"] != "www.example.org" || reality["publicKey"] != fakeKey || reality["shortId"] != "ab12" {
		t.Fatalf("realitySettings = %v", reality)
	}
	server := out["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
	if server["address"] != "server.example" || server["port"] != float64(8443) {
		t.Fatalf("server = %v", server)
	}
}

func TestFromLinkRejectsOtherTransports(t *testing.T) {
	if _, err := FromLink(rawLink); err != errNotXHTTP {
		t.Fatalf("RAW link: err = %v", err)
	}
	if _, err := FromLink("https://example.org/"); err == nil {
		t.Fatal("a non-VLESS link was accepted")
	}
	if _, err := XrayJSON(Profile{Kind: KindVLESS, Link: rawLink}); err != errNotXHTTP {
		t.Fatalf("RAW profile: err = %v", err)
	}
}

func TestFromSubscription(t *testing.T) {
	second := strings.Replace(xhttpLink, "server.example:8443", "198.51.100.7:443", 1)
	second = strings.Replace(second, "#Test%20XHTTP", "#Second", 1)
	plain := rawLink + "\n" + xhttpLink + "\nss://ignored\n" + second + "\n"
	for name, body := range map[string]string{
		"plain":  plain,
		"base64": base64.StdEncoding.EncodeToString([]byte(plain)),
	} {
		got, err := FromSubscription([]byte(body))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(got) != 2 || got[0].Name != "Test XHTTP" || got[1].Name != "Second" || got[1].Host != "198.51.100.7" || got[1].Port != 443 {
			t.Fatalf("%s: got %+v", name, got)
		}
	}
	if _, err := FromSubscription([]byte(rawLink)); err == nil {
		t.Fatal("a subscription without XHTTP servers was accepted")
	}
}

func TestProxy(t *testing.T) {
	p, err := Proxy("SOCKS5", "", " proxy.example ", 1080, "user", "secret")
	if err != nil {
		t.Fatal(err)
	}
	if want := (Profile{Name: "proxy.example", Kind: KindSOCKS5, Host: "proxy.example", Port: 1080, User: "user", Pass: "secret"}); p != want {
		t.Fatalf("got %+v", p)
	}
	out := outbounds(t, p)[0]
	wantSettings := map[string]any{"address": "proxy.example", "port": float64(1080), "user": "user", "pass": "secret"}
	if out["tag"] != TagProxy || out["protocol"] != "socks" || !reflect.DeepEqual(out["settings"], wantSettings) {
		t.Fatalf("socks outbound = %v", out)
	}

	p, err = Proxy("http", "Office", "[2001:db8::1]", 3128, "", "")
	if err != nil {
		t.Fatal(err)
	}
	out = outbounds(t, p)[0]
	wantSettings = map[string]any{"address": "2001:db8::1", "port": float64(3128)}
	if p.Name != "Office" || out["protocol"] != "http" || !reflect.DeepEqual(out["settings"], wantSettings) {
		t.Fatalf("http outbound = %v", out)
	}

	bad := []struct {
		kind, host       string
		port             int
		user, pass, what string
	}{
		{"ftp", "proxy.example", 1080, "", "", "kind"},
		{"socks5", "", 1080, "", "", "empty host"},
		{"socks5", "http://proxy.example", 1080, "", "", "host with a scheme"},
		{"socks5", "proxy.example:1080", 1080, "", "", "host with a port"},
		{"http", "proxy.example", 0, "", "", "port 0"},
		{"http", "proxy.example", 70000, "", "", "port 70000"},
		{"http", "proxy.example", 3128, "", "secret", "password without a login"},
	}
	for _, b := range bad {
		if _, err := Proxy(b.kind, "", b.host, b.port, b.user, b.pass); err == nil {
			t.Errorf("%s was accepted", b.what)
		}
	}
}

func doc(t *testing.T, p Profile) map[string]any {
	t.Helper()
	raw, err := XrayJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func outbounds(t *testing.T, p Profile) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, o := range doc(t, p)["outbounds"].([]any) {
		out = append(out, o.(map[string]any))
	}
	return out
}

func profiles(t *testing.T) map[string]Profile {
	t.Helper()
	v, err := FromLink(xhttpLink)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]Profile{
		"vless":  v,
		"socks5": {Name: "s", Kind: KindSOCKS5, Host: "192.0.2.10", Port: 1080},
		"http":   {Name: "h", Kind: KindHTTP, Host: "192.0.2.11", Port: 3128, User: "u", Pass: "p"},
	}
}

// The only inbound is the TUN: nothing listens on a local port.
func TestNoLocalPort(t *testing.T) {
	for name, p := range profiles(t) {
		in := doc(t, p)["inbounds"].([]any)
		if len(in) != 1 {
			t.Fatalf("%s: %d inbounds", name, len(in))
		}
		tun := in[0].(map[string]any)
		if tun["protocol"] != "tun" || tun["port"] != float64(0) || tun["listen"] != nil {
			t.Fatalf("%s: inbound = %v", name, tun)
		}
		sniff := tun["sniffing"].(map[string]any)
		if sniff["enabled"] != true || sniff["routeOnly"] != true {
			t.Fatalf("%s: sniffing = %v", name, sniff)
		}
		if _, ok := doc(t, p)["api"]; ok {
			t.Fatalf("%s: the document has an API section", name)
		}
	}
}

func TestRouting(t *testing.T) {
	for name, p := range profiles(t) {
		d := doc(t, p)
		outs := outbounds(t, p)
		if outs[0]["tag"] != TagProxy {
			t.Fatalf("%s: the default outbound is %v", name, outs[0]["tag"])
		}
		protocols := map[string]any{}
		for _, o := range outs {
			protocols[o["tag"].(string)] = o["protocol"]
		}
		if protocols[TagDirect] != "freedom" || protocols[TagDNS] != "dns" || protocols[TagBlock] != "blackhole" {
			t.Fatalf("%s: outbounds = %v", name, protocols)
		}
		rules := d["routing"].(map[string]any)["rules"].([]any)
		rule := func(i int) map[string]any { return rules[i].(map[string]any) }

		// DNS first: no later rule may send port 53 direct.
		if r := rule(0); r["port"] != "53" || r["outboundTag"] != TagDNS || !reflect.DeepEqual(r["inboundTag"], []any{TagTun}) || len(r) != 4 {
			t.Fatalf("%s: rule 0 = %v", name, r)
		}
		// Xray's own DNS queries leave through the proxy.
		if r := rule(1); r["outboundTag"] != TagProxy || !reflect.DeepEqual(r["inboundTag"], []any{TagDNSIn}) || len(r) != 3 {
			t.Fatalf("%s: rule 1 = %v", name, r)
		}
		domains := rule(2)["domain"].([]any)
		for _, want := range []string{"domain:ru", "domain:su", "domain:xn--p1ai", "geosite:category-ru"} {
			if !contains(domains, want) {
				t.Errorf("%s: %s is not direct", name, want)
			}
		}
		if rule(2)["outboundTag"] != TagDirect {
			t.Fatalf("%s: rule 2 = %v", name, rule(2))
		}
		if r := rule(3); !reflect.DeepEqual(r["ip"], []any{"geoip:ru"}) || r["outboundTag"] != TagDirect {
			t.Fatalf("%s: rule 3 = %v", name, r)
		}
		// Nothing else is direct.
		for i := 4; i < len(rules); i++ {
			if rule(i)["outboundTag"] == TagDirect {
				t.Fatalf("%s: rule %d is direct: %v", name, i, rule(i))
			}
		}
		if p.Kind == KindHTTP {
			if r := rule(4); r["network"] != "udp" || r["outboundTag"] != TagBlock {
				t.Fatalf("http: rule 4 = %v", r)
			}
		} else if len(rules) != 4 {
			t.Fatalf("%s: %d rules", name, len(rules))
		}
	}
}

func TestDNSThroughTunnel(t *testing.T) {
	for name, p := range profiles(t) {
		d := doc(t, p)
		dns := d["dns"].(map[string]any)
		if dns["tag"] != TagDNSIn {
			t.Fatalf("%s: dns tag = %v", name, dns["tag"])
		}
		servers := dns["servers"].([]any)
		if len(servers) == 0 {
			t.Fatalf("%s: no DNS servers", name)
		}
		for _, s := range servers {
			// "localhost" and "+local" servers would use the network's DNS.
			text, ok := s.(string)
			if !ok || !strings.HasPrefix(text, "https://") || strings.Contains(text, "local") {
				t.Fatalf("%s: DNS server %v does not go through the proxy", name, s)
			}
		}
		for _, o := range outbounds(t, p) {
			if o["tag"] != TagDNS {
				continue
			}
			proxy := o["streamSettings"].(map[string]any)["sockopt"].(map[string]any)["dialerProxy"]
			s := o["settings"].(map[string]any)
			if proxy != TagProxy || s["rewriteNetwork"] != "tcp" || s["rewriteAddress"] != RawDNS {
				t.Fatalf("%s: dns outbound = %v", name, o)
			}
		}
	}
}

func contains(list []any, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func TestMask(t *testing.T) {
	v, _ := FromLink(xhttpLink)
	if got := v.Mask("bad id " + fakeUUID + " key " + fakeKey + " sid ab12"); got != "bad id *** key *** sid ***" {
		t.Fatalf("got %q", got)
	}
	s := Profile{Kind: KindSOCKS5, Pass: "secret"}
	if got := s.Mask("auth secret failed"); got != "auth *** failed" {
		t.Fatalf("got %q", got)
	}
}
