package mobile

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	routingsession "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/infra/conf/serial"

	"ashgate/internal/mobilecfg"
)

// Fake servers only: documentation addresses and made-up keys.
const fakeLink = "vless://11111111-2222-4333-8444-555555555555@server.example:8443?type=xhttp&security=reality" +
	"&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=ab12&sni=www.example.org&path=%2Fapi#Test"

// TestRouter loads each kind of profile into the real Xray with the geodata
// the APK ships and asks its router where connections go. CI sets
// ASHGATE_GEODATA to the directory with geoip.dat and geosite.dat.
func TestRouter(t *testing.T) {
	dir := os.Getenv("ASHGATE_GEODATA")
	if dir == "" {
		t.Skip("ASHGATE_GEODATA is not set")
	}
	for _, f := range []string{"geoip.dat", "geosite.dat"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("xray.location.asset", dir)

	link, err := ParseLink(fakeLink)
	if err != nil {
		t.Fatal(err)
	}
	socks, err := ParseProxy("socks5", "", "192.0.2.10", 1080, "user", "secret")
	if err != nil {
		t.Fatal(err)
	}
	httpProxy, err := ParseProxy("http", "", "192.0.2.11", 3128, "", "")
	if err != nil {
		t.Fatal(err)
	}

	type conn struct {
		what    string
		inbound string
		network xnet.Network
		ip      string
		port    uint16
		domain  string // the sniffed name, if any
		want    string
	}
	const foreign, russian = "1.1.1.1", "77.88.8.8"
	common := []conn{
		{"a foreign site", mobilecfg.TagTun, xnet.Network_TCP, foreign, 443, "example.com", mobilecfg.TagProxy},
		{"a foreign address without a name", mobilecfg.TagTun, xnet.Network_TCP, foreign, 443, "", mobilecfg.TagProxy},
		{"a foreign IPv6 address", mobilecfg.TagTun, xnet.Network_TCP, "2606:4700:4700::1111", 443, "", mobilecfg.TagProxy},
		{".ru", mobilecfg.TagTun, xnet.Network_TCP, foreign, 443, "example.ru", mobilecfg.TagDirect},
		{"a subdomain of .ru", mobilecfg.TagTun, xnet.Network_TCP, foreign, 80, "www.example.ru", mobilecfg.TagDirect},
		{".su", mobilecfg.TagTun, xnet.Network_TCP, foreign, 443, "example.su", mobilecfg.TagDirect},
		{".рф", mobilecfg.TagTun, xnet.Network_TCP, foreign, 443, "example.xn--p1ai", mobilecfg.TagDirect},
		{"geosite:category-ru", mobilecfg.TagTun, xnet.Network_TCP, foreign, 443, "vk.com", mobilecfg.TagDirect},
		{"a Russian address", mobilecfg.TagTun, xnet.Network_TCP, russian, 443, "", mobilecfg.TagDirect},
		{"a name that only ends like .ru", mobilecfg.TagTun, xnet.Network_TCP, foreign, 443, "example.guru", mobilecfg.TagProxy},
		{"DNS over UDP", mobilecfg.TagTun, xnet.Network_UDP, foreign, 53, "", mobilecfg.TagDNS},
		{"DNS over TCP", mobilecfg.TagTun, xnet.Network_TCP, foreign, 53, "", mobilecfg.TagDNS},
		{"DNS to a Russian server", mobilecfg.TagTun, xnet.Network_UDP, russian, 53, "", mobilecfg.TagDNS},
		{"Xray's own DNS query", mobilecfg.TagDNSIn, xnet.Network_TCP, foreign, 443, "", mobilecfg.TagProxy},
	}
	for name, tc := range map[string]struct {
		profile string
		udp     string // where foreign UDP goes
	}{
		"vless":  {link, mobilecfg.TagProxy},
		"socks5": {socks, mobilecfg.TagProxy},
		"http":   {httpProxy, mobilecfg.TagBlock},
	} {
		t.Run(name, func(t *testing.T) {
			var p mobilecfg.Profile
			if err := json.Unmarshal([]byte(tc.profile), &p); err != nil {
				t.Fatal(err)
			}
			raw, err := mobilecfg.XrayJSON(p)
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := serial.LoadJSONConfig(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			if len(cfg.Inbound) != 1 {
				t.Fatalf("%d inbounds", len(cfg.Inbound))
			}
			inst, err := core.New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer inst.Close()
			router := inst.GetFeature(routing.RouterType()).(routing.Router)

			conns := append([]conn{{"foreign UDP", mobilecfg.TagTun, xnet.Network_UDP, foreign, 443, "", tc.udp}}, common...)
			for _, c := range conns {
				target := xnet.Destination{Network: c.network, Address: xnet.ParseAddress(c.ip), Port: xnet.Port(c.port)}
				out := &session.Outbound{Target: target}
				if c.domain != "" {
					out.RouteTarget = xnet.Destination{Network: c.network, Address: xnet.DomainAddress(c.domain), Port: xnet.Port(c.port)}
				}
				ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: c.inbound})
				ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{out})
				got := mobilecfg.TagProxy // the first outbound takes what no rule matches
				if route, err := router.PickRoute(routingsession.AsRoutingContext(ctx)); err == nil {
					got = route.GetOutboundTag()
				}
				if got != c.want {
					t.Errorf("%s goes to %q, want %q", c.what, got, c.want)
				}
			}
		})
	}
}
