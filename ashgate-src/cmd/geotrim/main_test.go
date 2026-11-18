package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/xtls/xray-core/common/geodata"
	"google.golang.org/protobuf/proto"
)

func write(t *testing.T, path string, m proto.Message) {
	t.Helper()
	raw, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestTrimKeepsOnlyRussia(t *testing.T) {
	dir := t.TempDir()
	cidr := func(b ...byte) []*geodata.CIDR { return []*geodata.CIDR{{Ip: b, Prefix: 8}} }
	write(t, filepath.Join(dir, "geoip.dat"), &geodata.GeoIPList{Entry: []*geodata.GeoIP{
		{Code: "US", Cidr: cidr(8, 0, 0, 0)},
		{Code: "RU", Cidr: cidr(5, 0, 0, 0)},
		{Code: "PRIVATE", Cidr: cidr(10, 0, 0, 0)},
	}})
	dom := func(v string) []*geodata.Domain { return []*geodata.Domain{{Type: geodata.Domain_Domain, Value: v}} }
	write(t, filepath.Join(dir, "geosite.dat"), &geodata.GeoSiteList{Entry: []*geodata.GeoSite{
		{Code: "GOOGLE", Domain: dom("google.com")},
		{Code: "CATEGORY-RU", Domain: dom("yandex.ru")},
		{Code: "RU", Domain: dom("ru")},
	}})
	if err := trimDir(dir); err != nil {
		t.Fatal(err)
	}

	var ip geodata.GeoIPList
	raw, _ := os.ReadFile(filepath.Join(dir, "geoip.dat"))
	if err := proto.Unmarshal(raw, &ip); err != nil {
		t.Fatal(err)
	}
	if len(ip.Entry) != 1 || ip.Entry[0].Code != "RU" || len(ip.Entry[0].Cidr) != 1 {
		t.Fatalf("geoip after trim: %v", ip.Entry)
	}
	var site geodata.GeoSiteList
	raw, _ = os.ReadFile(filepath.Join(dir, "geosite.dat"))
	if err := proto.Unmarshal(raw, &site); err != nil {
		t.Fatal(err)
	}
	if len(site.Entry) != 1 || site.Entry[0].Code != "CATEGORY-RU" || site.Entry[0].Domain[0].Value != "yandex.ru" {
		t.Fatalf("geosite after trim: %v", site.Entry)
	}
}

func TestTrimFailsWithoutRussia(t *testing.T) {
	raw, _ := proto.Marshal(&geodata.GeoIPList{Entry: []*geodata.GeoIP{{Code: "US", Cidr: []*geodata.CIDR{{Ip: []byte{8, 0, 0, 0}, Prefix: 8}}}}})
	if _, err := trimIP(raw, keepIP); err == nil {
		t.Fatal("geoip without RU must fail")
	}
	raw, _ = proto.Marshal(&geodata.GeoSiteList{Entry: []*geodata.GeoSite{{Code: "CATEGORY-RU"}}})
	if _, err := trimSite(raw, keepSite); err == nil {
		t.Fatal("empty category-ru must fail")
	}
	if _, err := trimIP([]byte{0xff, 0xff}, keepIP); err == nil {
		t.Fatal("garbage must fail")
	}
}
