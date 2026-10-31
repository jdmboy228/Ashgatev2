package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ashgate/internal/vless"
)

func TestLoadSaveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ashgate.json")
	on := true
	cfg := &Config{
		Proxies: []Proxy{{
			Name:     "home",
			Type:     "socks5",
			Address:  "127.0.0.1:1080",
			Username: "u",
			Password: "p",
		}},
		Rules: []Rule{{
			Enabled: &on,
			Process: `C:\Tools\curl.exe`,
			Action:  "proxy",
			Proxy:   "home",
		}},
	}
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 1 || got.DNS.Mode != "proxy" || got.UDPUnsupported != "block" {
		t.Fatalf("defaults not applied: %+v", got)
	}
	if len(got.DNS.Servers) != 2 || got.Proxies[0].Password != "p" {
		t.Fatalf("fields lost: %+v", got)
	}
	if !got.Rules[0].IsEnabled() || got.Rules[0].Process != `C:\Tools\curl.exe` {
		t.Fatalf("rule: %+v", got.Rules[0])
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", st.Mode().Perm())
	}
}

func TestMissingEnabledMeansOn(t *testing.T) {
	raw := []byte(`{
		"proxies": [{"name": "h", "type": "http", "address": "10.0.0.1:8080"}],
		"rules": [{"process": "curl.exe", "action": "proxy", "proxy": "h"}]
	}`)
	dir := t.TempDir()
	path := filepath.Join(dir, "c.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Rules[0].IsEnabled() {
		t.Fatal("omitted enabled should be true")
	}
	if cfg.Relay.TCP4 != "127.0.0.1:34010" {
		t.Fatal(cfg.Relay.TCP4)
	}
}

func TestValidateErrors(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{"bad type", Config{Proxies: []Proxy{{Name: "a", Type: "ss", Address: "127.0.0.1:1"}}}, "type"},
		{"dup", Config{Proxies: []Proxy{
			{Name: "a", Type: "socks5", Address: "127.0.0.1:1"},
			{Name: "a", Type: "socks5", Address: "127.0.0.1:2"},
		}}, "duplicate"},
		{"unknown proxy", Config{Rules: []Rule{{Process: "a.exe", Action: "proxy", Proxy: "missing"}}}, "unknown proxy"},
		{"svchost", Config{Rules: []Rule{{Process: `C:\Windows\System32\svchost.exe`, Action: "direct"}}}, "svchost"},
		{"direct with proxy", Config{
			Proxies: []Proxy{{Name: "a", Type: "http", Address: "127.0.0.1:1"}},
			Rules:   []Rule{{Process: "a.exe", Action: "direct", Proxy: "a"}},
		}, "must be empty"},
		{"block with proxy", Config{
			Proxies: []Proxy{{Name: "a", Type: "http", Address: "127.0.0.1:1"}},
			Rules:   []Rule{{Process: "a.exe", Action: "block", Proxy: "a"}},
		}, "must be empty"},
		{"bad theme", Config{UI: UI{Theme: "blue"}}, "theme"},
		{"bad udp", Config{UDPUnsupported: "drop"}, "udpUnsupported"},
		{"system dns", Config{DNS: DNS{IncludeSystemResolver: true}}, "systemResolverProxy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.ApplyDefaults()
			err := tc.cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestLoadOrInit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.json")
	cfg, err := LoadOrInit(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Version != 1 {
		t.Fatal(cfg.Version)
	}
	again, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if again.DNS.Mode != "proxy" {
		t.Fatal(again.DNS.Mode)
	}
}

func TestExampleConfig(t *testing.T) {
	cfg, err := Load("../../configs/ashgate.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Proxies) != 1 || cfg.Proxies[0].Type != "socks5" {
		t.Fatalf("%+v", cfg.Proxies)
	}
	if len(cfg.Rules) != 1 || cfg.Rules[0].IsEnabled() {
		t.Fatal("the sample curl rule must ship disabled")
	}
	if cfg.UI.Theme != "" {
		t.Fatal("0.1.0 example has no theme")
	}
}

func TestBlockActionRoundTrip(t *testing.T) {
	raw := []byte(`{
		"version": 1,
		"proxies": [{"name": "h", "type": "socks5", "address": "127.0.0.1:1080"}],
		"rules": [
			{"process": "curl.exe", "action": "proxy", "proxy": "h"},
			{"process": "telemetry.exe", "action": "block"}
		]
	}`)
	path := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Rules[1].Action != "block" || cfg.Rules[1].Proxy != "" {
		t.Fatalf("%+v", cfg.Rules[1])
	}
	cfg.UI.Theme = "light"
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	again, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if again.UI.Theme != "light" || again.Rules[0].Action != "proxy" {
		t.Fatalf("%+v", again)
	}
}

func TestVLESSLinkRoundTrip(t *testing.T) {
	const link = "vless://b7e2c1a0-4f3a-4c2b-9a11-111111111111@203.0.113.10:443?encryption=none&security=reality&type=xhttp&path=%2Fxhttp&mode=auto&sni=www.microsoft.com&fp=chrome&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&sid=ab12&flow=xtls-rprx-vision#aeza-se"
	raw := []byte(`{
		"proxies": [
			{"name": "local", "type": "socks5", "address": "127.0.0.1:1080"},
			{"name": "aeza", "type": "vless", "link": "` + link + `"}
		],
		"rules": [{"process": "telegram.exe", "action": "proxy", "proxy": "aeza"}]
	}`)
	path := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Proxies[0].Type != "socks5" || cfg.Proxies[0].VLESS != nil {
		t.Fatalf("socks proxy changed: %+v", cfg.Proxies[0])
	}
	p := cfg.Proxies[1]
	if p.Address != "203.0.113.10:443" || p.VLESS == nil || p.VLESS.Network != "xhttp" || p.VLESS.UUID == "" {
		t.Fatalf("%+v", p)
	}
	if p.Local != "" {
		t.Fatal("local bridge address must not be loaded from disk")
	}
	if p.SOCKSPort != 0 {
		t.Fatalf("socks port %d", p.SOCKSPort)
	}
	cfg.Proxies[1].Local = "127.0.0.1:9"
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	again, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(again), "127.0.0.1:9") {
		t.Fatal("local bridge address was written to config.json")
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Proxies[1].VLESS.Security != "reality" || loaded.Rules[0].Proxy != "aeza" {
		t.Fatalf("%+v", loaded.Proxies[1])
	}
}

func TestLocalSOCKSPortValidation(t *testing.T) {
	const link = "vless://b7e2c1a0-4f3a-4c2b-9a11-111111111111@203.0.113.10:443?encryption=none&type=tcp&security=none"
	base := func() *Config {
		cfg := Default()
		cfg.Proxies = []Proxy{{
			Name: "aeza", Type: "vless", Address: "203.0.113.10:443", SOCKSPort: 10808, Link: link,
		}}
		return cfg
	}
	cfg := base()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "c.json")
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Proxies[0].SOCKSPort != 10808 || loaded.Proxies[0].Local != "" {
		t.Fatalf("%+v", loaded.Proxies[0])
	}
	dup := base()
	dup.Proxies = append(dup.Proxies, Proxy{
		Name: "b", Type: "vless", Address: "203.0.113.11:443", SOCKSPort: 10808, Link: link,
	})
	if err := dup.Validate(); err == nil || !strings.Contains(err.Error(), "10808") {
		t.Fatal(err)
	}
	bad := base()
	bad.Proxies[0].SOCKSPort = 34010
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "приёмником") {
		t.Fatal(err)
	}
	old := Default()
	old.Proxies = []Proxy{{Name: "local", Type: "socks5", Address: "127.0.0.1:1080"}}
	if err := old.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestPathFromArgs(t *testing.T) {
	if got := PathFromArgs([]string{"run", "-config", `D:\a.json`}); got != `D:\a.json` {
		t.Fatal(got)
	}
	if got := PathFromArgs([]string{"--config=./ash.json"}); got != "./ash.json" {
		t.Fatal(got)
	}
	if got := PathFromArgs(nil); got == "" {
		t.Fatal("empty default path")
	}
}

func TestDolphinFieldsSurviveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	body := []byte(`{
  "version": 1,
  "dolphin": {"apiRoute": "auto", "apiProxy": "aeza"},
  "proxies": [{"name": "local", "type": "socks5", "address": "127.0.0.1:1080"}],
  "rules": []
}`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Proxies[0].Name != "local" || cfg.Extra["dolphin"] == nil {
		t.Fatalf("load %+v extra %s", cfg.Proxies, cfg.Extra["dolphin"])
	}
	on := true
	cfg.Rules = []Rule{{Enabled: &on, Process: "curl.exe", Action: "direct"}}
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"apiRoute"`)) || !bytes.Contains(raw, []byte("curl.exe")) {
		t.Fatalf("round trip dropped fields: %s", raw)
	}
	again, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if again.Extra["dolphin"] == nil || len(again.Rules) != 1 {
		t.Fatalf("reload extra %s rules %d", again.Extra["dolphin"], len(again.Rules))
	}
}

func TestDNSServerMustBeIP(t *testing.T) {
	cfg := Default()
	cfg.DNS.Servers = []string{"dns.google:53"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("older files with a host name must still load: %v", err)
	}
	if err := cfg.CheckDNSServers(); err == nil {
		t.Fatal("host name accepted as dns server")
	}
	cfg.DNS.Servers = []string{"[2606:4700::1111]:53", "1.1.1.1:53"}
	if err := cfg.CheckDNSServers(); err != nil {
		t.Fatal(err)
	}
}

func TestGroupValidation(t *testing.T) {
	base := func() *Config {
		c := Default()
		c.Proxies = []Proxy{{Name: "p", Type: "socks5", Address: "127.0.0.1:1080"}}
		c.Groups = []Group{{Name: "Игры", Action: "proxy", Proxy: "p"}}
		c.Rules = []Rule{{Process: "steam.exe", Action: "direct", Group: "Игры"}}
		return c
	}
	if err := base().Validate(); err != nil {
		t.Fatal(err)
	}
	c := base()
	c.Rules[0].Group = "Нет"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "unknown group") {
		t.Fatalf("unknown group: %v", err)
	}
	c = base()
	c.Groups = append(c.Groups, Group{Name: "Игры", Action: "direct"})
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate group") {
		t.Fatalf("duplicate: %v", err)
	}
	c = base()
	c.Groups[0].Proxy = "gone"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "unknown proxy") {
		t.Fatalf("group proxy: %v", err)
	}
}

func TestMaskMatchingEverythingRejected(t *testing.T) {
	for _, p := range []string{"*", "*.exe", `*\*.exe`, "?*"} {
		c := Default()
		c.Rules = []Rule{{Process: p, Action: "direct"}}
		if err := c.Validate(); err == nil {
			t.Fatalf("%q accepted", p)
		}
	}
	c := Default()
	c.Rules = []Rule{{Process: `*\Discord\*.exe`, Action: "direct"}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestProxyNames(t *testing.T) {
	for _, name := range []string{"aeza", "Швеция 1", "Sweden-1.vless", "Узел_2", "我的服务器"} {
		if !validName(name) {
			t.Errorf("%q rejected", name)
		}
	}
	for _, name := range []string{"", " lead", "trail ", "-dash", "a/b", "a:b", `quo"te`, "tab\tname", strings.Repeat("я", 65)} {
		if validName(name) {
			t.Errorf("%q accepted", name)
		}
	}
	// Every name the link parser suggests must be a valid name.
	for _, frag := range []string{"🇸🇪 Швеция-1 (VLESS)", "aeza se", "  _node_ ", "a+b/c", strings.Repeat("я", 100)} {
		if s := vless.SuggestName(frag); s != "" && !validName(s) {
			t.Errorf("SuggestName(%q) = %q is not a valid name", frag, s)
		}
	}
}

func TestRelayMustBeLoopback(t *testing.T) {
	for _, tc := range []struct {
		tcp4, tcp6 string
		ok         bool
	}{
		{"127.0.0.1:34010", "[::1]:34010", true},
		{"127.0.0.2:34010", "[::1]:34010", true},
		{"0.0.0.0:34010", "[::1]:34010", false},
		{"192.168.1.10:34010", "[::1]:34010", false},
		{"127.0.0.1:34010", "[::]:34010", false},
		{"[::1]:34010", "[::1]:34010", false},
		{"localhost:34010", "[::1]:34010", false},
	} {
		c := Default()
		c.Relay.TCP4, c.Relay.TCP6 = tc.tcp4, tc.tcp6
		if err := c.Validate(); (err == nil) != tc.ok {
			t.Errorf("relay %s %s: err=%v", tc.tcp4, tc.tcp6, err)
		}
	}
}
