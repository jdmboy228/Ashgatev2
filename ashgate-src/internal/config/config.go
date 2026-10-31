// Package config loads and stores the Ashgate JSON configuration.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"ashgate/internal/vless"
)

// Config is the on-disk configuration.
type Config struct {
	Version        int    `json:"version"`
	Relay          Relay  `json:"relay"`
	DNS            DNS    `json:"dns"`
	BypassPrivate  bool   `json:"bypassPrivate"`
	UDPUnsupported string `json:"udpUnsupported"`
	// KillSwitch keeps proxied applications off the direct network: while
	// capture runs nothing of theirs bypasses the proxy, and while it is
	// stopped Windows Firewall blocks them.
	KillSwitch bool    `json:"killSwitch,omitempty"`
	Log        Log     `json:"log"`
	UI         UI      `json:"ui,omitempty"`
	Proxies    []Proxy `json:"proxies"`
	Rules      []Rule  `json:"rules"`
	// Groups bundle rules under one switch and one route; see Rule.Group.
	Groups []Group `json:"groups,omitempty"`
	// Extra keeps JSON keys this version does not understand, such as the
	// Dolphin block from 0.4.x. Saving the file must not drop them.
	Extra map[string]json.RawMessage `json:"-"`
}

// UI holds window preferences. Empty fields keep the 0.1.0 meaning.
type UI struct {
	Theme string `json:"theme,omitempty"`
}

// Relay is the local TCP endpoint used as the transparent-proxy target.
type Relay struct {
	TCP4 string `json:"tcp4"`
	TCP6 string `json:"tcp6"`
}

// DNS controls how port-53 traffic of proxied applications is forwarded.
type DNS struct {
	// Mode is "proxy" (send queries to Servers through the rule's proxy)
	// or "original" (send them to the destination the application chose).
	Mode                  string   `json:"mode"`
	Servers               []string `json:"servers"`
	IncludeSystemResolver bool     `json:"includeSystemResolver"`
	SystemResolverProxy   string   `json:"systemResolverProxy"`
}

// Log selects the optional JSON-lines connection log.
type Log struct {
	File  string `json:"file,omitempty"`
	Level string `json:"level,omitempty"`
}

// Proxy is one upstream proxy.
// Local is the SOCKS address of a running VLESS bridge. It is not saved.
// SOCKSPort, when set on a VLESS proxy, publishes that bridge on
// 127.0.0.1:SOCKSPort for other applications. Zero keeps a random port.
// LocalUser and LocalPass authenticate that published inbound.
type Proxy struct {
	Name      string        `json:"name"`
	Type      string        `json:"type"`
	Address   string        `json:"address"`
	Username  string        `json:"username,omitempty"`
	Password  string        `json:"password,omitempty"`
	Link      string        `json:"link,omitempty"`
	VLESS     *vless.Params `json:"vless,omitempty"`
	SOCKSPort int           `json:"socksPort,omitempty"`
	LocalUser string        `json:"localUser,omitempty"`
	LocalPass string        `json:"localPass,omitempty"`
	Local     string        `json:"-"`
}

// Rule maps one application to a proxy, a direct connection, or a drop.
type Rule struct {
	Enabled *bool  `json:"enabled,omitempty"`
	Process string `json:"process"`
	Action  string `json:"action"`
	Proxy   string `json:"proxy,omitempty"`
	// Children, when not false, applies the rule to processes the
	// application starts, at any depth. A missing flag means true.
	Children *bool `json:"children,omitempty"`
	// KillSwitch overrides Config.KillSwitch for this rule; nil follows it.
	KillSwitch *bool `json:"killSwitch,omitempty"`
	// TCPOnly drops the application's UDP instead of proxying it, so
	// QUIC and similar fall back to TCP through the proxy.
	TCPOnly bool `json:"tcpOnly,omitempty"`
	// Group names the group this rule belongs to. The group's switch and
	// route (action and proxy) apply to all its rules.
	Group string `json:"group,omitempty"`
}

// Group is a named set of rules with one switch and one route.
type Group struct {
	Name      string `json:"name"`
	Enabled   *bool  `json:"enabled,omitempty"`
	Action    string `json:"action"`
	Proxy     string `json:"proxy,omitempty"`
	Collapsed bool   `json:"collapsed,omitempty"`
}

// IsEnabled reports whether the group is on. A missing flag means on.
func (g Group) IsEnabled() bool { return g.Enabled == nil || *g.Enabled }

// EffectiveRules returns the rules as the engine applies them: a grouped
// rule takes its group's switch and route, and every rule's KillSwitch is
// set (rule override or the global default).
func (c *Config) EffectiveRules() []Rule {
	groups := make(map[string]Group, len(c.Groups))
	for _, g := range c.Groups {
		groups[g.Name] = g
	}
	out := make([]Rule, len(c.Rules))
	for i, r := range c.Rules {
		if g, ok := groups[r.Group]; ok && r.Group != "" {
			on := r.IsEnabled() && g.IsEnabled()
			r.Enabled = &on
			r.Action, r.Proxy = g.Action, g.Proxy
		}
		ks := c.KillSwitch
		if r.KillSwitch != nil {
			ks = *r.KillSwitch
		}
		r.KillSwitch = &ks
		out[i] = r
	}
	return out
}

// RuleKillSwitch reports the kill switch in effect for r.
func (r Rule) RuleKillSwitch() bool { return r.KillSwitch != nil && *r.KillSwitch }

// IsEnabled reports whether the rule is active. A missing flag means enabled.
func (r Rule) IsEnabled() bool {
	return r.Enabled == nil || *r.Enabled
}

// CoversChildren reports whether child processes inherit the rule.
func (r Rule) CoversChildren() bool {
	return r.Children == nil || *r.Children
}

// Default returns a config with the built-in defaults and no rules.
func Default() *Config {
	cfg := &Config{}
	cfg.ApplyDefaults()
	return cfg
}

// ApplyDefaults fills zero-valued fields. Explicit values are kept.
func (c *Config) ApplyDefaults() {
	if c.Version == 0 {
		c.Version = 1
	}
	if c.Relay.TCP4 == "" {
		c.Relay.TCP4 = "127.0.0.1:34010"
	}
	if c.Relay.TCP6 == "" {
		c.Relay.TCP6 = "[::1]:34010"
	}
	if c.DNS.Mode == "" {
		c.DNS.Mode = "proxy"
	}
	if c.DNS.Mode == "proxy" && len(c.DNS.Servers) == 0 {
		c.DNS.Servers = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	if c.UDPUnsupported == "" {
		c.UDPUnsupported = "block"
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Proxies == nil {
		c.Proxies = []Proxy{}
	}
	if c.Rules == nil {
		c.Rules = []Rule{}
	}
	for i := range c.Rules {
		if c.Rules[i].Enabled == nil {
			v := true
			c.Rules[i].Enabled = &v
		}
	}
}

// Validate checks the config after defaults have been applied.
func (c *Config) Validate() error {
	if c.Version != 1 {
		return fmt.Errorf("unsupported config version %d", c.Version)
	}
	if err := loopbackRelay(c.Relay.TCP4, false); err != nil {
		return fmt.Errorf("relay.tcp4: %w", err)
	}
	if err := loopbackRelay(c.Relay.TCP6, true); err != nil {
		return fmt.Errorf("relay.tcp6: %w", err)
	}
	switch c.DNS.Mode {
	case "proxy", "original":
	default:
		return fmt.Errorf("dns.mode must be proxy or original, got %q", c.DNS.Mode)
	}
	if c.DNS.Mode == "proxy" {
		if len(c.DNS.Servers) == 0 {
			return errors.New("dns.servers is required when dns.mode is proxy")
		}
		for _, s := range c.DNS.Servers {
			if _, _, err := splitAddr(s); err != nil {
				return fmt.Errorf("dns server %q: %w", s, err)
			}
		}
	}
	switch c.UDPUnsupported {
	case "block", "direct":
	default:
		return fmt.Errorf("udpUnsupported must be block or direct, got %q", c.UDPUnsupported)
	}
	switch c.Log.Level {
	case "info", "debug":
	default:
		return fmt.Errorf("log.level must be info or debug, got %q", c.Log.Level)
	}
	switch c.UI.Theme {
	case "", "dark", "light":
	default:
		return fmt.Errorf("ui.theme must be dark or light, got %q", c.UI.Theme)
	}

	names := make(map[string]struct{}, len(c.Proxies))
	for i, p := range c.Proxies {
		if !validName(p.Name) {
			return fmt.Errorf("proxies[%d]: invalid name %q", i, p.Name)
		}
		if _, ok := names[p.Name]; ok {
			return fmt.Errorf("proxies[%d]: duplicate name %q", i, p.Name)
		}
		names[p.Name] = struct{}{}
		switch c.Proxies[i].Type {
		case "socks5", "http", "vless":
		default:
			return fmt.Errorf("proxies[%d]: type must be socks5, http or vless, got %q", i, c.Proxies[i].Type)
		}
		if c.Proxies[i].Type == "vless" {
			if err := c.Proxies[i].Prepare(); err != nil {
				return fmt.Errorf("proxies[%d]: %w", i, err)
			}
		}
		if _, _, err := splitAddr(c.Proxies[i].Address); err != nil {
			return fmt.Errorf("proxies[%d] address: %w", i, err)
		}
		if len(p.Username) > 255 || len(p.Password) > 255 {
			return fmt.Errorf("proxies[%d]: username and password must be at most 255 bytes", i)
		}
	}
	if err := validateLocalPorts(c); err != nil {
		return err
	}

	if c.DNS.IncludeSystemResolver {
		if c.DNS.SystemResolverProxy == "" {
			return errors.New("dns.systemResolverProxy is required when includeSystemResolver is true")
		}
		if _, ok := names[c.DNS.SystemResolverProxy]; !ok {
			return fmt.Errorf("dns.systemResolverProxy %q is not a configured proxy", c.DNS.SystemResolverProxy)
		}
	}

	groups := map[string]bool{}
	for i, g := range c.Groups {
		name := strings.TrimSpace(g.Name)
		if name == "" || len(name) > 64 || name != g.Name {
			return fmt.Errorf("groups[%d]: invalid name %q", i, g.Name)
		}
		if groups[name] {
			return fmt.Errorf("groups[%d]: duplicate group %q", i, name)
		}
		groups[name] = true
		if err := checkRoute(g.Action, g.Proxy, names); err != nil {
			return fmt.Errorf("groups[%d]: %w", i, err)
		}
	}
	for i, r := range c.Rules {
		if r.Group != "" && !groups[r.Group] {
			return fmt.Errorf("rules[%d]: unknown group %q", i, r.Group)
		}
		if strings.TrimSpace(r.Process) == "" {
			return fmt.Errorf("rules[%d]: process is required", i)
		}
		base := strings.ToLower(r.Process)
		base = strings.ReplaceAll(base, "/", `\`)
		if idx := strings.LastIndex(base, `\`); idx >= 0 {
			base = base[idx+1:]
		}
		if matchesEverything(r.Process) {
			return fmt.Errorf("rules[%d]: mask %q matches every program", i, r.Process)
		}
		if base == "svchost.exe" {
			return fmt.Errorf("rules[%d]: do not match svchost.exe; use dns.includeSystemResolver for system DNS", i)
		}
		if r.Group != "" {
			continue // the group's route applies and is checked above
		}
		if err := checkRoute(r.Action, r.Proxy, names); err != nil {
			return fmt.Errorf("rules[%d]: %w", i, err)
		}
	}
	return nil
}

// loopbackRelay requires the engine's relay to listen on loopback: on any
// other address the network could reach it and ride proxied flows.
func loopbackRelay(addr string, v6 bool) error {
	host, _, err := splitAddr(addr)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() || (ip.To4() == nil) != v6 {
		if v6 {
			return fmt.Errorf("must be [::1]:port, got %q", addr)
		}
		return fmt.Errorf("must be a 127.0.0.0/8 address, got %q", addr)
	}
	return nil
}

func checkRoute(action, proxy string, names map[string]struct{}) error {
	switch action {
	case "proxy":
		if proxy == "" {
			return errors.New("proxy is required when action is proxy")
		}
		if _, ok := names[proxy]; !ok {
			return fmt.Errorf("unknown proxy %q", proxy)
		}
	case "direct", "block":
		if proxy != "" {
			return errors.New("proxy must be empty when action is direct or block")
		}
	default:
		return fmt.Errorf("action must be proxy, direct or block, got %q", action)
	}
	return nil
}

// CheckDNSServers reports a DNS server given as a host name. The engine sends
// queries to an IP, so a name is ignored at run time. Validate still accepts
// it so older files keep loading; the window refuses to save a new one.
func (c *Config) CheckDNSServers() error {
	if c.DNS.Mode != "proxy" {
		return nil
	}
	for _, s := range c.DNS.Servers {
		host, _, err := splitAddr(s)
		if err != nil {
			return fmt.Errorf("dns server %q: %w", s, err)
		}
		if net.ParseIP(host) == nil {
			return fmt.Errorf("dns server %q: must be an IP address", s)
		}
	}
	return nil
}

// Prepare fills a VLESS proxy from its share link when the structured
// fields are still empty. A parsed struct is kept, so manual edits win.
func (p *Proxy) Prepare() error {
	if p == nil || p.Type != "vless" {
		return nil
	}
	if p.VLESS == nil || strings.TrimSpace(p.VLESS.UUID) == "" {
		if strings.TrimSpace(p.Link) == "" {
			return errors.New("Не удалось разобрать ссылку VLESS")
		}
		parsed, err := vless.ParseLink(p.Link)
		if err != nil {
			return err
		}
		cp := parsed.Params
		p.VLESS = &cp
		if strings.TrimSpace(p.Address) == "" {
			p.Address = parsed.Address
		}
		return nil
	}
	return p.VLESS.Normalize()
}

// ProxyByName returns the named proxy.
func (c *Config) ProxyByName(name string) (Proxy, bool) {
	for _, p := range c.Proxies {
		if p.Name == name {
			return p, true
		}
	}
	return Proxy{}, false
}

// knownConfigKeys are the fields this version reads. Anything else is kept
// verbatim so a newer or older file can round-trip.
var knownConfigKeys = map[string]bool{
	"version": true, "relay": true, "dns": true, "bypassPrivate": true,
	"udpUnsupported": true, "killSwitch": true, "log": true, "ui": true, "proxies": true, "rules": true,
	"groups": true,
}

// Load reads a config file, applies defaults, and validates it.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	cfg.Extra = map[string]json.RawMessage{}
	for k, v := range doc {
		if !knownConfigKeys[k] {
			cfg.Extra[k] = append(json.RawMessage(nil), v...)
		}
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// LoadOrInit loads the file or writes the defaults when it does not exist.
func LoadOrInit(path string) (*Config, error) {
	// The window, "run" and the service all start here: lock down the
	// shared folder before reading anything from it.
	secureDir(filepath.Dir(path))
	cfg, err := Load(path)
	if err == nil {
		return cfg, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	cfg = Default()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := Save(path, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Save writes the config atomically with mode 0600.
func Save(path string, cfg *Config) error {
	if cfg == nil {
		return errors.New("nil config")
	}
	cp := *cfg
	cp.ApplyDefaults()
	if err := cp.Validate(); err != nil {
		return err
	}
	data, err := cp.marshal()
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	secureDir(dir)
	tmp := path + ".tmp"
	// A leftover or planted temp file would keep its own owner and access
	// list through the rename. Start from a new file.
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (c *Config) marshal() ([]byte, error) {
	if len(c.Extra) == 0 {
		return json.MarshalIndent(c, "", "  ")
	}
	body, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	for k, v := range c.Extra {
		if knownConfigKeys[k] {
			continue
		}
		doc[k] = append(json.RawMessage(nil), v...)
	}
	return json.MarshalIndent(doc, "", "  ")
}

// CloneExtra copies preserved JSON keys.
func CloneExtra(in map[string]json.RawMessage) map[string]json.RawMessage {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]json.RawMessage, len(in))
	for k, v := range in {
		out[k] = append(json.RawMessage(nil), v...)
	}
	return out
}

func validateLocalPorts(c *Config) error {
	relay4, _ := portOf(c.Relay.TCP4)
	relay6, _ := portOf(c.Relay.TCP6)
	used := map[int]string{}
	for _, p := range c.Proxies {
		if p.Type != "vless" {
			continue
		}
		if p.LocalPass != "" && strings.TrimSpace(p.LocalUser) == "" {
			return fmt.Errorf("прокси %s: укажите логин локального SOCKS5", p.Name)
		}
		if len(p.LocalUser) > 255 || len(p.LocalPass) > 255 {
			return fmt.Errorf("прокси %s: логин и пароль локального SOCKS5 не длиннее 255 байт", p.Name)
		}
		if p.SOCKSPort == 0 {
			continue
		}
		if p.SOCKSPort < 1 || p.SOCKSPort > 65535 {
			return fmt.Errorf("прокси %s: локальный SOCKS5-порт должен быть от 1 до 65535", p.Name)
		}
		if p.SOCKSPort == relay4 || p.SOCKSPort == relay6 {
			return fmt.Errorf("прокси %s: локальный SOCKS5-порт %d занят приёмником Ashgate", p.Name, p.SOCKSPort)
		}
		if prev, ok := used[p.SOCKSPort]; ok {
			return fmt.Errorf("локальный SOCKS5-порт %d указан у прокси %s и %s", p.SOCKSPort, prev, p.Name)
		}
		used[p.SOCKSPort] = p.Name
		if p.SOCKSPort == 65535 {
			continue
		}
		httpPort := p.SOCKSPort + 1
		if httpPort == relay4 || httpPort == relay6 {
			return fmt.Errorf("прокси %s: HTTP-порт %d занят приёмником Ashgate", p.Name, httpPort)
		}
		if prev, ok := used[httpPort]; ok {
			return fmt.Errorf("прокси %s: HTTP-порт %d совпадает с локальным портом прокси %s", p.Name, httpPort, prev)
		}
		used[httpPort] = p.Name
	}
	return nil
}

func portOf(addr string) (int, error) {
	_, p, err := splitAddr(addr)
	if err != nil {
		return 0, err
	}
	return int(p), nil
}

// validName accepts a proxy name: letters and digits of any script (so a
// 3x-ui remark such as "Швеция 1" works), spaces, '.', '_' and '-', up to 64
// characters, starting with a letter or digit and without a trailing space.
// Names are only labels and keys for rules, groups and DNS; nothing parses
// them. app.js (validProxyName) mirrors this rule.
func validName(name string) bool {
	if name == "" || utf8.RuneCountInString(name) > 64 || strings.TrimSpace(name) != name {
		return false
	}
	for i, r := range name {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r):
		case (r == ' ' || r == '_' || r == '.' || r == '-') && i > 0:
		default:
			return false
		}
	}
	return true
}

// PathFromArgs returns the -config path from args, or DefaultPath when absent.
// Unknown tokens are ignored so a service command line such as
// "run -config C:\\path" still yields the path.
func PathFromArgs(args []string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-config" || a == "--config":
			if i+1 < len(args) {
				return args[i+1]
			}
		case strings.HasPrefix(a, "-config="):
			return strings.TrimPrefix(a, "-config=")
		case strings.HasPrefix(a, "--config="):
			return strings.TrimPrefix(a, "--config=")
		}
	}
	return DefaultPath()
}

func splitAddr(addr string) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	if host == "" {
		return "", 0, errors.New("missing host")
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return "", 0, err
	}
	if port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("port %d out of range", port)
	}
	return host, uint16(port), nil
}

// matchesEverything reports a process mask made only of wildcards, such as
// "*" or "*.exe": it would route every program on the PC.
func matchesEverything(process string) bool {
	p := strings.ToLower(strings.Trim(strings.TrimSpace(process), `"`))
	if !strings.ContainsAny(p, "*?") {
		return false
	}
	p = strings.NewReplacer("*", "", "?", "", ".exe", "", `\`, "", "/", "", ".", "").Replace(p)
	return p == ""
}
