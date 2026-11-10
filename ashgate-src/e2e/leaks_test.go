//go:build windows && e2e

package e2e

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"ashgate/e2e/harness"
	"ashgate/internal/config"
	"ashgate/internal/secret"
)

func directHost() string { return strings.Split(harness.DirectHostIP, ":")[0] }

const plainSOCKS = 10808

// TestLeaks is the leaks job. Every phase captures all network-card
// traffic with pktmon; the proxied app only ever talks to documentation
// addresses, so any of its packets on the card is a leak.
func TestLeaks(t *testing.T) {
	env := harness.LoadEnv(t)
	harness.EnsureQuit(env.Exe)
	tcpOnly := env.ClientExe(t, harness.ClientTCPOnly)
	rules := map[string]string{tcpOnly: harness.SubName}
	// Edge stands for Opera and every Chromium browser (see Browser).
	edge := harness.EdgeExe()
	if edge != "" {
		rules[edge] = harness.SubName
	}
	s := harness.NewSession(t, harness.SessionOpts{
		Rules: rules,
		Opts:  map[string]harness.RuleOpts{tcpOnly: {KillSwitch: harness.Bool(true), TCPOnly: true}},
	})
	a := s.App
	pid := uint32(a.PID)
	localPass := env.Secrets.Add("local-pass", "lp"+harness.RandHex(10), true)
	err := a.UpdateConfig(func(c *config.Config) {
		// Debug logs every DNS packet that goes direct and why, so a leak
		// in the pcap can be traced in ashgate.log.
		c.Log.Level = "debug"
		c.Proxies = append(c.Proxies, config.Proxy{Name: "e2e-plain", Type: "vless", Address: s.Fx.XHTTP.Addr,
			Link: s.Fx.PlainLink, SOCKSPort: plainSOCKS, LocalUser: "e2elocal", LocalPass: localPass})
		// Not under .example/.test/.local: Xray sends those "local" suffixes
		// to the system DNS whenever a direct list exists.
		c.DirectDomains = append(c.DirectDomains, "e2e-direct.example.com")
		// The zones are list entries: ru stays, su is deleted (SystemResolver).
		c.DirectDomains = slices.DeleteFunc(c.DirectDomains, func(d string) bool { return d == "su" })
	})
	if err != nil {
		t.Fatalf("plain proxy and direct domain: %v", err)
	}
	time.Sleep(3 * time.Second)
	nic, err := harness.MainNIC()
	if err != nil {
		t.Fatal(err)
	}
	env.WriteJSON("leaks/nic.json", nic)

	// phase runs fn under pktmon and a watch of ashgate.exe's own sockets.
	phase := func(t *testing.T, name string, fn func()) ([]harness.Packet, []harness.Sock) {
		t.Helper()
		c, err := harness.StartCapture(env, name)
		if err != nil {
			t.Fatalf("pktmon: %v", err)
		}
		w := harness.WatchSockets(pid)
		fn()
		socks := w.Stop()
		pkts, err := c.Stop()
		if err != nil {
			t.Fatalf("pktmon: %v", err)
		}
		return pkts, socks
	}
	// ownDirect lists ashgate.exe connections to anything but loopback
	// (allowed: the addresses in allow).
	ownDirect := func(socks []harness.Sock, allow ...string) []string {
		ok := map[string]bool{}
		for _, x := range allow {
			ok[x] = true
		}
		var out []string
		for _, sk := range socks {
			if sk.Remote.IsLoopback() || ok[sk.Remote.String()] {
				continue
			}
			out = append(out, fmt.Sprintf("%s:%d", sk.Remote, sk.RPort))
		}
		return out
	}

	t.Run("DNS", func(t *testing.T) {
		tun := "t" + harness.RandHex(5) + ".e2e-tunnel.example.com"
		tun2 := "u" + harness.RandHex(5) + ".e2e-tunnel.example.com"
		dir := "d" + harness.RandHex(5) + ".e2e-direct.example.com"
		doh := s.Fx.DoHBytes()
		var r1, r2, r3 harness.ClientResult
		pkts, socks := phase(t, "dns", func() {
			r1 = harness.RunClient(s.Client, "dns", "-server", "1.1.1.1:53", "-name", tun)
			r2 = harness.RunClient(s.Client, "dns", "-server", "8.8.8.8:53", "-name", tun2, "-tcp")
			r3 = harness.RunClient(s.Client, "dns", "-server", "1.1.1.1:53", "-name", dir)
			time.Sleep(2 * time.Second)
		})
		t.Logf("dns answers: tunnel udp %s / tcp %s / direct %s", r1, r2, r3)
		for _, m := range []string{tun, tun2} {
			if leak := harness.Filter(pkts, harness.DNSFor(m)); len(leak) > 0 {
				t.Errorf("the proxied app's DNS query for %s left the machine in plain text:%s", m, harness.Brief(leak, 5))
			}
		}
		public := harness.Filter(pkts, func(p harness.Packet) bool {
			return p.DstPort == 53 && (p.Dst == "1.1.1.1" || p.Dst == "8.8.8.8")
		})
		if len(public) > 0 {
			t.Errorf("plain DNS to public resolvers on the card:%s", harness.Brief(public, 5))
		}
		if len(harness.Filter(pkts, harness.DNSFor(dir))) == 0 {
			t.Errorf("%s (a direct domain) was not resolved directly by the system DNS", dir)
		}
		if s.Fx.DoHBytes() == doh {
			t.Errorf("no DoH went through the tunnel to the test server")
		}
		if d := ownDirect(socks); len(d) > 0 {
			t.Errorf("ashgate.exe connected directly to %v during DNS (DoH must go through the tunnel)", d)
		}
	})

	// getaddrinfo goes through the Windows DNS client (svchost.exe), which
	// resolves for every program, and Ashgate cannot tell which one asked:
	// a routed app's name goes through the tunnel, bypass names (the direct
	// list, with the zones ru and рф by default, LAN names) to the
	// provider's DNS. The zone su was deleted from the list above.
	t.Run("SystemResolver", func(t *testing.T) {
		if direct := readConfig(t).DirectDomains; !slices.Contains(direct, "ru") || slices.Contains(direct, "su") {
			t.Errorf("direct list %v: want the zone ru kept and su deleted", direct)
		}
		_, _ = harness.Run("ipconfig", "/flushdns")
		tun := "g" + harness.RandHex(5) + ".e2e-tunnel.example.com"
		dir := "x" + harness.RandHex(5) + ".e2e-direct.example.com"
		ru := "e2e-" + harness.RandHex(6) + ".ru"
		su := "e2e-" + harness.RandHex(6) + ".su"
		ctl := "c" + harness.RandHex(5) + ".e2e-tunnel.example.com"
		doh := s.Fx.DoHBytes()
		var rTun, rDir, rRU, rLoop, rCtl harness.ClientResult
		var loopTook time.Duration
		pkts, _ := phase(t, "getaddrinfo", func() {
			rTun = harness.RunClient(s.Client, "lookup", "-name", tun, "-timeout", "15s")
			rDir = harness.RunClient(s.Client, "lookup", "-name", dir, "-timeout", "15s")
			rRU = harness.RunClient(s.Client, "lookup", "-name", ru, "-timeout", "15s")
			harness.RunClient(s.Client, "lookup", "-name", su, "-timeout", "15s")
			// The app's own query for a bypass name: Xray asks Windows, and
			// Windows' query must go to the provider, not loop back to Xray.
			start := time.Now()
			rLoop = harness.RunClient(s.Client, "dns", "-server", "1.1.1.1:53", "-name", "ya.ru", "-timeout", "8s")
			loopTook = time.Since(start)
			// An app without a rule keeps its own DNS.
			rCtl = harness.RunClient(s.Direct, "dns", "-server", "1.1.1.1:53", "-name", ctl, "-timeout", "4s")
			time.Sleep(time.Second)
		})
		t.Logf("getaddrinfo: tunnel %s / direct %s / ru %s; ya.ru via Xray %s in %s; control %s", rTun, rDir, rRU, rLoop, loopTook.Round(time.Millisecond), rCtl)
		if leak := harness.Filter(pkts, harness.DNSFor(tun)); len(leak) > 0 {
			t.Errorf("getaddrinfo of a routed app left the machine in plain text (Windows DNS client):%s", harness.Brief(leak, 5))
		}
		if len(harness.Filter(pkts, harness.DNSFor(dir))) == 0 {
			t.Errorf("%s (direct list) did not go to the provider's DNS", dir)
		}
		if len(harness.Filter(pkts, harness.DNSFor(ru))) == 0 {
			t.Errorf("%s (the list entry ru) did not go to the provider's DNS", ru)
		}
		if leak := harness.Filter(pkts, harness.DNSFor(su)); len(leak) > 0 {
			t.Errorf("%s (.su, deleted from the list) left the machine in plain text:%s", su, harness.Brief(leak, 5))
		}
		if !rLoop.OK || !strings.Contains(rLoop.Answer, "rcode=0") || strings.Contains(rLoop.Answer, "answers=0") {
			t.Errorf("ya.ru through Xray's DNS got no address in %s: %s (svchost → Ashgate → Xray → svchost loop?)", loopTook.Round(time.Millisecond), rLoop)
		}
		if len(harness.Filter(pkts, harness.DNSFor(ctl))) == 0 {
			t.Errorf("an app without a rule: its own DNS query did not go direct")
		}
		if s.Fx.DoHBytes() == doh {
			t.Errorf("no DoH through the tunnel during getaddrinfo")
		}
	})

	// The case from dnsleaktest: a Chromium browser's own lookups go through
	// the tunnel, and when they fail it asks Windows instead. Neither may
	// leave the machine.
	t.Run("Browser", func(t *testing.T) {
		if edge == "" {
			env.Note("skipped", "browser DNS leak test: Microsoft Edge is not on the runner")
			t.Skip("no msedge.exe")
		}
		direct := readConfig(t).DirectDomains
		load := func(name string) (string, []harness.Packet) {
			marker := "b" + harness.RandHex(6)
			names := make([]string, 30)
			for i := range names {
				names[i] = fmt.Sprintf("n%d-%s.e2e-tunnel.example.com", i, marker)
			}
			page := env.Path("leaks", name+".html")
			if err := harness.LeakPage(page, names); err != nil {
				t.Fatal(err)
			}
			profile, err := os.MkdirTemp("", "ashgate-e2e-edge-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(profile)
			ports := harness.WatchUDPPorts()
			pkts, _ := phase(t, name, func() {
				// Long enough for its own lookups to time out and fall back
				// to Windows, as Opera did.
				ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
				defer cancel()
				err := exec.CommandContext(ctx, edge, "--headless=new", "--disable-gpu", "--no-first-run",
					"--no-default-browser-check", "--user-data-dir="+profile, "file:///"+filepath.ToSlash(page)).Run()
				t.Logf("%s: msedge stopped after 40 s (killed, as planned): %v", name, err)
				_, _ = harness.Run("taskkill", "/F", "/T", "/IM", "msedge.exe")
				time.Sleep(2 * time.Second)
			})
			ports.Stop()
			// Any other plain DNS on the card: whose was it? Routed Edge and
			// the Windows DNS client may send only bypass names.
			for _, p := range pkts {
				if p.Proto != "udp" || p.DstPort != 53 || len(p.DNS) == 0 || harness.BypassAll(p.DNS, direct) {
					continue
				}
				owner := ports.Owner(p.SrcPort)
				low := strings.ToLower(owner)
				switch {
				case strings.Contains(low, strings.ToLower(edge)), strings.Contains(low, `\svchost.exe`):
					t.Errorf("%s: plain DNS from %s: %s", name, owner, p)
				default:
					t.Logf("%s: plain DNS from a program without a rule (%q): %s", name, owner, p)
				}
			}
			return marker, pkts
		}
		doh := s.Fx.DoHBytes()
		marker, pkts := load("browser")
		if leak := harness.Filter(pkts, harness.DNSFor(marker)); len(leak) > 0 {
			t.Errorf("Edge's lookups left the machine in plain text:%s", harness.Brief(leak, 5))
		}
		if s.Fx.DoHBytes() == doh {
			t.Errorf("no DoH through the tunnel while Edge loaded the page")
		}
		s.Fx.SetDoH(false)
		defer s.Fx.SetDoH(true)
		doh = s.Fx.DoHBytes()
		marker, pkts = load("browser-doh-down")
		if leak := harness.Filter(pkts, harness.DNSFor(marker)); len(leak) > 0 {
			t.Errorf("with DoH failing, Edge's lookups left the machine in plain text (fallback to Windows):%s", harness.Brief(leak, 5))
		}
		if got := s.Fx.DoHBytes() - doh; got > 0 {
			t.Errorf("DoH carried %d bytes while it was cut off: the fallback was not tested", got)
		}
	})

	// A router that hands out its link-local address as the DNS server.
	t.Run("LinkLocalDNS", func(t *testing.T) {
		undo, err := harness.SetupLinkLocalDNS(nic)
		if err != nil {
			env.Note("skipped", "link-local DNS leak test: "+err.Error())
			t.Skip(err)
		}
		defer undo()
		m6 := "v" + harness.RandHex(5) + ".e2e-tunnel.example.com"
		m4 := "w" + harness.RandHex(5) + ".e2e-tunnel.example.com"
		ctl := "y" + harness.RandHex(5) + ".e2e-tunnel.example.com"
		pkts, _ := phase(t, "linklocal-dns", func() {
			harness.RunClient(s.Client, "dns", "-server", harness.LinkLocalDNS6Addr(nic), "-name", m6, "-timeout", "4s")
			harness.RunClient(s.Client, "dns", "-server", harness.LinkLocalDNS4+":53", "-name", m4, "-timeout", "4s")
			harness.RunClient(s.Client, "dns", "-server", harness.LinkLocalDNS4+":53", "-name", m4, "-tcp", "-timeout", "4s")
			harness.RunClient(s.Direct, "dns", "-server", harness.LinkLocalDNS6Addr(nic), "-name", ctl, "-timeout", "2s")
			time.Sleep(time.Second)
		})
		if len(harness.Filter(pkts, harness.DNSFor(ctl))) == 0 {
			t.Fatalf("the control app's query to %s was not seen on the card: the setup does not make leaks visible", harness.LinkLocalDNS6)
		}
		for _, m := range []string{m6, m4} {
			if leak := harness.Filter(pkts, harness.DNSFor(m)); len(leak) > 0 {
				t.Errorf("DNS to a link-local server left the machine in plain text:%s", harness.Brief(leak, 5))
			}
		}
		syn := harness.Filter(pkts, func(p harness.Packet) bool {
			return p.SYN && p.Dst == harness.LinkLocalDNS4 && p.DstPort == 53
		})
		if len(syn) > 0 {
			t.Errorf("DNS over TCP to a link-local server went direct:%s", harness.Brief(syn, 5))
		}
	})

	// Many queries at once, each from a new socket (a browser loading a
	// page): the owner of some is not known yet when the packet arrives.
	t.Run("DNSBurst", func(t *testing.T) {
		m := "burst" + harness.RandHex(5) + ".e2e-tunnel.example.com"
		var r harness.ClientResult
		pkts, _ := phase(t, "dns-burst", func() {
			r = harness.RunClient(s.Client, "dnsburst", "-server", "1.1.1.1:53", "-name", m, "-count", "300", "-timeout", "15s")
			time.Sleep(time.Second)
		})
		t.Logf("burst: %d answered, %d not", r.Count, r.Failed)
		if leak := harness.Filter(pkts, harness.DNSFor(m)); len(leak) > 0 {
			t.Errorf("%d burst queries left the machine in plain text:%s", len(leak), harness.Brief(leak, 5))
		}
	})

	t.Run("IPv6", func(t *testing.T) {
		undo, err := harness.SetupFakeIPv6(nic)
		if err != nil {
			env.Note("skipped", "IPv6 leak test: "+err.Error())
			t.Skip(err)
		}
		defer undo()
		since := time.Now()
		var tcp, udp, ctl harness.ClientResult
		pkts, _ := phase(t, "ipv6", func() {
			tcp = harness.RunClient(s.Client, "get", "-url", harness.URL(harness.TargetV6), "-n", "2000000", "-seed", "v6")
			udp = harness.RunClient(s.Client, "udp", "-addr", harness.TargetV6UDP)
			ctl = harness.RunClient(s.Direct, "tcp", "-addr", "[2001:db8:2::99]:18080", "-timeout", "3s")
		})
		if !tcp.OK {
			t.Errorf("IPv6 TCP through the tunnel: %s", tcp)
		}
		if !udp.OK {
			t.Errorf("IPv6 UDP through the tunnel: %s", udp)
		}
		_ = ctl
		if len(harness.Filter(pkts, func(p harness.Packet) bool { return p.Dst == "2001:db8:2::99" })) == 0 {
			t.Fatalf("the control app's IPv6 SYN was not seen on the card: the fake IPv6 route does not make leaks visible")
		}
		if leak := harness.Filter(pkts, harness.ToTestNet("2001:db8:2::99")); len(leak) > 0 {
			t.Errorf("IPv6 leak:%s", harness.Brief(leak, 10))
		}
		if len(s.Fx.AccessSince(since, "2001:db8:2::10")) == 0 {
			t.Errorf("the test server saw no IPv6 destination through the tunnel")
		}
	})

	t.Run("UDPQUICSTUN", func(t *testing.T) {
		var echo, quic, stun, toEcho, toStun harness.ClientResult
		pkts, _ := phase(t, "udp", func() {
			echo = harness.RunClient(s.Client, "udp", "-addr", harness.TargetUDP)
			quic = harness.RunClient(s.Client, "udp", "-addr", harness.TargetQUIC, "-timeout", "3s")
			stun = harness.RunClient(s.Client, "stun", "-addr", harness.TargetSTUN)
			toEcho = harness.RunClient(tcpOnly, "udp", "-addr", harness.TargetUDP, "-timeout", "3s")
			toStun = harness.RunClient(tcpOnly, "stun", "-addr", harness.TargetSTUN, "-timeout", "3s")
		})
		if !echo.OK {
			t.Errorf("UDP echo through the tunnel: %s", echo)
		}
		if !stun.OK {
			t.Errorf("STUN through the tunnel: %s", stun)
		}
		if toEcho.OK || toStun.OK {
			t.Errorf("a tcpOnly app got UDP answers (echo %v, stun %v)", toEcho.OK, toStun.OK)
		}
		t.Logf("QUIC-like UDP 443: %s", quic)
		if leak := harness.Filter(pkts, harness.ToTestNet()); len(leak) > 0 {
			t.Errorf("UDP/QUIC/STUN on the card:%s", harness.Brief(leak, 10))
		}
	})

	t.Run("DomainExceptions", func(t *testing.T) {
		since := time.Now()
		directIP := strings.Split(harness.DirectHostIP, ":")[0]
		var tun, dir harness.ClientResult
		pkts, socks := phase(t, "domains", func() {
			tun = harness.RunClient(s.Client, "get", "-url", harness.URL(harness.TargetHostIP), "-host", "tunnel.example.com", "-n", "100000")
			dir = harness.RunClient(s.Client, "get", "-url", harness.URL(harness.DirectHostIP), "-host", "x.e2e-direct.example.com", "-n", "1000", "-stall", "5s")
		})
		if !tun.OK {
			t.Errorf("Host tunnel.example.com through the tunnel: %s", tun)
		}
		_ = dir
		if len(harness.Filter(pkts, func(p harness.Packet) bool { return p.Dst == directIP && p.SYN })) == 0 {
			t.Errorf("Host x.e2e-direct.example.com did not go direct (no SYN to %s on the card)", directIP)
		}
		if len(s.Fx.AccessSince(since, directIP)) > 0 {
			t.Errorf("a direct domain went through the tunnel")
		}
		if leak := harness.Filter(pkts, harness.ToTestNet(directIP)); len(leak) > 0 {
			t.Errorf("tunnel traffic on the card:%s", harness.Brief(leak, 10))
		}
		if d := ownDirect(socks, directIP); len(d) > 0 {
			t.Errorf("ashgate.exe connected directly to %v", d)
		}
		// The request to the black hole never gets an answer. Wait until
		// the relay has let go of it (it closes an unanswered upstream a
		// few seconds after the client is gone), so that its dial retries
		// do not run into the next subtests.
		if err := harness.Eventually(30*time.Second, 500*time.Millisecond, func() error {
			for _, sk := range harness.SocketsOf(pid) {
				if sk.Remote.String() == directIP {
					return fmt.Errorf("ashgate.exe still has a socket to %s", directIP)
				}
			}
			return nil
		}); err != nil {
			t.Errorf("the direct-domain flow did not end: %v", err)
		}
	})

	t.Run("KillSwitchServersDown", func(t *testing.T) {
		s.Fx.XHTTP.Set(harness.GateRefuse)
		s.Fx.RAW.Set(harness.GateRefuse)
		defer s.Fx.XHTTP.Set(harness.GatePass)
		defer s.Fx.RAW.Set(harness.GatePass)
		var rs []harness.ClientResult
		mk := "k" + harness.RandHex(5) + ".e2e-tunnel.example.com"
		pkts, _ := phase(t, "ks-servers-down", func() {
			// get, not a bare connect: the local relay accepts the TCP
			// handshake itself before it dials the server.
			for i := 0; i < 3; i++ {
				rs = append(rs, harness.RunClient(s.Client, "get", "-url", harness.URL(harness.TargetTCP), "-n", "1000", "-stall", "5s"))
				rs = append(rs, harness.RunClient(s.Client, "udp", "-addr", harness.TargetUDP, "-timeout", "2s"))
			}
			// DNS with no tunnel: it fails, it does not go direct.
			harness.RunClient(s.Client, "dns", "-server", "1.1.1.1:53", "-name", "a"+mk, "-timeout", "4s")
			harness.RunClient(s.Client, "lookup", "-name", "b"+mk, "-timeout", "10s")
		})
		if leak := harness.Filter(pkts, harness.DNSFor(mk)); len(leak) > 0 {
			t.Errorf("DNS with the servers down left the machine in plain text:%s", harness.Brief(leak, 5))
		}
		for _, r := range rs {
			if r.OK {
				t.Errorf("the proxied app got through with both servers refused")
				break
			}
		}
		if leak := harness.Filter(pkts, harness.ToTestNet(directHost())); len(leak) > 0 {
			t.Errorf("kill switch: direct packets with the servers down:%s", harness.Brief(leak, 10))
		}
	})

	// With both servers refused the active one changed back and forth.
	// Let the primary take over again before the next subtests: a return
	// in the middle of one would end its connections.
	if _, err := harness.WaitActive(a, s.Client, "XHTTP", 8*time.Minute); err != nil {
		t.Errorf("no return to the primary after the servers came back: %v", err)
	}
	time.Sleep(2 * time.Second)

	t.Run("KillSwitchCaptureStopped", func(t *testing.T) {
		if err := a.StopCapture(); err != nil {
			t.Fatal(err)
		}
		if err := waitKillRules(s.Client, 20*time.Second); err != nil {
			t.Fatal(err)
		}
		var r harness.ClientResult
		pkts, _ := phase(t, "ks-stopped", func() {
			r = harness.RunClient(s.Client, "tcp", "-addr", harness.TargetTCP, "-timeout", "3s")
		})
		if r.OK {
			t.Errorf("the proxied app connected while capture was stopped")
		}
		if leak := harness.Filter(pkts, harness.ToTestNet(directHost())); len(leak) > 0 {
			t.Errorf("kill switch: direct packets while stopped:%s", harness.Brief(leak, 10))
		}
		if err := a.StartCapture(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("HealthAndSubscriptionThroughTunnel", func(t *testing.T) {
		// Capture was just restarted and nothing has used the tunnel since,
		// so it is not proven: the refresh checks it once first, and then
		// the update must come through the tunnel.
		verified := time.Now()
		since := verified
		pkts, socks := phase(t, "sub-refresh", func() {
			if err := a.Post("/api/subscription/refresh", map[string]string{"name": harness.SubName}, nil); err != nil {
				t.Errorf("refresh: %v", err)
			}
			_ = harness.Eventually(40*time.Second, time.Second, func() error {
				if len(s.Fx.Sub.Since(since)) == 0 {
					return fmt.Errorf("no subscription request yet")
				}
				return nil
			})
		})
		hits := s.Fx.Sub.Since(since)
		if len(hits) == 0 {
			t.Fatalf("the refresh never reached the subscription server")
		}
		for _, h := range hits {
			if h.Origin != harness.OriginTunnel {
				t.Errorf("subscription refresh with the tunnel up came from %s, want the tunnel", h.Origin)
			}
		}
		for _, h := range s.Fx.Health.Since(verified) {
			if h.Origin != harness.OriginTunnel {
				t.Errorf("health check at %s came from %s, want the tunnel", h.Time.Format("15:04:05"), h.Origin)
			}
		}
		if leak := harness.Filter(pkts, harness.DNSFor("gstatic")); len(leak) > 0 {
			t.Errorf("health-check host resolved on the card:%s", harness.Brief(leak, 5))
		}
		if d := ownDirect(socks, directHost()); len(d) > 0 {
			t.Errorf("ashgate.exe connected directly to %v during the refresh", d)
		}
	})

	// A VLESS server given by host name: Ashgate looks it up over DoH
	// (dns.bootstrap here), never with the provider's DNS.
	t.Run("ServerHostname", func(t *testing.T) {
		host := "vps-" + harness.RandHex(5) + ".e2e-server.example.com"
		boot, err := harness.StartBootDoH(map[string]string{host: "127.0.0.1"})
		if err != nil {
			t.Fatal(err)
		}
		defer boot.Close()
		_, port, _ := net.SplitHostPort(s.Fx.XHTTP.Addr)
		named := net.JoinHostPort(host, port)
		link := strings.Replace(s.Fx.PlainLink, s.Fx.XHTTP.Addr, named, 1)
		var rep struct {
			OK     bool   `json:"ok"`
			Detail string `json:"detail"`
		}
		pkts, socks := phase(t, "server-hostname", func() {
			err = a.UpdateConfig(func(c *config.Config) {
				c.DNS.Bootstrap = []string{boot.URL}
				c.Proxies = append(c.Proxies, config.Proxy{Name: "e2e-named", Type: "vless", Address: named, Link: link})
			})
			if err != nil {
				t.Errorf("add the named server: %v", err)
				return
			}
			if err := a.Post("/api/probe", map[string]string{"name": "e2e-named"}, &rep); err != nil {
				t.Errorf("probe: %v", err)
			}
		})
		defer func() {
			_ = a.UpdateConfig(func(c *config.Config) {
				c.DNS.Bootstrap = nil
				c.Proxies = slices.DeleteFunc(c.Proxies, func(p config.Proxy) bool { return p.Name == "e2e-named" })
			})
		}()
		if !rep.OK {
			t.Errorf("a VLESS server given by host name did not work: %s", rep.Detail)
		}
		if !slices.Contains(boot.Asked(), host) {
			t.Errorf("%s was not looked up over DoH (asked: %v)", host, boot.Asked())
		}
		if leak := harness.Filter(pkts, harness.DNSFor("e2e-server")); len(leak) > 0 {
			t.Errorf("the server name went out in plain DNS:%s", harness.Brief(leak, 5))
		}
		// DirectHostIP is direct by design (the Direct domain of
		// DomainExceptions); a leftover connection of an earlier subtest to
		// it says nothing about how the VLESS server's name was resolved.
		if d := ownDirect(socks, directHost()); len(d) > 0 {
			t.Errorf("ashgate.exe connected directly to %v while resolving its server", d)
		}
	})

	t.Run("LocalPorts", func(t *testing.T) {
		for _, sk := range harness.SocketsOf(pid) {
			if (sk.State == harness.TCPListen || sk.Proto == "udp") && !sk.Local.IsLoopback() {
				t.Errorf("ashgate.exe %s socket on %s:%d (not loopback)", sk.Proto, sk.Local, sk.LPort)
			}
		}
		pub := fmt.Sprintf("127.0.0.1:%d", plainSOCKS)
		if err := harness.Eventually(20*time.Second, 500*time.Millisecond, func() error {
			c, err := net.DialTimeout("tcp", pub, time.Second)
			if err == nil {
				c.Close()
			}
			return err
		}); err != nil {
			t.Fatalf("published SOCKS5 %s not listening: %v", pub, err)
		}
		if m := socksMethod(pub, 0x00); m != 0xFF {
			t.Errorf("published SOCKS5 accepted no-auth (method %#x), want 0xFF", m)
		}
		if socksLogin(pub, "e2elocal", "wrong") {
			t.Errorf("published SOCKS5 accepted a wrong password")
		}
		if code := socksUDPAssociate(pub, "e2elocal", localPass); code == 0 {
			t.Errorf("published SOCKS5 granted UDP ASSOCIATE")
		}
		httpPub := fmt.Sprintf("127.0.0.1:%d", plainSOCKS+1)
		if st := httpConnectStatus(httpPub, ""); st != 407 {
			t.Errorf("published HTTP proxy without login answered %d, want 407", st)
		}
		if nic.IPv4 != "" {
			if c, err := net.DialTimeout("tcp", net.JoinHostPort(nic.IPv4, fmt.Sprint(plainSOCKS)), 2*time.Second); err == nil {
				c.Close()
				t.Errorf("published SOCKS5 answers on the network address %s", nic.IPv4)
			}
		}
		base := fmt.Sprintf("http://127.0.0.1:%d/api/state", a.UIPort)
		if st := get(base, "", ""); st != 403 {
			t.Errorf("API without the token answered %d, want 403", st)
		}
		if st := get(base, a.Token, "evil.example"); st != 403 {
			t.Errorf("API with a foreign Host header answered %d, want 403", st)
		}
		if st := get(base, a.Token, ""); st != 200 {
			t.Errorf("API with the token answered %d", st)
		}
		since := time.Now()
		c, err := net.DialTimeout("tcp", "127.0.0.1:34010", 2*time.Second)
		if err == nil {
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = c.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
			n, _ := io.ReadAll(c)
			c.Close()
			if len(n) > 0 {
				t.Errorf("the relay answered a connection it has no mapping for (%d bytes)", len(n))
			}
		}
		time.Sleep(time.Second)
		if acc := s.Fx.AccessLog(); len(acc) > 0 && acc[len(acc)-1].Time.After(since) && strings.Contains(acc[len(acc)-1].Dest, "34010") {
			t.Errorf("the relay forwarded an unmapped connection")
		}
	})

	t.Run("Secrets", func(t *testing.T) {
		if err := harness.MiniDump(pid, filepath.Join(harness.DumpDir, "ashgate-mini.dmp")); err != nil {
			t.Logf("minidump: %v", err)
		}
		cfgRaw, _ := os.ReadFile(harness.ConfigPath())
		a.Quit()
		found, unreadable := env.Secrets.Scan(harness.ScanRoots(), harness.PlainAllowed)
		env.WriteJSON("leaks/secret-scan.json", map[string]any{"found": found, "unreadable": unreadable})
		for _, f := range found {
			t.Errorf("secret %s found in %s", f.Secret, f.File)
		}
		for _, name := range []string{s.Fx.SubURL, s.Fx.SubToken} {
			if strings.Contains(string(cfgRaw), name) {
				t.Errorf("config.json holds the subscription URL or token in plain text")
			}
		}
		_ = os.Remove(filepath.Join(harness.DumpDir, "ashgate-mini.dmp"))
	})

	t.Run("DPAPI", func(t *testing.T) {
		c := readConfig(t)
		sealed := subOf(c).Sealed
		if !strings.HasPrefix(sealed, "dpapi:") {
			t.Fatalf("subscription is not sealed with DPAPI: %.12q…", sealed)
		}
		if raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(sealed, "dpapi:")); err == nil {
			if strings.Contains(string(raw), "vless://") || strings.Contains(string(raw), s.Fx.SubToken) {
				t.Errorf("the sealed blob contains plain text")
			}
		}
		_ = os.MkdirAll(harness.SharedDir, 0o777)
		blob := filepath.Join(harness.SharedDir, "sealed.txt")
		if err := os.WriteFile(blob, []byte(sealed), 0o644); err != nil {
			t.Fatal(err)
		}
		_, _ = harness.Run("icacls", blob, "/grant", "*S-1-1-0:R")
		defer os.Remove(blob)
		if r := harness.RunClient(s.Client, "dpapi", "-in", blob); !r.OK {
			t.Errorf("the installing user cannot open the sealed subscription: %s", r.Error)
		}
		u, err := harness.NewOtherUser(env)
		if err != nil {
			t.Fatalf("other user: %v", err)
		}
		defer u.Delete()
		var openErr error
		profile, err := u.As(func() error {
			_, openErr = secret.Open(sealed)
			return nil
		})
		switch {
		case err != nil:
			env.Note("skipped", "DPAPI as another user: "+err.Error())
			t.Errorf("as another user: %v", err)
		case openErr == nil:
			t.Errorf("another Windows user decrypted the subscription")
		default:
			t.Logf("another user (profile loaded: %v): %v", profile, openErr)
		}
		if r, err := harness.RunAsSystem(s.Client, "dpapi", "-in", blob); err != nil {
			t.Errorf("run as SYSTEM: %v", err)
		} else if r.OK {
			t.Errorf("SYSTEM decrypted the subscription (it must be sealed for the user only)")
		}
	})

	t.Run("SettingsACL", func(t *testing.T) { checkSettingsACL(t, env) })
}

func socksMethod(addr string, method byte) byte {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return 0xFE
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = c.Write([]byte{5, 1, method})
	var b [2]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		return 0xFF
	}
	return b[1]
}

func socksAuth(c net.Conn, user, pass string) bool {
	_, _ = c.Write([]byte{5, 1, 2})
	var b [2]byte
	if _, err := io.ReadFull(c, b[:]); err != nil || b[1] != 2 {
		return false
	}
	msg := append([]byte{1, byte(len(user))}, user...)
	msg = append(append(msg, byte(len(pass))), pass...)
	_, _ = c.Write(msg)
	if _, err := io.ReadFull(c, b[:]); err != nil {
		return false
	}
	return b[1] == 0
}

func socksLogin(addr, user, pass string) bool {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	return socksAuth(c, user, pass)
}

// socksUDPAssociate returns the SOCKS5 reply code (0 = granted, 0xFF = closed).
func socksUDPAssociate(addr, user, pass string) byte {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return 0xFE
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if !socksAuth(c, user, pass) {
		return 0xFD
	}
	_, _ = c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	var b [4]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		return 0xFF
	}
	return b[1]
}

func httpConnectStatus(addr, auth string) int {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return -1
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	req := "CONNECT 198.51.100.10:18080 HTTP/1.1\r\nHost: 198.51.100.10:18080\r\n"
	if auth != "" {
		req += "Proxy-Authorization: Basic " + auth + "\r\n"
	}
	_, _ = io.WriteString(c, req+"\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return -1
	}
	return resp.StatusCode
}

func get(url, token, host string) int {
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	if token != "" {
		req.Header.Set("X-Ashgate-Token", token)
	}
	if host != "" {
		req.Host = host
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return -1
	}
	resp.Body.Close()
	return resp.StatusCode
}
