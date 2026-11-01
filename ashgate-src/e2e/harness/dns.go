//go:build windows && e2e

package harness

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

// BootDoH is a fake DoH resolver on loopback for dns.bootstrap: it answers
// A queries for its names with 127.0.0.1 and remembers every name asked.
type BootDoH struct {
	URL   string
	srv   *http.Server
	mu    sync.Mutex
	names map[string]string // name (no trailing dot) -> IPv4
	asked []string
}

// StartBootDoH serves names (host -> IPv4) at URL.
func StartBootDoH(names map[string]string) (*BootDoH, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	b := &BootDoH{URL: "http://" + ln.Addr().String() + "/dns-query", names: map[string]string{}}
	for k, v := range names {
		b.names[strings.ToLower(k)] = v
	}
	b.srv = &http.Server{Handler: http.HandlerFunc(b.serve)}
	go func() { _ = b.srv.Serve(ln) }()
	return b, nil
}

// Close stops the resolver.
func (b *BootDoH) Close() { _ = b.srv.Close() }

// Asked is every name queried so far.
func (b *BootDoH) Asked() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.asked...)
}

func (b *BootDoH) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	var q dnsmessage.Message
	if err := q.Unpack(body); err != nil || len(q.Questions) != 1 {
		http.Error(w, "bad query", http.StatusBadRequest)
		return
	}
	qq := q.Questions[0]
	name := strings.TrimSuffix(strings.ToLower(qq.Name.String()), ".")
	b.mu.Lock()
	b.asked = append(b.asked, name)
	ip := b.names[name]
	b.mu.Unlock()
	resp := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: q.ID, Response: true, RecursionAvailable: true},
		Questions: q.Questions,
	}
	if ip4 := net.ParseIP(ip).To4(); ip4 != nil && qq.Type == dnsmessage.TypeA {
		resp.Answers = []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: qq.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
			Body:   &dnsmessage.AResource{A: [4]byte(ip4)},
		}}
	} else if ip == "" {
		resp.Header.RCode = dnsmessage.RCodeNameError
	}
	out, err := resp.Pack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	_, _ = w.Write(out)
}

// Link-local DNS servers, the kind a home router hands out. Permanent
// neighbours make a packet to them really leave on the card, so a leak
// shows in the capture instead of dying in neighbour discovery.
const (
	LinkLocalDNS6 = "fe80::53"
	LinkLocalDNS4 = "169.254.53.53"
	llMAC         = "02-00-5e-10-00-53"
)

// SetupLinkLocalDNS adds the neighbours (and an on-link route for the
// IPv4 one). Undo removes them.
func SetupLinkLocalDNS(nic NIC) (undo func(), err error) {
	idx := strconv.Itoa(nic.Index)
	script := fmt.Sprintf(`$ErrorActionPreference='Stop';`+
		`New-NetNeighbor -InterfaceIndex %[1]s -IPAddress %[2]s -LinkLayerAddress %[4]s -State Permanent | Out-Null;`+
		`New-NetRoute -InterfaceIndex %[1]s -DestinationPrefix %[3]s/32 -NextHop 0.0.0.0 -PolicyStore ActiveStore | Out-Null;`+
		`New-NetNeighbor -InterfaceIndex %[1]s -IPAddress %[3]s -LinkLayerAddress %[4]s -State Permanent | Out-Null;`+
		`Start-Sleep -Seconds 2`, idx, LinkLocalDNS6, LinkLocalDNS4, llMAC)
	undo = func() {
		_, _ = PS(fmt.Sprintf(`Remove-NetNeighbor -InterfaceIndex %[1]s -IPAddress %[2]s -Confirm:$false -ErrorAction SilentlyContinue;`+
			`Remove-NetNeighbor -InterfaceIndex %[1]s -IPAddress %[3]s -Confirm:$false -ErrorAction SilentlyContinue;`+
			`Remove-NetRoute -InterfaceIndex %[1]s -DestinationPrefix %[3]s/32 -Confirm:$false -ErrorAction SilentlyContinue`,
			idx, LinkLocalDNS6, LinkLocalDNS4))
	}
	if out, err := PS(script); err != nil {
		undo()
		return func() {}, fmt.Errorf("link-local DNS: %v: %s", err, out)
	}
	return undo, nil
}

// LinkLocalDNS6Addr is the IPv6 server with the card's zone, for a dial.
func LinkLocalDNS6Addr(nic NIC) string {
	return net.JoinHostPort(LinkLocalDNS6+"%"+strconv.Itoa(nic.Index), "53")
}

// EdgeExe is Microsoft Edge on the runner, or "" when it is missing.
func EdgeExe() string {
	for _, dir := range []string{os.Getenv("ProgramFiles(x86)"), os.Getenv("ProgramFiles")} {
		if dir == "" {
			continue
		}
		p := filepath.Join(dir, "Microsoft", "Edge", "Application", "msedge.exe")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// LeakPage writes an HTML page that loads one image from each name, the
// way dnsleaktest's extended test makes the browser resolve them.
func LeakPage(path string, names []string) error {
	var b strings.Builder
	b.WriteString("<!doctype html><title>dns</title>\n")
	for _, n := range names {
		fmt.Fprintf(&b, "<img src=\"http://%s/x.png\" width=1 height=1>\n", n)
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}
