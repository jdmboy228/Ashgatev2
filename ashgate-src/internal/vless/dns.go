package vless

import "net"

// dohByIP lists resolvers that answer DoH on their own IP address, so no
// name has to be resolved to reach them.
var dohByIP = map[string]string{
	"1.1.1.1": "https://1.1.1.1/dns-query", "1.0.0.1": "https://1.0.0.1/dns-query",
	"8.8.8.8": "https://8.8.8.8/dns-query", "8.8.4.4": "https://8.8.4.4/dns-query",
	"9.9.9.9": "https://9.9.9.9/dns-query", "149.112.112.112": "https://149.112.112.112/dns-query",
	"77.88.8.8": "https://77.88.8.8/dns-query", "77.88.8.1": "https://77.88.8.1/dns-query",
	"94.140.14.14": "https://94.140.14.14/dns-query", "94.140.15.15": "https://94.140.15.15/dns-query",
}

// DNSServers turns the configured DNS servers ("1.1.1.1:53") into Xray DNS
// addresses: DoH where the resolver offers it on its IP, DNS over TCP
// otherwise. Xray sends both through the tunnel.
func DNSServers(servers []string) []string {
	var out []string
	for _, s := range servers {
		host, port, err := net.SplitHostPort(s)
		if err != nil || net.ParseIP(host) == nil {
			continue
		}
		if doh, ok := dohByIP[host]; ok && port == "53" {
			out = append(out, doh)
			continue
		}
		out = append(out, "tcp://"+net.JoinHostPort(host, port))
	}
	return out
}
