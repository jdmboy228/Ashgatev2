//go:build windows && e2e

package harness

import (
	"fmt"
	"strconv"
)

// Fake IPv6 setup on the runner's network card. GitHub runners have no
// IPv6 route, so without it an IPv6 connect fails before a packet exists
// and a leak could never show. With an address, a route and a permanent
// neighbour, a packet that escapes the tunnel really goes out on the card.
const (
	v6Addr    = "2001:db8:1::10"
	v6Gateway = "2001:db8:1::1"
	v6Prefix  = "2001:db8:2::/48"
	v6MAC     = "02-00-5e-10-00-01"
)

// SetupFakeIPv6 adds the address, neighbour and route. Undo removes them.
func SetupFakeIPv6(nic NIC) (undo func(), err error) {
	idx := strconv.Itoa(nic.Index)
	script := fmt.Sprintf(`$ErrorActionPreference='Stop';`+
		`New-NetIPAddress -InterfaceIndex %[1]s -IPAddress %[2]s -PrefixLength 64 -SkipAsSource $false | Out-Null;`+
		`New-NetNeighbor -InterfaceIndex %[1]s -IPAddress %[3]s -LinkLayerAddress %[4]s -State Permanent | Out-Null;`+
		`New-NetRoute -InterfaceIndex %[1]s -DestinationPrefix %[5]s -NextHop %[3]s | Out-Null;`+
		`Start-Sleep -Seconds 3`, idx, v6Addr, v6Gateway, v6MAC, v6Prefix)
	undo = func() {
		_, _ = PS(fmt.Sprintf(`Remove-NetRoute -InterfaceIndex %[1]s -DestinationPrefix %[4]s -Confirm:$false -ErrorAction SilentlyContinue;`+
			`Remove-NetNeighbor -InterfaceIndex %[1]s -IPAddress %[3]s -Confirm:$false -ErrorAction SilentlyContinue;`+
			`Remove-NetIPAddress -InterfaceIndex %[1]s -IPAddress %[2]s -Confirm:$false -ErrorAction SilentlyContinue`,
			idx, v6Addr, v6Gateway, v6Prefix))
	}
	if out, err := PS(script); err != nil {
		undo()
		return func() {}, fmt.Errorf("fake IPv6: %v: %s", err, out)
	}
	return undo, nil
}

// AddTestRoute adds a route for TEST-NET-3 (203.0.113.0/24) through the
// default gateway: a routing-table change that keeps the runner online.
// (A second static IPv4 address would switch the card from DHCP to static
// and cut the runner off.) Undo removes it.
func AddTestRoute(nic NIC) (undo func(), err error) {
	idx := strconv.Itoa(nic.Index)
	out, err := PS(fmt.Sprintf(`$g = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex %[1]s | Select-Object -First 1).NextHop;`+
		`New-NetRoute -InterfaceIndex %[1]s -DestinationPrefix 203.0.113.0/24 -NextHop $g -PolicyStore ActiveStore | Out-Null`, idx))
	if err != nil {
		return func() {}, fmt.Errorf("test route: %v: %s", err, out)
	}
	return func() {
		_, _ = PS(fmt.Sprintf(`Remove-NetRoute -InterfaceIndex %s -DestinationPrefix 203.0.113.0/24 -Confirm:$false -ErrorAction SilentlyContinue`, idx))
	}, nil
}

// EnsureFirewallOn turns on every Windows Firewall profile: the kill switch
// blocks programs through it while capture is stopped.
func EnsureFirewallOn() error {
	_, err := PS(`Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True`)
	return err
}
