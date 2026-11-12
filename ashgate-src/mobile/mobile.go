// Package mobile is the Android app's core, bound with gomobile. It reads
// profiles and runs Xray on the VpnService's TUN descriptor. Profiles cross
// the boundary as JSON (see mobilecfg.Profile).
package mobile

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
	"sync"

	"ashgate/internal/mobilecfg"
	"ashgate/internal/vless"
)

// Mtu is the TUN's MTU; VpnService.Builder gets the same value.
const Mtu = mobilecfg.MTU

// ParseLink reads a vless:// link (XHTTP only) into a profile.
func ParseLink(link string) (string, error) {
	p, err := mobilecfg.FromLink(link)
	if err != nil {
		return "", err
	}
	return encode(p)
}

// ParseSubscription reads a 3x-ui subscription body into a JSON array of
// its XHTTP profiles.
func ParseSubscription(body []byte) (string, error) {
	list, err := mobilecfg.FromSubscription(body)
	if err != nil {
		return "", err
	}
	return encode(list)
}

// ParseProxy checks a SOCKS5 or HTTP proxy from the form into a profile.
func ParseProxy(kind, name, host string, port int, user, pass string) (string, error) {
	p, err := mobilecfg.Proxy(kind, name, host, port, user, pass)
	if err != nil {
		return "", err
	}
	return encode(p)
}

func encode(v any) (string, error) {
	raw, err := json.Marshal(v)
	return string(raw), err
}

var (
	mu      sync.Mutex
	running io.Closer
)

// Start runs Xray for a profile on the TUN descriptor fd. Xray reads a
// duplicate, so the caller still owns and closes fd. assetDir holds
// geoip.dat and geosite.dat.
func Start(profileJSON string, fd int, assetDir string) error {
	var p mobilecfg.Profile
	if err := json.Unmarshal([]byte(profileJSON), &p); err != nil {
		return errors.New("Профиль повреждён")
	}
	raw, err := mobilecfg.XrayJSON(p)
	if err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	if running != nil {
		_ = running.Close()
		running = nil
	}
	os.Setenv("xray.location.asset", assetDir)
	os.Setenv("xray.tun.fd", strconv.Itoa(fd))
	inst, err := vless.Run(raw)
	if err != nil {
		return errors.New("Не удалось запустить Xray: " + p.Mask(err.Error()))
	}
	running = inst
	return nil
}

// Stop ends Xray. It is safe to call when nothing runs.
func Stop() {
	mu.Lock()
	defer mu.Unlock()
	if running != nil {
		_ = running.Close()
		running = nil
	}
}
