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
	"strings"
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
	mu            sync.Mutex
	running       io.Closer
	activeProfile mobilecfg.Profile
	gen           uint64
)

func formatError(p mobilecfg.Profile, err error) error {
	msg := p.Mask(err.Error())
	if p.Kind != mobilecfg.KindVLESS && strings.HasPrefix(msg, "VLESS: ") {
		msg = "Прокси: " + strings.TrimPrefix(msg, "VLESS: ")
	}
	return errors.New(msg)
}

// Start runs Xray for a profile on the TUN descriptor fd and verifies that
// the connection through the proxy server is up and stable before returning.
// Xray reads a duplicate, so the caller still owns and closes fd. assetDir
// holds geosite.dat.
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
	gen++
	myGen := gen
	prev := running
	running = nil
	activeProfile = mobilecfg.Profile{}
	if prev != nil {
		_ = prev.Close()
	}
	os.Setenv("xray.location.asset", assetDir)
	os.Setenv("xray.tun.fd", strconv.Itoa(fd))
	inst, err := vless.Run(raw)
	if err != nil {
		mu.Unlock()
		return errors.New("Не удалось запустить Xray: " + p.Mask(err.Error()))
	}
	running = inst
	activeProfile = p
	mu.Unlock()

	if err := vless.Verify(inst); err != nil {
		_ = inst.Close()
		mu.Lock()
		if running == inst {
			running = nil
			activeProfile = mobilecfg.Profile{}
		}
		mu.Unlock()
		return formatError(p, err)
	}
	mu.Lock()
	if gen != myGen || running != inst {
		mu.Unlock()
		_ = inst.Close()
		return errors.New("Подключение отменено")
	}
	mu.Unlock()
	return nil
}

// Check verifies that the running tunnel still passes traffic through its
// proxy server. It returns an error when nothing runs or the server stopped
// answering.
func Check() error {
	mu.Lock()
	inst := running
	p := activeProfile
	mu.Unlock()
	if inst == nil {
		return errors.New("Туннель не запущен")
	}
	if err := vless.Check(inst); err != nil {
		return formatError(p, err)
	}
	return nil
}

// Stop ends Xray and aborts any in-flight Start or Check. It is safe to call
// when nothing runs.
func Stop() {
	mu.Lock()
	gen++
	r := running
	running = nil
	activeProfile = mobilecfg.Profile{}
	mu.Unlock()
	if r != nil {
		_ = r.Close()
	}
}
