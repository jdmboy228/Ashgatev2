// Package mobile is the Android app's core, bound with gomobile. It reads
// profiles and runs Xray on the VpnService's TUN descriptor. Profiles cross
// the boundary as JSON (see mobilecfg.Profile).
package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"ashgate/internal/bootstrap"
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
	// startMu сериализует вызовы Start (защищает глобальные переменные окружения xray.tun.fd / asset).
	startMu sync.Mutex
	// mu защищает только лёгкие поля состояния; блокирующие I/O и Close выполняются вне mu,
	// чтобы Stop() никогда не ждал запуска Xray.
	mu            sync.Mutex
	running       io.Closer
	activeProfile mobilecfg.Profile
	gen           uint64
	cancelBoot    context.CancelFunc
)

// resolveServerIP резолвит доменное имя сервера через DoH по IP (internal/bootstrap),
// чтобы имя VPN-сервера не утекало в системный DNS провайдера.
func resolveServerIP(ctx context.Context, host, assetDir string) (string, error) {
	if host == "" || net.ParseIP(host) != nil {
		return "", nil
	}
	if assetDir != "" {
		bootstrap.Default.SetFile(filepath.Join(filepath.Dir(assetDir), "dnscache.json"))
	}
	rctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	ips, err := bootstrap.Default.LookupIP(rctx, host)
	if err != nil || len(ips) == 0 {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		why := "нет адреса"
		if err != nil {
			why = err.Error()
		}
		return "", fmt.Errorf("VLESS: не удалось узнать адрес сервера %s без DNS провайдера (%s). Укажите в ссылке IP-адрес сервера", host, why)
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String(), nil
		}
	}
	return ips[0].String(), nil
}

func formatError(p mobilecfg.Profile, err error) error {
	if errors.Is(err, context.Canceled) {
		return errors.New("Подключение отменено")
	}
	msg := p.Mask(err.Error())
	if p.Kind != mobilecfg.KindVLESS && strings.HasPrefix(msg, "VLESS: ") {
		msg = "Прокси: " + strings.TrimPrefix(msg, "VLESS: ")
	}
	return errors.New(msg)
}

// Start запускает Xray для профиля на дескрипторе TUN fd и проверяет, что
// соединение через прокси-сервер поднялось и стабильно. Xray дублирует fd,
// поэтому вызывающая сторона продолжает владеть им и закрывает его сама.
func Start(profileJSON string, fd int, assetDir string) error {
	var p mobilecfg.Profile
	if err := json.Unmarshal([]byte(profileJSON), &p); err != nil {
		return errors.New("Профиль повреждён")
	}
	host, err := mobilecfg.ServerHost(p)
	if err != nil {
		return err
	}

	startMu.Lock()
	defer startMu.Unlock()

	bootCtx, bootCancel := context.WithCancel(context.Background())
	mu.Lock()
	gen++
	myGen := gen
	prev := running
	running = nil
	activeProfile = mobilecfg.Profile{}
	oldBoot := cancelBoot
	cancelBoot = bootCancel
	mu.Unlock()
	if oldBoot != nil {
		oldBoot()
	}
	defer func() {
		bootCancel()
		mu.Lock()
		if gen == myGen {
			cancelBoot = nil
		}
		mu.Unlock()
	}()

	if prev != nil {
		_ = prev.Close()
	}

	mu.Lock()
	if gen != myGen {
		mu.Unlock()
		return errors.New("Подключение отменено")
	}
	mu.Unlock()

	resolvedIP, err := resolveServerIP(bootCtx, host, assetDir)
	if err != nil {
		return formatError(p, err)
	}
	raw, err := mobilecfg.XrayJSONWithAddress(p, resolvedIP)
	if err != nil {
		return err
	}

	mu.Lock()
	if gen != myGen {
		mu.Unlock()
		return errors.New("Подключение отменено")
	}
	mu.Unlock()

	os.Setenv("xray.location.asset", assetDir)
	os.Setenv("xray.tun.fd", strconv.Itoa(fd))
	inst, err := vless.Run(raw)
	if err != nil {
		return errors.New("Не удалось запустить Xray: " + p.Mask(err.Error()))
	}

	mu.Lock()
	if gen != myGen {
		mu.Unlock()
		_ = inst.Close()
		return errors.New("Подключение отменено")
	}
	running = inst
	activeProfile = p
	mu.Unlock()

	if err := vless.Verify(inst); err != nil {
		// Сначала убираем инстанс из глобального состояния под замком,
		// чтобы параллельный Check не получил уже закрываемый инстанс.
		mu.Lock()
		cancelled := gen != myGen
		if running == inst {
			running = nil
			activeProfile = mobilecfg.Profile{}
		}
		mu.Unlock()
		_ = inst.Close()
		if cancelled || errors.Is(err, context.Canceled) {
			return errors.New("Подключение отменено")
		}
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

// Check проверяет, что запущенный туннель продолжает пропускать трафик через
// прокси-сервер. Возвращает ошибку, если туннель не запущен или сервер перестал отвечать.
func Check() error {
	mu.Lock()
	inst := running
	p := activeProfile
	myGen := gen
	mu.Unlock()
	if inst == nil {
		return errors.New("Туннель не запущен")
	}
	if err := vless.Check(inst); err != nil {
		mu.Lock()
		stale := gen != myGen || running != inst
		mu.Unlock()
		if stale || errors.Is(err, context.Canceled) {
			return errors.New("Подключение отменено")
		}
		return formatError(p, err)
	}
	return nil
}

// Stop останавливает Xray и прерывает любые текущие Start или Check.
// Безопасен при вызове в остановленном состоянии и не блокируется на запуске Xray.
func Stop() {
	mu.Lock()
	gen++
	r := running
	running = nil
	activeProfile = mobilecfg.Profile{}
	boot := cancelBoot
	cancelBoot = nil
	mu.Unlock()
	if boot != nil {
		boot()
	}
	if r != nil {
		_ = r.Close()
	}
}
