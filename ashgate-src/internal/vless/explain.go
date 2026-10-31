package vless

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

type logLine struct {
	at time.Time
	s  string
}

var (
	logMu    sync.Mutex
	logLines []logLine
)

func pushLog(s string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return
	}
	logMu.Lock()
	defer logMu.Unlock()
	logLines = append(logLines, logLine{at: time.Now(), s: s})
	if len(logLines) > 64 {
		logLines = logLines[len(logLines)-64:]
	}
}

// RecentLog is the Xray log text recorded since t. Tests use it when a
// handshake fails without a useful SOCKS reply.
func RecentLog(since time.Time) string {
	logMu.Lock()
	defer logMu.Unlock()
	var b strings.Builder
	for _, line := range logLines {
		if !line.at.Before(since) {
			b.WriteString(line.s)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

const certFailed = "VLESS: сервер не прошёл проверку подлинности. Для REALITY проверьте публичный ключ, short id и SNI, для TLS — сертификат сервера (pcs)"

// Explain turns a dial or handshake failure into a short Russian log line.
// Errors that are already specific are returned unchanged.
func Explain(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New("VLESS: нет ответа от сервера (таймаут)")
	}
	msg := err.Error()
	low := strings.ToLower(msg)
	blob := low + "\n" + strings.ToLower(RecentLog(time.Now().Add(-12*time.Second)))
	switch {
	case strings.Contains(msg, "Не удалось разобрать ссылку VLESS"):
		return err
	case strings.Contains(msg, "локальный мост не запущен"):
		return err
	case strings.Contains(blob, "reality") || (strings.Contains(blob, "handshake") && (strings.Contains(blob, "fail") || strings.Contains(blob, "не уда"))):
		return errors.New("REALITY: рукопожатие не удалось. Проверьте публичный ключ, short id и SNI")
	case strings.Contains(blob, "x509:") || strings.Contains(blob, "certificate signed by unknown authority"):
		// REALITY with a wrong key ends up checking the decoy site's
		// certificate; TLS fails here on an untrusted certificate.
		return errors.New(certFailed)
	case strings.Contains(low, "timeout") || strings.Contains(low, "deadline") || strings.Contains(low, "i/o timeout"):
		return errors.New("VLESS: нет ответа от сервера (таймаут)")
	case strings.Contains(low, "connection refused") || strings.Contains(low, "general failure") || strings.Contains(low, "host unreachable") || strings.Contains(low, "network unreachable") || strings.Contains(low, "actively refused"):
		return errors.New("VLESS: сервер отклонил соединение")
	default:
		return err
	}
}
