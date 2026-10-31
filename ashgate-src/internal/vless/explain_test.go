package vless

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestExplainRussianFailures(t *testing.T) {
	if got := Explain(context.DeadlineExceeded); got.Error() != "VLESS: нет ответа от сервера (таймаут)" {
		t.Fatal(got)
	}
	if got := Explain(fmt.Errorf("read tcp 127.0.0.1:1: i/o timeout")); got.Error() != "VLESS: нет ответа от сервера (таймаут)" {
		t.Fatal(got)
	}
	if got := Explain(errors.New("socks5: connection refused")); got.Error() != "VLESS: сервер отклонил соединение" {
		t.Fatal(got)
	}
	if got := Explain(errors.New("socks5: general failure")); got.Error() != "VLESS: сервер отклонил соединение" {
		t.Fatal(got)
	}
	pushLog("REALITY: processed invalid connection from 127.0.0.1")
	got := Explain(errors.New("socks5: general failure"))
	if got.Error() != "REALITY: рукопожатие не удалось. Проверьте публичный ключ, short id и SNI" {
		t.Fatal(got)
	}
	// The REALITY line above must not leak into a later, unrelated refusal
	// once it falls out of the window. Stamp it as old.
	logMu.Lock()
	for i := range logLines {
		logLines[i].at = time.Now().Add(-time.Minute)
	}
	logMu.Unlock()
	if got := Explain(errors.New("socks5: connection refused")); got.Error() != "VLESS: сервер отклонил соединение" {
		t.Fatal(got)
	}
	if got := Explain(errors.New("x509: certificate signed by unknown authority")); got.Error() != certFailed {
		t.Fatal(got)
	}
	plain := errors.New("Не удалось разобрать ссылку VLESS: неверный UUID")
	if Explain(plain) != plain {
		t.Fatal(Explain(plain))
	}
}
