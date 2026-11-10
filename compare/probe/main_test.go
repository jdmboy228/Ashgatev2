package main

import "testing"

func TestQueryMessage(t *testing.T) {
	msg := queryMessage("a.probe.example")
	if len(msg) < 12 || msg[2] != 0x01 || msg[5] != 0x01 {
		t.Fatalf("header %x", msg)
	}
	// a, probe, example
	if msg[12] != 1 || msg[13] != 'a' {
		t.Fatalf("first label %x", msg[12:])
	}
}
