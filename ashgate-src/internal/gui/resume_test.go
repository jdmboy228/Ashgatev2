package gui

import (
	"path/filepath"
	"testing"
)

func TestResumeMarkIsUsedOnce(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.json")
	if consumeResume(cfg) {
		t.Fatal("no mark yet")
	}
	if err := markResume(cfg); err != nil {
		t.Fatal(err)
	}
	if !consumeResume(cfg) {
		t.Fatal("mark should be found")
	}
	if consumeResume(cfg) {
		t.Fatal("mark should be removed after use")
	}
}
