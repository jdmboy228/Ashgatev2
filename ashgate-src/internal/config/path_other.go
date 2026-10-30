//go:build !windows

package config

import (
	"os"
	"path/filepath"
)

// DefaultPath is the config location used when -config is not set.
func DefaultPath() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "ashgate", "config.json")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "ashgate.json"
	}
	return filepath.Join(home, ".config", "ashgate", "config.json")
}

// secureDir has nothing to do outside Windows: the directory is created
// with mode 0755 and the files with 0600.
func secureDir(string) {}
