//go:build !windows

package process

import "ashgate/internal/rules"

// App is one running executable.
type App struct {
	PID    uint32 `json:"pid"`
	Name   string `json:"name"`
	Path   string `json:"path"`
	Window bool   `json:"window"`
	Title string `json:"title,omitempty"`
	Mask  string `json:"mask,omitempty"`
}

// List is empty outside Windows.
func List() ([]App, error) { return nil, nil }

// Snapshot is empty outside Windows.
func Snapshot() []rules.Process { return nil }
