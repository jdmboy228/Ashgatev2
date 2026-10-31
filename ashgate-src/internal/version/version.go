// Package version is the Ashgate release string baked into the CLI and GUI.
package version

import (
	"runtime/debug"
	"sync"
	"time"
)

// Version is the user-visible release.
const Version = "0.7.7"

// Info identifies the exact build. Go records the git commit when the exe
// is built from a git checkout; without one the fields are empty.
type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"` // short hash
	Time    string `json:"time,omitempty"`   // commit time, RFC 3339
	// Modified means the build had uncommitted changes.
	Modified bool `json:"modified,omitempty"`
}

var (
	once  sync.Once
	build Info
)

// Build returns the version and git commit of the running exe.
func Build() Info {
	once.Do(func() {
		build = Info{Version: Version}
		bi, ok := debug.ReadBuildInfo()
		if !ok {
			return
		}
		build = fromSettings(bi.Settings)
	})
	return build
}

func fromSettings(settings []debug.BuildSetting) Info {
	out := Info{Version: Version}
	for _, s := range settings {
		switch s.Key {
		case "vcs.revision":
			out.Commit = s.Value
			if len(out.Commit) > 7 {
				out.Commit = out.Commit[:7]
			}
		case "vcs.time":
			if t, err := time.Parse(time.RFC3339, s.Value); err == nil {
				out.Time = t.UTC().Format(time.RFC3339)
			}
		case "vcs.modified":
			out.Modified = s.Value == "true"
		}
	}
	return out
}

// String is "0.6.0 (912208e, 2026-10-26)", or just the version.
func (i Info) String() string {
	s := i.Version
	if i.Commit == "" {
		return s
	}
	s += " (" + i.Commit
	if len(i.Time) >= 10 {
		s += ", " + i.Time[:10]
	}
	if i.Modified {
		s += ", изменён"
	}
	return s + ")"
}
