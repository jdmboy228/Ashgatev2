package gui

import (
	"os"
	"path/filepath"
)

// resumeFile marks that capture was on when the window was asked to quit
// for an update (ashgate quit). The next start turns capture back on and
// removes the mark, so an update does not silently leave apps unprotected.
const resumeFile = "resume-capture"

func resumePath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), resumeFile)
}

// markResume records that the next start should turn capture on.
func markResume(configPath string) error {
	return os.WriteFile(resumePath(configPath), []byte("1\n"), 0o600)
}

// consumeResume reports whether a resume mark was left, and removes it.
func consumeResume(configPath string) bool {
	p := resumePath(configPath)
	if _, err := os.Stat(p); err != nil {
		return false
	}
	_ = os.Remove(p)
	return true
}
