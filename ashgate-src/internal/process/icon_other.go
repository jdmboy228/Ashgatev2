//go:build !windows

package process

import (
	"errors"
	"strings"
)

// IsLocalExePath reports whether path is an absolute local-drive .exe path
// (e.g. C:\Program Files\App\app.exe), rejecting UNC, device, relative and non-exe paths.
func IsLocalExePath(path string) bool {
	low := strings.ToLower(strings.TrimSpace(path))
	return strings.HasSuffix(low, ".exe") &&
		len(low) > len(`a:\.exe`) &&
		low[0] >= 'a' && low[0] <= 'z' &&
		low[1] == ':' && low[2] == '\\' &&
		low[len(low)-5] != '\\' && low[len(low)-5] != '/' &&
		!strings.ContainsRune(low, 0)
}

// ExeIconPNG is the Windows extractor. Other systems have no exe icons.
func ExeIconPNG(path string) ([]byte, error) {
	if !IsLocalExePath(path) {
		return nil, errors.New("недопустимый путь к приложению")
	}
	return nil, errors.New("иконка exe доступна в Windows")
}
