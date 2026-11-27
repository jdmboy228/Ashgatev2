//go:build !windows

package process

// FileMeta holds static metadata extracted offline from an executable.
type FileMeta struct {
	Signer         string
	CertThumbprint string
	Company        string
	Product        string
	Description    string
}

// Inspector is a no-op metadata inspector on non-Windows platforms.
type Inspector struct{}

// NewInspector creates a stub inspector.
func NewInspector() *Inspector { return &Inspector{} }

// FileMetadata returns empty metadata on non-Windows platforms.
func (*Inspector) FileMetadata(string) FileMeta { return FileMeta{} }

// CommandLine returns "" on non-Windows platforms.
func (*Inspector) CommandLine(uint32, int64) string { return "" }

// HasModuleInDirs reports whether pid has a loaded module under one of dirs.
// Always false on non-Windows platforms.
func (*Inspector) HasModuleInDirs(uint32, int64, []string) bool { return false }
