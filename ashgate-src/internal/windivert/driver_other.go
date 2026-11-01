//go:build !windows

package windivert

// StopDriver has no driver to stop outside Windows.
func StopDriver() error { return nil }
