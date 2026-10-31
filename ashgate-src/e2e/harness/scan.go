//go:build windows && e2e

package harness

import (
	"os"
	"path/filepath"
	"strings"
)

// ScanRoots are the places Ashgate (or WebView2, or Windows on its behalf)
// may write to: settings and logs, temp folders, the WebView2 profile and
// crash dumps.
func ScanRoots() []string {
	roots := []string{ProgramData(), os.TempDir(), `C:\Windows\Temp`, DumpDir,
		`C:\ProgramData\Microsoft\Windows\WER`}
	if la := os.Getenv("LOCALAPPDATA"); la != "" {
		roots = append(roots, filepath.Join(la, "Ashgate"), filepath.Join(la, "CrashDumps"))
	}
	return roots
}

// DumpDir receives WER dumps of ashgate.exe (see EnableWERDumps) and the
// harness's own minidump.
const DumpDir = `C:\ashgate-e2e\dumps`

// EnableWERDumps makes Windows keep a minidump if ashgate.exe crashes.
func EnableWERDumps() error {
	_ = os.MkdirAll(DumpDir, 0o755)
	_, err := PS(`$k='HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\ashgate.exe';` +
		`New-Item -Path $k -Force | Out-Null;` +
		`Set-ItemProperty -Path $k -Name DumpFolder -Value '` + DumpDir + `' -Type ExpandString;` +
		`Set-ItemProperty -Path $k -Name DumpType -Value 1 -Type DWord;` +
		`Set-ItemProperty -Path $k -Name DumpCount -Value 5 -Type DWord`)
	return err
}

// PlainAllowed is the rule for the secret scan: values that config.json
// keeps in plain text by design may sit in config.json (and its temp copy
// while it is being replaced), nowhere else.
func PlainAllowed(path string, sec Secret) bool {
	if !sec.PlainOK {
		return false
	}
	dir, base := filepath.Dir(path), strings.ToLower(filepath.Base(path))
	return strings.EqualFold(dir, ProgramData()) && (base == "config.json" || base == "config.json.tmp")
}
