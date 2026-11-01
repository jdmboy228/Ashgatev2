//go:build windows

package config

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
)

// DefaultPath prefers ProgramData so the elevated engine and the GUI share
// one file, and falls back to the user profile when ProgramData is not writable.
func DefaultPath() string {
	shared := sharedPath()
	if dirWritable(filepath.Dir(shared)) || fileExists(shared) {
		return shared
	}
	base := os.Getenv("AppData")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, "AppData", "Roaming")
	}
	return filepath.Join(base, "Ashgate", "config.json")
}

func dirWritable(dir string) bool {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false
	}
	f, err := os.CreateTemp(dir, ".ashgate-write-*")
	if err != nil {
		return false
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return true
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func sharedPath() string {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return filepath.Join(programData, "Ashgate", "config.json")
}

// sharedDirSDDL gives SYSTEM and Administrators full control, inherited by
// every file. ProgramData itself lets any user create files in a subfolder;
// the elevated window reads config.json, resume-capture and the kill-switch
// state from here, and writes through config.json.tmp, so a standard user
// must not be able to plant those. Nobody else may read them either:
// config.json keeps proxy passwords and VLESS keys in plain text. secureDir
// adds read access for the user who runs Ashgate, so Explorer still opens
// the folder for them ("Открыть папку").
const sharedDirSDDL = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// ownerReadACE is the extra entry for the user running the elevated window.
func ownerReadACE() string {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return ""
	}
	return "(A;OICI;0x1200a9;;;" + u.User.Sid.String() + ")"
}

var secureOnce sync.Once

// secureDir locks down the shared ProgramData folder once per process. It
// only acts when this process is elevated (the window and the service are)
// and dir is that folder; a -config path elsewhere is left as the user set it.
// Failures are ignored: the folder still works with its inherited rights.
func secureDir(dir string) {
	if !strings.EqualFold(filepath.Clean(dir), filepath.Dir(sharedPath())) {
		return
	}
	secureOnce.Do(func() {
		if !windows.GetCurrentProcessToken().IsElevated() {
			return
		}
		sd, err := windows.SecurityDescriptorFromString(sharedDirSDDL + ownerReadACE())
		if err != nil {
			return
		}
		// A standard user who ran ashgate first owns the folder, and an
		// owner can always rewrite its access list. Take ownership first.
		if owner, _, err := sd.Owner(); err == nil {
			_ = windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
				windows.OWNER_SECURITY_INFORMATION, owner, nil, nil, nil)
		}
		dacl, _, err := sd.DACL()
		if err != nil {
			return
		}
		_ = windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			nil, nil, dacl, nil)
	})
}
