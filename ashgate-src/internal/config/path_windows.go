//go:build windows

package config

import (
	"errors"
	"fmt"
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

// ProtectedDir is the shared ProgramData folder, created and locked down
// when needed. A file the elevated window hands to another elevated
// program (the autostart task) is written here, not to %TEMP%, where the
// user's own programs could swap it before it is read.
func ProtectedDir() (string, error) {
	dir := filepath.Dir(sharedPath())
	if err := checkNotReparsePoint(dir); err != nil &&
		!errors.Is(err, windows.ERROR_FILE_NOT_FOUND) &&
		!errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	if err := secureDir(dir); err != nil {
		return "", err
	}
	return dir, nil
}

func sharedPath() string {
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil || programData == "" {
		programData = os.Getenv("ProgramData")
	}
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

var (
	secureMu      sync.Mutex
	securedShared bool
)

func checkNotReparsePoint(dir string) error {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	attrs, err := windows.GetFileAttributes(p)
	if err != nil {
		return err
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("refusing reparse point on protected config directory %q", dir)
	}
	return nil
}

// secureDir locks down the shared ProgramData folder when this process is
// elevated (the window and the service are) and dir is that folder; a -config
// path elsewhere is left as the user set it. Reparse points (such as NTFS
// junctions) are always rejected, and ACL application is latched only after it
// succeeds.
func secureDir(dir string) error {
	if !strings.EqualFold(filepath.Clean(dir), filepath.Dir(sharedPath())) {
		return nil
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		return nil
	}
	if err := checkNotReparsePoint(dir); err != nil {
		return err
	}
	secureMu.Lock()
	defer secureMu.Unlock()
	if securedShared {
		return nil
	}
	sd, err := windows.SecurityDescriptorFromString(sharedDirSDDL + ownerReadACE())
	if err != nil {
		return err
	}
	// A standard user who ran ashgate first owns the folder, and an
	// owner can always rewrite its access list. Take ownership first.
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if owner == nil {
		return errors.New("shared folder security descriptor missing owner")
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION, owner, nil, nil, nil); err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if dacl == nil {
		return errors.New("shared folder security descriptor missing DACL")
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		return err
	}
	securedShared = true
	return nil
}
