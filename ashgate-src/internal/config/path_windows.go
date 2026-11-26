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

// ownerReadACE is the extra entry for the user running the elevated window:
// directory listing / read only (no OICI inheritance), so Explorer still opens
// the folder ("Открыть папку") and log files can be read, while config.json
// and sealed subscriptions do not inherit non-elevated read access.
func ownerReadACE() string {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return ""
	}
	return "(A;;0x1200a9;;;" + u.User.Sid.String() + ")"
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

const maxSecureDepth = 32

// enableTakeOwnership enables SeTakeOwnershipPrivilege on the current process
// token on a best-effort basis so an elevated process can take ownership of
// pre-planted files whose DACL excludes Administrators.
func enableTakeOwnership() {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		return
	}
	defer tok.Close()
	name, err := windows.UTF16PtrFromString("SeTakeOwnershipPrivilege")
	if err != nil {
		return
	}
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, name, &luid); err != nil {
		return
	}
	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{{
			Luid:       luid,
			Attributes: windows.SE_PRIVILEGE_ENABLED,
		}},
	}
	_ = windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil)
}

// secureHandle atomically locks down a single file or directory by handle,
// refusing reparse points (junctions/symlinks) on both opens. Ownership is
// taken in a first WRITE_OWNER handle so attacker-protected DACLs that exclude
// Administrators do not cause ACCESS_DENIED before the second WRITE_DAC handle
// applies the explicit, non-nil protected DACL.
func secureHandle(path string, owner *windows.SID, dacl *windows.ACL, isDir bool) error {
	if owner == nil || dacl == nil {
		return errors.New("refusing to apply nil owner or nil DACL")
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if isDir {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	const share = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE

	hOwn, err := windows.CreateFile(p,
		windows.WRITE_OWNER|windows.FILE_READ_ATTRIBUTES,
		share, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return fmt.Errorf("open for ownership %q: %w", path, err)
	}
	var fi windows.ByHandleFileInformation
	err = windows.GetFileInformationByHandle(hOwn, &fi)
	if err == nil && fi.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		err = fmt.Errorf("refusing reparse point %q", path)
	}
	if err == nil {
		err = windows.SetSecurityInfo(hOwn, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION, owner, nil, nil, nil)
	}
	windows.CloseHandle(hOwn)
	if err != nil {
		return fmt.Errorf("set owner %q: %w", path, err)
	}

	hDacl, err := windows.CreateFile(p,
		windows.READ_CONTROL|windows.WRITE_DAC|windows.FILE_READ_ATTRIBUTES,
		share, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return fmt.Errorf("open for DACL %q: %w", path, err)
	}
	defer windows.CloseHandle(hDacl)
	var fi2 windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(hDacl, &fi2); err != nil {
		return err
	}
	if fi2.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("refusing reparse point %q", path)
	}
	if err := windows.SetSecurityInfo(hDacl, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("set DACL %q: %w", path, err)
	}
	return nil
}

func secureTree(dir string, owner *windows.SID, dirDACL, fileDACL *windows.ACL, depth int) error {
	if depth > maxSecureDepth {
		return fmt.Errorf("protected directory nesting too deep at %q", dir)
	}
	if err := secureHandle(dir, owner, dirDACL, true); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		child := filepath.Join(dir, e.Name())
		if e.Type()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return fmt.Errorf("refusing reparse point %q", child)
		}
		if err := checkNotReparsePoint(child); err != nil {
			return err
		}
		if e.IsDir() {
			if depth == 0 && strings.EqualFold(e.Name(), "WebView2") {
				// Lock down any leftover 0.9.5 ProgramData\Ashgate\WebView2
				// directory handle itself without recursing into deep Chromium
				// cache trees; Ashgate only removes this directory via os.Root.
				if err := secureHandle(child, owner, fileDACL, true); err != nil {
					return err
				}
				continue
			}
			if err := secureTree(child, owner, dirDACL, fileDACL, depth+1); err != nil {
				return err
			}
		} else {
			dacl := fileDACL
			if depth == 0 && strings.HasPrefix(strings.ToLower(e.Name()), "ashgate.log") {
				// Allow the current user to read log files in Explorer/Notepad.
				dacl = dirDACL
			}
			if err := secureHandle(child, owner, dacl, false); err != nil {
				return err
			}
		}
	}
	return nil
}

// secureDir locks down the shared ProgramData folder when this process is
// elevated (the window and the service are) and dir is that folder; a -config
// path elsewhere is left as the user set it. Reparse points (such as NTFS
// junctions) are always rejected, existing files/subdirectories inside dir
// also have their owner and protected DACL reset by handle, and ACL
// application is latched only after it succeeds.
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
	dirSD, err := windows.SecurityDescriptorFromString(sharedDirSDDL + ownerReadACE())
	if err != nil {
		return err
	}
	fileSD, err := windows.SecurityDescriptorFromString(sharedDirSDDL)
	if err != nil {
		return err
	}
	// A standard user who ran ashgate first owns the folder (and any
	// pre-planted files inside it), and an owner can always rewrite the
	// access list. Take ownership and apply the explicit protected DACL
	// by handle on the folder and all existing children.
	owner, _, err := dirSD.Owner()
	if err != nil {
		return err
	}
	if owner == nil {
		return errors.New("shared folder security descriptor missing owner")
	}
	dirDACL, _, err := dirSD.DACL()
	if err != nil {
		return err
	}
	if dirDACL == nil {
		return errors.New("shared folder security descriptor missing DACL")
	}
	fileDACL, _, err := fileSD.DACL()
	if err != nil {
		return err
	}
	if fileDACL == nil {
		return errors.New("shared file security descriptor missing DACL")
	}
	enableTakeOwnership()
	if err := secureTree(dir, owner, dirDACL, fileDACL, 0); err != nil {
		return err
	}
	securedShared = true
	return nil
}
