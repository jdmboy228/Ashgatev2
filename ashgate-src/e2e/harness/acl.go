//go:build windows && e2e

package harness

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ACE is one access entry of a file's DACL.
type ACE struct {
	Allow   bool   `json:"allow"`
	SID     string `json:"sid"`
	Account string `json:"account"`
	Mask    uint32 `json:"mask"`
	Inherit bool   `json:"inheritOnly"`
}

// Read access bits for files and folders (FILE_READ_DATA / LIST_DIRECTORY,
// GENERIC_READ, GENERIC_ALL, MAXIMUM_ALLOWED).
const readBits = 0x0001 | 0x80000000 | 0x10000000 | 0x02000000

// GrantsRead reports whether the entry lets its trustee read the object.
func (a ACE) GrantsRead() bool { return a.Allow && !a.Inherit && a.Mask&readBits != 0 }

// DACL lists the access entries of path.
func DACL(path string) (owner string, aces []ACE, err error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return "", nil, err
	}
	if o, _, err := sd.Owner(); err == nil && o != nil {
		owner = o.String()
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return owner, nil, fmt.Errorf("no DACL on %s (everyone has access): %v", path, err)
	}
	for i := uint16(0); i < acl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, uint32(i), &ace); err != nil {
			return owner, aces, err
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		e := ACE{
			Allow:   ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE,
			SID:     sid.String(),
			Mask:    uint32(ace.Mask),
			Inherit: ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0,
		}
		if acct, dom, _, err := sid.LookupAccount(""); err == nil {
			e.Account = dom + `\` + acct
		}
		aces = append(aces, e)
	}
	return owner, aces, nil
}

// Well-known SIDs that must never read Ashgate's settings.
var broadSIDs = map[string]string{
	"S-1-1-0":      "Everyone",
	"S-1-5-11":     "Authenticated Users",
	"S-1-5-32-545": "Users",
	"S-1-5-4":      "INTERACTIVE",
	"S-1-5-32-546": "Guests",
	"S-1-5-7":      "ANONYMOUS LOGON",
}

// AllowedReaders is SYSTEM, Administrators and the current (installing) user.
func AllowedReaders() map[string]bool {
	ok := map[string]bool{"S-1-5-18": true, "S-1-5-32-544": true}
	if u, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil {
		ok[u.User.Sid.String()] = true
	}
	return ok
}

// ReadersBeyond lists entries that grant read to anyone outside allowed.
func ReadersBeyond(aces []ACE, allowed map[string]bool) []ACE {
	var out []ACE
	for _, a := range aces {
		if a.GrantsRead() && !allowed[a.SID] {
			out = append(out, a)
		}
	}
	return out
}

// IsBroad names a well-known group SID, or "".
func IsBroad(sid string) string { return broadSIDs[sid] }

// OtherUser is a standard local account made for the "someone else" tests.
type OtherUser struct {
	Name, Pass string
}

// NewOtherUser creates a standard (non-admin) local user.
func NewOtherUser(env *Env) (OtherUser, error) {
	u := OtherUser{Name: "e2eother", Pass: "Aa1!" + RandHex(10)}
	env.Secrets.Add("other-user-pass", u.Pass, false)
	_, _ = Run("net", "user", u.Name, "/delete")
	if out, err := Run("net", "user", u.Name, u.Pass, "/add", "/y"); err != nil {
		return u, fmt.Errorf("net user /add: %v: %s", err, out)
	}
	if err := os.MkdirAll(SharedDir, 0o777); err != nil {
		return u, err
	}
	_, _ = Run("icacls", SharedDir, "/grant", "*S-1-1-0:(OI)(CI)M")
	return u, nil
}

// Delete removes the account and its profile.
func (u OtherUser) Delete() {
	_, _ = Run("net", "user", u.Name, "/delete")
	_, _ = PS(`Get-CimInstance Win32_UserProfile | Where-Object { $_.LocalPath -like '*\` + u.Name + `' } | Remove-CimInstance -ErrorAction SilentlyContinue`)
}

var (
	advapi32                 = windows.NewLazySystemDLL("advapi32.dll")
	userenv                  = windows.NewLazySystemDLL("userenv.dll")
	pLogonUser               = advapi32.NewProc("LogonUserW")
	pImpersonateLoggedOnUser = advapi32.NewProc("ImpersonateLoggedOnUser")
	pLoadUserProfile         = userenv.NewProc("LoadUserProfileW")
	pUnloadUserProfile       = userenv.NewProc("UnloadUserProfile")
)

type profileInfo struct {
	Size, Flags                                        uint32
	UserName, ProfilePath, DefaultPath, Server, Policy *uint16
	Profile                                            windows.Handle
}

// As runs fn on this goroutine's thread while it impersonates the user
// (logged on, profile loaded when possible, so DPAPI has the user's keys).
// No process is started: an earlier Start-Process -Credential version hung
// on the runner. profile reports whether the user's profile was loaded.
func (u OtherUser) As(fn func() error) (profile bool, err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	name, _ := windows.UTF16PtrFromString(u.Name)
	dom, _ := windows.UTF16PtrFromString(".")
	pw, _ := windows.UTF16PtrFromString(u.Pass)
	var tok windows.Token
	const interactive, network, providerDefault = 2, 3, 0
	r, _, e := pLogonUser.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(dom)), uintptr(unsafe.Pointer(pw)),
		interactive, providerDefault, uintptr(unsafe.Pointer(&tok)))
	if r == 0 {
		r, _, e = pLogonUser.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(dom)), uintptr(unsafe.Pointer(pw)),
			network, providerDefault, uintptr(unsafe.Pointer(&tok)))
		if r == 0 {
			return false, fmt.Errorf("LogonUser %s: %v", u.Name, e)
		}
	}
	defer tok.Close()
	enablePrivileges("SeBackupPrivilege", "SeRestorePrivilege")
	pi := profileInfo{Flags: 1 /* PI_NOUI */, UserName: name}
	pi.Size = uint32(unsafe.Sizeof(pi))
	if r, _, _ := pLoadUserProfile.Call(uintptr(tok), uintptr(unsafe.Pointer(&pi))); r != 0 {
		profile = true
		defer pUnloadUserProfile.Call(uintptr(tok), uintptr(pi.Profile))
	}
	if r, _, e := pImpersonateLoggedOnUser.Call(uintptr(tok)); r == 0 {
		return profile, fmt.Errorf("ImpersonateLoggedOnUser: %v", e)
	}
	defer windows.RevertToSelf()
	return profile, fn()
}

// enablePrivileges turns on privileges the elevated token holds but keeps
// disabled (LoadUserProfile needs backup and restore).
func enablePrivileges(names ...string) {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		return
	}
	defer tok.Close()
	for _, n := range names {
		var luid windows.LUID
		np, _ := windows.UTF16PtrFromString(n)
		if windows.LookupPrivilegeValue(nil, np, &luid) != nil {
			continue
		}
		tp := windows.Tokenprivileges{PrivilegeCount: 1}
		tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
		_ = windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil)
	}
}

// RunAsSystem runs exe as LocalSystem through a one-off scheduled task.
func RunAsSystem(exe string, args ...string) (ClientResult, error) {
	out := filepath.Join(SharedDir, fmt.Sprintf("sys-%d.json", time.Now().UnixNano()))
	_ = os.MkdirAll(SharedDir, 0o777)
	// Every path here is under C:\ashgate-e2e (no spaces), so no quoting
	// has to survive schtasks /TR.
	cmdLine := fmt.Sprintf(`cmd.exe /c %s %s > %s`, exe, strings.Join(args, " "), out)
	name := "ashgate-e2e-system"
	if o, err := Run("schtasks", "/Create", "/TN", name, "/SC", "ONCE", "/ST", "23:59", "/RU", "SYSTEM", "/TR", cmdLine, "/F"); err != nil {
		return ClientResult{}, fmt.Errorf("schtasks create: %v: %s", err, o)
	}
	defer Run("schtasks", "/Delete", "/TN", name, "/F")
	if o, err := Run("schtasks", "/Run", "/TN", name); err != nil {
		return ClientResult{}, fmt.Errorf("schtasks run: %v: %s", err, o)
	}
	var r ClientResult
	err := Eventually(30*time.Second, 500*time.Millisecond, func() error {
		var e error
		r, e = readResult(out)
		return e
	})
	return r, err
}

func readResult(path string) (ClientResult, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return ClientResult{}, err
	}
	var r ClientResult
	if err := json.Unmarshal(lastLine(b), &r); err != nil {
		return r, fmt.Errorf("result %q: %v", string(b), err)
	}
	return r, nil
}
