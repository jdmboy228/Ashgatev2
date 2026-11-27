//go:build windows

package process

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

	"ashgate/internal/rules"

	"golang.org/x/sys/windows"
)

// FileMeta holds static metadata extracted offline from a Windows executable.
// Used exclusively to rank companion suggestions in the UI — never for
// automatic proxying and never called on the packet hot path.
type FileMeta struct {
	Signer         string
	CertThumbprint string
	Company        string
	Product        string
	Description    string
}

type metaCacheEntry struct {
	modTime int64
	size    int64
	meta    FileMeta
}

type cmdCacheKey struct {
	pid     uint32
	started int64
}

type cmdCacheEntry struct {
	cmd string
	at  time.Time
}

type modCacheEntry struct {
	dirs []string
	at   time.Time
}

// Inspector caches offline PE metadata (Authenticode signer and version info)
// and running process command lines for companion candidate scoring.
type Inspector struct {
	mu    sync.Mutex
	files map[string]metaCacheEntry
	cmds  map[cmdCacheKey]cmdCacheEntry
	mods  map[cmdCacheKey]modCacheEntry
}

// NewInspector creates a reusable metadata inspector with bounded in-memory caches.
func NewInspector() *Inspector {
	return &Inspector{
		files: make(map[string]metaCacheEntry),
		cmds:  make(map[cmdCacheKey]cmdCacheEntry),
		mods:  make(map[cmdCacheKey]modCacheEntry),
	}
}

const (
	maxMetaCacheEntries = 512
	maxCmdCacheEntries  = 512
	cmdCacheTTL         = 30 * time.Second
	maxModCacheEntries  = 512
	modCacheTTL         = 30 * time.Second
)

// FileMetadata returns cached offline Authenticode signer and PE version info
// for path. Errors are swallowed and result in zero-valued fields.
func (ins *Inspector) FileMetadata(path string) FileMeta {
	path = strings.TrimSpace(path)
	if path == "" {
		return FileMeta{}
	}
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		return FileMeta{}
	}
	key := strings.ToLower(path)
	modTime := fi.ModTime().UnixNano()
	size := fi.Size()

	ins.mu.Lock()
	if e, ok := ins.files[key]; ok && e.modTime == modTime && e.size == size {
		ins.mu.Unlock()
		return e.meta
	}
	ins.mu.Unlock()

	meta := FileMeta{}
	meta.Signer, meta.CertThumbprint = readAuthenticodeSigner(path)
	meta.Company, meta.Product, meta.Description = readVersionStrings(path)

	ins.mu.Lock()
	if ins.files == nil {
		ins.files = make(map[string]metaCacheEntry)
	}
	if len(ins.files) >= maxMetaCacheEntries {
		clear(ins.files)
	}
	ins.files[key] = metaCacheEntry{modTime: modTime, size: size, meta: meta}
	ins.mu.Unlock()
	return meta
}

// CommandLine returns the command line of a running process using only
// PROCESS_QUERY_LIMITED_INFORMATION (Windows 8.1+). Returns "" on failure.
// When started is non-zero, it is compared against the process creation time
// so a reused PID never returns another process's command line.
func (ins *Inspector) CommandLine(pid uint32, started int64) string {
	if pid <= 4 {
		return ""
	}
	key := cmdCacheKey{pid: pid, started: started}
	now := time.Now()

	ins.mu.Lock()
	if e, ok := ins.cmds[key]; ok && now.Sub(e.at) < cmdCacheTTL {
		ins.mu.Unlock()
		return e.cmd
	}
	ins.mu.Unlock()

	cmd, _ := queryCommandLineErr(pid, started)

	ins.mu.Lock()
	if ins.cmds == nil {
		ins.cmds = make(map[cmdCacheKey]cmdCacheEntry)
	}
	if len(ins.cmds) >= maxCmdCacheEntries {
		for k, v := range ins.cmds {
			if now.Sub(v.at) >= cmdCacheTTL {
				delete(ins.cmds, k)
			}
		}
		if len(ins.cmds) >= maxCmdCacheEntries {
			clear(ins.cmds)
		}
	}
	ins.cmds[key] = cmdCacheEntry{cmd: cmd, at: now}
	ins.mu.Unlock()
	return cmd
}

// HasModuleInDirs reports whether the process pid has a loaded module whose
// directory is dirs[i] or lies under it. The loaded-module list is cached for
// modCacheTTL; access failures (protected process, exited PID) cache an empty
// list so the WinAPI is not hammered.
func (ins *Inspector) HasModuleInDirs(pid uint32, started int64, dirs []string) bool {
	if pid <= 4 || len(dirs) == 0 {
		return false
	}
	key := cmdCacheKey{pid: pid, started: started}
	now := time.Now()

	ins.mu.Lock()
	if e, ok := ins.mods[key]; ok && now.Sub(e.at) < modCacheTTL {
		modDirs := e.dirs
		ins.mu.Unlock()
		return matchModuleDirs(modDirs, dirs)
	}
	ins.mu.Unlock()

	modDirs, _ := queryModuleDirsErr(pid, started)

	ins.mu.Lock()
	if ins.mods == nil {
		ins.mods = make(map[cmdCacheKey]modCacheEntry)
	}
	if len(ins.mods) >= maxModCacheEntries {
		for k, v := range ins.mods {
			if now.Sub(v.at) >= modCacheTTL {
				delete(ins.mods, k)
			}
		}
		if len(ins.mods) >= maxModCacheEntries {
			clear(ins.mods)
		}
	}
	ins.mods[key] = modCacheEntry{dirs: modDirs, at: now}
	ins.mu.Unlock()
	return matchModuleDirs(modDirs, dirs)
}

// matchModuleDirs reports whether any module directory equals or is nested
// under any of the wanted directories.
func matchModuleDirs(modDirs, dirs []string) bool {
	for _, d := range dirs {
		d = normDir(d)
		if d == "" {
			continue
		}
		for _, md := range modDirs {
			if md == d || strings.HasPrefix(md, d+`\`) {
				return true
			}
		}
	}
	return false
}

// normDir normalizes a directory path, expands any Windows 8.3 short path
// segments (such as RUNNER~1 from CreateToolhelp32Snapshot), and strips a
// trailing separator (keeping a lone `\` root intact).
func normDir(p string) string {
	p = rules.NormalizePath(p)
	if strings.ContainsRune(p, '~') {
		if expanded := expandShortPath(p); expanded != p {
			p = rules.NormalizePath(expanded)
		}
	}
	if len(p) > 1 && strings.HasSuffix(p, `\`) {
		p = p[:len(p)-1]
	}
	return p
}

// expandShortPath resolves Windows 8.3 short path components via
// GetLongPathName, falling back to p unchanged on any error.
func expandShortPath(p string) string {
	if !strings.ContainsRune(p, '~') {
		return p
	}
	src, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return p
	}
	size := uint32(len(p) + 64)
	if size < 260 {
		size = 260
	}
	buf := make([]uint16, size)
	n, err := windows.GetLongPathName(src, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 {
		return p
	}
	if n >= uint32(len(buf)) {
		buf = make([]uint16, n+1)
		n, err = windows.GetLongPathName(src, &buf[0], uint32(len(buf)))
		if err != nil || n == 0 || n >= uint32(len(buf)) {
			return p
		}
	}
	return windows.UTF16ToString(buf[:n])
}

// moduleDirOf returns the normalized parent directory of a module path.
func moduleDirOf(normalizedExe string) string {
	i := strings.LastIndex(normalizedExe, `\`)
	if i < 0 {
		return ""
	}
	return normDir(normalizedExe[:i])
}

// queryModuleDirsErr lists the distinct normalized directories of the modules
// loaded in pid. When started is non-zero the process creation time is checked
// to guard against PID reuse. Access failures return the directories gathered
// so far plus an error.
func queryModuleDirsErr(pid uint32, started int64) ([]string, error) {
	if pid <= 4 {
		return nil, fmt.Errorf("system pid %d", pid)
	}
	if started != 0 {
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if err != nil {
			return nil, fmt.Errorf("OpenProcess(%d): %w", pid, err)
		}
		var create, exit, kernel, user windows.Filetime
		err = windows.GetProcessTimes(h, &create, &exit, &kernel, &user)
		windows.CloseHandle(h)
		if err != nil {
			return nil, fmt.Errorf("GetProcessTimes(%d): %w", pid, err)
		}
		if ct := create.Nanoseconds(); ct != 0 && ct != started {
			return nil, fmt.Errorf("pid %d reused (created=%d want=%d)", pid, ct, started)
		}
	}

	// ERROR_BAD_LENGTH is the documented transient failure while the target
	// process is loading modules; retry a few times as the docs suggest.
	var snap windows.Handle
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		snap, err = windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, pid)
		if err == nil {
			break
		}
		if err != windows.ERROR_BAD_LENGTH {
			return nil, fmt.Errorf("CreateToolhelp32Snapshot(%d): %w", pid, err)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot(%d): %w", pid, err)
	}
	defer windows.CloseHandle(snap)

	var me windows.ModuleEntry32
	me.Size = uint32(unsafe.Sizeof(me))
	seen := make(map[string]struct{}, 16)
	dirs := make([]string, 0, 16)
	for err = windows.Module32First(snap, &me); err == nil; {
		if md := moduleDirOf(rules.NormalizePath(windows.UTF16ToString(me.ExePath[:]))); md != "" {
			if _, dup := seen[md]; !dup {
				seen[md] = struct{}{}
				dirs = append(dirs, md)
			}
		}
		me.Size = uint32(unsafe.Sizeof(me))
		err = windows.Module32Next(snap, &me)
	}
	return dirs, nil
}

var (
	modCrypt32                  = windows.NewLazySystemDLL("crypt32.dll")
	procCryptQueryObject        = modCrypt32.NewProc("CryptQueryObject")
	procCryptMsgGetParam        = modCrypt32.NewProc("CryptMsgGetParam")
	procCryptMsgClose           = modCrypt32.NewProc("CryptMsgClose")
	procCertGetNameStringW      = modCrypt32.NewProc("CertGetNameStringW")
	modVersion                  = windows.NewLazySystemDLL("version.dll")
	procGetFileVersionInfoSizeW = modVersion.NewProc("GetFileVersionInfoSizeW")
	procGetFileVersionInfoW     = modVersion.NewProc("GetFileVersionInfoW")
	procVerQueryValueW          = modVersion.NewProc("VerQueryValueW")
)

const (
	certQueryObjectFile                  = 1
	certQueryContentFlagPKCS7SignedEmbed = 1 << 10
	certQueryFormatFlagBinary            = 1 << 1
	cmsgSignerInfoParam                  = 6
	certNameSimpleDisplayType            = 4
	processCommandLineInformation        = 60
	maxCommandLineBufferBytes            = 128 * 1024
)

// cmsgSignerInfoHead matches the leading fields of WinCrypt CMSG_SIGNER_INFO.
type cmsgSignerInfoHead struct {
	Version      uint32
	Issuer       windows.CertNameBlob
	SerialNumber windows.CryptIntegerBlob
}

// readAuthenticodeSigner reads the embedded PKCS#7 signer's display name and
// the SHA-256 thumbprint of the signer certificate's raw DER bytes directly
// from the PE file without network revocation checks.
func readAuthenticodeSigner(path string) (signer, thumbprint string) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", ""
	}
	var encoding, contentType, formatType uint32
	var hStore windows.Handle
	var hMsg uintptr
	r1, _, _ := procCryptQueryObject.Call(
		certQueryObjectFile,
		uintptr(unsafe.Pointer(pathPtr)),
		certQueryContentFlagPKCS7SignedEmbed,
		certQueryFormatFlagBinary,
		0,
		uintptr(unsafe.Pointer(&encoding)),
		uintptr(unsafe.Pointer(&contentType)),
		uintptr(unsafe.Pointer(&formatType)),
		uintptr(unsafe.Pointer(&hStore)),
		uintptr(unsafe.Pointer(&hMsg)),
		0,
	)
	if r1 == 0 {
		return "", ""
	}
	if hStore != 0 {
		defer windows.CertCloseStore(hStore, 0)
	}
	if hMsg != 0 {
		defer procCryptMsgClose.Call(hMsg)
	}
	if hStore == 0 || hMsg == 0 {
		return "", ""
	}

	var siSize uint32
	r1, _, _ = procCryptMsgGetParam.Call(
		hMsg,
		cmsgSignerInfoParam,
		0,
		0,
		uintptr(unsafe.Pointer(&siSize)),
	)
	if r1 == 0 || siSize < uint32(unsafe.Sizeof(cmsgSignerInfoHead{})) || siSize > 1<<20 {
		return "", ""
	}
	buf := make([]byte, siSize)
	r1, _, _ = procCryptMsgGetParam.Call(
		hMsg,
		cmsgSignerInfoParam,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&siSize)),
	)
	if r1 == 0 {
		return "", ""
	}
	si := (*cmsgSignerInfoHead)(unsafe.Pointer(&buf[0]))
	wantIssuer := blobBytes(si.Issuer.Data, si.Issuer.Size)
	wantSerial := blobBytes(si.SerialNumber.Data, si.SerialNumber.Size)
	if len(wantIssuer) == 0 || len(wantSerial) == 0 {
		return "", ""
	}
	var certCtx *windows.CertContext
	for {
		next, err := windows.CertEnumCertificatesInStore(hStore, certCtx)
		if err != nil || next == nil {
			certCtx = nil
			break
		}
		certCtx = next
		if certCtx.CertInfo == nil {
			continue
		}
		gotIssuer := blobBytes(certCtx.CertInfo.Issuer.Data, certCtx.CertInfo.Issuer.Size)
		gotSerial := blobBytes(certCtx.CertInfo.SerialNumber.Data, certCtx.CertInfo.SerialNumber.Size)
		if bytes.Equal(gotIssuer, wantIssuer) && bytes.Equal(gotSerial, wantSerial) {
			break
		}
	}
	if certCtx == nil {
		return "", ""
	}
	defer windows.CertFreeCertificateContext(certCtx)

	if der := blobBytes(certCtx.EncodedCert, certCtx.Length); len(der) > 0 {
		sum := sha256.Sum256(der)
		thumbprint = hex.EncodeToString(sum[:])
	}

	var nameBuf [256]uint16
	n, _, _ := procCertGetNameStringW.Call(
		uintptr(unsafe.Pointer(certCtx)),
		certNameSimpleDisplayType,
		0,
		0,
		uintptr(unsafe.Pointer(&nameBuf[0])),
		uintptr(len(nameBuf)),
	)
	if n <= 1 {
		return "", ""
	}
	return strings.TrimSpace(windows.UTF16ToString(nameBuf[:min(int(n), len(nameBuf))])), thumbprint
}

func blobBytes(data *byte, size uint32) []byte {
	if data == nil || size == 0 || size > 64*1024 {
		return nil
	}
	return unsafe.Slice(data, size)
}

// readVersionStrings extracts CompanyName, ProductName and FileDescription
// from a PE file's VS_VERSION_INFO resource.
func readVersionStrings(path string) (company, product, desc string) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", "", ""
	}
	var handle uint32
	size, _, _ := procGetFileVersionInfoSizeW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&handle)),
	)
	if size == 0 || size > 4<<20 {
		return "", "", ""
	}
	buf := make([]byte, size)
	r1, _, _ := procGetFileVersionInfoW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		0,
		size,
		uintptr(unsafe.Pointer(&buf[0])),
	)
	if r1 == 0 {
		return "", "", ""
	}

	prefixes := []string{"040904b0", "040904e4"}
	if transPtr, transLen, ok := verQuery(buf, `\VarFileInfo\Translation`); ok && transLen >= 4 {
		var fromTable []string
		for off := uintptr(0); off+4 <= uintptr(transLen) && len(fromTable) < 16; off += 4 {
			lang := *(*uint16)(unsafe.Add(transPtr, off))
			cp := *(*uint16)(unsafe.Add(transPtr, off+2))
			fromTable = append(fromTable, fmt.Sprintf("%04x%04x", lang, cp))
		}
		prefixes = append(fromTable, prefixes...)
	}

	queryField := func(field string) string {
		for _, pfx := range prefixes {
			if ptr, n, ok := verQuery(buf, `\StringFileInfo\`+pfx+`\`+field); ok && n > 0 {
				s := strings.TrimSpace(windows.UTF16ToString(unsafe.Slice((*uint16)(ptr), n)))
				if s != "" {
					return s
				}
			}
		}
		return ""
	}
	return queryField("CompanyName"), queryField("ProductName"), queryField("FileDescription")
}

func verQuery(buf []byte, subBlock string) (unsafe.Pointer, uint32, bool) {
	subPtr, err := windows.UTF16PtrFromString(subBlock)
	if err != nil {
		return nil, 0, false
	}
	var ptr unsafe.Pointer
	var length uint32
	r1, _, _ := procVerQueryValueW.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(subPtr)),
		uintptr(unsafe.Pointer(&ptr)),
		uintptr(unsafe.Pointer(&length)),
	)
	if r1 == 0 || ptr == nil || length == 0 {
		return nil, 0, false
	}
	return ptr, length, true
}

// queryCommandLineErr queries ProcessCommandLineInformation using the canonical
// two-step size probe (required on Windows Server builds where an oversized or
// static buffer fails with STATUS_INFO_LENGTH_MISMATCH). When started > 0, it
// verifies the process creation time matches started to guard against PID reuse.
func queryCommandLineErr(pid uint32, started int64) (string, error) {
	if pid <= 4 {
		return "", fmt.Errorf("system pid %d", pid)
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(h)

	if started != 0 {
		var create, exit, kernel, user windows.Filetime
		if err := windows.GetProcessTimes(h, &create, &exit, &kernel, &user); err == nil {
			if ct := create.Nanoseconds(); ct != 0 && ct != started {
				return "", fmt.Errorf("pid %d reused (created=%d want=%d)", pid, ct, started)
			}
		}
	}

	const headerSize = uint32(unsafe.Sizeof(windows.NTUnicodeString{}))
	var retLen uint32
	err = windows.NtQueryInformationProcess(h, processCommandLineInformation, nil, 0, &retLen)
	if retLen < headerSize || retLen > maxCommandLineBufferBytes {
		return "", fmt.Errorf("size probe: err=%v retLen=%d", err, retLen)
	}

	// Retry up to 2 times in case the required length grew slightly between calls.
	var buf []byte
	for attempt := 0; attempt < 2; attempt++ {
		if retLen < headerSize || retLen > maxCommandLineBufferBytes {
			return "", fmt.Errorf("invalid retLen=%d", retLen)
		}
		words := make([]uint64, (retLen+7)/8)
		buf = unsafe.Slice((*byte)(unsafe.Pointer(&words[0])), len(words)*8)
		var outLen uint32
		err = windows.NtQueryInformationProcess(
			h,
			processCommandLineInformation,
			unsafe.Pointer(&buf[0]),
			retLen,
			&outLen,
		)
		if err == nil {
			break
		}
		if outLen > retLen && outLen <= maxCommandLineBufferBytes {
			retLen = outLen
			continue
		}
		return "", fmt.Errorf("query(len=%d): err=%v outLen=%d", retLen, err, outLen)
	}
	if err != nil {
		return "", fmt.Errorf("query retry failed: %v", err)
	}

	us := (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0]))
	if us.Length == 0 || us.Buffer == nil {
		return "", fmt.Errorf("empty UNICODE_STRING (len=%d max=%d buf=%v)", us.Length, us.MaximumLength, us.Buffer)
	}
	base := uintptr(unsafe.Pointer(&buf[0]))
	end := base + uintptr(len(buf))
	ptr := uintptr(unsafe.Pointer(us.Buffer))
	byteLen := uintptr(us.Length)
	if ptr < base || ptr > end || byteLen > end-ptr {
		return "", fmt.Errorf("out-of-bounds buffer ptr=%x range=[%x,%x) len=%d", ptr, base, end, byteLen)
	}
	return strings.TrimSpace(windows.UTF16ToString(unsafe.Slice((*uint16)(us.Buffer), us.Length/2))), nil
}
