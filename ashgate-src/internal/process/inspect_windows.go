//go:build windows

package process

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// FileMeta holds static metadata extracted offline from a Windows executable.
// Used exclusively to rank companion suggestions in the UI — never for
// automatic proxying and never called on the packet hot path.
type FileMeta struct {
	Signer      string
	Company     string
	Product     string
	Description string
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

// Inspector caches offline PE metadata (Authenticode signer and version info)
// and running process command lines for companion candidate scoring.
type Inspector struct {
	mu    sync.Mutex
	files map[string]metaCacheEntry
	cmds  map[cmdCacheKey]cmdCacheEntry
}

// NewInspector creates a reusable metadata inspector with bounded in-memory caches.
func NewInspector() *Inspector {
	return &Inspector{
		files: make(map[string]metaCacheEntry),
		cmds:  make(map[cmdCacheKey]cmdCacheEntry),
	}
}

const (
	maxMetaCacheEntries = 512
	maxCmdCacheEntries  = 512
	cmdCacheTTL         = 30 * time.Second
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

	meta := FileMeta{
		Signer: readAuthenticodeSigner(path),
	}
	meta.Company, meta.Product, meta.Description = readVersionStrings(path)

	ins.mu.Lock()
	if len(ins.files) >= maxMetaCacheEntries {
		clear(ins.files)
	}
	ins.files[key] = metaCacheEntry{modTime: modTime, size: size, meta: meta}
	ins.mu.Unlock()
	return meta
}

// CommandLine returns the command line of a running process using only
// PROCESS_QUERY_LIMITED_INFORMATION (Windows 8.1+). Returns "" on failure.
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

	cmd := queryCommandLine(pid)

	ins.mu.Lock()
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
	maxCommandLineBufferBytes            = 64 * 1024
)

// cmsgSignerInfoHead matches the leading fields of WinCrypt CMSG_SIGNER_INFO.
type cmsgSignerInfoHead struct {
	Version      uint32
	Issuer       windows.CertNameBlob
	SerialNumber windows.CryptIntegerBlob
}

// readAuthenticodeSigner reads the embedded PKCS#7 signer's display name
// directly from the PE file without network revocation checks.
func readAuthenticodeSigner(path string) string {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return ""
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
		return ""
	}
	if hStore != 0 {
		defer windows.CertCloseStore(hStore, 0)
	}
	if hMsg != 0 {
		defer procCryptMsgClose.Call(hMsg)
	}
	if hStore == 0 || hMsg == 0 {
		return ""
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
		return ""
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
		return ""
	}
	si := (*cmsgSignerInfoHead)(unsafe.Pointer(&buf[0]))
	wantIssuer := blobBytes(si.Issuer.Data, si.Issuer.Size)
	wantSerial := blobBytes(si.SerialNumber.Data, si.SerialNumber.Size)
	if len(wantIssuer) == 0 || len(wantSerial) == 0 {
		return ""
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
		return ""
	}
	defer windows.CertFreeCertificateContext(certCtx)

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
		return ""
	}
	return strings.TrimSpace(windows.UTF16ToString(nameBuf[:min(int(n), len(nameBuf))]))
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
		lang := *(*uint16)(transPtr)
		cp := *(*uint16)(unsafe.Add(transPtr, 2))
		prefixes = append([]string{fmt.Sprintf("%04x%04x", lang, cp)}, prefixes...)
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

// queryCommandLine fetches a process's command line via ProcessCommandLineInformation.
func queryCommandLine(pid uint32) string {
	cmd, _ := queryCommandLineErr(pid)
	return cmd
}

// queryCommandLineErr queries ProcessCommandLineInformation using the canonical
// two-step size probe (required on Windows Server builds where an oversized or
// static buffer fails with STATUS_INFO_LENGTH_MISMATCH).
func queryCommandLineErr(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(h)

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
	if ptr < base || ptr+byteLen > end {
		return "", fmt.Errorf("out-of-bounds buffer ptr=%x range=[%x,%x) len=%d", ptr, base, end, byteLen)
	}
	return strings.TrimSpace(us.String()), nil
}
