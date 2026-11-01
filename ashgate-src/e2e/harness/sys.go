//go:build windows && e2e

package harness

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	psapi    = windows.NewLazySystemDLL("psapi.dll")
	iphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	pIsIconic              = user32.NewProc("IsIconic")
	pGetWindowRect         = user32.NewProc("GetWindowRect")
	pSetWindowPos          = user32.NewProc("SetWindowPos")
	pPostMessage           = user32.NewProc("PostMessageW")
	pGetWindowText         = user32.NewProc("GetWindowTextW")
	pGetProcessHandleCount = kernel32.NewProc("GetProcessHandleCount")
	pGetProcessMemoryInfo  = psapi.NewProc("GetProcessMemoryInfo")
	pGetExtendedTcpTable   = iphlpapi.NewProc("GetExtendedTcpTable")
	pGetExtendedUdpTable   = iphlpapi.NewProc("GetExtendedUdpTable")
)

// cmdTimeout bounds every helper command: a hung PowerShell must fail one
// check, not eat the whole job.
const cmdTimeout = 3 * time.Minute

// PS runs a PowerShell script and returns its trimmed output.
func PS(script string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-Command", "[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ProgressPreference='SilentlyContinue'; "+script)
	out, err := cmd.CombinedOutput()
	s := strings.TrimSpace(string(out))
	if err != nil {
		return s, fmt.Errorf("powershell: %v: %s", err, s)
	}
	return s, nil
}

// Run runs a program and returns its combined output.
func Run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// Proc is one process from a Toolhelp snapshot.
type Proc struct {
	PID     uint32
	PPID    uint32
	Name    string
	Threads uint32
}

// Procs lists all processes.
func Procs() []Proc {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	var out []Proc
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		out = append(out, Proc{PID: e.ProcessID, PPID: e.ParentProcessID, Name: windows.UTF16ToString(e.ExeFile[:]), Threads: e.Threads})
	}
	return out
}

// PIDsByName lists processes with that image name.
func PIDsByName(name string) []uint32 {
	var out []uint32
	for _, p := range Procs() {
		if strings.EqualFold(p.Name, name) {
			out = append(out, p.PID)
		}
	}
	return out
}

// Descendants lists every process below pid.
func Descendants(pid uint32) []Proc {
	all := Procs()
	var out []Proc
	parents := map[uint32]bool{pid: true}
	for changed := true; changed; {
		changed = false
		for _, p := range all {
			if parents[p.PPID] && !parents[p.PID] && p.PID != pid {
				parents[p.PID] = true
				out = append(out, p)
				changed = true
			}
		}
	}
	return out
}

// Alive reports whether pid still runs.
func Alive(pid uint32) bool {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	ev, _ := windows.WaitForSingleObject(h, 0)
	return ev == uint32(windows.WAIT_TIMEOUT)
}

// ImagePath is the full exe path of pid.
func ImagePath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

// Usage is one sample of a process's resources.
type Usage struct {
	CPU        time.Duration // user + kernel
	WorkingSet uint64
	Private    uint64
	Handles    uint32
	Threads    uint32
}

type memCounters struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
	PrivateUsage               uintptr
}

// Sample reads CPU time, memory and handle counts of pid.
func Sample(pid uint32) (Usage, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return Usage{}, err
	}
	defer windows.CloseHandle(h)
	var u Usage
	var c, x, k, us windows.Filetime
	if err := windows.GetProcessTimes(h, &c, &x, &k, &us); err != nil {
		return u, err
	}
	ft := func(f windows.Filetime) time.Duration {
		return time.Duration((uint64(f.HighDateTime)<<32 | uint64(f.LowDateTime)) * 100)
	}
	u.CPU = ft(k) + ft(us)
	var m memCounters
	m.CB = uint32(unsafe.Sizeof(m))
	if r, _, e := pGetProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&m)), uintptr(m.CB)); r == 0 {
		return u, e
	}
	u.WorkingSet, u.Private = uint64(m.WorkingSetSize), uint64(m.PrivateUsage)
	var hc uint32
	pGetProcessHandleCount.Call(uintptr(h), uintptr(unsafe.Pointer(&hc)))
	u.Handles = hc
	for _, p := range Procs() {
		if p.PID == pid {
			u.Threads = p.Threads
		}
	}
	return u, nil
}

// Window is one top-level window.
type Window struct {
	HWND    windows.HWND
	PID     uint32
	Class   string
	Title   string
	Visible bool
	Iconic  bool
	Rect    [4]int32
}

var (
	enumMu   sync.Mutex
	enumPID  uint32
	enumOut  []Window
	enumProc = syscall.NewCallback(func(h windows.HWND, _ uintptr) uintptr {
		var p uint32
		_, _ = windows.GetWindowThreadProcessId(h, &p)
		if enumPID != 0 && p != enumPID {
			return 1
		}
		w := Window{HWND: h, PID: p, Visible: windows.IsWindowVisible(h)}
		cls := make([]uint16, 256)
		if n, err := windows.GetClassName(h, &cls[0], int32(len(cls))); err == nil {
			w.Class = windows.UTF16ToString(cls[:n])
		}
		title := make([]uint16, 512)
		n, _, _ := pGetWindowText.Call(uintptr(h), uintptr(unsafe.Pointer(&title[0])), uintptr(len(title)))
		w.Title = windows.UTF16ToString(title[:n])
		r, _, _ := pIsIconic.Call(uintptr(h))
		w.Iconic = r != 0
		pGetWindowRect.Call(uintptr(h), uintptr(unsafe.Pointer(&w.Rect)))
		enumOut = append(enumOut, w)
		return 1
	})
)

// Windows lists the top-level windows of pid (all pids when pid is 0).
// One callback serves every call: Go allows only a limited number of
// syscall.NewCallback per process.
func Windows(pid uint32) []Window {
	enumMu.Lock()
	defer enumMu.Unlock()
	enumPID, enumOut = pid, nil
	_ = windows.EnumWindows(enumProc, nil)
	out := enumOut
	enumOut = nil
	return out
}

// MainWindow is the visible "Ashgate" window of pid, if any.
func MainWindow(pid uint32) (Window, bool) {
	for _, w := range Windows(pid) {
		if w.Visible && w.Title == "Ashgate" {
			return w, true
		}
	}
	return Window{}, false
}

// Resize moves and sizes a window (physical pixels).
func Resize(h windows.HWND, x, y, w, hgt int) {
	const swpNoZOrder = 0x0004
	pSetWindowPos.Call(uintptr(h), 0, uintptr(x), uintptr(y), uintptr(w), uintptr(hgt), swpNoZOrder)
}

// PostMessage posts msg to a window.
func PostMessage(h windows.HWND, msg uint32, wp, lp uintptr) {
	pPostMessage.Call(uintptr(h), uintptr(msg), wp, lp)
}

// Screenshot saves the whole desktop as a PNG.
func Screenshot(path string) error {
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	script := `Add-Type -AssemblyName System.Windows.Forms,System.Drawing;` +
		`$b=[System.Windows.Forms.SystemInformation]::VirtualScreen;` +
		`$bmp=New-Object System.Drawing.Bitmap $b.Width,$b.Height;` +
		`$g=[System.Drawing.Graphics]::FromImage($bmp);` +
		`$g.CopyFromScreen($b.Left,$b.Top,0,0,$bmp.Size);` +
		`$bmp.Save('` + strings.ReplaceAll(path, "'", "''") + `',[System.Drawing.Imaging.ImageFormat]::Png)`
	_, err := PS(script)
	return err
}

// Sock is one TCP or UDP socket with its owner.
type Sock struct {
	Proto  string // "tcp" or "udp"
	Local  net.IP
	LPort  int
	Remote net.IP
	RPort  int
	State  int // MIB_TCP_STATE; 2 = LISTEN, 5 = ESTABLISHED
	PID    uint32
}

// TCPListen is MIB_TCP_STATE_LISTEN.
const TCPListen = 2

func readTable(proc *windows.LazyProc, af, class uintptr) ([]byte, error) {
	var size uint32
	proc.Call(0, uintptr(unsafe.Pointer(&size)), 0, af, class, 0)
	for i := 0; i < 5; i++ {
		buf := make([]byte, size+4096)
		size = uint32(len(buf))
		r, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, af, class, 0)
		if r == 0 {
			return buf[:size], nil
		}
		if r != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			return nil, syscall.Errno(r)
		}
	}
	return nil, errors.New("ip helper table keeps growing")
}

func port(b []byte) int { return int(b[0])<<8 | int(b[1]) }

// Sockets lists every TCP and UDP socket with its owning process.
func Sockets() []Sock {
	var out []Sock
	const ownerPIDAll = 5 // TCP_TABLE_OWNER_PID_ALL
	if b, err := readTable(pGetExtendedTcpTable, windows.AF_INET, ownerPIDAll); err == nil && len(b) >= 4 {
		n := int(binary.LittleEndian.Uint32(b))
		for i := 0; i < n && 4+(i+1)*24 <= len(b); i++ {
			r := b[4+i*24:]
			out = append(out, Sock{Proto: "tcp", State: int(binary.LittleEndian.Uint32(r)),
				Local: net.IP(append([]byte(nil), r[4:8]...)), LPort: port(r[8:]),
				Remote: net.IP(append([]byte(nil), r[12:16]...)), RPort: port(r[16:]),
				PID: binary.LittleEndian.Uint32(r[20:])})
		}
	}
	if b, err := readTable(pGetExtendedTcpTable, windows.AF_INET6, ownerPIDAll); err == nil && len(b) >= 4 {
		n := int(binary.LittleEndian.Uint32(b))
		const sz = 56
		for i := 0; i < n && 4+(i+1)*sz <= len(b); i++ {
			r := b[4+i*sz:]
			out = append(out, Sock{Proto: "tcp",
				Local: net.IP(append([]byte(nil), r[0:16]...)), LPort: port(r[20:]),
				Remote: net.IP(append([]byte(nil), r[24:40]...)), RPort: port(r[44:]),
				State: int(binary.LittleEndian.Uint32(r[48:])), PID: binary.LittleEndian.Uint32(r[52:])})
		}
	}
	const udpOwnerPID = 1 // UDP_TABLE_OWNER_PID
	if b, err := readTable(pGetExtendedUdpTable, windows.AF_INET, udpOwnerPID); err == nil && len(b) >= 4 {
		n := int(binary.LittleEndian.Uint32(b))
		for i := 0; i < n && 4+(i+1)*12 <= len(b); i++ {
			r := b[4+i*12:]
			out = append(out, Sock{Proto: "udp", Local: net.IP(append([]byte(nil), r[0:4]...)),
				LPort: port(r[4:]), PID: binary.LittleEndian.Uint32(r[8:])})
		}
	}
	if b, err := readTable(pGetExtendedUdpTable, windows.AF_INET6, udpOwnerPID); err == nil && len(b) >= 4 {
		n := int(binary.LittleEndian.Uint32(b))
		const sz = 28
		for i := 0; i < n && 4+(i+1)*sz <= len(b); i++ {
			r := b[4+i*sz:]
			out = append(out, Sock{Proto: "udp", Local: net.IP(append([]byte(nil), r[0:16]...)),
				LPort: port(r[20:]), PID: binary.LittleEndian.Uint32(r[24:])})
		}
	}
	return out
}

// SocketsOf filters Sockets by owner.
func SocketsOf(pids ...uint32) []Sock {
	want := map[uint32]bool{}
	for _, p := range pids {
		want[p] = true
	}
	var out []Sock
	for _, s := range Sockets() {
		if want[s.PID] {
			out = append(out, s)
		}
	}
	return out
}

// OwnerOf finds the process whose TCP socket has local address local and
// peer remote: the other end of a connection a server accepted.
func OwnerOf(local, remote *net.TCPAddr) uint32 {
	for _, s := range Sockets() {
		if s.Proto != "tcp" || s.LPort != local.Port || s.RPort != remote.Port {
			continue
		}
		if s.Local.Equal(local.IP) || (s.Local.IsUnspecified()) {
			return s.PID
		}
	}
	return 0
}

// PortFree reports whether a TCP port can be bound on loopback.
func PortFree(network, addr string) bool {
	if strings.HasPrefix(network, "udp") {
		c, err := net.ListenPacket(network, addr)
		if err != nil {
			return false
		}
		c.Close()
		return true
	}
	l, err := net.Listen(network, addr)
	if err != nil {
		return false
	}
	l.Close()
	return true
}

// ServiceState is the state of a Windows service, or "" when it does not exist.
func ServiceState(name string) string {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return "?"
	}
	defer windows.CloseServiceHandle(m)
	n, _ := windows.UTF16PtrFromString(name)
	s, err := windows.OpenService(m, n, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return ""
	}
	defer windows.CloseServiceHandle(s)
	var st windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(s, &st); err != nil {
		return "?"
	}
	switch st.CurrentState {
	case windows.SERVICE_RUNNING:
		return "RUNNING"
	case windows.SERVICE_STOPPED:
		return "STOPPED"
	case windows.SERVICE_STOP_PENDING:
		return "STOP_PENDING"
	case windows.SERVICE_START_PENDING:
		return "START_PENDING"
	}
	return fmt.Sprint(st.CurrentState)
}

// DriverLoaded reports whether `driverquery` lists the driver as running.
func DriverLoaded(name string) bool {
	out, err := PS(`(Get-CimInstance Win32_SystemDriver -Filter "Name='` + name + `'" | Select-Object -ExpandProperty State)`)
	return err == nil && strings.EqualFold(strings.TrimSpace(out), "Running")
}

// FirewallRule is one Windows Firewall rule with its program filter.
type FirewallRule struct {
	Name      string `json:"name"`
	Direction string `json:"direction"`
	Action    string `json:"action"`
	Enabled   string `json:"enabled"`
	Program   string `json:"program"`
}

// FirewallRules lists rules with that display name.
func FirewallRules(display string) ([]FirewallRule, error) {
	out, err := PS(`$r = @(Get-NetFirewallRule -DisplayName '` + display + `' -ErrorAction SilentlyContinue | ForEach-Object {` +
		` $p = ($_ | Get-NetFirewallApplicationFilter).Program;` +
		` [pscustomobject]@{name=$_.DisplayName; direction="$($_.Direction)"; action="$($_.Action)"; enabled="$($_.Enabled)"; program=$p} });` +
		` ConvertTo-Json -InputObject $r -Compress`)
	if err != nil {
		return nil, err
	}
	var rules []FirewallRule
	if out == "" || out == "null" {
		return nil, nil
	}
	if err := json.Unmarshal([]byte(out), &rules); err != nil {
		return nil, fmt.Errorf("firewall json: %v: %s", err, out)
	}
	return rules, nil
}

// TaskXML exports a scheduled task, or "" when it does not exist.
func TaskXML(name string) string {
	out, err := PS(`Export-ScheduledTask -TaskName '` + name + `' -ErrorAction Stop`)
	if err != nil {
		return ""
	}
	return out
}

// Manifest reads the RT_MANIFEST resource of an exe.
func Manifest(exe string) (string, error) {
	const asData = 0x00000002 | 0x00000020 // LOAD_LIBRARY_AS_DATAFILE | AS_IMAGE_RESOURCE
	h, err := windows.LoadLibraryEx(exe, 0, asData)
	if err != nil {
		return "", err
	}
	defer windows.FreeLibrary(h)
	res, err := windows.FindResource(h, windows.ResourceID(1), windows.RT_MANIFEST)
	if err != nil {
		return "", err
	}
	b, err := windows.LoadResourceData(h, res)
	if err != nil {
		return "", err
	}
	return string(bytes.Clone(b)), nil
}

// FileVersion reads the version resource of a file, "" when it has none.
func FileVersion(path string) string {
	out, _ := PS(`(Get-Item -LiteralPath '` + strings.ReplaceAll(path, "'", "''") + `').VersionInfo.FileVersion`)
	return strings.TrimSpace(out)
}

// NIC is the runner's main network adapter.
type NIC struct {
	Index int    `json:"ifIndex"`
	Name  string `json:"name"`
	IPv4  string `json:"ipv4"`
	DNS   []string
}

// MainNIC finds the adapter with the default route.
func MainNIC() (NIC, error) {
	out, err := PS(`$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1;` +
		`$a = Get-NetAdapter -InterfaceIndex $r.ifIndex;` +
		`$ip = (Get-NetIPAddress -InterfaceIndex $r.ifIndex -AddressFamily IPv4 | Select-Object -First 1).IPAddress;` +
		`$dns = @((Get-DnsClientServerAddress -InterfaceIndex $r.ifIndex -AddressFamily IPv4).ServerAddresses);` +
		`ConvertTo-Json -Compress @{ifIndex=$r.ifIndex; name=$a.Name; ipv4=$ip; DNS=$dns}`)
	if err != nil {
		return NIC{}, err
	}
	var n NIC
	err = json.Unmarshal([]byte(out), &n)
	return n, err
}
