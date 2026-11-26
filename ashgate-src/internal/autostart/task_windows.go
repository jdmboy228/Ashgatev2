//go:build windows

package autostart

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"

	"ashgate/internal/config"
	"golang.org/x/sys/windows"
)

var (
	kernel32                = windows.NewLazySystemDLL("kernel32.dll")
	procMultiByteToWideChar = kernel32.NewProc("MultiByteToWideChar")
)

const taskName = `\Ashgate`

// Enabled reports whether the logon task that opens the Ashgate window exists.
func Enabled() (bool, error) {
	cmd := exec.Command(schtasks(), "/Query", "/TN", taskName)
	cmd.SysProcAttr = noWindow()
	if err := cmd.Run(); err != nil {
		return false, nil
	}
	return true, nil
}

// Enable registers a logon task for the current user. It runs the GUI elevated
// and interactive, with no execution time limit, including on battery.
func Enable(exe, configPath string) error {
	if exe == "" {
		return fmt.Errorf("не найден ashgate.exe")
	}
	u, err := user.Current()
	if err != nil || u.Username == "" {
		return fmt.Errorf("не удалось определить текущего пользователя")
	}
	xml := taskXML(u.Username, exe, configPath)
	// The task runs elevated at every logon. In %TEMP% another program of
	// the user could swap the file before schtasks reads it; standard
	// users cannot write to the protected folder.
	dir, err := config.ProtectedDir()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "autostart-task.xml")
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(path)
	if _, err := f.Write(encodeUTF16(xml)); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	cmd := exec.Command(schtasks(), "/Create", "/TN", taskName, "/XML", path, "/F")
	cmd.SysProcAttr = noWindow()
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(decodeConsole(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("не удалось записать задачу автозапуска: %s", msg)
	}
	return nil
}

// Disable removes the logon task. A missing task is not an error.
func Disable() error {
	if on, _ := Enabled(); !on {
		return nil
	}
	cmd := exec.Command(schtasks(), "/Delete", "/TN", taskName, "/F")
	cmd.SysProcAttr = noWindow()
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	decoded := decodeConsole(out)
	msg := strings.ToLower(decoded)
	if strings.Contains(msg, "cannot find") || strings.Contains(msg, "не удается найти") || strings.Contains(msg, "не удаётся найти") {
		return nil
	}
	text := strings.TrimSpace(decoded)
	if text == "" {
		text = err.Error()
	}
	return fmt.Errorf("не удалось удалить задачу автозапуска: %s", text)
}

func taskXML(userID, exe, configPath string) string {
	args := "--autostart"
	if configPath != "" {
		args += " -config " + quoteArg(configPath)
	}
	return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Ashgate</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>` + xmlEscape(userID) + `</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>` + xmlEscape(userID) + `</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>` + xmlEscape(exe) + `</Command>
      <Arguments>` + xmlEscape(args) + `</Arguments>
    </Exec>
  </Actions>
</Task>
`
}

func quoteArg(s string) string {
	if s == "" {
		return `""`
	}
	if !strings.ContainsAny(s, " \t\"") {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	slashes := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			slashes++
		case '"':
			b.WriteString(strings.Repeat(`\`, slashes*2+1))
			b.WriteByte('"')
			slashes = 0
		default:
			if slashes > 0 {
				b.WriteString(strings.Repeat(`\`, slashes))
				slashes = 0
			}
			b.WriteByte(s[i])
		}
	}
	if slashes > 0 {
		b.WriteString(strings.Repeat(`\`, slashes*2))
	}
	b.WriteByte('"')
	return b.String()
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}

func encodeUTF16(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2+len(u)*2)
	b[0], b[1] = 0xFF, 0xFE
	for i, r := range u {
		binary.LittleEndian.PutUint16(b[2+i*2:], r)
	}
	return b
}

// schtasks is the absolute path of schtasks.exe. This process is elevated,
// so it must not pick up a schtasks.exe from a directory on PATH or an
// untrusted SystemRoot environment variable.
func schtasks() string {
	dir, err := windows.GetSystemDirectory()
	if err != nil || dir == "" {
		dir = `C:\Windows\System32`
	}
	return filepath.Join(dir, "schtasks.exe")
}

// decodeConsole converts OEM codepage output (e.g. Russian CP866) to UTF-8.
func decodeConsole(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if utf8.Valid(b) {
		return string(b)
	}
	const cpOEM = 1
	n, _, _ := procMultiByteToWideChar.Call(
		cpOEM, 0,
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)),
		0, 0,
	)
	if n == 0 {
		runtime.KeepAlive(b)
		return string(b)
	}
	w := make([]uint16, n)
	m, _, _ := procMultiByteToWideChar.Call(
		cpOEM, 0,
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)),
		uintptr(unsafe.Pointer(&w[0])), n,
	)
	runtime.KeepAlive(b)
	if m == 0 {
		return string(b)
	}
	s := windows.UTF16ToString(w[:m])
	runtime.KeepAlive(w)
	return s
}

func noWindow() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}
