//go:build windows

package autostart

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf16"
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
	f, err := os.CreateTemp("", "ashgate-task-*.xml")
	if err != nil {
		return err
	}
	path := f.Name()
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
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("не удалось записать задачу автозапуска: %s", msg)
	}
	return nil
}

// Disable removes the logon task. A missing task is not an error.
func Disable() error {
	cmd := exec.Command(schtasks(), "/Delete", "/TN", taskName, "/F")
	cmd.SysProcAttr = noWindow()
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	msg := strings.ToLower(string(out))
	if strings.Contains(msg, "cannot find") || strings.Contains(msg, "не удается найти") || strings.Contains(msg, "не удаётся найти") {
		return nil
	}
	text := strings.TrimSpace(string(out))
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
// so it must not pick up a schtasks.exe from a directory on PATH.
func schtasks() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "schtasks.exe")
}

func noWindow() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}
