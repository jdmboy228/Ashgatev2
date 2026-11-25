//go:build windows

package process

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

func windowsDir() string {
	if d := os.Getenv("SystemRoot"); d != "" {
		return d
	}
	return `C:\Windows`
}

var fileExists = func(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

// scanInstalled reads, in this order: Start menu shortcuts (all users and
// the current user), App Paths and the Uninstall entries' DisplayIcon.
func scanInstalled() []Installed {
	var out []Installed
	for _, env := range []string{"ProgramData", "APPDATA"} {
		if base := strings.TrimSpace(os.Getenv(env)); base != "" {
			out = append(out, scanShortcuts(filepath.Join(base, `Microsoft\Windows\Start Menu\Programs`))...)
		}
	}
	for _, root := range []registry.Key{registry.LOCAL_MACHINE, registry.CURRENT_USER} {
		out = append(out, scanAppPaths(root)...)
	}
	for _, src := range []struct {
		root registry.Key
		path string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
	} {
		out = append(out, scanUninstall(src.root, src.path)...)
	}
	return out
}

func scanShortcuts(root string) []Installed {
	var out []Installed
	if root == "" || !filepath.IsAbs(root) {
		return nil
	}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.EqualFold(filepath.Ext(path), ".lnk") {
			return nil
		}
		if info, err := d.Info(); err != nil || info.Size() > 1<<20 {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		target, err := ParseLNK(data)
		if err != nil {
			return nil
		}
		out = append(out, Installed{Name: strings.TrimSuffix(d.Name(), filepath.Ext(d.Name())), Path: target})
		return nil
	})
	return out
}

func scanAppPaths(root registry.Key) []Installed {
	k, err := registry.OpenKey(root, `SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths`, registry.ENUMERATE_SUB_KEYS|registry.READ)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, _ := k.ReadSubKeyNames(-1)
	var out []Installed
	for _, n := range names {
		sk, err := registry.OpenKey(k, n, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		v, _, err := sk.GetStringValue("")
		sk.Close()
		if err == nil && v != "" {
			out = append(out, Installed{Name: strings.TrimSuffix(n, filepath.Ext(n)), Path: v})
		}
	}
	return out
}

func scanUninstall(root registry.Key, path string) []Installed {
	k, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS|registry.READ)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, _ := k.ReadSubKeyNames(-1)
	var out []Installed
	for _, n := range names {
		sk, err := registry.OpenKey(k, n, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		name, _, _ := sk.GetStringValue("DisplayName")
		icon, _, _ := sk.GetStringValue("DisplayIcon")
		sk.Close()
		if name != "" && icon != "" {
			out = append(out, Installed{Name: name, Path: icon})
		}
	}
	return out
}
