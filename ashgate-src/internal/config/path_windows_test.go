//go:build windows

package config

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// config.json keeps proxy passwords and VLESS keys in plain text: the
// shared folder must not let Users, Everyone or Authenticated Users read it.
func TestSharedDirIsNotReadableByEveryone(t *testing.T) {
	sddl := sharedDirSDDL + ownerReadACE()
	for _, group := range []string{";;;BU)", ";;;WD)", ";;;AU)", ";;;IU)"} {
		if strings.Contains(sddl, group) {
			t.Errorf("shared folder SDDL grants %s: %s", strings.Trim(group, ";)"), sddl)
		}
	}
	if ownerReadACE() == "" {
		t.Fatal("no entry for the current user")
	}
	if _, err := windows.SecurityDescriptorFromString(sddl); err != nil {
		t.Fatalf("SDDL %s: %v", sddl, err)
	}
}
