//go:build windows && e2e

// Package e2e is the Windows end-to-end suite. Each Test* is one job of
// .github/workflows/windows-e2e.yml and drives the Ashgate that the job
// installed from Setup.exe. Build with: go test -c -tags e2e ./e2e
package e2e

import (
	"fmt"
	"os"
	"testing"

	"ashgate/e2e/harness"
)

func TestMain(m *testing.M) {
	_ = harness.EnableWERDumps()
	code := m.Run()
	// Never leave the CI-only debugging policy or a running app behind.
	if err := harness.SetDebugPolicy(false); err != nil {
		fmt.Fprintln(os.Stderr, "debug policy:", err)
	}
	pf := os.Getenv("ProgramFiles")
	harness.EnsureQuit(pf + `\Ashgate\ashgate.exe`)
	os.Exit(code)
}
