package atomicfile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteReplacesAndDropsLeftoverTemp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	// A planted temp file must not survive into the result.
	if err := os.WriteFile(path+".tmp", []byte("planted"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("two")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "two" {
		t.Fatalf("%q %v", got, err)
	}
	if leftover, err := filepath.Glob(path + ".*.tmp"); err != nil || len(leftover) != 0 {
		t.Fatalf("temp files left: %v %v", leftover, err)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", st.Mode().Perm())
		}
	}
}
