// Package atomicfile replaces small state files in one step.
package atomicfile

import (
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// Write replaces path with data, mode 0600, through a unique temporary file
// in the same directory so concurrent writers cannot collide on a fixed temp
// name and a leftover file cannot survive the rename.
func Write(path string, data []byte) error {
	dir, base := filepath.Dir(path), filepath.Base(path)
	f, err := os.CreateTemp(dir, base+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		for i := 0; i < 5; i++ {
			err = os.Rename(tmp, path)
			if err == nil || runtime.GOOS != "windows" {
				break
			}
			time.Sleep(time.Duration(i+1) * 10 * time.Millisecond)
		}
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}
