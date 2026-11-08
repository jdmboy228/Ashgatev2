// Package atomicfile replaces small state files in one step.
package atomicfile

import (
	"errors"
	"os"
)

// Write replaces path with data, mode 0600, through path+".tmp". A
// leftover or planted temp file would keep its own owner and access list
// through the rename, so it is removed first and the new one must not
// exist when it is created.
func Write(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}
