//go:build e2e

// Package stream makes the deterministic byte streams the e2e target
// server sends and the test client checks: the same seed always gives the
// same bytes, so both sides can hash them without sending a checksum.
package stream

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math/rand/v2"
)

// Reader returns n bytes generated from seed.
func Reader(seed string, n int64) io.Reader {
	return io.LimitReader(rand.NewChaCha8(sha256.Sum256([]byte(seed))), n)
}

// Sum is the SHA-256 (hex) of Reader(seed, n).
func Sum(seed string, n int64) string {
	h := sha256.New()
	_, _ = io.Copy(h, Reader(seed, n))
	return hex.EncodeToString(h.Sum(nil))
}
