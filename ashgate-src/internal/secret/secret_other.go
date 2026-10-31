//go:build !windows

package secret

// Outside Windows there is no DPAPI. Ashgate only runs on Windows; this
// form exists for tests and is marked so it is never mistaken for sealed.
const prefix = "plain:"

func protect(plain []byte) ([]byte, error) { return append([]byte(nil), plain...), nil }

func unprotect(sealed []byte) ([]byte, error) { return append([]byte(nil), sealed...), nil }
