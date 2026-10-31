// Package secret seals small values at rest. On Windows it uses DPAPI in
// the user's scope: only the same Windows account can open them.
package secret

import (
	"encoding/base64"
	"errors"
	"strings"
)

// entropy ties sealed values to Ashgate: another program running as the
// same user must also know it to open them through DPAPI.
var entropy = []byte("ashgate/subscription/v1")

// Seal returns plain encrypted for this user, as text for config.json.
func Seal(plain []byte) (string, error) {
	out, err := protect(plain)
	if err != nil {
		return "", err
	}
	return prefix + base64.StdEncoding.EncodeToString(out), nil
}

// Open reverses Seal.
func Open(sealed string) ([]byte, error) {
	rest, ok := strings.CutPrefix(sealed, prefix)
	if !ok {
		return nil, errors.New("секрет сохранён в другом формате")
	}
	raw, err := base64.StdEncoding.DecodeString(rest)
	if err != nil {
		return nil, errors.New("секрет повреждён")
	}
	return unprotect(raw)
}
