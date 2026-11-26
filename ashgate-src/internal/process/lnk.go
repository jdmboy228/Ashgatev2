package process

import (
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"unicode/utf16"
)

// Shell link (.lnk) layout, from [MS-SHLLINK].
const (
	lnkHeaderSize   = 0x4C
	lnkHasIDList    = 0x01
	lnkHasLinkInfo  = 0x02
	lnkHasName      = 0x04
	lnkHasRelPath   = 0x08
	lnkHasWorkDir   = 0x10
	lnkHasArgs      = 0x20
	lnkHasIconLoc   = 0x40
	lnkIsUnicode    = 0x80
	lnkLocalPath    = 0x01 // LinkInfoFlags: VolumeIDAndLocalBasePath
	lnkEnvBlockSig  = 0xA0000001
	lnkEnvBlockSize = 0x314
)

var errNoTarget = errors.New("lnk: no local target path")

// ParseLNK returns the target path of a Windows shortcut. It reads the
// Unicode local path when present, then the environment-variable target
// (expanded), then an ASCII-only local path. Advertised (MSI) shortcuts and
// shell-namespace targets have none of these and return an error.
func ParseLNK(b []byte) (string, error) {
	if len(b) < lnkHeaderSize || binary.LittleEndian.Uint32(b) != lnkHeaderSize {
		return "", errors.New("lnk: bad header")
	}
	flags := binary.LittleEndian.Uint32(b[0x14:])
	off := lnkHeaderSize
	if flags&lnkHasIDList != 0 {
		if off+2 > len(b) {
			return "", errors.New("lnk: truncated id list")
		}
		off += 2 + int(binary.LittleEndian.Uint16(b[off:]))
	}
	var unicodePath, ansiPath string
	if flags&lnkHasLinkInfo != 0 {
		if off+28 > len(b) {
			return "", errors.New("lnk: truncated link info")
		}
		info := b[off:]
		size := int(binary.LittleEndian.Uint32(info))
		if size < 28 || size > len(info) {
			return "", errors.New("lnk: bad link info size")
		}
		info = info[:size]
		hdr := binary.LittleEndian.Uint32(info[4:])
		lflags := binary.LittleEndian.Uint32(info[8:])
		if lflags&lnkLocalPath != 0 {
			base := cstr(info, int(binary.LittleEndian.Uint32(info[16:])))
			suffix := cstr(info, int(binary.LittleEndian.Uint32(info[24:])))
			ansiPath = joinSuffix(base, suffix)
			if hdr >= 0x24 && len(info) >= 36 {
				ub := wstr(info, int(binary.LittleEndian.Uint32(info[28:])))
				us := wstr(info, int(binary.LittleEndian.Uint32(info[32:])))
				unicodePath = joinSuffix(ub, us)
			}
		}
		off += size
	}
	if unicodePath != "" {
		return unicodePath, nil
	}
	// Skip the string data to reach the extra data blocks.
	for _, f := range []uint32{lnkHasName, lnkHasRelPath, lnkHasWorkDir, lnkHasArgs, lnkHasIconLoc} {
		if flags&f == 0 {
			continue
		}
		if off+2 > len(b) {
			return "", errors.New("lnk: truncated string data")
		}
		n := int(binary.LittleEndian.Uint16(b[off:]))
		if flags&lnkIsUnicode != 0 {
			n *= 2
		}
		off += 2 + n
	}
	for off+8 <= len(b) {
		size := int(binary.LittleEndian.Uint32(b[off:]))
		if size < 8 || off+size > len(b) {
			break
		}
		if binary.LittleEndian.Uint32(b[off+4:]) == lnkEnvBlockSig && size >= lnkEnvBlockSize {
			if t := expandEnv(wstr(b[off:off+size], 8+260)); t != "" {
				return t, nil
			}
			if t := expandEnv(cstr(b[off:off+8+260], 8)); t != "" && isASCII(t) {
				return t, nil
			}
		}
		off += size
	}
	if ansiPath != "" && isASCII(ansiPath) {
		return ansiPath, nil
	}
	return "", errNoTarget
}

func joinSuffix(base, suffix string) string {
	if base == "" {
		return ""
	}
	if suffix == "" {
		return base
	}
	if !strings.HasSuffix(base, `\`) {
		base += `\`
	}
	return base + suffix
}

func cstr(b []byte, off int) string {
	if off <= 0 || off >= len(b) {
		return ""
	}
	end := off
	for end < len(b) && b[end] != 0 {
		end++
	}
	return string(b[off:end])
}

func wstr(b []byte, off int) string {
	if off <= 0 || off+1 >= len(b) {
		return ""
	}
	var u []uint16
	for i := off; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// expandEnv expands %NAME% references the way Windows does.
func expandEnv(s string) string {
	var out strings.Builder
	for {
		i := strings.IndexByte(s, '%')
		if i < 0 {
			out.WriteString(s)
			return out.String()
		}
		j := strings.IndexByte(s[i+1:], '%')
		if j < 0 {
			out.WriteString(s)
			return out.String()
		}
		name := s[i+1 : i+1+j]
		out.WriteString(s[:i])
		if v, ok := os.LookupEnv(name); ok && name != "" {
			out.WriteString(v)
			s = s[i+2+j:]
		} else {
			out.WriteByte('%')
			s = s[i+1:]
		}
	}
}
