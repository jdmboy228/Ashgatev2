//go:build windows && e2e

package harness

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf16"
)

// Secret is one fake credential made up for this run. PlainOK marks values
// that config.json keeps in plain text by design (VLESS fields and proxy
// passwords, see the README); they still must not appear anywhere else.
type Secret struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	PlainOK bool   `json:"plainOK,omitempty"`
}

// Secrets registers every fake value so logs can be masked and searched.
type Secrets struct {
	mu    sync.Mutex
	path  string
	items []Secret
}

// NewSecrets keeps the register in path (an artifact that is masked
// itself before upload: the workflow never uploads it).
func NewSecrets(path string) *Secrets {
	s := &Secrets{path: path}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &s.items)
	}
	return s
}

// Add registers value and tells the runner to mask it in the job log.
func (s *Secrets) Add(name, value string, plainOK bool) string {
	if value == "" {
		return value
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, it := range s.items {
		if it.Value == value {
			return value
		}
	}
	s.items = append(s.items, Secret{Name: name, Value: value, PlainOK: plainOK})
	fmt.Printf("::add-mask::%s\n", value)
	if b, err := json.Marshal(s.items); err == nil {
		_ = os.WriteFile(s.path, b, 0o600)
	}
	return value
}

// All returns a copy of the register.
func (s *Secrets) All() []Secret {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Secret(nil), s.items...)
}

// RandHex is n random bytes as hex.
func RandHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// RandUUID is a random version 4 UUID.
func RandUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// variants are the encodings a value can hide in on disk.
func variants(v string) [][]byte {
	out := [][]byte{[]byte(v)}
	add := func(s string) {
		if s == "" || s == v {
			return
		}
		out = append(out, []byte(s))
	}
	if looksUUID(v) {
		add(strings.ReplaceAll(v, "-", ""))
		add(strings.ToUpper(v))
	}
	add(url.QueryEscape(v))
	add(url.PathEscape(v))
	// UTF-16LE: Windows APIs, registry, the WebView2 profile.
	u := utf16.Encode([]rune(v))
	w := make([]byte, 0, len(u)*2)
	for _, r := range u {
		w = append(w, byte(r), byte(r>>8))
	}
	out = append(out, w)
	// Inside a larger base64 blob the value can start at any of three
	// byte offsets; keep the part of each encoding that does not depend
	// on its neighbours.
	if len(v) >= 12 {
		for k := 0; k < 3; k++ {
			pad := bytes.Repeat([]byte{0}, k)
			for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
				e := enc.EncodeToString(append(pad, v...))
				skip := (k*4 + 2) / 3
				if k == 0 {
					skip = 0
				}
				end := len(e) - 4
				if end-skip >= 8 {
					out = append(out, []byte(strings.TrimRight(e[skip:end], "=")))
				}
			}
		}
	}
	return out
}

func looksUUID(v string) bool {
	return len(v) == 36 && strings.Count(v, "-") == 4
}

// Finding is one secret found in one file.
type Finding struct {
	File   string `json:"file"`
	Secret string `json:"secret"`
}

// Scan searches every file under roots. allowed says whether a plain-text
// hit is acceptable in that file (config.json for PlainOK values).
// Files that cannot be read are listed in unreadable.
func (s *Secrets) Scan(roots []string, allowed func(path string, sec Secret) bool) (found []Finding, unreadable []string) {
	items := s.All()
	type pat struct {
		sec Secret
		vs  [][]byte
	}
	pats := make([]pat, 0, len(items))
	for _, it := range items {
		pats = append(pats, pat{it, variants(it.Value)})
	}
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				if !os.IsNotExist(err) {
					unreadable = append(unreadable, path)
				}
				return nil
			}
			if d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.Size() > 512<<20 {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				unreadable = append(unreadable, path)
				return nil
			}
			for _, p := range pats {
				for _, v := range p.vs {
					if bytes.Contains(b, v) {
						if allowed == nil || !allowed(path, p.sec) {
							found = append(found, Finding{File: path, Secret: p.sec.Name})
						}
						break
					}
				}
			}
			return nil
		})
	}
	return found, unreadable
}

var textExt = map[string]bool{
	".log": true, ".txt": true, ".json": true, ".xml": true, ".md": true,
	".html": true, ".csv": true, ".1": true, ".2": true, ".ini": true, ".iss": true,
}

// MaskTree copies src to dst and replaces every registered value in text
// files with ***. Binary files are copied unchanged.
func (s *Secrets) MaskTree(src, dst string) error {
	items := s.All()
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(src, path)
		to := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(to, 0o755)
		}
		if filepath.Base(path) == "secrets.json" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if textExt[strings.ToLower(filepath.Ext(path))] {
			for _, it := range items {
				for _, v := range variants(it.Value) {
					b = bytes.ReplaceAll(b, v, []byte("***"))
				}
			}
		}
		return os.WriteFile(to, b, 0o644)
	})
}
