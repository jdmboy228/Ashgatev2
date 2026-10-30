// Package update asks GitHub whether a newer Ashgate release exists. It
// reads version.json from the root of the repository.
package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// URL is version.json on the main branch.
const URL = "https://raw.githubusercontent.com/jdmboy228/Ashgatev2/main/version.json"

// Manifest is the content of version.json.
type Manifest struct {
	Version      string `json:"version"`
	DownloadURL  string `json:"download_url"`
	ReleaseNotes string `json:"release_notes"`
}

// Result is what the Settings page shows.
type Result struct {
	Current   string `json:"current"`
	Latest    string `json:"latest"`
	Available bool   `json:"available"`
	Notes     string `json:"notes,omitempty"`
	// URL is the download page. It is always https.
	URL string `json:"url,omitempty"`
}

const (
	timeout  = 15 * time.Second
	maxBody  = 64 << 10
	maxNotes = 600 // runes shown in the window
)

// Check fetches the manifest at src and compares it with current.
// client may be nil.
func Check(ctx context.Context, client *http.Client, src, current string) (Result, error) {
	if client == nil {
		client = http.DefaultClient
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("User-Agent", "Ashgate/"+current)
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return Result{}, errors.New("GitHub не ответил за 15 секунд")
		}
		return Result{}, errors.New("нет связи с GitHub")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("GitHub ответил %d", resp.StatusCode)
	}
	var m Manifest
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&m); err != nil {
		return Result{}, errors.New("version.json повреждён")
	}
	return compare(m, current)
}

func compare(m Manifest, current string) (Result, error) {
	latest := strings.TrimSpace(m.Version)
	if _, _, ok := parse(latest); !ok {
		return Result{}, fmt.Errorf("в version.json неверная версия %q", latest)
	}
	link, err := safeURL(m.DownloadURL)
	if err != nil {
		return Result{}, err
	}
	res := Result{Current: current, Latest: latest, URL: link, Notes: clip(strings.TrimSpace(m.ReleaseNotes), maxNotes)}
	res.Available = Compare(latest, current) > 0
	return res, nil
}

// safeURL accepts only an https link. The window opens it in the browser
// from an elevated process; any other scheme could start a local program.
func safeURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return "", errors.New("в version.json неверная ссылка на загрузку")
	}
	return u.String(), nil
}

// Compare orders two versions such as "0.7.3" or "v0.8.0-beta.1": it is
// negative when a < b, zero when equal, positive when a > b. Missing parts
// count as zero; a pre-release sorts before its release. A version that
// does not parse sorts before every valid one.
func Compare(a, b string) int {
	an, apre, aok := parse(a)
	bn, bpre, bok := parse(b)
	switch {
	case !aok && !bok:
		return 0
	case !aok:
		return -1
	case !bok:
		return 1
	}
	for i := 0; i < len(an) || i < len(bn); i++ {
		var x, y int
		if i < len(an) {
			x = an[i]
		}
		if i < len(bn) {
			y = bn[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	switch {
	case apre == bpre:
		return 0
	case apre == "":
		return 1
	case bpre == "":
		return -1
	case apre < bpre:
		return -1
	default:
		return 1
	}
}

func parse(v string) (nums []int, pre string, ok bool) {
	v = strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(v), "v"), "V")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i] // build metadata does not order
	}
	if i := strings.IndexByte(v, '-'); i >= 0 {
		v, pre = v[:i], v[i+1:]
	}
	if v == "" {
		return nil, "", false
	}
	for _, part := range strings.Split(v, ".") {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return nil, "", false
		}
		nums = append(nums, n)
	}
	return nums, pre, true
}

func clip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return strings.TrimSpace(string(r[:n])) + "…"
}
