// Package subs reads 3x-ui subscriptions: a URL that returns vless:// links,
// one per line, as base64 or plain text. All links of one subscription form
// one failover group.
package subs

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"ashgate/internal/secret"
	"ashgate/internal/vless"
)

// Entry is one server of a subscription.
type Entry struct {
	// Link is the whole vless:// line. Lists are compared by it.
	Link    string
	Name    string
	Address string
	Params  vless.Params
}

// Transport is the entry's transport as the window shows it.
func (e Entry) Transport() string {
	switch e.Params.Network {
	case "xhttp":
		return "XHTTP"
	case "tcp":
		return "RAW"
	default:
		return strings.ToUpper(e.Params.Network)
	}
}

// Label names the entry without secrets: "Швеция · XHTTP".
func (e Entry) Label() string {
	if e.Name == "" {
		return e.Transport()
	}
	return e.Name + " · " + e.Transport()
}

// Parse reads a subscription body. Base64 (standard or URL alphabet, with
// or without padding) and plain text are accepted. Lines that are not
// vless:// links, or that the link parser rejects, are skipped; the order
// of the rest is kept.
func Parse(body []byte) (entries []Entry, skipped int) {
	for _, line := range strings.Split(decode(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(line), "vless://") {
			skipped++
			continue
		}
		p, err := vless.ParseLink(line)
		if err != nil {
			skipped++
			continue
		}
		entries = append(entries, Entry{Link: line, Name: p.Name, Address: p.Address, Params: p.Params})
	}
	return entries, skipped
}

func decode(body []byte) string {
	text := strings.TrimSpace(string(body))
	if strings.Contains(text, "://") {
		return text
	}
	compact := strings.Join(strings.Fields(text), "")
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if raw, err := enc.DecodeString(compact); err == nil && bytes.Contains(raw, []byte("://")) {
			return string(raw)
		}
	}
	return text
}

// rank orders transports: XHTTP is the primary, RAW (TCP) the backup,
// anything else comes after.
func rank(e Entry) int {
	switch e.Params.Network {
	case "xhttp":
		return 0
	case "tcp":
		return 1
	default:
		return 2
	}
}

// Order sorts entries by transport priority and keeps the subscription's
// order within one transport.
func Order(entries []Entry) []Entry {
	out := append([]Entry(nil), entries...)
	sort.SliceStable(out, func(i, j int) bool { return rank(out[i]) < rank(out[j]) })
	return out
}

// Apply orders a fresh list and finds the active entry in it. Links are
// compared as whole strings: while the active link is still there it stays
// active and nothing reconnects. When it is gone, the best entry takes over
// and reconnect is true.
func Apply(fresh []Entry, activeLink string) (ordered []Entry, active int, reconnect bool) {
	ordered = Order(fresh)
	for i, e := range ordered {
		if activeLink != "" && e.Link == activeLink {
			return ordered, i, false
		}
	}
	return ordered, 0, true
}

// maxBody bounds a subscription response.
const maxBody = 1 << 20

// Fetch downloads and validates a subscription: HTTP 200 and at least one
// valid vless:// link. Errors never contain the URL, which holds a token.
func Fetch(ctx context.Context, client *http.Client, rawURL string) ([]Entry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, errors.New("неверный адрес подписки")
	}
	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // url.Error repeats the URL
		}
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "timeout") {
			return nil, errors.New("сервер подписки не ответил вовремя")
		}
		return nil, errors.New("нет связи с сервером подписки")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("сервер подписки ответил %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, errors.New("ответ подписки оборвался")
	}
	entries, _ := Parse(body)
	if len(entries) == 0 {
		return nil, errors.New("в подписке нет ни одной рабочей ссылки vless://")
	}
	return entries, nil
}

// CheckURL accepts an http or https subscription address.
func CheckURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("адрес подписки должен начинаться с https:// или http://")
	}
	return nil
}

// Mask keeps only the scheme and host of a subscription URL, for logs and
// the window: the path and query carry the access token.
func Mask(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "подписка"
	}
	return u.Scheme + "://" + u.Host + "/…"
}

// Secret is what a subscription keeps sealed at rest.
type Secret struct {
	URL   string   `json:"url"`
	Links []string `json:"links"`
}

// Seal encrypts the URL and links for config.json (DPAPI on Windows).
func Seal(s Secret) (string, error) {
	raw, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return secret.Seal(raw)
}

// Open decrypts a sealed subscription.
func Open(sealed string) (Secret, error) {
	raw, err := secret.Open(sealed)
	if err != nil {
		return Secret{}, err
	}
	var s Secret
	if err := json.Unmarshal(raw, &s); err != nil {
		return Secret{}, errors.New("подписка повреждена")
	}
	return s, nil
}

// Entries parses stored links back into ordered entries.
func Entries(links []string) []Entry {
	entries, _ := Parse([]byte(strings.Join(links, "\n")))
	return Order(entries)
}

// Links returns the entries' links in order.
func Links(entries []Entry) []string {
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.Link
	}
	return out
}
