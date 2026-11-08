//go:build windows && e2e

// ashgate-e2e-client is the "proxied app" of the end-to-end tests. Ashgate
// matches it by its exe path; copies under other names stand for apps with
// other rules or none. Every command prints one JSON object to stdout.
//
//	get    -url U -n N -seed S [-host H] [-stall 10s]    download, compare SHA-256
//	put    -url U -n N -seed S                           upload, compare SHA-256
//	par    -url U -n N -seed S -streams K                K parallel downloads
//	hold   -url U -secs T -rate R -seed S                long stream, checked per chunk
//	churn  -url U -count N                               N short requests
//	tcp    -addr A [-timeout 5s]                         just connect
//	udp    -addr A [-timeout 5s]                         one echo round trip
//	stun   -addr A                                       STUN binding request
//	dns    -server A -name N [-tcp]                      own DNS query (not getaddrinfo)
//	dnsburst -server A -name N -count K                  K queries at once, each from a new socket
//	lookup -name N                                       getaddrinfo (system resolver)
//	dpapi  -in F                                         CryptUnprotectData a sealed value
//	read   -path P                                       try to read a file
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"ashgate/e2e/stream"
)

type result struct {
	OK      bool    `json:"ok"`
	Bytes   int64   `json:"bytes,omitempty"`
	Secs    float64 `json:"secs,omitempty"`
	MBps    float64 `json:"mbps,omitempty"`
	SHA     string  `json:"sha,omitempty"`
	Want    string  `json:"want,omitempty"`
	Answer  string  `json:"answer,omitempty"`
	Error   string  `json:"error,omitempty"`
	Stalls  int     `json:"stalls,omitempty"`
	Count   int     `json:"count,omitempty"`
	Failed  int     `json:"failed,omitempty"`
	MaxGapS float64 `json:"maxGapSecs,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: ashgate-e2e-client <command> [flags]")
		os.Exit(2)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	u := fs.String("url", "", "")
	n := fs.Int64("n", 1<<20, "")
	seed := fs.String("seed", "e2e", "")
	host := fs.String("host", "", "")
	stall := fs.Duration("stall", 10*time.Second, "")
	streams := fs.Int("streams", 4, "")
	secs := fs.Int("secs", 60, "")
	rate := fs.Int("rate", 64<<10, "")
	count := fs.Int("count", 10, "")
	addr := fs.String("addr", "", "")
	timeout := fs.Duration("timeout", 5*time.Second, "")
	server := fs.String("server", "1.1.1.1:53", "")
	name := fs.String("name", "", "")
	useTCP := fs.Bool("tcp", false, "")
	in := fs.String("in", "", "")
	path := fs.String("path", "", "")
	_ = fs.Parse(os.Args[2:])

	var r result
	switch cmd {
	case "get":
		r = get(*u, *host, *n, *seed, *stall)
	case "put":
		r = put(*u, *n, *seed)
	case "par":
		r = par(*u, *n, *seed, *streams, *stall)
	case "hold":
		r = hold(*u, *secs, *rate, *seed, *stall)
	case "churn":
		r = churn(*u, *count)
	case "tcp":
		r = dialTCP(*addr, *timeout)
	case "udp":
		r = udpEcho(*addr, *timeout)
	case "stun":
		r = stunBinding(*addr, *timeout)
	case "dns":
		r = dnsQuery(*server, *name, *useTCP, *timeout)
	case "dnsburst":
		r = dnsBurst(*server, *name, *count, *timeout)
	case "lookup":
		r = lookup(*name, *timeout)
	case "dpapi":
		r = dpapiOpen(*in)
	case "read":
		r = readFile(*path)
	default:
		r = result{Error: "unknown command " + cmd}
	}
	b, _ := json.Marshal(r)
	fmt.Println(string(b))
	if !r.OK {
		os.Exit(1)
	}
}

func client(string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, ResponseHeaderTimeout: 30 * time.Second},
		Timeout:   10 * time.Minute,
	}
}

// watched copies src while tracking the longest gap between reads.
func watched(dst io.Writer, src io.Reader, stall time.Duration, onStall func()) (int64, float64, error) {
	buf := make([]byte, 64<<10)
	var total int64
	var maxGap float64
	last := time.Now()
	type chunk struct {
		n   int
		err error
	}
	for {
		ch := make(chan chunk, 1)
		go func() {
			k, err := src.Read(buf)
			ch <- chunk{k, err}
		}()
		select {
		case c := <-ch:
			if g := time.Since(last).Seconds(); g > maxGap {
				maxGap = g
			}
			last = time.Now()
			if c.n > 0 {
				_, _ = dst.Write(buf[:c.n])
				total += int64(c.n)
			}
			if c.err == io.EOF {
				return total, maxGap, nil
			}
			if c.err != nil {
				return total, maxGap, c.err
			}
		case <-time.After(stall):
			onStall()
			return total, stall.Seconds(), fmt.Errorf("stall: no bytes for %s after %d bytes", stall, total)
		}
	}
}

func get(u, host string, n int64, seed string, stall time.Duration) result {
	start := time.Now()
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/bytes?n=%d&seed=%s", strings.TrimRight(u, "/"), n, seed), nil)
	if err != nil {
		return result{Error: err.Error()}
	}
	if host != "" {
		req.Host = host
	}
	resp, err := client(host).Do(req)
	if err != nil {
		return result{Error: err.Error(), Secs: time.Since(start).Seconds()}
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return result{Error: "status " + resp.Status}
	}
	h := sha256.New()
	stalls := 0
	got, gap, err := watched(h, resp.Body, stall, func() { stalls++; resp.Body.Close() })
	r := result{Bytes: got, Secs: time.Since(start).Seconds(), SHA: hex.EncodeToString(h.Sum(nil)),
		Want: stream.Sum(seed, n), Stalls: stalls, MaxGapS: gap}
	if r.Secs > 0 {
		r.MBps = float64(got) / r.Secs / 1e6
	}
	switch {
	case err != nil:
		r.Error = err.Error()
	case got != n:
		r.Error = fmt.Sprintf("got %d bytes, want %d", got, n)
	case r.SHA != r.Want:
		r.Error = "SHA-256 mismatch: corrupted bytes"
	default:
		r.OK = true
	}
	return r
}

func put(u string, n int64, seed string) result {
	start := time.Now()
	resp, err := client("").Post(strings.TrimRight(u, "/")+"/upload", "application/octet-stream", stream.Reader(seed, n))
	if err != nil {
		return result{Error: err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	r := result{Bytes: n, Secs: time.Since(start).Seconds(), Want: stream.Sum(seed, n)}
	if r.Secs > 0 {
		r.MBps = float64(n) / r.Secs / 1e6
	}
	var got int64
	fmt.Sscanf(string(body), "%s %d", &r.SHA, &got)
	switch {
	case got != n:
		r.Error = fmt.Sprintf("server got %d bytes, sent %d", got, n)
	case r.SHA != r.Want:
		r.Error = "SHA-256 mismatch: corrupted bytes"
	default:
		r.OK = true
	}
	return r
}

func par(u string, n int64, seed string, k int, stall time.Duration) result {
	start := time.Now()
	var wg sync.WaitGroup
	res := make([]result, k)
	for i := 0; i < k; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res[i] = get(u, "", n, fmt.Sprintf("%s-%d", seed, i), stall)
		}(i)
	}
	wg.Wait()
	out := result{OK: true, Count: k, Secs: time.Since(start).Seconds()}
	for _, r := range res {
		out.Bytes += r.Bytes
		out.Stalls += r.Stalls
		if r.MaxGapS > out.MaxGapS {
			out.MaxGapS = r.MaxGapS
		}
		if !r.OK {
			out.OK = false
			out.Failed++
			if out.Error == "" {
				out.Error = r.Error
			}
		}
	}
	if out.Secs > 0 {
		out.MBps = float64(out.Bytes) / out.Secs / 1e6
	}
	return out
}

func hold(u string, secs, rate int, seed string, stall time.Duration) result {
	start := time.Now()
	// The stream itself lasts secs; the stall watcher catches a hang.
	c := client("")
	c.Timeout = time.Duration(secs)*time.Second + time.Minute
	resp, err := c.Get(fmt.Sprintf("%s/hold?secs=%d&rate=%d&seed=%s", strings.TrimRight(u, "/"), secs, rate, seed))
	if err != nil {
		return result{Error: err.Error()}
	}
	defer resp.Body.Close()
	want := int64(secs) * int64(rate)
	// Compare chunk by chunk against the same generator, so corruption is
	// caught where it happens.
	exp := stream.Reader(seed, want)
	cmp := &compareWriter{exp: exp, bad: -1}
	stalls := 0
	got, gap, err := watched(cmp, resp.Body, stall, func() { stalls++; resp.Body.Close() })
	r := result{Bytes: got, Secs: time.Since(start).Seconds(), Stalls: stalls, MaxGapS: gap}
	switch {
	case err != nil:
		r.Error = err.Error()
	case cmp.bad >= 0:
		r.Error = fmt.Sprintf("corrupted byte at offset %d", cmp.bad)
	case got != want:
		r.Error = fmt.Sprintf("got %d bytes, want %d", got, want)
	default:
		r.OK = true
	}
	return r
}

type compareWriter struct {
	exp io.Reader
	off int64
	bad int64
	buf []byte
}

func (c *compareWriter) Write(p []byte) (int, error) {
	if cap(c.buf) < len(p) {
		c.buf = make([]byte, len(p))
	}
	e := c.buf[:len(p)]
	k, _ := io.ReadFull(c.exp, e)
	if c.bad < 0 {
		for i := 0; i < len(p); i++ {
			if i >= k || p[i] != e[i] {
				c.bad = c.off + int64(i)
				break
			}
		}
	}
	c.off += int64(len(p))
	return len(p), nil
}

func churn(u string, count int) result {
	r := result{Count: count}
	start := time.Now()
	for i := 0; i < count; i++ {
		resp, err := client("").Get(strings.TrimRight(u, "/") + "/ok")
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(b) == "ok" {
				continue
			}
			err = errors.New("bad body")
		}
		r.Failed++
		if r.Error == "" {
			r.Error = err.Error()
		}
	}
	r.Secs = time.Since(start).Seconds()
	r.OK = r.Failed == 0
	return r
}

func dialTCP(addr string, timeout time.Duration) result {
	start := time.Now()
	c, err := net.DialTimeout("tcp", addr, timeout)
	r := result{Secs: time.Since(start).Seconds()}
	if err != nil {
		r.Error = err.Error()
		return r
	}
	c.Close()
	r.OK = true
	return r
}

func udpEcho(addr string, timeout time.Duration) result {
	c, err := net.Dial("udp", addr)
	if err != nil {
		return result{Error: err.Error()}
	}
	defer c.Close()
	msg := make([]byte, 600)
	for i := range msg {
		msg[i] = byte(rand.IntN(256))
	}
	start := time.Now()
	buf := make([]byte, 2048)
	for try := 0; try < 3; try++ {
		_, _ = c.Write(msg)
		_ = c.SetReadDeadline(time.Now().Add(timeout / 3))
		k, err := c.Read(buf)
		if err == nil && bytes.Equal(buf[:k], msg) {
			return result{OK: true, Bytes: int64(k), Secs: time.Since(start).Seconds()}
		}
	}
	return result{Error: "no echo", Secs: time.Since(start).Seconds()}
}

func stunBinding(addr string, timeout time.Duration) result {
	c, err := net.Dial("udp", addr)
	if err != nil {
		return result{Error: err.Error()}
	}
	defer c.Close()
	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:], 0x0001)
	binary.BigEndian.PutUint32(req[4:], 0x2112A442)
	for i := 8; i < 20; i++ {
		req[i] = byte(rand.IntN(256))
	}
	buf := make([]byte, 1024)
	for try := 0; try < 3; try++ {
		_, _ = c.Write(req)
		_ = c.SetReadDeadline(time.Now().Add(timeout / 3))
		k, err := c.Read(buf)
		if err == nil && k >= 20 && binary.BigEndian.Uint16(buf) == 0x0101 && bytes.Equal(buf[8:20], req[8:20]) {
			return result{OK: true, Bytes: int64(k)}
		}
	}
	return result{Error: "no STUN answer"}
}

func dnsQuery(server, name string, useTCP bool, timeout time.Duration) result {
	q := buildQuery(uint16(rand.IntN(65535)), name)
	network := "udp"
	if useTCP {
		network = "tcp"
	}
	c, err := net.DialTimeout(network, server, timeout)
	if err != nil {
		return result{Error: err.Error()}
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	if useTCP {
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(q)))
		_, _ = c.Write(append(l[:], q...))
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return result{Error: err.Error()}
		}
		resp := make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(c, resp); err != nil {
			return result{Error: err.Error()}
		}
		return result{OK: true, Answer: rcode(resp)}
	}
	_, _ = c.Write(q)
	buf := make([]byte, 1500)
	k, err := c.Read(buf)
	if err != nil {
		return result{Error: err.Error()}
	}
	return result{OK: true, Answer: rcode(buf[:k])}
}

// dnsBurst sends count queries for q<i>.name at once, each from its own
// new socket, like a browser loading a page. Count is how many got any
// reply; it is OK when every one did.
func dnsBurst(server, name string, count int, timeout time.Duration) result {
	var wg sync.WaitGroup
	var mu sync.Mutex
	answered := 0
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if r := dnsQuery(server, fmt.Sprintf("q%d.%s", i, name), false, timeout); r.OK {
				mu.Lock()
				answered++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	return result{OK: answered == count, Count: answered, Failed: count - answered}
}

func rcode(msg []byte) string {
	if len(msg) < 4 {
		return "short"
	}
	return fmt.Sprintf("rcode=%d answers=%d", msg[3]&0x0f, binary.BigEndian.Uint16(msg[6:]))
}

func buildQuery(id uint16, name string) []byte {
	var b []byte
	b = binary.BigEndian.AppendUint16(b, id)
	b = append(b, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0)
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0, 0, 1, 0, 1)
}

func lookup(name string, timeout time.Duration) result {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, name)
	if err != nil {
		// NXDOMAIN is a fine answer: the query was made.
		return result{OK: true, Answer: err.Error()}
	}
	return result{OK: true, Answer: strings.Join(addrs, ",")}
}

// dpapiOpen tries to decrypt Ashgate's sealed subscription as the user
// this process runs as. It must fail for anyone but the user who sealed it.
func dpapiOpen(file string) result {
	b, err := os.ReadFile(file)
	if err != nil {
		return result{Error: "read: " + err.Error()}
	}
	s := strings.TrimSpace(string(b))
	if !strings.HasPrefix(s, "dpapi:") {
		return result{Error: "not a dpapi value"}
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, "dpapi:"))
	if err != nil {
		return result{Error: "base64: " + err.Error()}
	}
	entropy := []byte("ashgate/subscription/v1")
	in := windows.DataBlob{Size: uint32(len(raw)), Data: &raw[0]}
	ent := windows.DataBlob{Size: uint32(len(entropy)), Data: &entropy[0]}
	var out windows.DataBlob
	const uiForbidden = 0x1
	if err := windows.CryptUnprotectData(&in, nil, &ent, 0, nil, uiForbidden, &out); err != nil {
		return result{Error: "CryptUnprotectData: " + err.Error()}
	}
	n := out.Size
	_ = unsafe.Slice(out.Data, n)
	windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return result{OK: true, Bytes: int64(n)}
}

func readFile(path string) result {
	b, err := os.ReadFile(path)
	if err != nil {
		return result{Error: err.Error()}
	}
	return result{OK: true, Bytes: int64(len(b))}
}
