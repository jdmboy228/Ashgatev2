// probe is the workload application. It never reads a proxy's config or
// logs. Every connection is a direct socket so the client under test has to
// catch it itself. HTTP_PROXY is ignored.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: compare-probe ping|dns|lookup|down|up|latency")
		os.Exit(2)
	}
	res := run(os.Args[1], os.Args[2:])
	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(res); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

type result struct {
	OK       bool      `json:"ok"`
	Error    string    `json:"error,omitempty"`
	Bytes    int64     `json:"bytes,omitempty"`
	Seconds  float64   `json:"seconds,omitempty"`
	Answer   string    `json:"answer,omitempty"`
	Samples  []float64 `json:"samples_ms,omitempty"`
	MedianMS float64   `json:"median_ms,omitempty"`
	P95MS    float64   `json:"p95_ms,omitempty"`
}

func run(cmd string, args []string) result {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	url := fs.String("url", "", "http url")
	server := fs.String("server", "1.1.1.1:53", "dns server")
	name := fs.String("name", "", "dns name")
	proto := fs.String("proto", "udp", "udp or tcp")
	n := fs.Int64("bytes", 8<<20, "byte count")
	count := fs.Int("count", 20, "latency samples")
	timeout := fs.Duration("timeout", 8*time.Second, "per-attempt timeout")
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return result{Error: err.Error()}
	}
	switch cmd {
	case "ping":
		return httpOp(*url, http.MethodGet, nil, *timeout, func(resp *http.Response) (int64, string, error) {
			b, err := io.ReadAll(io.LimitReader(resp.Body, 64))
			if err != nil {
				return 0, "", err
			}
			if resp.StatusCode != 200 || string(b) != "pong" {
				return 0, "", fmt.Errorf("status %d body %q", resp.StatusCode, b)
			}
			return int64(len(b)), "pong", nil
		})
	case "down":
		u := *url
		if u == "" {
			return result{Error: "need -url"}
		}
		if *n < 0 {
			*n = 0
		}
		sep := "?"
		if bytes.Contains([]byte(u), []byte("?")) {
			sep = "&"
		}
		u = fmt.Sprintf("%s%sn=%d", u, sep, *n)
		return httpOp(u, http.MethodGet, nil, *timeout, func(resp *http.Response) (int64, string, error) {
			if resp.StatusCode != 200 {
				return 0, "", fmt.Errorf("status %d", resp.StatusCode)
			}
			n, err := io.Copy(io.Discard, resp.Body)
			return n, "", err
		})
	case "up":
		body := bytes.NewReader(bytes.Repeat([]byte{0x61}, int(*n)))
		return httpOp(*url, http.MethodPost, body, *timeout, func(resp *http.Response) (int64, string, error) {
			b, err := io.ReadAll(io.LimitReader(resp.Body, 64))
			if err != nil {
				return 0, "", err
			}
			if resp.StatusCode != 200 {
				return 0, "", fmt.Errorf("status %d body %q", resp.StatusCode, b)
			}
			var got int64
			if _, err := fmt.Sscan(string(b), &got); err != nil {
				return 0, "", err
			}
			if got != *n {
				return got, "", fmt.Errorf("server counted %d, sent %d", got, *n)
			}
			return got, "", nil
		})
	case "latency":
		return latency(*url, *count, *timeout)
	case "dns":
		return dnsQuery(*proto, *server, *name, *timeout)
	case "lookup":
		return lookup(*name, *timeout)
	default:
		return result{Error: "unknown command " + cmd}
	}
}

func directClient(timeout time.Duration) *http.Client {
	d := &net.Dialer{Timeout: timeout}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           d.DialContext,
			DisableKeepAlives:     true,
			ForceAttemptHTTP2:     false,
			TLSHandshakeTimeout:   timeout,
			ExpectContinueTimeout: time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func httpOp(url, method string, body io.Reader, timeout time.Duration, read func(*http.Response) (int64, string, error)) result {
	if url == "" {
		return result{Error: "need -url"}
	}
	start := time.Now()
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return result{Error: err.Error()}
	}
	req.Close = true
	resp, err := directClient(timeout).Do(req)
	if err != nil {
		return result{Error: err.Error(), Seconds: time.Since(start).Seconds()}
	}
	defer resp.Body.Close()
	n, answer, err := read(resp)
	out := result{OK: err == nil, Bytes: n, Answer: answer, Seconds: time.Since(start).Seconds()}
	if err != nil {
		out.Error = err.Error()
	}
	return out
}

func latency(url string, count int, timeout time.Duration) result {
	if url == "" {
		return result{Error: "need -url"}
	}
	if count < 1 {
		count = 1
	}
	samples := make([]float64, 0, count)
	var last string
	for i := 0; i < count; i++ {
		one := time.Now()
		r := httpOp(url, http.MethodGet, nil, timeout, func(resp *http.Response) (int64, string, error) {
			b, err := io.ReadAll(io.LimitReader(resp.Body, 64))
			if err != nil {
				return 0, "", err
			}
			if resp.StatusCode != 200 || string(b) != "pong" {
				return 0, "", fmt.Errorf("status %d", resp.StatusCode)
			}
			return int64(len(b)), "pong", nil
		})
		if !r.OK {
			last = r.Error
			continue
		}
		samples = append(samples, float64(time.Since(one).Microseconds())/1000)
	}
	if len(samples) == 0 {
		return result{Error: last}
	}
	sort.Float64s(samples)
	return result{OK: true, Samples: samples, MedianMS: percentile(samples, 0.50), P95MS: percentile(samples, 0.95)}
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	i := int(p * float64(len(sorted)-1))
	if i < 0 {
		i = 0
	}
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}

func lookup(name string, timeout time.Duration) result {
	if name == "" {
		return result{Error: "need -name"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	addrs, err := net.DefaultResolver.LookupHost(ctx, name)
	out := result{Seconds: time.Since(start).Seconds()}
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.OK = true
	if len(addrs) > 0 {
		out.Answer = addrs[0]
	}
	return out
}

func dnsQuery(proto, server, name string, timeout time.Duration) result {
	if name == "" {
		return result{Error: "need -name"}
	}
	if proto != "udp" && proto != "tcp" {
		return result{Error: "proto must be udp or tcp"}
	}
	msg := queryMessage(name)
	start := time.Now()
	conn, err := net.DialTimeout(proto, server, timeout)
	if err != nil {
		return result{Error: err.Error()}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if proto == "tcp" {
		hdr := []byte{byte(len(msg) >> 8), byte(len(msg))}
		if _, err := conn.Write(append(hdr, msg...)); err != nil {
			return result{Error: err.Error()}
		}
	} else if _, err := conn.Write(msg); err != nil {
		return result{Error: err.Error()}
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	out := result{Seconds: time.Since(start).Seconds(), Bytes: int64(n)}
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.OK = n > 0
	out.Answer = fmt.Sprintf("bytes=%d", n)
	return out
}

// queryMessage is a minimal DNS query for name, type A, with a random id.
func queryMessage(name string) []byte {
	id := make([]byte, 2)
	_, _ = rand.Read(id)
	msg := []byte{id[0], id[1], 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, label := range splitLabels(name) {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0x00, 0x00, 0x01, 0x00, 0x01)
	return msg
}

func splitLabels(name string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			if i > start {
				out = append(out, name[start:i])
			}
			start = i + 1
		}
	}
	return out
}
