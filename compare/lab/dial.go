package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// dialSelf checks the fixture with xray itself, before any client runs.
func dialSelf(xrayPath, labPath, transport string) error {
	raw, err := os.ReadFile(labPath)
	if err != nil {
		return err
	}
	var fix Fixture
	if err := json.Unmarshal(raw, &fix); err != nil {
		return err
	}
	ep := fix.XHTTP
	network := "xhttp"
	flow := ""
	if transport == "raw" {
		ep = fix.RAW
		network = fix.RawNetwork
		if network == "" {
			network = "raw"
		}
		flow = "xtls-rprx-vision"
	} else if transport != "xhttp" {
		return fmt.Errorf("transport must be xhttp or raw")
	}
	dir, err := os.MkdirTemp("", "lab-dial-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	socksPort := freePort()
	user := map[string]any{"id": ep.UUID, "encryption": "none"}
	if flow != "" {
		user["flow"] = flow
	}
	stream := map[string]any{
		"network": network, "security": "reality",
		"realitySettings": map[string]any{
			"serverName": fix.SNI, "fingerprint": fix.Fingerprint,
			"publicKey": fix.RealityPublicKey, "shortId": fix.ShortID,
		},
	}
	if network == "xhttp" {
		stream["xhttpSettings"] = map[string]any{"path": xhttpPath, "mode": "auto"}
	}
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": socksPort, "protocol": "socks",
			"settings": map[string]any{"udp": false, "auth": "noauth"},
		}},
		"outbounds": []any{map[string]any{
			"protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{
				"address": ep.Host, "port": ep.Port, "users": []any{user},
			}}},
			"streamSettings": stream,
		}},
	}
	path := filepath.Join(dir, "client.json")
	buf, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		return err
	}
	stderr, err := os.Create(filepath.Join(dir, "stderr.log"))
	if err != nil {
		return err
	}
	defer stderr.Close()
	cmd := exec.Command(xrayPath, "run", "-config", path)
	cmd.Dir = filepath.Dir(xrayPath)
	cmd.Stdout = stderr
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()
	deadline := time.Now().Add(20 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		last = socksHTTP(socksPort, "198.51.100.10", echoPortA, "/ping", "pong")
		if last == nil {
			fmt.Println("ok")
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	tail, _ := os.ReadFile(stderr.Name())
	if len(tail) > 1500 {
		tail = tail[len(tail)-1500:]
	}
	return fmt.Errorf("self-test %s: %v\n%s", transport, last, tail)
}

func socksHTTP(port int, host string, destPort int, path, want string) error {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(c, greet); err != nil {
		return err
	}
	if greet[0] != 0x05 || greet[1] != 0x00 {
		return fmt.Errorf("socks greeting %v", greet)
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return fmt.Errorf("need ipv4 host")
	}
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, ip...)
	req = binary.BigEndian.AppendUint16(req, uint16(destPort))
	if _, err := c.Write(req); err != nil {
		return err
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return err
	}
	if hdr[1] != 0x00 {
		return fmt.Errorf("socks connect status %d", hdr[1])
	}
	switch hdr[3] {
	case 0x01:
		_, err = io.CopyN(io.Discard, c, 4+2)
	case 0x04:
		_, err = io.CopyN(io.Discard, c, 16+2)
	case 0x03:
		var n [1]byte
		_, err = io.ReadFull(c, n[:])
		if err == nil {
			_, err = io.CopyN(io.Discard, c, int64(n[0])+2)
		}
	default:
		err = fmt.Errorf("socks atyp %d", hdr[3])
	}
	if err != nil {
		return err
	}
	reqHTTP := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host)
	if _, err := io.WriteString(c, reqHTTP); err != nil {
		return err
	}
	buf, err := io.ReadAll(io.LimitReader(c, 4096))
	if err != nil && len(buf) == 0 {
		return err
	}
	if !contains(buf, []byte(want)) {
		return fmt.Errorf("response %q", trim(buf))
	}
	return nil
}

func contains(b, sub []byte) bool {
	return len(sub) == 0 || (len(b) >= len(sub) && indexOf(b, sub) >= 0)
}

func indexOf(b, sub []byte) int {
	for i := 0; i+len(sub) <= len(b); i++ {
		ok := true
		for j := range sub {
			if b[i+j] != sub[j] {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}

func trim(b []byte) string {
	s := string(b)
	if len(s) > 180 {
		s = s[:180]
	}
	return s
}
