// Command geotrim cuts Xray's geodata down to the lists the Android core
// uses, so the APK does not carry every country of the world:
//
//	geotrim DIR
//
// rewrites DIR/geoip.dat with only geoip:ru and DIR/geosite.dat with only
// geosite:category-ru (mobilecfg.XrayJSON names nothing else). It fails if
// a list is missing, so a changed upstream release cannot ship an empty
// Russian bypass.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/xtls/xray-core/common/geodata"
	"google.golang.org/protobuf/proto"
)

// Lists the Android document refers to (see mobilecfg.XrayJSON).
var (
	keepIP   = []string{"ru"}
	keepSite = []string{"category-ru"}
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: geotrim DIR")
		os.Exit(2)
	}
	if err := trimDir(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "geotrim:", err)
		os.Exit(1)
	}
}

func trimDir(dir string) error {
	ipPath := filepath.Join(dir, "geoip.dat")
	if _, err := os.Stat(ipPath); err == nil {
		if err := rewrite(ipPath, func(raw []byte) ([]byte, error) {
			return trimIP(raw, keepIP)
		}); err != nil {
			return err
		}
	}
	return rewrite(filepath.Join(dir, "geosite.dat"), func(raw []byte) ([]byte, error) {
		return trimSite(raw, keepSite)
	})
}

func rewrite(path string, trim func([]byte) ([]byte, error)) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	out, err := trim(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return os.WriteFile(path, out, 0o644)
}

func wanted(code string, keep []string) bool {
	for _, k := range keep {
		if strings.EqualFold(code, k) {
			return true
		}
	}
	return false
}

func trimIP(raw []byte, keep []string) ([]byte, error) {
	var list geodata.GeoIPList
	if err := proto.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	var out geodata.GeoIPList
	for _, e := range list.Entry {
		if wanted(e.Code, keep) {
			out.Entry = append(out.Entry, e)
		}
	}
	if err := complete(keep, len(out.Entry), func(i int) (string, int) {
		return out.Entry[i].Code, len(out.Entry[i].Cidr)
	}); err != nil {
		return nil, err
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(&out)
}

func trimSite(raw []byte, keep []string) ([]byte, error) {
	var list geodata.GeoSiteList
	if err := proto.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	var out geodata.GeoSiteList
	for _, e := range list.Entry {
		if wanted(e.Code, keep) {
			out.Entry = append(out.Entry, e)
		}
	}
	if err := complete(keep, len(out.Entry), func(i int) (string, int) {
		return out.Entry[i].Code, len(out.Entry[i].Domain)
	}); err != nil {
		return nil, err
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(&out)
}

// complete checks that every kept list is present and not empty.
func complete(keep []string, n int, entry func(int) (code string, size int)) error {
	for _, k := range keep {
		found := false
		for i := 0; i < n; i++ {
			code, size := entry(i)
			if strings.EqualFold(code, k) {
				if size == 0 {
					return fmt.Errorf("list %q is empty", k)
				}
				found = true
			}
		}
		if !found {
			return fmt.Errorf("list %q is missing", k)
		}
	}
	return nil
}
