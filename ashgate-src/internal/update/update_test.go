package update

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"ashgate/internal/version"
)

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.7.3", "0.7.3", 0},
		{"0.7.10", "0.7.9", 1},
		{"0.8", "0.8.0", 0},
		{"v1.0.0", "0.9.9", 1},
		{"0.8.0-beta", "0.8.0", -1},
		{"0.8.0-beta.2", "0.8.0-beta.1", 1},
		{"0.8.0+abc", "0.8.0", 0},
		{"junk", "0.1.0", -1},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCheck(t *testing.T) {
	body := `{"version":"9.0.0","download_url":"https://github.com/jdmboy228/Ashgatev2/releases/latest","release_notes":"Новое"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	res, err := Check(context.Background(), srv.Client(), srv.URL, "0.7.3")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Available || res.Latest != "9.0.0" || res.Notes != "Новое" {
		t.Fatalf("%+v", res)
	}
	res, err = Check(context.Background(), srv.Client(), srv.URL, "9.0.0")
	if err != nil || res.Available {
		t.Fatalf("same version: %+v %v", res, err)
	}
}

func TestRejectsUnsafeLink(t *testing.T) {
	for _, link := range []string{"", "http://example.com/x", "file:///C:/Windows/System32/calc.exe", "ms-settings:", "https://user:pw@example.com/"} {
		if _, err := compare(Manifest{Version: "1.0.0", DownloadURL: link}, "0.1.0"); err == nil {
			t.Errorf("accepted %q", link)
		}
	}
}

// TestManifestMatchesVersion keeps version.json at the repository root in
// step with the version compiled into the exe.
func TestManifestMatchesVersion(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "version.json"))
	if err != nil {
		t.Skip("version.json not found:", err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m.Version != version.Version {
		t.Fatalf("version.json says %s, internal/version says %s", m.Version, version.Version)
	}
	if _, err := compare(m, version.Version); err != nil {
		t.Fatal(err)
	}
}
