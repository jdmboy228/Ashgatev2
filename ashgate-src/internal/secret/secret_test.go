package secret

import "testing"

func TestSealOpen(t *testing.T) {
	s, err := Seal([]byte("https://sub.example.com/sub/token"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(s)
	if err != nil || string(got) != "https://sub.example.com/sub/token" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := Open("other:abc"); err == nil {
		t.Fatal("opened an unknown format")
	}
}
