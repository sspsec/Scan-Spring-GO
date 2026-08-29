package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFormatURL(t *testing.T) {
	cases := map[string]string{
		"example.com":           "http://example.com/",
		"http://example.com":    "http://example.com/",
		"https://example.com":   "https://example.com/",
		"example.com:443":       "https://example.com/",
		"example.com/path":      "http://example.com/path/",
		"https://example.com/a": "https://example.com/a/",
	}
	for in, want := range cases {
		if got := formatURL(in); got != want {
			t.Errorf("formatURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCollectTargets(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "urls.txt")
	content := "http://a.com\n\n# comment\nb.com\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := collectTargets("http://single.com", p)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"http://single.com", "http://a.com", "b.com"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCollectTargetsEmpty(t *testing.T) {
	if _, err := collectTargets("", ""); err == nil {
		t.Fatal("expected error for empty targets")
	}
}
