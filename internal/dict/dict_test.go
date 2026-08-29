package dict

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		" /actuator/env ": "actuator/env",
		"//swagger":       "swagger",
		"\uFEFFx":         "x",
		".":               "",
		"..":              "",
		"":                "",
		"actuator":        "actuator",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "dict.txt")
	content := "# 这是注释\n\n/actuator/env\nactuator/env\nswagger\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := LoadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"actuator/env", "swagger"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestLoadFileMissing(t *testing.T) {
	if _, err := LoadFile(filepath.Join(t.TempDir(), "nope.txt")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestMerge(t *testing.T) {
	got := Merge([]string{"a", "b"}, []string{"b", "c"})
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestDefaultDedup(t *testing.T) {
	def := Default()
	if len(def) == 0 {
		t.Fatal("default dict is empty")
	}
	seen := map[string]bool{}
	for _, e := range def {
		if seen[e] {
			t.Fatalf("duplicate endpoint in default dict: %s", e)
		}
		seen[e] = true
	}
}
