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

func TestCVE202222963Detect(t *testing.T) {
	// 缩短休眠与阈值，加速测试
	oldSleep, oldThresh := scFuncSleepMs, scFuncThresh
	scFuncSleepMs = 1500
	scFuncThresh = 1000 * time.Millisecond
	defer func() { scFuncSleepMs, scFuncThresh = oldSleep, oldThresh }()

	newTarget := func(delay time.Duration) model.Target {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.Header.Get("spring.cloud.function.routing-expression"), "sleep") {
				time.Sleep(delay)
			}
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"Internal Server Error"}`))
		}))
		t.Cleanup(ts.Close)
		return model.Target{URL: ts.URL + "/", Client: client.New("", 30*time.Second)}
	}

	// 漏洞：表达式被求值（休眠生效）
	verdict, err := (&cve202222963{}).Detect(context.Background(), newTarget(1500*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if !verdict.Vulnerable {
		t.Fatalf("expected vulnerable, got %+v", verdict)
	}

	// 已修复：头不求值，无延迟
	verdict, err = (&cve202222963{}).Detect(context.Background(), newTarget(0))
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Vulnerable {
		t.Fatalf("expected clean for patched target, got %+v", verdict)
	}
}

func TestCVE202222963ExploitContentType(t *testing.T) {
	var gotCT string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
	}))
	defer ts.Close()

	tgt := model.Target{URL: ts.URL + "/", Client: client.New("", time.Second)}
	if _, _, err := (&cve202222963{}).Exploit(context.Background(), tgt, "id"); err != nil {
		t.Fatal(err)
	}
	// 官方 PoC 要求 text/plain：form-urlencoded 会在 SpEL 求值前就解析失败
	if !strings.HasPrefix(gotCT, "text/plain") {
		t.Fatalf("Content-Type = %q, want text/plain", gotCT)
	}
}
