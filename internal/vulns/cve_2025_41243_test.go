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

func cve41243Server(t *testing.T, routeGET func(http.ResponseWriter, *http.Request), fileBody string) model.Target {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /actuator/gateway/routes/ssp41243probe", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("GET /actuator/gateway/routes/ssp41243probe", routeGET)
	mux.HandleFunc("DELETE /actuator/gateway/routes/ssp41243probe", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("POST /actuator/gateway/routes/ssp41243fs", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("GET /actuator/gateway/routes/ssp41243fs", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"filters":["[[AddResponseHeader X-SSP-Read = 'SSPBEGINroot:x:0:0:root:/root:/bin/bashSSPEND'], order = 1]"]}`))
	})
	mux.HandleFunc("GET /webjars/etc/passwd", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(fileBody))
	})
	mux.HandleFunc("POST /actuator/gateway/refresh", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return model.Target{URL: ts.URL + "/", Client: client.New("", time.Second)}
}

func TestCVE202541243DetectVulnerable(t *testing.T) {
	tgt := cve41243Server(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"filters":[{"args":{"name":"X-SSP-Marker","value":"SSPPROBE/usr/lib/jvm/java-17"}}]}`))
	}, "")

	verdict, err := (&cve202541243{}).Detect(context.Background(), tgt)
	if err != nil {
		t.Fatal(err)
	}
	if !verdict.Vulnerable {
		t.Fatalf("expected vulnerable, got %+v", verdict)
	}
	if !strings.Contains(verdict.Evidence, "/usr/lib/jvm") {
		t.Fatalf("evidence should contain evaluated java.home: %+v", verdict)
	}
}

func TestCVE202541243DetectPatched(t *testing.T) {
	// 补丁版：表达式未求值，响应仍包含字面量 #{ 与异常关键字
	tgt := cve41243Server(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"filters":[{"args":{"value":"#{'SSPPROBE' + @systemProperties['java.home']}"},"error":"SpelEvaluationException EL1005E"}}]}`))
	}, "")

	verdict, err := (&cve202541243{}).Detect(context.Background(), tgt)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Vulnerable {
		t.Fatalf("expected patched target to be clean, got %+v", verdict)
	}
}

func TestCVE202541243DetectNotExposed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	tgt := model.Target{URL: ts.URL + "/", Client: client.New("", time.Second)}
	verdict, err := (&cve202541243{}).Detect(context.Background(), tgt)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Vulnerable {
		t.Fatalf("expected clean when actuator not exposed, got %+v", verdict)
	}
}

func TestCVE202541243Exploit(t *testing.T) {
	tgt := cve41243Server(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}, "root:x:0:0:root:/root:/bin/bash\n")

	out, note, err := (&cve202541243{}).Exploit(context.Background(), tgt, "/etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "root:x") {
		t.Fatalf("expected file content in output, got %q", out)
	}
	if !strings.Contains(note, "恢复") {
		t.Fatalf("expected restore note, got %q", note)
	}
}
