package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sspsec/Scan-Spring-GO/internal/client"
	"github.com/sspsec/Scan-Spring-GO/internal/model"
)

func TestLeakScanFindings(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/actuator/env", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"timestamp":"2026-08-29","status":"up"}`))
	})
	mux.HandleFunc("/swagger-ui.html", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>swagger ui</html>"))
	})
	mux.HandleFunc("/druid/index.html", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>druid console</html>"))
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("please need login first"))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	tgt := model.Target{URL: ts.URL + "/", Client: client.New("", time.Second)}
	findings, skip := LeakScan(context.Background(), tgt, Options{
		Endpoints: []string{"actuator/env", "actuator/env", "swagger-ui.html", "druid/index.html", "login"},
		Threads:   4,
	})
	if skip != "" {
		t.Fatalf("unexpected skip reason: %s", skip)
	}
	if len(findings) != 3 {
		t.Fatalf("want 3 findings, got %d: %+v", len(findings), findings)
	}

	kinds := map[string]bool{}
	for _, f := range findings {
		if f.Status != http.StatusOK {
			t.Errorf("unexpected status %d for %s", f.Status, f.URL)
		}
		kinds[f.Kind] = true
	}
	for _, want := range []string{"actuator", "swagger", "druid"} {
		if !kinds[want] {
			t.Errorf("missing kind %q in %+v", want, findings)
		}
	}
}

func TestLeakScan503Skip(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	tgt := model.Target{URL: ts.URL + "/", Client: client.New("", time.Second)}
	findings, skip := LeakScan(context.Background(), tgt, Options{
		Endpoints: []string{"a", "b", "c"},
		Threads:   2,
	})
	if skip == "" {
		t.Fatal("expected skip reason on 503")
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings after 503 abort, got %+v", findings)
	}
}

func TestLeakScanVerboseTimeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte("late"))
	}))
	defer ts.Close()

	var msgs []string
	tgt := model.Target{URL: ts.URL + "/", Client: client.New("", 100*time.Millisecond)}
	findings, _ := LeakScan(context.Background(), tgt, Options{
		Endpoints: []string{"slow"},
		Threads:   1,
		Verbose:   true,
		Logf:      func(format string, args ...any) { msgs = append(msgs, format) },
	})
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %+v", findings)
	}
	if len(msgs) == 0 {
		t.Fatal("expected verbose log for timed-out request")
	}
}
