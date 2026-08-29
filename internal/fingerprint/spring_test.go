package fingerprint

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

func serverWithProbe(t *testing.T, probeBody string) model.Target {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/__ssp_probe_") {
			_, _ = w.Write([]byte(probeBody))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(ts.Close)
	return model.Target{URL: ts.URL + "/", Client: client.New("", time.Second)}
}

func TestDetectWhitelabel(t *testing.T) {
	tgt := serverWithProbe(t, "<html><body>Whitelabel Error Page</body></html>")
	res, err := Detect(context.Background(), tgt)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsSpring {
		t.Fatalf("expected Spring detection: %+v", res)
	}
	if res.Confidence != "high" {
		t.Fatalf("expected high confidence, got %s", res.Confidence)
	}
}

func TestDetectBootJSONError(t *testing.T) {
	tgt := serverWithProbe(t, `{"timestamp":"2026-08-29","status":500,"error":"Internal Server Error"}`)
	res, err := Detect(context.Background(), tgt)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsSpring {
		t.Fatalf("expected Spring detection: %+v", res)
	}
	if res.Confidence != "medium" {
		t.Fatalf("expected medium confidence, got %s", res.Confidence)
	}
}

func TestDetectNone(t *testing.T) {
	tgt := serverWithProbe(t, "plain 404 page")
	res, err := Detect(context.Background(), tgt)
	if err != nil {
		t.Fatal(err)
	}
	if res.IsSpring || res.Confidence != "none" {
		t.Fatalf("expected no detection: %+v", res)
	}
}
