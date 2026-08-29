package client

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDoSetsRandomUA(t *testing.T) {
	var gotUA string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	c := New("", time.Second)
	_, body, err := Do(context.Background(), c, http.MethodGet, ts.URL, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "ok") {
		t.Fatalf("unexpected body: %s", body)
	}
	if gotUA == "" {
		t.Fatal("User-Agent was not set")
	}
}

func TestDoRespectsProvidedUA(t *testing.T) {
	var gotUA string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
	}))
	defer ts.Close()

	c := New("", time.Second)
	if _, _, err := Do(context.Background(), c, http.MethodGet, ts.URL,
		map[string]string{"User-Agent": "ssp-test"}, ""); err != nil {
		t.Fatal(err)
	}
	if gotUA != "ssp-test" {
		t.Fatalf("custom UA overwritten, got %q", gotUA)
	}
}

func TestDoPostPayload(t *testing.T) {
	var gotBody string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
	}))
	defer ts.Close()

	c := New("", time.Second)
	if _, _, err := Do(context.Background(), c, http.MethodPost, ts.URL, nil, "a=1&b=2"); err != nil {
		t.Fatal(err)
	}
	if gotBody != "a=1&b=2" {
		t.Fatalf("payload not delivered, got %q", gotBody)
	}
}

func TestNoRedirectFollow(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/target")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/target", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("target"))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	c := New("", time.Second)
	resp, _, err := Do(context.Background(), c, http.MethodGet, ts.URL+"/redirect", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("redirect was followed, status = %d", resp.StatusCode)
	}
}

func TestNewInvalidProxyNoPanic(t *testing.T) {
	c := New("http://:bad", time.Second)
	if c == nil {
		t.Fatal("expected fallback client")
	}
}
