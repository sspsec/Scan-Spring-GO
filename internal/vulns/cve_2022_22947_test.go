package vulns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sspsec/Scan-Spring-GO/internal/client"
	"github.com/sspsec/Scan-Spring-GO/internal/model"
)

func TestCVE202222947Detect(t *testing.T) {
	var deleted atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("POST /actuator/gateway/routes/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("POST /actuator/gateway/refresh", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /actuator/gateway/routes/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"args":{"value":"uid=0(root) gid=0(root) groups=0(root)"}}`))
	})
	mux.HandleFunc("DELETE /actuator/gateway/routes/", func(w http.ResponseWriter, r *http.Request) {
		deleted.Store(true)
		w.WriteHeader(http.StatusOK)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	tgt := model.Target{URL: ts.URL + "/", Client: client.New("", time.Second)}
	verdict, err := (&cve202222947{}).Detect(context.Background(), tgt)
	if err != nil {
		t.Fatal(err)
	}
	if !verdict.Vulnerable {
		t.Fatalf("expected vulnerable, got %+v", verdict)
	}
	if !deleted.Load() {
		t.Fatal("expected probe route cleanup (DELETE) after detection")
	}
}
