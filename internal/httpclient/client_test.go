// @spec system-correlation
//
// AC traceability:
// @ac AC-14  (TestClient_ForwardsHeaderFromCtx)
// @ac AC-15  (TestClient_PreservesExplicitHeader)
// @ac AC-16  (TestClient_NoHeaderWhenAbsent)

package httpclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Hanalyx/openwatch/internal/correlation"
)

// @ac AC-14  (When ctx has a correlation ID, the outbound request carries)
// X-Correlation-Id matching it.
func TestClient_ForwardsHeaderFromCtx(t *testing.T) {
	t.Run("system-correlation/AC-14", func(t *testing.T) {

		var seenHeader string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seenHeader = r.Header.Get(correlation.HeaderName)
		}))
		defer srv.Close()

		c := NewClient()
		ctx := correlation.Set(context.Background(), "req-test-001")

		resp, err := c.Get(ctx, srv.URL)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		resp.Body.Close()

		if seenHeader != "req-test-001" {
			t.Errorf("downstream saw X-Correlation-Id = %q, want req-test-001", seenHeader)
		}
	})
}

// @ac AC-15  (An explicitly-set X-Correlation-Id on the outbound request is)
// preserved (not overwritten by the context value).
func TestClient_PreservesExplicitHeader(t *testing.T) {
	t.Run("system-correlation/AC-15", func(t *testing.T) {

		var seenHeader string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seenHeader = r.Header.Get(correlation.HeaderName)
		}))
		defer srv.Close()

		c := NewClient()
		ctx := correlation.Set(context.Background(), "req-from-ctx")

		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
		req.Header.Set(correlation.HeaderName, "explicit-override")

		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		resp.Body.Close()

		if seenHeader != "explicit-override" {
			t.Errorf("downstream saw X-Correlation-Id = %q, want explicit-override", seenHeader)
		}
	})
}

// @ac AC-16  (When ctx has no correlation ID, the outbound request does NOT)
// carry an empty X-Correlation-Id header.
func TestClient_NoHeaderWhenAbsent(t *testing.T) {
	t.Run("system-correlation/AC-16", func(t *testing.T) {

		var headerPresent bool
		var headerValue string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			v, ok := r.Header[correlation.HeaderName]
			headerPresent = ok
			if ok && len(v) > 0 {
				headerValue = v[0]
			}
		}))
		defer srv.Close()

		c := NewClient()
		// Plain Background() — no correlation id set.
		resp, err := c.Get(context.Background(), srv.URL)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		resp.Body.Close()

		if headerPresent {
			t.Errorf("downstream received X-Correlation-Id = %q, want absent", headerValue)
		}
	})
}
