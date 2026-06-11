// @spec system-correlation
//
// AC traceability:
// @ac AC-09  (TestHTTPMiddleware_SetsResponseHeader, TestHTTPMiddleware_SetsContext)
// @ac AC-10  (TestHTTPMiddleware_EchoesValidClient)
// @ac AC-11  (TestHTTPMiddleware_RegeneratesInvalid)

package correlation

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// @ac AC-09  (Middleware sets X-Correlation-Id response header to the same value)
// that From(r.Context()) returns inside the next handler.
func TestHTTPMiddleware_SetsResponseHeader(t *testing.T) {
	t.Run("system-correlation/AC-09", func(t *testing.T) {

		var seen string
		h := HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, ok := From(r.Context())
			if !ok {
				t.Fatal("From(r.Context()) returned ok=false in handler")
			}
			seen = id
			w.WriteHeader(http.StatusNoContent)
		}))

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		got := rec.Header().Get(HeaderName)
		if got == "" {
			t.Fatal("response missing X-Correlation-Id")
		}
		if got != seen {
			t.Errorf("response header %q != context id %q", got, seen)
		}
		if !strings.HasPrefix(got, "req-") {
			t.Errorf("got %q, want req- prefix", got)
		}
	})
}

// @ac AC-09  ((companion): handler-side context has the id.)
func TestHTTPMiddleware_SetsContext(t *testing.T) {
	t.Run("system-correlation/AC-09", func(t *testing.T) {

		called := false
		h := HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			if _, ok := From(r.Context()); !ok {
				t.Error("context missing correlation id")
			}
		}))
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		h.ServeHTTP(httptest.NewRecorder(), req)
		if !called {
			t.Fatal("next handler not called")
		}
	})
}

// @ac AC-10  (Valid client X-Correlation-Id is echoed unchanged.)
func TestHTTPMiddleware_EchoesValidClient(t *testing.T) {
	t.Run("system-correlation/AC-10", func(t *testing.T) {

		client := "my-test-id-001"
		var seenInCtx string

		h := HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, _ := From(r.Context())
			seenInCtx = id
		}))

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(HeaderName, client)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Header().Get(HeaderName) != client {
			t.Errorf("response header = %q, want %q", rec.Header().Get(HeaderName), client)
		}
		if seenInCtx != client {
			t.Errorf("context id = %q, want %q", seenInCtx, client)
		}
	})
}

// @ac AC-11  (Invalid client header regenerates and the response carries a req- ID.)
// Also verifies handler-side context has the regenerated value, not the bad input.
func TestHTTPMiddleware_RegeneratesInvalid(t *testing.T) {
	t.Run("system-correlation/AC-11", func(t *testing.T) {

		bads := []string{
			strings.Repeat("a", 100), // too long
			"has spaces",             // bad charset
			"boot-impersonator",      // reserved prefix
			"<script>alert(1)</script>",
		}
		for _, bad := range bads {
			t.Run(bad, func(t *testing.T) {
				var seenInCtx string
				h := HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					seenInCtx, _ = From(r.Context())
				}))

				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set(HeaderName, bad)
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)

				respHdr := rec.Header().Get(HeaderName)
				if respHdr == bad {
					t.Errorf("response echoed bad input %q (should have been regenerated)", bad)
				}
				if !strings.HasPrefix(respHdr, "req-") {
					t.Errorf("response header = %q, want req- prefix", respHdr)
				}
				if seenInCtx != respHdr {
					t.Errorf("context id %q != response header %q", seenInCtx, respHdr)
				}
			})
		}
	})
}
