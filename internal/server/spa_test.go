// @spec system-http-server
package server

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// SPA serving: the embedded single-page app is returned for non-API routes
// (with an index.html fallback for client-side routing), and unmatched /api/
// paths return 404 rather than the SPA. These tests run against whatever is
// staged in internal/server/spa/ — the lightweight stub in CI, the real
// `vite build` output locally — so they assert structure, not page content.
//
// Subtests are named "system-http-server/AC-NN" so specter maps the test
// result to the acceptance criterion (sync ingests test names, not source
// comments).

func doSPAGet(t *testing.T, path string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	newSPAHandler().ServeHTTP(rec, req)
	return rec.Result()
}

// @ac AC-12
func TestSPA_RootServesIndexHTML(t *testing.T) {
	t.Run("system-http-server/AC-12", func(t *testing.T) {
		resp := doSPAGet(t, "/")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET / status = %d, want 200", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("GET / content-type = %q, want text/html", ct)
		}
		buf := make([]byte, 64)
		n, _ := resp.Body.Read(buf)
		if !strings.Contains(strings.ToLower(string(buf[:n])), "<!doctype html") {
			t.Errorf("GET / body does not look like an HTML document: %q", string(buf[:n]))
		}
	})
}

// @ac AC-13
func TestSPA_ClientRouteFallsBackToIndex(t *testing.T) {
	t.Run("system-http-server/AC-13", func(t *testing.T) {
		// A client-side route that is not a real file must still return the SPA
		// shell (200 + HTML) so deep links and reloads resolve.
		resp := doSPAGet(t, "/hosts/deep/link")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /hosts/deep/link status = %d, want 200 (SPA fallback)", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("fallback content-type = %q, want text/html", ct)
		}
	})
}

// @ac AC-14
func TestSPA_UnmatchedAPIPathReturns404(t *testing.T) {
	t.Run("system-http-server/AC-14", func(t *testing.T) {
		resp := doSPAGet(t, "/api/v1/definitely-not-a-route")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("GET unmatched /api/ status = %d, want 404", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); strings.HasPrefix(ct, "text/html") {
			t.Errorf("unmatched /api/ path served HTML (%q) — must not serve the SPA", ct)
		}
	})
}

// @ac AC-15
// AC-15: a compressible static asset is gzip-encoded when (and only when)
// the client sends Accept-Encoding: gzip, with a Vary: Accept-Encoding
// header so caches key on it. The gzipped body decodes to the original.
func TestSPA_GzipWhenAccepted(t *testing.T) {
	t.Run("system-http-server/AC-15", func(t *testing.T) {
		h := newSPAHandler()

		req := httptest.NewRequest(http.MethodGet, "/assets/app-abc123.js", nil)
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		resp := rec.Result()
		defer resp.Body.Close()

		if got := resp.Header.Get("Content-Encoding"); got != "gzip" {
			t.Fatalf("Content-Encoding = %q, want gzip", got)
		}
		if v := resp.Header.Get("Vary"); !strings.Contains(v, "Accept-Encoding") {
			t.Errorf("Vary = %q, want to contain Accept-Encoding", v)
		}
		gr, err := gzip.NewReader(resp.Body)
		if err != nil {
			t.Fatalf("body is not valid gzip: %v", err)
		}
		dec, _ := io.ReadAll(gr)
		if !bytes.Contains(dec, []byte("console.log")) {
			t.Errorf("decoded gzip body missing original content")
		}

		// No Accept-Encoding → identity (never force-encode).
		req2 := httptest.NewRequest(http.MethodGet, "/assets/app-abc123.js", nil)
		rec2 := httptest.NewRecorder()
		h.ServeHTTP(rec2, req2)
		if ce := rec2.Result().Header.Get("Content-Encoding"); ce != "" {
			t.Errorf("no Accept-Encoding but Content-Encoding = %q, want identity", ce)
		}
	})
}

// @ac AC-16
// AC-16: content-hashed assets under assets/ are served immutable + long
// max-age (the browser never re-requests them); the SPA shell (index.html)
// is no-cache so deploys are picked up; an ETag enables a 304 revalidation.
func TestSPA_CacheHeaders(t *testing.T) {
	t.Run("system-http-server/AC-16", func(t *testing.T) {
		h := newSPAHandler()

		req := httptest.NewRequest(http.MethodGet, "/assets/app-abc123.js", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		resp := rec.Result()
		cc := resp.Header.Get("Cache-Control")
		if !strings.Contains(cc, "immutable") || !strings.Contains(cc, "max-age=31536000") {
			t.Errorf("asset Cache-Control = %q, want immutable + max-age=31536000", cc)
		}
		etag := resp.Header.Get("ETag")
		if etag == "" {
			t.Fatal("asset has no ETag")
		}

		// Matching If-None-Match → 304 Not Modified.
		req2 := httptest.NewRequest(http.MethodGet, "/assets/app-abc123.js", nil)
		req2.Header.Set("If-None-Match", etag)
		rec2 := httptest.NewRecorder()
		h.ServeHTTP(rec2, req2)
		if rec2.Result().StatusCode != http.StatusNotModified {
			t.Errorf("If-None-Match (matching) status = %d, want 304", rec2.Result().StatusCode)
		}

		// The SPA shell must revalidate so a new deploy is seen immediately.
		req3 := httptest.NewRequest(http.MethodGet, "/", nil)
		rec3 := httptest.NewRecorder()
		h.ServeHTTP(rec3, req3)
		if got := rec3.Result().Header.Get("Cache-Control"); got != "no-cache" {
			t.Errorf("index.html Cache-Control = %q, want no-cache", got)
		}
	})
}

// @ac AC-17
// AC-17: every response carries the security headers (HSTS, CSP, nosniff,
// frame-deny, referrer-policy); /docs gets a Swagger-compatible CSP that
// still denies framing. Regression guard for the pre-release finding that
// the server set NO security headers at all.
func TestSecurityHeaders(t *testing.T) {
	t.Run("system-http-server/AC-17", func(t *testing.T) {
		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		h := securityHeaders(next)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/dashboard", nil))
		hd := rec.Header()
		if !strings.Contains(hd.Get("Strict-Transport-Security"), "includeSubDomains") {
			t.Errorf("HSTS = %q", hd.Get("Strict-Transport-Security"))
		}
		if hd.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("X-Content-Type-Options = %q, want nosniff", hd.Get("X-Content-Type-Options"))
		}
		if hd.Get("X-Frame-Options") != "DENY" {
			t.Errorf("X-Frame-Options = %q, want DENY", hd.Get("X-Frame-Options"))
		}
		if hd.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("Referrer-Policy = %q, want no-referrer", hd.Get("Referrer-Policy"))
		}
		csp := hd.Get("Content-Security-Policy")
		if !strings.Contains(csp, "frame-ancestors 'none'") || !strings.Contains(csp, "default-src 'self'") {
			t.Errorf("app CSP missing frame-ancestors/default-src: %q", csp)
		}
		if strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
			t.Errorf("app CSP must not allow inline scripts: %q", csp)
		}

		// /docs gets a relaxed (Swagger-compatible) CSP, still no framing.
		rec2 := httptest.NewRecorder()
		h.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/docs", nil))
		dcsp := rec2.Header().Get("Content-Security-Policy")
		if !strings.Contains(dcsp, "script-src 'self' 'unsafe-inline'") {
			t.Errorf("/docs CSP should relax script-src: %q", dcsp)
		}
		if !strings.Contains(dcsp, "frame-ancestors 'none'") {
			t.Errorf("/docs CSP must still deny framing: %q", dcsp)
		}
	})
}
