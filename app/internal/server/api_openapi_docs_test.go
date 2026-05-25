// @spec api-openapi-docs
//
// In-process tests for the OpenAPI spec + Swagger UI endpoints.

package server

import (
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

// @ac AC-01
// AC-01: GET /api/v1/openapi.yaml returns 200 with YAML content and no
// authentication required.
func TestOpenAPIDocs_SpecServed(t *testing.T) {
	t.Run("api-openapi-docs/AC-01", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		resp, err := http.Get(url + SpecPath)
		if err != nil {
			t.Fatalf("get spec: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		ct := resp.Header.Get("Content-Type")
		if !strings.Contains(ct, "yaml") {
			t.Errorf("Content-Type = %q, want yaml flavor", ct)
		}
		body, _ := io.ReadAll(resp.Body)
		// YAML files routinely start with a comment header before the
		// top-level keys. The body MUST contain the openapi top-level
		// key (the spec marker); position is irrelevant.
		if !strings.Contains(string(body), "\nopenapi:") && !strings.HasPrefix(string(body), "openapi:") {
			t.Errorf("spec body lacks 'openapi:' top-level key: %q...", body[:min(80, len(body))])
		}
		if !strings.Contains(string(body), "paths:") {
			t.Errorf("spec body lacks 'paths:' section; not a real OpenAPI doc")
		}
	})
}

// @ac AC-02
// AC-02: GET /docs returns HTML referencing the spec URL — Swagger UI
// loaded successfully and points at the right place.
func TestOpenAPIDocs_UIServed(t *testing.T) {
	t.Run("api-openapi-docs/AC-02", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		// swgui's handler treats the configured base path as a directory;
		// a request without the trailing slash redirects to the slashed form.
		resp, err := http.Get(url + DocsPath + "/")
		if err != nil {
			t.Fatalf("get docs: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		ct := resp.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "text/html") {
			t.Errorf("Content-Type = %q, want text/html", ct)
		}
		body, _ := io.ReadAll(resp.Body)
		s := string(body)
		if !strings.Contains(s, SpecPath) {
			t.Errorf("HTML does not reference %s — Swagger UI won't load the spec", SpecPath)
		}
		// Swagger UI v5's HTML always references "swagger-ui" in the
		// rendered title/script tags.
		if !strings.Contains(s, "swagger-ui") {
			t.Errorf("HTML lacks 'swagger-ui' marker; rendering broken")
		}
	})
}

// @ac AC-03
// AC-03: Swagger UI's JS / CSS assets are served same-origin from the
// binary, not from a CDN. Air-gap clean.
func TestOpenAPIDocs_AssetsAreSameOrigin(t *testing.T) {
	t.Run("api-openapi-docs/AC-03", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		resp, err := http.Get(url + DocsPath + "/")
		if err != nil {
			t.Fatalf("get docs: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		s := string(body)
		// No CDN host should appear in the HTML's script / link tags.
		// These are the usual suspects for swagger UI distributions.
		for _, cdnMarker := range []string{
			"unpkg.com",
			"cdn.jsdelivr.net",
			"cdnjs.cloudflare.com",
			"swagger.io/swagger-ui-dist",
		} {
			if strings.Contains(s, cdnMarker) {
				t.Errorf("HTML references CDN %q — must be air-gap clean (same-origin assets)", cdnMarker)
			}
		}
		// Confirm same-origin JS asset URLs exist (e.g.,
		// /docs/swagger-ui-bundle.js or similar relative path).
		if !strings.Contains(s, ".js") {
			t.Errorf("HTML has no .js reference; assets missing?")
		}
	})
}

// @ac AC-04
// AC-04: the embedded spec is byte-identical to app/api/openapi.yaml.
// Build-time copy must stay in sync.
func TestOpenAPIDocs_EmbeddedMatchesSource(t *testing.T) {
	t.Run("api-openapi-docs/AC-04", func(t *testing.T) {
		src, err := os.ReadFile("../../api/openapi.yaml")
		if err != nil {
			t.Fatalf("read source openapi.yaml: %v", err)
		}
		if string(src) != string(openAPISpec) {
			t.Errorf("embedded openapi spec drifted from source (rebuild via 'make build')")
		}
	})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
