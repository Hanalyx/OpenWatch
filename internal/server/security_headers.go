package server

import (
	"net/http"
	"strings"
)

// Security response headers — the hardening an NGINX/Caddy edge would
// normally add. The single binary serves both the SPA and the API from one
// origin, so all of it must live here. Spec system-http-server C-12.
const (
	hstsValue       = "max-age=63072000; includeSubDomains"
	referrerPolicy  = "no-referrer"
	frameOptions    = "DENY"
	contentTypeOpts = "nosniff"

	// appCSP locks the SPA + API origin down. Vite emits external module
	// bundles (no inline JS) so script-src 'self' is sufficient; MUI/emotion
	// inject <style> at runtime so style-src needs 'unsafe-inline'. No
	// framing (clickjacking), no plugins, no <base>/form hijack.
	appCSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; " +
		"frame-ancestors 'none'; base-uri 'self'; object-src 'none'; form-action 'self'"

	// docsCSP relaxes script/style for the embedded Swagger UI (it bootstraps
	// via an inline script). Framing is still denied.
	docsCSP = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; object-src 'none'"
)

// securityHeaders sets HSTS, CSP, X-Content-Type-Options, X-Frame-Options,
// and Referrer-Policy on every response (API, SPA, and error paths alike).
// Mounted right after correlation. Spec system-http-server C-12 / AC-17.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", hstsValue)
		h.Set("X-Content-Type-Options", contentTypeOpts)
		h.Set("X-Frame-Options", frameOptions)
		h.Set("Referrer-Policy", referrerPolicy)
		if strings.HasPrefix(r.URL.Path, DocsPath) {
			h.Set("Content-Security-Policy", docsCSP)
		} else {
			h.Set("Content-Security-Policy", appCSP)
		}
		next.ServeHTTP(w, r)
	})
}
