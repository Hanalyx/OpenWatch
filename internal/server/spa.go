package server

import (
	"io/fs"
	"net/http"
	"strings"

	"embed"
)

// spaFiles holds the built single-page app. It is a build-time directory:
// `make build` populates internal/server/spa/ with the real `vite build`
// output; `make vet|lint|test*` populate it with a lightweight stub so the
// embed directive below compiles without a Node toolchain. The directory is
// gitignored (mirrors internal/server/openapi_embed.yaml).
//
//go:embed all:spa
var spaFiles embed.FS

// newSPAHandler serves the embedded SPA. Real static assets (hashed JS/CSS,
// favicon, etc.) are served directly from the embedded FS; every other
// non-API path falls back to index.html so client-side routing survives deep
// links and page reloads. Requests under /api/ never fall through to the SPA —
// an unknown API route returns 404 so callers get a not-found, not an HTML page.
func newSPAHandler() http.Handler {
	sub, err := fs.Sub(spaFiles, "spa")
	if err != nil {
		// Only happens if the embed directory is missing at build time, which
		// the Makefile prevents. Fail loudly rather than serve nothing.
		panic("server: embedded spa/ directory not found: " + err.Error())
	}
	index, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		panic("server: embedded spa/index.html not found: " + err.Error())
	}
	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.Error(w, "404 page not found", http.StatusNotFound)
			return
		}
		clean := strings.TrimPrefix(r.URL.Path, "/")
		if clean != "" {
			if info, statErr := fs.Stat(sub, clean); statErr == nil && !info.IsDir() {
				fileServer.ServeHTTP(w, r)
				return
			}
		}
		// SPA fallback: client-side route or a refreshed deep link.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(index)
	})
}
