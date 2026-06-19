package server

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
)

// spaFiles holds the built single-page app. It is a build-time directory:
// `make build` populates internal/server/spa/ with the real `vite build`
// output; `make vet|lint|test*` populate it with a lightweight stub so the
// embed directive below compiles without a Node toolchain. The directory is
// gitignored (mirrors internal/server/openapi_embed.yaml).
//
//go:embed all:spa
var spaFiles embed.FS

// asset is one precomputed static file. Compression and the content hash
// are computed ONCE at handler construction (the embedded FS is fixed at
// build time), so request handling is a map lookup + a buffer write — the
// gzip CPU cost is never paid per request. This is the optimization an
// NGINX/Caddy front would otherwise provide; baking it into the binary
// keeps the single-binary deployment self-contained.
type asset struct {
	raw          []byte
	gz           []byte // nil when not compressible / gzip didn't help
	contentType  string
	etag         string
	cacheControl string
}

type spaHandler struct {
	assets map[string]*asset // keyed by clean path, e.g. "assets/index-abc.js"
	index  *asset            // served for the SPA fallback (client routes)
}

// newSPAHandler serves the embedded SPA with production-grade static
// delivery: gzip (when the client accepts it), immutable caching for the
// content-hashed assets Vite emits under assets/, ETag revalidation for the
// rest, and an index.html fallback so client-side routing survives deep
// links and reloads. Requests under /api/ never fall through — an unknown
// API route returns 404 so callers get a not-found, not an HTML page.
func newSPAHandler() http.Handler {
	sub, err := fs.Sub(spaFiles, "spa")
	if err != nil {
		// Only happens if the embed directory is missing at build time, which
		// the Makefile prevents. Fail loudly rather than serve nothing.
		panic("server: embedded spa/ directory not found: " + err.Error())
	}
	return newSPAHandlerFS(sub)
}

// newSPAHandlerFS builds the SPA handler over an arbitrary file system. The
// production constructor passes the embedded spa/ sub-FS; tests pass an
// in-memory fixture so static-delivery assertions (gzip, cache, ETag) don't
// depend on whatever filenames a `vite build` or the Makefile stub happens to
// stage. Splitting this out is the seam that makes those tests self-contained.
func newSPAHandlerFS(sub fs.FS) http.Handler {
	h := &spaHandler{assets: make(map[string]*asset)}
	walkErr := fs.WalkDir(sub, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, rerr := fs.ReadFile(sub, p)
		if rerr != nil {
			return rerr
		}
		a := buildAsset(p, raw)
		h.assets[p] = a
		if p == "index.html" {
			h.index = a
		}
		return nil
	})
	if walkErr != nil {
		panic("server: reading embedded spa/: " + walkErr.Error())
	}
	if h.index == nil {
		panic("server: embedded spa/index.html not found")
	}
	return h
}

// buildAsset precomputes the content type, ETag, cache policy, and (for
// compressible types) the gzip-encoded body for one embedded file.
func buildAsset(p string, raw []byte) *asset {
	sum := sha256.Sum256(raw)
	a := &asset{
		raw:          raw,
		contentType:  contentTypeFor(p),
		etag:         `"` + hex.EncodeToString(sum[:])[:16] + `"`,
		cacheControl: cachePolicy(p),
	}
	// Compress once at startup. Skip tiny bodies (the gzip framing overhead
	// isn't worth it) and only keep the result if it actually shrank.
	if compressible(p) && len(raw) >= 256 {
		var b bytes.Buffer
		zw, _ := gzip.NewWriterLevel(&b, gzip.BestCompression)
		if _, werr := zw.Write(raw); werr == nil && zw.Close() == nil && b.Len() < len(raw) {
			a.gz = append([]byte(nil), b.Bytes()...)
		}
	}
	return a
}

// cachePolicy returns the Cache-Control header for a given embedded path.
// Vite emits content-hashed filenames under assets/ (e.g. index-abc123.js),
// so those are immutable and cacheable for a year — the browser never
// re-requests them. Everything else (index.html, favicon, manifest) is
// revalidated so a new deploy is picked up immediately; the ETag makes that
// revalidation a cheap 304.
func cachePolicy(p string) string {
	if strings.HasPrefix(p, "assets/") {
		return "public, max-age=31536000, immutable"
	}
	return "no-cache"
}

// compressible reports whether a file's bytes are worth gzip-encoding.
// Already-compressed media (png/jpg/woff2/…) is excluded — re-compressing
// it wastes CPU and can grow the payload.
func compressible(p string) bool {
	switch strings.ToLower(path.Ext(p)) {
	case ".html", ".css", ".js", ".mjs", ".json", ".map", ".svg", ".txt", ".xml", ".webmanifest", ".wasm":
		return true
	}
	return false
}

// contentTypeFor maps an extension to a Content-Type, filling gaps the
// stdlib mime table can leave (notably .js on some platforms).
func contentTypeFor(p string) string {
	if ct := mime.TypeByExtension(path.Ext(p)); ct != "" {
		return ct
	}
	switch strings.ToLower(path.Ext(p)) {
	case ".js", ".mjs":
		return "text/javascript; charset=utf-8"
	case ".map", ".json":
		return "application/json"
	case ".webmanifest":
		return "application/manifest+json"
	case ".wasm":
		return "application/wasm"
	case ".svg":
		return "image/svg+xml"
	}
	return "application/octet-stream"
}

func (h *spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		http.Error(w, "404 page not found", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Look the path up in the precomputed table only — request handling
	// never touches the filesystem, so there is no path-traversal surface.
	clean := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	a, ok := h.assets[clean]
	if !ok || clean == "" {
		a = h.index // SPA fallback: client-side route or a refreshed deep link
	}
	h.serveAsset(w, r, a)
}

func (h *spaHandler) serveAsset(w http.ResponseWriter, r *http.Request, a *asset) {
	hdr := w.Header()
	hdr.Set("Content-Type", a.contentType)
	hdr.Set("Cache-Control", a.cacheControl)
	hdr.Set("ETag", a.etag)
	hdr.Set("Vary", "Accept-Encoding")

	if match := r.Header.Get("If-None-Match"); match != "" && etagMatches(match, a.etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	body := a.raw
	if a.gz != nil && clientAcceptsGzip(r) {
		hdr.Set("Content-Encoding", "gzip")
		body = a.gz
	}
	hdr.Set("Content-Length", strconv.Itoa(len(body)))

	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

// clientAcceptsGzip reports whether the request's Accept-Encoding lists gzip.
func clientAcceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		// Strip any q-value (e.g. "gzip;q=0.8") before comparing.
		if strings.EqualFold(strings.TrimSpace(strings.SplitN(part, ";", 2)[0]), "gzip") {
			return true
		}
	}
	return false
}

// etagMatches reports whether an If-None-Match header value covers etag,
// tolerating the weak-validator prefix and the "*" wildcard.
func etagMatches(headerVal, etag string) bool {
	for _, tag := range strings.Split(headerVal, ",") {
		tag = strings.TrimSpace(tag)
		tag = strings.TrimPrefix(tag, "W/")
		if tag == "*" || tag == etag {
			return true
		}
	}
	return false
}
