// OpenAPI spec + Swagger UI served from the binary. Both endpoints are
// unauthenticated reference material and MUST be mounted before the
// identity binder + permission middleware.
//
// Spec: app/specs/api/openapi-docs.spec.yaml.

package server

import (
	_ "embed"
	"net/http"

	"github.com/go-chi/chi/v5"
	v5emb "github.com/swaggest/swgui/v5emb"
)

// openAPISpec is the OpenAPI YAML shipped with this binary. Embedded at
// build time so the docs travel with the artifact and require no
// runtime filesystem access — air-gap clean.
//
// openapi_embed.yaml is a gitignored build-time copy of api/openapi.yaml
// (go:embed cannot reference paths outside the package dir). It is kept in
// sync by `make generate-api` / `make build`; the directive below lets
// `go generate ./...` refresh it too, and TestOpenAPIDocs_EmbeddedMatchesSource
// fails the build if it ever drifts.
//
//go:generate cp ../../api/openapi.yaml openapi_embed.yaml
//go:embed openapi_embed.yaml
var openAPISpec []byte

// SpecPath is the route the OpenAPI YAML is served from. Swagger UI
// loads its schema from here.
const SpecPath = "/api/v1/openapi.yaml"

// DocsPath is the route Swagger UI is mounted at.
const DocsPath = "/docs"

// mountOpenAPIDocs wires the unauthenticated spec + Swagger UI routes
// onto r. Call BEFORE any identity / authorization middleware — these
// endpoints are reference material, not data, and reviewers in
// air-gapped environments need browser access without first solving
// the bootstrap dance.
//
// Spec api-openapi-docs C-02, AC-01, AC-02.
func mountOpenAPIDocs(r chi.Router) {
	r.Get(SpecPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(openAPISpec)
	})

	// swgui/v5emb embeds the Swagger UI v5 dist files (HTML + JS + CSS)
	// in the package; nothing is fetched from a CDN. The handler is
	// mounted under DocsPath and serves its assets relative to that
	// prefix.
	docsHandler := v5emb.NewHandler("OpenWatch API", SpecPath, DocsPath+"/")
	r.Mount(DocsPath, docsHandler)
}
