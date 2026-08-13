// @spec system-idempotency
//
// AC traceability:
//   AC-15  TestIdempotency_NoCachedRouteDependsOnAResponseHeader
//
// This file reads api/openapi.yaml and nothing else. It needs no database
// and no server, because the defect it guards against is declared in the
// contract before any code runs.

package idempotency

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// openAPIDoc is the slice of the contract this check reads: for every
// operation, the parameters it declares and the headers its responses
// declare. Everything else in the document is ignored.
//
// Responses carry a $ref as well as inline headers, because most 4xx bodies
// here are shared components. A header added to one of those would otherwise
// be invisible to this check while applying to every route that references
// it, which is the wider blast radius of the two.
type openAPIDoc struct {
	Paths map[string]map[string]struct {
		OperationID string                  `yaml:"operationId"`
		Parameters  []parameterNode         `yaml:"parameters"`
		Responses   map[string]responseNode `yaml:"responses"`
	} `yaml:"paths"`
	Components struct {
		Responses  map[string]responseNode  `yaml:"responses"`
		Parameters map[string]parameterNode `yaml:"parameters"`
	} `yaml:"components"`
}

type parameterNode struct {
	Name string `yaml:"name"`
	In   string `yaml:"in"`
	Ref  string `yaml:"$ref"`
}

type responseNode struct {
	Ref     string         `yaml:"$ref"`
	Headers map[string]any `yaml:"headers"`
}

// declaresIdempotencyKey reports whether an operation takes the header,
// following a $ref into components/parameters and reading the resolved
// parameter's own name rather than the key it is filed under.
//
// Matching the ref string instead would tie this check to what the component
// happens to be called. A shared parameter named IdempotencyKeyHeader would
// then make every route using it invisible here, and the vacuity guard would
// stay quiet because other routes still declare it inline. That is the same
// defect this file exists to catch: a check that still runs, still passes, and
// no longer covers what it names.
func declaresIdempotencyKey(doc openAPIDoc, params []parameterNode) bool {
	const prefix = "#/components/parameters/"
	for _, p := range params {
		if p.Ref != "" && strings.HasPrefix(p.Ref, prefix) {
			p = doc.Components.Parameters[strings.TrimPrefix(p.Ref, prefix)]
		}
		if p.In == "header" && p.Name == HeaderName {
			return true
		}
	}
	return false
}

// headersOf returns the headers a response declares, following one level of
// $ref into components/responses. OpenAPI allows a $ref to name another $ref;
// this repo's contract does not, and the vacuity guard in the test above is
// what would notice if that changed.
func headersOf(doc openAPIDoc, r responseNode) map[string]any {
	if r.Ref == "" {
		return r.Headers
	}
	const prefix = "#/components/responses/"
	if !strings.HasPrefix(r.Ref, prefix) {
		return r.Headers
	}
	return doc.Components.Responses[strings.TrimPrefix(r.Ref, prefix)].Headers
}

// @ac AC-15
// AC-15: a route that caches must not carry meaning in a response header.
//
// replayCached writes three things: Content-Type, the stored status and the
// stored body. Every other header the handler set is gone on the second call.
// A route that declares Idempotency-Key and also declares a response header is
// therefore a route whose repeat call returns 2xx with the header missing,
// which the client reads as a success it cannot act on. Login is the shape of
// the problem: three Set-Cookie headers, a 200, and no session.
//
// No route does this today. The point of the check is the day someone adds
// one, which is a contract edit rather than a code edit, so nothing else in
// the suite would notice.
func TestIdempotency_NoCachedRouteDependsOnAResponseHeader(t *testing.T) {
	t.Run("system-idempotency/AC-15", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi.yaml"))
		if err != nil {
			t.Fatalf("read openapi.yaml: %v", err)
		}
		var doc openAPIDoc
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("parse openapi.yaml: %v", err)
		}

		var cached []string
		for path, item := range doc.Paths {
			for method, op := range item {
				switch method {
				case "post", "put", "patch", "delete":
				default:
					// GET, HEAD and OPTIONS never reach the cache (C-02).
					continue
				}
				if !declaresIdempotencyKey(doc, op.Parameters) {
					continue
				}
				cached = append(cached, method+" "+path)

				for code, resp := range op.Responses {
					for name := range headersOf(doc, resp) {
						// Set-Cookie is wrong on any response of a cached
						// route, not only a 2xx: it is never captured, so it
						// can never be replayed.
						if strings.EqualFold(name, "Set-Cookie") {
							t.Errorf("%s %s declares Set-Cookie on %s; a replay never carries it",
								method, path, code)
							continue
						}
						if strings.HasPrefix(code, "2") {
							t.Errorf("%s %s declares response header %q on %s; a replay writes only "+
								"Content-Type, status and body, so the repeat call would omit it",
								method, path, name, code)
						}
					}
				}
			}
		}

		// A check that finds no routes is a check that proves nothing. If the
		// parameter is renamed or the parsing drifts, this is what says so.
		if len(cached) == 0 {
			t.Fatalf("no operation declares the %s parameter; either the contract changed "+
				"or this check stopped reading it, and either way it is no longer guarding anything",
				HeaderName)
		}
		sort.Strings(cached)
		t.Logf("checked %d operations declaring %s:\n  %s",
			len(cached), HeaderName, strings.Join(cached, "\n  "))
	})
}

// @ac AC-15
// AC-15: the replay path is the reason for the rule above, so assert it
// directly rather than trusting the comment. If replayCached ever learns to
// restore headers, this fails and the contract rule can be relaxed on
// purpose instead of drifting out of date.
func TestIdempotency_ReplayWritesOnlyContentTypeStatusAndBody(t *testing.T) {
	t.Run("system-idempotency/AC-15", func(t *testing.T) {
		src, err := os.ReadFile("middleware.go")
		if err != nil {
			t.Fatalf("read middleware.go: %v", err)
		}
		body := funcBody(string(src), "func replayCached(")
		if body == "" {
			t.Fatal("replayCached not found; this check no longer reads the replay path")
		}
		if n := strings.Count(body, "w.Header().Set("); n != 1 {
			t.Errorf("replayCached sets %d headers, want exactly 1 (Content-Type). "+
				"If it now restores captured headers, AC-15's contract rule needs revisiting.", n)
		}
		if !strings.Contains(body, `"Content-Type"`) {
			t.Error("replayCached no longer sets Content-Type")
		}
	})
}

// funcBody returns the source between a function's opening marker and the
// next top-level declaration, or "" when the marker is absent.
func funcBody(src, marker string) string {
	i := strings.Index(src, marker)
	if i < 0 {
		return ""
	}
	rest := src[i+len(marker):]
	if j := strings.Index(rest, "\nfunc "); j >= 0 {
		return rest[:j]
	}
	return rest
}
