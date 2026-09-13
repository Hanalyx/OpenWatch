// @spec system-compliance-scoring
//
// The removal, checked against the shipped artifacts rather than a grep run
// once by hand. A field that comes back in a later edit has to fail something.
package server

import (
	"os"
	"strings"
	"testing"

	"github.com/Hanalyx/openwatch/internal/specfixture"
)

// @ac AC-32
// AC-32: passing_fraction and total_evaluations are gone from the contract and
// from both generated clients.
//
// The point of checking the GENERATED artifacts, not just the source, is that a
// client's break is what makes the removal detectable. A consumer that still
// reads either field must fail at compile time in Go or at type-check time in
// TypeScript, rather than silently receiving a different quantity.
func TestRemovedFields_GoneFromContractAndClients(t *testing.T) {
	t.Run("system-compliance-scoring/AC-32", func(t *testing.T) {
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/system/compliance-scoring.spec.yaml", "system-compliance-scoring"), "AC-32")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		// Paths are relative to this package; the fixture names them from the
		// repository root, which is where a reader looks for them.
		roots := map[string]string{
			"api/openapi.yaml":                  "../../api/openapi.yaml",
			"internal/server/api/server.gen.go": "../../internal/server/api/server.gen.go",
			"frontend/src/api/schema.d.ts":      "../../frontend/src/api/schema.d.ts",
		}
		artifacts := in.List("artifacts")
		if len(artifacts) == 0 {
			t.Fatal("fixture names no artifacts")
		}

		counts := map[string]int{"passing_fraction": 0, "total_evaluations": 0}
		for _, raw := range artifacts {
			name, ok := raw.(string)
			if !ok {
				t.Fatalf("artifacts holds %T, want strings", raw)
			}
			path, known := roots[name]
			if !known {
				t.Fatalf("fixture names artifact %q, which this test does not know how to read", name)
			}
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			for field := range counts {
				if n := strings.Count(string(body), field); n > 0 {
					counts[field] += n
					t.Errorf("%s still contains %q %d time(s); it is removed with no alias, so "+
						"a client reading it must fail rather than receive a different quantity",
						name, field, n)
				}
			}
		}

		if want := exp.Int("occurrences_of_passing_fraction"); counts["passing_fraction"] != want {
			t.Errorf("passing_fraction occurrences = %d, want %d", counts["passing_fraction"], want)
		}
		if want := exp.Int("occurrences_of_total_evaluations"); counts["total_evaluations"] != want {
			t.Errorf("total_evaluations occurrences = %d, want %d", counts["total_evaluations"], want)
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}
