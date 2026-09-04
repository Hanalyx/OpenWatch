// @spec system-compliance-scoring
//
// The reason vocabulary is not published early.
//
// Every field named here becomes meaningful in 1.1.0, when KN-OW-021 gives
// each skipped outcome a typed reason. Until then OpenWatch cannot tell an
// inapplicable rule from an unevaluated one, so publishing any of them,
// even as null or zero, would state a fact nobody measured.
package server

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/Hanalyx/openwatch/internal/compliance"
	"github.com/Hanalyx/openwatch/internal/specfixture"
)

// schemaPropertyNames returns every property name declared anywhere in the
// OpenAPI document.
//
// It walks the parsed tree and collects the KEYS under each "properties"
// map. A raw substring count would be the wrong instrument: not_applicable
// is a legitimate corpus_identity_status enum VALUE under AC-33, so a
// grep-shaped test would fail on correct code and teach whoever hit it to
// add an exemption.
func schemaPropertyNames(t *testing.T, path string) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	names := map[string]bool{}
	var walk func(node any, underProperties bool)
	walk = func(node any, underProperties bool) {
		switch n := node.(type) {
		case map[string]any:
			for k, v := range n {
				if underProperties {
					names[k] = true
				}
				walk(v, k == "properties")
			}
		case []any:
			for _, v := range n {
				walk(v, false)
			}
		}
	}
	walk(doc, false)
	if len(names) == 0 {
		t.Fatal("the walker found no property names at all; it has gone blind and a clean " +
			"result from it would mean nothing")
	}
	return names
}

// @ac AC-16
// AC-16: no reason-specific fact is published or inferred while skips are
// untyped. Each field must be absent from the response, not null and not
// defaulted.
func TestReasonFields_AbsentUntilSkipsAreTyped(t *testing.T) {
	t.Run("system-compliance-scoring/AC-16", func(t *testing.T) {
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/system/compliance-scoring.spec.yaml", "system-compliance-scoring"), "AC-16")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		// The contract half. A field absent from the schema cannot be
		// serialized as null or defaulted by any handler.
		declared := schemaPropertyNames(t, "../../api/openapi.yaml")
		forbidden := exp.StrList("absent_fields")
		if len(forbidden) == 0 {
			t.Fatal("fixture names no fields; an absence check over nothing proves nothing")
		}
		for _, field := range forbidden {
			if declared[field] {
				t.Errorf("api/openapi.yaml declares a property %q; it is part of the reason "+
					"vocabulary KN-OW-021 defines, so publishing it now states a classification "+
					"no scan produced", field)
			}
		}
		// The instrument must be able to see a property that IS there,
		// otherwise the loop above passes on an empty map.
		if !declared["skip_reason"] {
			t.Error("the property walker cannot see skip_reason, which the contract does " +
				"declare; its clean result above means nothing")
		}

		// The behavior half, over the fixture's own counts. Untyped skips are
		// counted raw and classified nowhere.
		if in.Str("lens") == "" {
			t.Fatal("fixture states no lens")
		}
		c := in.Map("counts")
		counts := compliance.Counts{Pass: c.Int("pass"), Fail: c.Int("fail"), Skipped: c.Int("skipped")}
		c.AllConsumed()
		if in.Bool("skip_reasons_typed") {
			t.Fatal("fixture must describe the untyped world; that is what gates these fields")
		}

		if counts.NotApplicable != 0 || counts.NotAssessed != 0 {
			t.Errorf("counts classify %d skips as not-applicable and %d as not-assessed from "+
				"%d untyped skips; neither is derivable from an untyped skip",
				counts.NotApplicable, counts.NotAssessed, counts.Skipped)
		}
		// InScope must not absorb the skips either. Doing so would publish the
		// same inference through a denominator instead of a field.
		if got, want := counts.InScope(), counts.Pass+counts.Fail; got != want {
			t.Errorf("in-scope denominator = %d, want %d; folding %d untyped skips into it "+
				"asserts they were in scope, which is the inference this criterion forbids",
				got, want, counts.Skipped)
		}
		if cov := compliance.AssessmentCoverage(counts, false); cov.Pct.Present() {
			t.Error("a coverage percentage was published from untyped skips")
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}
