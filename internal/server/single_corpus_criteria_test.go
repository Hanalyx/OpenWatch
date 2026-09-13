// @spec system-compliance-scoring
//
// The degenerate provenance case: every contributor agrees, and it is the
// only case where the singular convenience fields carry a value.
package server

import (
	"encoding/json"
	"testing"

	"github.com/Hanalyx/openwatch/internal/compliance"
	"github.com/Hanalyx/openwatch/internal/report"
	"github.com/Hanalyx/openwatch/internal/specfixture"
)

// @ac AC-20
// AC-20: single corpus on a score-bearing artifact, across the report kinds
// that compute a fleet score and the two aggregate responses.
//
// Every kind here is built from the SAME envelope constructor. The point of
// naming four is that a second construction path is exactly how the product
// ended up with several formulas, so each one is asserted rather than
// assumed to inherit the first.
func TestSingleCorpus_IdentifiedAcrossScoreBearingKinds(t *testing.T) {
	t.Run("system-compliance-scoring/AC-20", func(t *testing.T) {
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/system/compliance-scoring.spec.yaml", "system-compliance-scoring"), "AC-20")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		contributors := []compliance.CorpusContributor{}
		scored := 0
		for _, c := range in.MapList("contributors") {
			hosts := c.Int("hosts")
			version := c.Str("corpus_version")
			contributors = append(contributors, compliance.CorpusContributor{
				Version:            &version,
				Digest:             c.Str("corpus_digest"),
				ContributorsScored: hosts,
			})
			scored += hosts
			c.AllConsumed()
		}
		without := in.Int("hosts_without_corpus_identity")

		env, err := compliance.ScoreBearingEnvelope("all_rules",
			compliance.AggregationEqualHostMean, nil, scored, contributors, without, scored)
		if err != nil {
			t.Fatalf("envelope: %v", err)
		}

		// assertEnvelope runs the same expectations against whatever shape a
		// kind serializes the envelope into.
		assertEnvelope := func(kind string, doc map[string]json.RawMessage) {
			t.Helper()
			str := func(field string) string {
				var v any
				if raw, ok := doc[field]; ok {
					_ = json.Unmarshal(raw, &v)
				}
				if s, ok := v.(string); ok {
					return s
				}
				return ""
			}
			if got := str("corpus_identity_status"); got != exp.Str("corpus_identity_status") {
				t.Errorf("%s: corpus_identity_status = %q, want %q",
					kind, got, exp.Str("corpus_identity_status"))
			}
			// The ONE state where the singular fields carry a value. One entry
			// in corpora is not enough on its own: partially_identified also
			// has one, alongside contributors that named none.
			if got := str("corpus_version"); got != exp.Str("corpus_version") {
				t.Errorf("%s: corpus_version = %q, want %q",
					kind, got, exp.Str("corpus_version"))
			}
			if got := str("corpus_digest"); got != exp.Str("corpus_digest") {
				t.Errorf("%s: corpus_digest = %q, want %q",
					kind, got, exp.Str("corpus_digest"))
			}
			var gotWithout int
			if raw, ok := doc["hosts_without_corpus_identity"]; ok {
				_ = json.Unmarshal(raw, &gotWithout)
			}
			if gotWithout != exp.Int("hosts_without_corpus_identity") {
				t.Errorf("%s: hosts_without_corpus_identity = %d, want %d",
					kind, gotWithout, exp.Int("hosts_without_corpus_identity"))
			}
			var corpora []struct {
				Version            *string `json:"corpus_version"`
				Digest             string  `json:"corpus_digest"`
				ContributorsScored int     `json:"contributors_scored"`
			}
			if raw, ok := doc["corpora"]; ok {
				if err := json.Unmarshal(raw, &corpora); err != nil {
					t.Fatalf("%s: decode corpora: %v", kind, err)
				}
			}
			wantCorpora := exp.MapList("corpora")
			if len(corpora) != len(wantCorpora) {
				t.Fatalf("%s: corpora = %+v, want %d entries", kind, corpora, len(wantCorpora))
			}
			for i, w := range wantCorpora {
				if corpora[i].Version == nil || *corpora[i].Version != w.Str("corpus_version") {
					t.Errorf("%s: corpora[%d].corpus_version = %v, want %q",
						kind, i, corpora[i].Version, w.Str("corpus_version"))
				}
				if corpora[i].Digest != w.Str("corpus_digest") {
					t.Errorf("%s: corpora[%d].corpus_digest = %q, want %q",
						kind, i, corpora[i].Digest, w.Str("corpus_digest"))
				}
				if corpora[i].ContributorsScored != w.Int("contributors_scored") {
					t.Errorf("%s: corpora[%d].contributors_scored = %d, want %d",
						kind, i, corpora[i].ContributorsScored, w.Int("contributors_scored"))
				}
				w.AllConsumed()
			}
		}

		// envelopeDoc marshals a value and returns the object holding the
		// envelope keys, wherever the kind nests it.
		envelopeDoc := func(kind string, v any) map[string]json.RawMessage {
			t.Helper()
			raw, err := json.Marshal(v)
			if err != nil {
				t.Fatalf("%s: marshal: %v", kind, err)
			}
			var probe map[string]json.RawMessage
			if err := json.Unmarshal(raw, &probe); err != nil {
				t.Fatalf("%s: decode: %v", kind, err)
			}
			for _, nest := range []string{"provenance", "rollup"} {
				if inner, ok := probe[nest]; ok {
					var next map[string]json.RawMessage
					if err := json.Unmarshal(inner, &next); err == nil {
						if _, isEnvelope := next["corpus_identity_status"]; isEnvelope {
							return next
						}
						if deeper, ok := next["provenance"]; ok {
							var last map[string]json.RawMessage
							if err := json.Unmarshal(deeper, &last); err == nil {
								return last
							}
						}
					}
				}
			}
			return probe
		}

		agg := compliance.Aggregate{HostsTotal: scored, HostsScored: scored}
		prov := report.NewScoreProvenance(env, agg)

		for _, kind := range in.StrList("artifact_kinds") {
			switch kind {
			case "executive":
				assertEnvelope(kind, envelopeDoc(kind, report.ExecutiveContent{Provenance: prov}))
			case "attestation":
				assertEnvelope(kind, envelopeDoc(kind, report.AttestationContent{
					Rollup: report.AttestationRollup{Provenance: prov}}))
			case "fleet_score", "group_score":
				// Both aggregate responses serialize through envelopeWire, the
				// single conversion the handlers share.
				assertEnvelope(kind, envelopeDoc(kind, envelopeWire(env)))
			default:
				t.Fatalf("fixture names unknown artifact kind %q", kind)
			}
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}
