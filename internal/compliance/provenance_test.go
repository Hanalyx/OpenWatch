// Unit tests for envelope construction. No @spec or @ac annotations: AC-16
// through AC-25 describe response and signed-artifact behavior, and these cover
// only the constructor. The annotations move to the contract tests.
package compliance

import "testing"

// oneEngine is the ordinary single-engine case: every contributing outcome was
// produced by the same scan engine version.
var oneEngine = []EngineContributor{{EngineVersion: "v0.9.0", ContributorsScored: 3}}

func ptr(s string) *string { return &s }

// Construction must refuse every shape that would produce provenance nobody can
// trust after it is signed. Each case is a way the first, unvalidated version
// of ScoreBearingEnvelope would have returned a usable envelope.
func TestScoreBearingEnvelope_RefusesInvalidProvenance(t *testing.T) {
	one := []CorpusContributor{{Version: ptr("0.10.0"), Digest: "aaa", ContributorsScored: 3}}
	cases := []struct {
		name         string
		lens, agg    string
		engine       []EngineContributor
		contributors []CorpusContributor
		unidentified int
		hostsScored  int
	}{
		{"empty lens", "", AggregationEqualHostMean, oneEngine, one, 0, 3},
		{"unknown aggregation", "all_rules", "pooled", oneEngine, one, 0, 3},
		{"empty engine version", "all_rules", AggregationEqualHostMean, []EngineContributor{{EngineVersion: "", ContributorsScored: 3}}, one, 0, 3},
		{"negative unidentified", "all_rules", AggregationEqualHostMean, oneEngine, one, -1, 3},
		{"empty digest", "all_rules", AggregationEqualHostMean, oneEngine,
			[]CorpusContributor{{Digest: "", ContributorsScored: 1}}, 0, 1},
		{"version pointer to empty string", "all_rules", AggregationEqualHostMean, oneEngine,
			[]CorpusContributor{{Version: ptr(""), Digest: "aaa", ContributorsScored: 1}}, 0, 1},
		{"zero contributors", "all_rules", AggregationEqualHostMean, oneEngine,
			[]CorpusContributor{{Digest: "aaa", ContributorsScored: 0}}, 0, 0},
		{"negative contributors", "all_rules", AggregationEqualHostMean, oneEngine,
			[]CorpusContributor{{Digest: "aaa", ContributorsScored: -2}}, 0, 0},
		{"same digest, conflicting versions", "all_rules", AggregationEqualHostMean, oneEngine,
			[]CorpusContributor{
				{Version: ptr("0.10.0"), Digest: "aaa", ContributorsScored: 1},
				{Version: ptr("0.9.0"), Digest: "aaa", ContributorsScored: 1},
			}, 0, 2},
		{"counts do not reconcile", "all_rules", AggregationEqualHostMean, oneEngine, one, 0, 99},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ScoreBearingEnvelope(tc.lens, tc.agg, tc.engine, 0, tc.contributors, tc.unidentified, tc.hostsScored)
			if err == nil {
				t.Fatal("construction succeeded; this envelope must not be signable")
			}
		})
	}
}

// A duplicate digest with an identical version is one corpus reported twice, not
// two corpora. Merging is what keeps the status honest.
func TestScoreBearingEnvelope_MergesDuplicateDigest(t *testing.T) {
	env, err := ScoreBearingEnvelope("all_rules", AggregationEqualHostMean, oneEngine, 0,
		[]CorpusContributor{
			{Version: ptr("0.10.0"), Digest: "aaa", ContributorsScored: 2},
			{Version: ptr("0.10.0"), Digest: "aaa", ContributorsScored: 1},
		}, 0, 3)
	if err != nil {
		t.Fatalf("construction failed: %v", err)
	}
	if len(env.Corpora) != 1 {
		t.Fatalf("corpora = %d entries, want 1 merged entry", len(env.Corpora))
	}
	if got := env.Corpora[0].ContributorsScored; got != 3 {
		t.Errorf("contributors_scored = %d, want 3", got)
	}
	if env.Status != CorpusIdentified {
		t.Errorf("status = %q, want identified; unmerged duplicates would report mixed for one corpus", env.Status)
	}
}

// Ordering is deterministic, because a signature is taken over the canonical
// face and input order must not change the bytes.
func TestScoreBearingEnvelope_SortsByDigest(t *testing.T) {
	build := func(cs []CorpusContributor) Envelope {
		env, err := ScoreBearingEnvelope("all_rules", AggregationEqualHostMean, oneEngine, 0, cs, 0, 3)
		if err != nil {
			t.Fatalf("construction failed: %v", err)
		}
		return env
	}
	a := build([]CorpusContributor{
		{Version: ptr("0.10.0"), Digest: "bbb", ContributorsScored: 2},
		{Version: ptr("0.9.0"), Digest: "aaa", ContributorsScored: 1},
	})
	b := build([]CorpusContributor{
		{Version: ptr("0.9.0"), Digest: "aaa", ContributorsScored: 1},
		{Version: ptr("0.10.0"), Digest: "bbb", ContributorsScored: 2},
	})
	if a.Corpora[0].Digest != "aaa" || b.Corpora[0].Digest != "aaa" {
		t.Fatalf("corpora not sorted by digest: %v / %v", a.Corpora, b.Corpora)
	}
	if a.Status != CorpusMixed || b.Status != CorpusMixed {
		t.Errorf("status = %q / %q, want mixed for two distinct corpora", a.Status, b.Status)
	}
	if a.CorpusDigest != nil || a.CorpusVersion != nil {
		t.Error("singular corpus fields populated under mixed; they carry a value only under identified")
	}
}

// A read model states that corpus identity does not apply, and omits every
// field that has no referent. Decision record 10.
func TestReadModelEnvelope_OmitsWhatHasNoReferent(t *testing.T) {
	env := ReadModelEnvelope()
	if env.Class != ReadModel {
		t.Errorf("class = %q, want read_model", env.Class)
	}
	if env.Status != CorpusNotApplicable {
		t.Errorf("status = %q, want not_applicable; unavailable would claim identity is missing rather than inapplicable", env.Status)
	}
	if env.FormulaVersion != nil || env.AggregationMethod != nil || env.Lens != nil || env.EngineVersion != nil {
		t.Error("scoring metadata present on an artifact that computed no score")
	}
	if env.Corpora != nil || env.HostsWithoutCorpusIdentity != nil {
		t.Error("contributor accounting present on an artifact that aggregated no scan set")
	}
	if !env.Reconciles(0) {
		t.Error("a read model must reconcile trivially")
	}
}
