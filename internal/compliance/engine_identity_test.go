// @spec system-compliance-scoring
//
// The four engine-identity states, and the list itself.
//
// They exist because the first implementation carried a bare list of distinct
// version strings, which could not tell "every scored host agreed" from "one
// host said this and the rest said nothing".
package compliance

import (
	"testing"

	"github.com/Hanalyx/openwatch/internal/specfixture"
)

// @ac AC-36
// AC-36: each engine-identity state is reachable, the returned list is asserted
// in every one of them, the entries are sorted, duplicates merge, and the
// counts must reconcile.
func TestEngineIdentity_FourStates(t *testing.T) {
	t.Run("system-compliance-scoring/AC-36", func(t *testing.T) {
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/system/compliance-scoring.spec.yaml", "system-compliance-scoring"), "AC-36")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		// readEngines turns a fixture's engines list into contributors,
		// consuming every field so a renamed key fails here.
		readEngines := func(f *specfixture.Fields) []EngineContributor {
			out := []EngineContributor{}
			for _, e := range f.MapList("engines") {
				out = append(out, EngineContributor{
					EngineVersion:      e.Str("engine_version"),
					ContributorsScored: e.Int("contributors_scored"),
				})
				// Each ENTRY, not just the outer map. The parent's AllConsumed
				// checks the top-level keys only, so an unused key added inside
				// an engine entry would go unread and unnoticed.
				e.AllConsumed()
			}
			return out
		}
		build := func(name string) (Envelope, error) {
			f := in.Map(name)
			engines := readEngines(f)
			without := f.Int("hosts_without_engine_identity")
			scored := f.Int("hosts_scored")
			f.AllConsumed()
			return ScoreBearingEnvelope("all_rules", AggregationEqualHostMean,
				engines, without, nil, scored, scored)
		}
		// assertEngines compares the RETURNED list entry by entry, and the
		// returned unidentified count. A status derived correctly from a list
		// nobody reads would still let the list be wrong, and a constructor
		// could validate the input count and then serialize a different one.
		assertEngines := func(label string, env Envelope, key, countKey string) {
			t.Helper()
			got := env.Engines
			want := exp
			wantList := want.MapList(key)
			if len(got) != len(wantList) {
				t.Fatalf("%s: engines = %+v, want %d entries", label, got, len(wantList))
			}
			for i, w := range wantList {
				if got[i].EngineVersion != w.Str("engine_version") {
					t.Errorf("%s: engines[%d].engine_version = %q, want %q",
						label, i, got[i].EngineVersion, w.Str("engine_version"))
				}
				if got[i].ContributorsScored != w.Int("contributors_scored") {
					t.Errorf("%s: engines[%d].contributors_scored = %d, want %d",
						label, i, got[i].ContributorsScored, w.Int("contributors_scored"))
				}
				w.AllConsumed()
			}
			if env.HostsWithoutEngineIdentity == nil {
				t.Fatalf("%s: hosts_without_engine_identity is absent", label)
			}
			if *env.HostsWithoutEngineIdentity != exp.Int(countKey) {
				t.Errorf("%s: hosts_without_engine_identity = %d, want %d; the value read back "+
					"must be the one validated, not merely a correct input",
					label, *env.HostsWithoutEngineIdentity, exp.Int(countKey))
			}
		}

		// The identified case. It was missing entirely: the criterion claimed
		// four reachable states and covered three, with unavailable twice.
		idEnv, err := build("identified")
		if err != nil {
			t.Fatalf("identified: construction failed: %v", err)
		}
		if string(idEnv.EngineIdentityStatus) != exp.Str("identified_status") {
			t.Errorf("identified: status = %q, want %q",
				idEnv.EngineIdentityStatus, exp.Str("identified_status"))
		}
		if idEnv.EngineVersion == nil || *idEnv.EngineVersion != exp.Str("identified_engine_version") {
			t.Errorf("identified: engine_version = %v, want %q; this is the ONE state where the "+
				"singular field carries a value", idEnv.EngineVersion,
				exp.Str("identified_engine_version"))
		}
		assertEngines("identified", idEnv, "identified_engines",
			"identified_hosts_without_engine_identity")

		// The three states with no singular version.
		for _, tc := range []struct{ fixture, statusKey, versionKey, enginesKey, countKey string }{
			{"known_plus_unknown", "known_plus_unknown_status",
				"known_plus_unknown_engine_version", "known_plus_unknown_engines",
				"known_plus_unknown_hosts_without_engine_identity"},
			{"two_known", "two_known_status", "two_known_engine_version", "two_known_engines",
				"two_known_hosts_without_engine_identity"},
			{"all_unknown", "all_unknown_status", "all_unknown_engine_version",
				"all_unknown_engines", "all_unknown_hosts_without_engine_identity"},
			{"zero_scored", "zero_scored_status", "zero_scored_engine_version",
				"zero_scored_engines", "zero_scored_hosts_without_engine_identity"},
		} {
			env, err := build(tc.fixture)
			if err != nil {
				t.Fatalf("%s: construction failed: %v", tc.fixture, err)
			}
			if string(env.EngineIdentityStatus) != exp.Str(tc.statusKey) {
				t.Errorf("%s: status = %q, want %q",
					tc.fixture, env.EngineIdentityStatus, exp.Str(tc.statusKey))
			}
			exp.IsNull(tc.versionKey)
			if env.EngineVersion != nil {
				t.Errorf("%s: engine_version = %q, want null under %q; that version does not "+
					"speak for the contributors that named none",
					tc.fixture, *env.EngineVersion, env.EngineIdentityStatus)
			}
			assertEngines(tc.fixture, env, tc.enginesKey, tc.countKey)
		}

		// Sorting. A signature is taken over the canonical face, so input order
		// must not change the bytes.
		sorted, err := build("unsorted_input")
		if err != nil {
			t.Fatalf("unsorted_input: construction failed: %v", err)
		}
		wantOrder := exp.List("sorted_order")
		if len(sorted.Engines) != len(wantOrder) {
			t.Fatalf("sorted: %d entries, want %d", len(sorted.Engines), len(wantOrder))
		}
		for i, w := range wantOrder {
			if sorted.Engines[i].EngineVersion != w {
				t.Errorf("sorted: engines[%d] = %q, want %q; entries are ordered by version so "+
					"the same content always produces the same bytes",
					i, sorted.Engines[i].EngineVersion, w)
			}
		}

		// Duplicate versions are one engine reported twice, not two engines.
		// Left unmerged they would report mixed for a fleet that agreed.
		merged, err := build("duplicate_versions")
		if err != nil {
			t.Fatalf("duplicate_versions: construction failed: %v", err)
		}
		assertEngines("duplicate_versions", merged, "duplicate_versions_merged_to",
			"identified_hosts_without_engine_identity")
		if merged.EngineIdentityStatus != EngineIdentified {
			t.Errorf("duplicate_versions: status = %q, want identified; two entries naming one "+
				"engine are one engine", merged.EngineIdentityStatus)
		}

		// The reconciliation guard. One contributor claiming five scored hosts
		// is an accounting nobody can check later.
		if !exp.Bool("does_not_reconcile_rejected") {
			t.Fatal("fixture must require the unreconciled case to be rejected")
		}
		if _, err := build("does_not_reconcile"); err == nil {
			t.Error("an envelope whose engine counts do not sum to hosts_scored was accepted")
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}
