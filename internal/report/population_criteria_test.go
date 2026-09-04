// @spec system-compliance-scoring
//
// What a signed artifact counts, how its generation is identified, and the
// snapshot its content comes from.
package report

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/specfixture"
)

// seedPopulationHost seeds one host with rule state and matching frozen scan
// results, so the executive and attestation readers see the same fleet.
//
// A host with no counts gets a host row and nothing else: never scanned, no
// completed run, no results. That is the case the population-first queries
// exist for.
func seedPopulationHost(t *testing.T, pool *pgxpool.Pool, owner uuid.UUID,
	counts map[string]int, framework string, deleted bool) uuid.UUID {
	t.Helper()
	hostID := seedHost(t, pool, owner, deleted)
	total := 0
	for _, n := range counts {
		total += n
	}
	if total == 0 {
		return hostID
	}
	scanID := seedScanRun(t, pool, hostID)
	refs := `{"` + framework + `": ["x"]}`
	for _, status := range []string{"pass", "fail", "skipped", "error"} {
		for i := 0; i < counts[status]; i++ {
			ruleID := status + "-" + uuid.NewString()
			seedRuleStateFW(t, pool, hostID, ruleID, status, "medium", refs)
			seedScanResult(t, pool, scanID, hostID, ruleID, status, refs)
		}
	}
	return hostID
}

// @ac AC-37
// AC-37: participation counts account for every active in-scope host, not
// only the hosts that happen to have rows.
func TestPopulation_CountsEveryInScopeHost(t *testing.T) {
	t.Run("system-compliance-scoring/AC-37", func(t *testing.T) {
		ac := scoringAC(t, "AC-37")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		pool := freshPool(t)
		ctx := context.Background()
		svc := NewService(pool)
		owner := seedUser(t, pool)
		lens := in.Str("lens")

		var softDeleted uuid.UUID
		for _, h := range in.MapList("hosts") {
			c := h.Map("counts")
			counts := map[string]int{}
			for _, k := range []string{"pass", "fail", "skipped", "error"} {
				if c.Has(k) {
					counts[k] = c.Int(k)
				}
			}
			c.AllConsumed()
			fw := lens
			if h.Has("framework") {
				fw = h.Str("framework")
			}
			deleted := h.Has("deleted") && h.Bool("deleted")
			id := seedPopulationHost(t, pool, owner, counts, fw, deleted)
			// The fixture's own name for the case, so a failure says which
			// host shape broke rather than printing a uuid.
			if h.Str("id") == "soft_deleted" {
				if !deleted {
					t.Fatal("the soft_deleted fixture host is not marked deleted")
				}
				softDeleted = id
			}
			h.AllConsumed()
		}

		for _, kind := range in.StrList("kinds") {
			rep, err := svc.Generate(ctx, "ac37@example.com",
				GenerateRequest{Kind: Kind(kind), Framework: lens})
			if err != nil {
				t.Fatalf("%s: generate: %v", kind, err)
			}
			prov, score := provenanceOf(t, kind, rep.Content)

			if prov.HostsTotal != exp.Int("hosts_total") {
				t.Errorf("%s: hosts_total = %d, want %d; the population is every active "+
					"in-scope host, not the hosts that produced rows",
					kind, prov.HostsTotal, exp.Int("hosts_total"))
			}
			if prov.HostsScored != exp.Int("hosts_scored") {
				t.Errorf("%s: hosts_scored = %d, want %d",
					kind, prov.HostsScored, exp.Int("hosts_scored"))
			}
			if prov.HostsWithoutScore != exp.Int("hosts_without_score") {
				t.Errorf("%s: hosts_without_score = %d, want %d; a host that was never "+
					"scanned, produced no verdict, or carries nothing this lens matches is "+
					"counted here rather than dropped",
					kind, prov.HostsWithoutScore, exp.Int("hosts_without_score"))
			}
			// The reconciliation the counts exist for. Totals that do not add
			// up are undetectable once the artifact is signed.
			if !exp.Bool("participation_reconciles") {
				t.Fatal("fixture must require the counts to reconcile")
			}
			if prov.HostsScored+prov.HostsWithoutScore != prov.HostsTotal {
				t.Errorf("%s: %d scored plus %d without a score is not %d total",
					kind, prov.HostsScored, prov.HostsWithoutScore, prov.HostsTotal)
			}
			if score == nil || *score != exp.Num("score_pct") {
				t.Errorf("%s: score_pct = %v, want %v; the unscored hosts are counted, never "+
					"averaged in as zero", kind, score, exp.Num("score_pct"))
			}
			// The soft-deleted host is not in the population at all, so it
			// cannot be the reason a count happens to look right.
			if exp.Bool("soft_deleted_counted") {
				t.Fatal("fixture must exclude the soft-deleted host")
			}
			if raw, err := json.Marshal(rep.Content); err == nil &&
				softDeleted != uuid.Nil &&
				jsonContains(string(raw), softDeleted.String()) {
				t.Errorf("%s: the soft-deleted host appears in the artifact", kind)
			}
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

func jsonContains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		func() bool {
			for i := 0; i+len(needle) <= len(haystack); i++ {
				if haystack[i:i+len(needle)] == needle {
					return true
				}
			}
			return false
		}()
}

// provenanceOf pulls the envelope and score out of a kind's content.
func provenanceOf(t *testing.T, kind string, content []byte) (*ScoreProvenance, *float64) {
	t.Helper()
	switch Kind(kind) {
	case KindAttestation:
		var c AttestationContent
		if err := json.Unmarshal(content, &c); err != nil {
			t.Fatalf("decode attestation: %v", err)
		}
		if c.Rollup.Provenance == nil {
			t.Fatal("attestation carries no provenance")
		}
		return c.Rollup.Provenance, c.Rollup.ScorePct
	default:
		var c ExecutiveContent
		if err := json.Unmarshal(content, &c); err != nil {
			t.Fatalf("decode executive: %v", err)
		}
		if c.Provenance == nil {
			t.Fatal("executive carries no provenance")
		}
		return c.Provenance, c.ScorePct
	}
}

// @ac AC-38
// AC-38: only the ABSENCE of the provenance key means legacy. Present but
// unusable provenance is rejected rather than read as history.
func TestGeneration_DiscriminationIsStrict(t *testing.T) {
	t.Run("system-compliance-scoring/AC-38", func(t *testing.T) {
		ac := scoringAC(t, "AC-38")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		legacy := in.Map("legacy_shape")
		legacyKind := legacy.Str("kind")
		if legacy.Bool("provenance_key_present") {
			t.Fatal("the legacy shape is defined by the key being ABSENT")
		}
		legacy.AllConsumed()

		pct := 53
		legacyBytes, err := json.Marshal(legacyExecutiveContent{
			CompliancePct: &pct, TopFailingRules: []TopFailingRule{}})
		if err != nil {
			t.Fatalf("marshal legacy: %v", err)
		}
		if !exp.Bool("legacy_accepted") || !exp.Bool("legacy_requires_absent_key") {
			t.Fatal("fixture must accept the absent-key shape and require absence")
		}
		if !isLegacyArtifact(legacyKind, legacyBytes) {
			t.Fatal("an artifact with no provenance key was not read as legacy")
		}
		if err := checkScoreFields(legacyKind, legacyBytes); err != nil {
			t.Errorf("the legacy shape was rejected: %v", err)
		}

		// Every ambiguous shape, each built as RAW JSON so the test can
		// express what a struct cannot: a present key holding null.
		bodies := map[string]string{
			"provenance_null":                  `{"compliance_pct":53,"provenance":null}`,
			"provenance_empty_object":          `{"compliance_pct":53,"provenance":{}}`,
			"artifact_class_empty":             `{"provenance":{"artifact_class":""}}`,
			"artifact_class_unknown":           `{"provenance":{"artifact_class":"guess"}}`,
			"compliance_pct_null_on_current":   `{"compliance_pct":null,"score_pct":90,"provenance":{"artifact_class":"score_bearing"}}`,
			"rollup_compliance_pct_on_current": `{"rollup":{"compliance_pct":53,"score_pct":90,"provenance":{"artifact_class":"score_bearing"}}}`,
		}
		rejected := 0
		for _, shape := range in.MapList("rejected_shapes") {
			kind := shape.Str("kind")
			name := shape.Str("case")
			shape.AllConsumed()
			body, ok := bodies[name]
			if !ok {
				t.Fatalf("fixture names case %q, which this test does not build", name)
			}
			if err := checkScoreFields(kind, []byte(body)); err == nil {
				t.Errorf("%s (%s) was accepted; only an ABSENT provenance key means legacy, "+
					"and a current artifact carries exactly one score", name, kind)
				continue
			}
			rejected++
			// And none of them may be mistaken for history.
			if isLegacyArtifact(kind, []byte(body)) {
				t.Errorf("%s (%s) was read as legacy; something wrote a provenance field and "+
					"failed to fill it, which is not the same as never having had one",
					name, kind)
			}
		}
		if rejected != exp.Int("rejected_count") {
			t.Errorf("rejected %d shapes, want %d", rejected, exp.Int("rejected_count"))
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-39
// AC-39: the whole frozen content comes from one repeatable-read, read-only
// snapshot, so a scan completing mid-generation cannot land in half of it.
func TestFrozenContent_ComesFromOneSnapshot(t *testing.T) {
	t.Run("system-compliance-scoring/AC-39", func(t *testing.T) {
		ac := scoringAC(t, "AC-39")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		pool := freshPool(t)
		ctx := context.Background()
		svc := NewService(pool)
		owner := seedUser(t, pool)
		if in.Str("concurrent_write") == "" {
			t.Fatal("fixture must describe the concurrent write")
		}

		base := seedPopulationHost(t, pool, owner,
			map[string]int{"pass": 9, "fail": 1}, "framework_scored", false)
		_ = base

		// The snapshot's own properties, asserted by opening one and reading
		// what Postgres reports. A test that only compared two numbers could
		// pass on Read Committed whenever the race did not fire.
		var iso, mode string
		if err := svc.withFrozenSnapshot(ctx, func(q queryer) error {
			if err := q.QueryRow(ctx, "SHOW transaction_isolation").Scan(&iso); err != nil {
				return err
			}
			return q.QueryRow(ctx, "SHOW transaction_read_only").Scan(&mode)
		}); err != nil {
			t.Fatalf("open snapshot: %v", err)
		}
		if iso != exp.Str("isolation_level") {
			t.Errorf("transaction_isolation = %q, want %q; under read committed each "+
				"statement takes its own snapshot and the content can disagree with itself",
				iso, exp.Str("isolation_level"))
		}
		if wantRO := exp.Str("access_mode"); (mode == "on") != (wantRO == "read only") {
			t.Errorf("transaction_read_only = %q, want %q", mode, wantRO)
		}

		// The behavior: a write committed after the snapshot opens is
		// invisible to every read inside it.
		if !exp.Bool("content_reads_share_one_snapshot") ||
			!exp.Bool("concurrent_write_invisible") {
			t.Fatal("fixture must require one snapshot and an invisible concurrent write")
		}
		for _, kind := range in.StrList("kinds") {
			var first, second int
			err := svc.withFrozenSnapshot(ctx, func(q queryer) error {
				if err := q.QueryRow(ctx,
					`SELECT count(*)::int FROM hosts WHERE deleted_at IS NULL`).
					Scan(&first); err != nil {
					return err
				}
				// Committed by a DIFFERENT connection, after the snapshot's
				// first read. Under read committed the second count would see
				// it; under repeatable read it must not.
				seedHost(t, pool, owner, false)
				return q.QueryRow(ctx,
					`SELECT count(*)::int FROM hosts WHERE deleted_at IS NULL`).Scan(&second)
			})
			if err != nil {
				t.Fatalf("%s: snapshot: %v", kind, err)
			}
			if first != second {
				t.Errorf("%s: the snapshot saw %d hosts and then %d; a host that appeared "+
					"mid-generation reached part of the content, so a signed artifact can "+
					"describe two different fleets", kind, first, second)
			}
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}
