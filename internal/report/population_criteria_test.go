// @spec system-compliance-scoring
//
// What a signed artifact counts, how its generation is identified, and the
// snapshot its content comes from.
package report

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/db"

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
		bodies := map[string]map[string]string{
			"provenance_null": {
				"executive": `{"compliance_pct":53,"provenance":null}`},
			"provenance_empty_object": {
				"executive": `{"compliance_pct":53,"provenance":{}}`},
			"artifact_class_empty": {
				"executive": `{"provenance":{"artifact_class":""}}`},
			"artifact_class_unknown": {
				"executive": `{"provenance":{"artifact_class":"guess"}}`},
			"compliance_pct_null_on_current": {
				"executive": `{"compliance_pct":null,"score_pct":90,"provenance":{"artifact_class":"score_bearing"}}`},
			"rollup_compliance_pct_on_current": {
				"attestation": `{"rollup":{"compliance_pct":53,"score_pct":90,"provenance":{"artifact_class":"score_bearing"}}}`},
			// A score-bearing KIND declaring the read-model class. It parses,
			// and it drops the whole envelope while doing so.
			"score_bearing_kind_declares_read_model": {
				"executive":   `{"score_pct":90,"provenance":{"artifact_class":"read_model"}}`,
				"attestation": `{"rollup":{"score_pct":90,"provenance":{"artifact_class":"read_model"}}}`},
			// And the mirror: a read-model kind claiming to carry a score.
			"read_model_kind_declares_score_bearing": {
				"exception":   `{"provenance":{"artifact_class":"score_bearing"}}`,
				"remediation": `{"provenance":{"artifact_class":"score_bearing"}}`},
		}
		rejected := 0
		for _, shape := range in.MapList("rejected_shapes") {
			kind := shape.Str("kind")
			name := shape.Str("case")
			shape.AllConsumed()
			byKind, ok := bodies[name]
			if !ok {
				t.Fatalf("fixture names case %q, which this test does not build", name)
			}
			body, ok := byKind[kind]
			if !ok {
				t.Fatalf("case %q has no body for kind %q", name, kind)
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

		// The class is kind-SPECIFIC, not merely a known value. Asserted from
		// the fixture's own table so a change there has to change the code.
		if !exp.Bool("class_is_kind_specific") {
			t.Fatal("fixture must require the class to be kind-specific")
		}
		byKind := in.Map("expected_class_by_kind")
		for _, kind := range []string{"executive", "attestation", "exception", "remediation"} {
			want := byKind.Str(kind)
			got, known := expectedClassFor[Kind(kind)]
			if !known {
				t.Errorf("kind %q declares no expected artifact class", kind)
				continue
			}
			if string(got) != want {
				t.Errorf("kind %q expects class %q, want %q", kind, got, want)
			}
			// And the matching class is accepted, so the rejections above are
			// discrimination rather than a check that refuses everything.
			body := `{"provenance":{"artifact_class":"` + want + `"}}`
			if Kind(kind) == KindAttestation {
				body = `{"rollup":{"provenance":{"artifact_class":"` + want + `"}}}`
			}
			if err := checkScoreFields(kind, []byte(body)); err != nil {
				t.Errorf("kind %q rejected its own declared class %q: %v", kind, want, err)
			}
		}
		byKind.AllConsumed()

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-39
// AC-39: the whole frozen content comes from one repeatable-read, read-only
// snapshot, asserted THROUGH Generate.
//
// A test that called withFrozenSnapshot directly would stay green if Generate
// stopped using it, which is exactly the disconnection this criterion has to
// rule out.
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
		if in.Str("driven_through") != "Generate" {
			t.Fatalf("fixture drives %q; this criterion is about Generate",
				in.Str("driven_through"))
		}
		inside := in.StrList("inside_the_snapshot")
		for _, want := range []string{"group_membership", "group_name", "content_reads", "data_as_of"} {
			found := false
			for _, got := range inside {
				if got == want {
					found = true
				}
			}
			if !found {
				t.Errorf("fixture does not require %q inside the snapshot", want)
			}
		}

		seedPopulationHost(t, pool, owner,
			map[string]int{"pass": 9, "fail": 1}, "framework_scored", false)

		// The snapshot's declared properties.
		var iso, ro string
		if err := svc.withFrozenSnapshot(ctx, func(q queryer) error {
			if err := q.QueryRow(ctx, "SHOW transaction_isolation").Scan(&iso); err != nil {
				return err
			}
			return q.QueryRow(ctx, "SHOW transaction_read_only").Scan(&ro)
		}); err != nil {
			t.Fatalf("open snapshot: %v", err)
		}
		if iso != exp.Str("isolation_level") {
			t.Errorf("transaction_isolation = %q, want %q; under read committed each "+
				"statement takes its own snapshot and the content can disagree with itself",
				iso, exp.Str("isolation_level"))
		}
		if wantRO := exp.Str("access_mode"); (ro == "on") != (wantRO == "read only") {
			t.Errorf("transaction_read_only = %q, want %q", ro, wantRO)
		}
		if !exp.Bool("content_reads_share_one_snapshot") ||
			!exp.Bool("concurrent_write_invisible") {
			t.Fatal("fixture must require one snapshot and an invisible concurrent write")
		}

		// GENERATE must use it, and that has to be provable without racing.
		//
		// The queryer Generate hands its readers is captured through the group
		// scoper, which receives the SAME q every content reader gets. Two
		// reads of now() with a real gap between them are equal inside one
		// transaction and different on the pool, because each pooled statement
		// is its own transaction. That is a deterministic signal: a Generate
		// that bypassed the snapshot fails here every run, not sometimes.
		if !exp.Bool("generate_uses_the_snapshot") {
			t.Fatal("fixture must require Generate to use the snapshot")
		}
		probe := &snapshotProbe{t: t}
		probed := NewService(pool).WithGroups(probe)
		gid := uuid.New()
		if _, err := probed.Generate(ctx, "ac39@example.com",
			GenerateRequest{GroupID: &gid, Framework: "framework_scored"}); err != nil {
			t.Fatalf("probed generate: %v", err)
		}
		if probe.inSnapshot == 0 {
			t.Fatal("group scope was never resolved inside the snapshot; a scoped Generate " +
				"must reach ScopeGroupIn")
		}
		if probe.pooled > 0 {
			t.Errorf("group scope resolved through ScopeGroup %d time(s); membership read "+
				"outside the snapshot lets a host join or leave between the scope decision "+
				"and the content computed from it", probe.pooled)
		}
		if probe.first.IsZero() || probe.second.IsZero() {
			t.Fatal("the snapshot probe did not run")
		}
		if !probe.first.Equal(probe.second) {
			t.Errorf("the queryer Generate passed its readers returned two transaction "+
				"timestamps, %v then %v; each statement took its own snapshot, so the "+
				"artifact's parts can describe different fleet states",
				probe.first, probe.second)
		}

		// And the artifact itself: one population describes the whole of it,
		// and the sampling instant cannot postdate the row it was stored in.
		if !exp.Bool("data_as_of_is_the_snapshot_instant") {
			t.Fatal("fixture must require data_as_of to be the snapshot instant")
		}
		for _, kind := range in.StrList("kinds") {
			rep, err := svc.Generate(ctx, "ac39@example.com",
				GenerateRequest{Kind: Kind(kind), Framework: "framework_scored"})
			if err != nil {
				t.Fatalf("%s: generate: %v", kind, err)
			}
			prov, _ := provenanceOf(t, kind, rep.Content)
			if prov.HostsScored+prov.HostsWithoutScore != prov.HostsTotal {
				t.Errorf("%s: %d + %d != %d; the artifact's parts describe different "+
					"populations", kind, prov.HostsScored, prov.HostsWithoutScore,
					prov.HostsTotal)
			}
			if rep.DataAsOf.After(rep.CreatedAt) {
				t.Errorf("%s: data_as_of %v is after created_at %v; the sampling instant was "+
					"taken outside the snapshot and postdates the data it describes",
					kind, rep.DataAsOf, rep.CreatedAt)
			}
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// snapshotProbe records which resolution path a scoped Generate takes, and
// interrogates the queryer it was handed.
//
// It reads transaction_timestamp() twice with a real gap between them. Inside
// one transaction both reads return the transaction's start time and are
// equal; on the pool each statement is its own transaction and the two differ.
// So the probe distinguishes "Generate opened a snapshot" from "Generate used
// the pool" without depending on a race landing.
type snapshotProbe struct {
	t             *testing.T
	pooled        int
	inSnapshot    int
	first, second time.Time
}

func (p *snapshotProbe) ScopeGroup(context.Context, uuid.UUID) (string, []uuid.UUID, error) {
	p.pooled++
	return "Probed", []uuid.UUID{}, nil
}

func (p *snapshotProbe) ScopeGroupIn(ctx context.Context, q db.Queryer,
	_ uuid.UUID) (string, []uuid.UUID, error) {
	p.inSnapshot++
	if err := q.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&p.first); err != nil {
		return "", nil, err
	}
	// A real gap, so two pooled statements cannot coincidentally share a
	// timestamp at the resolution Postgres reports.
	var ignored string
	if err := q.QueryRow(ctx, "SELECT pg_sleep(0.05)::text").Scan(&ignored); err != nil {
		return "", nil, err
	}
	if err := q.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&p.second); err != nil {
		return "", nil, err
	}
	return "Probed", []uuid.UUID{}, nil
}

func activeHostCount(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*)::int FROM hosts WHERE deleted_at IS NULL`).Scan(&n); err != nil {
		t.Fatalf("count hosts: %v", err)
	}
	return n
}

// @ac AC-40
// AC-40: a stored artifact renders the same numbers however the fleet
// changes after it was signed.
func TestLegacyRender_UnaffectedByLaterHostDeletion(t *testing.T) {
	t.Run("system-compliance-scoring/AC-40", func(t *testing.T) {
		ac := scoringAC(t, "AC-40")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		pool := freshPool(t)
		ctx := context.Background()
		svc := NewService(pool)
		owner := seedUser(t, pool)
		if in.Str("artifact") != "pre_rollup_attestation" {
			t.Fatalf("fixture names artifact %q", in.Str("artifact"))
		}
		if in.Str("mutation") == "" {
			t.Fatal("fixture must describe the mutation")
		}

		ids := map[string]uuid.UUID{}
		for _, h := range in.MapList("hosts") {
			c := h.Map("counts")
			counts := map[string]int{"pass": c.Int("pass"), "fail": c.Int("fail")}
			c.AllConsumed()
			ids[h.Str("id")] = seedPopulationHost(t, pool, owner, counts, "framework_scored", false)
			h.AllConsumed()
		}

		// A stored attestation, then its rollup stripped, which is the shape
		// of an artifact signed before the rollup was part of the content.
		rep, err := svc.Generate(ctx, "ac40@example.com",
			GenerateRequest{Kind: KindAttestation, Framework: "framework_scored"})
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		var stored AttestationContent
		if err := json.Unmarshal(rep.Content, &stored); err != nil {
			t.Fatalf("decode: %v", err)
		}

		// Strip the rollup so the stored row is the pre-rollup shape, and
		// clear any cached face, so exporting takes the back-compat path.
		stripped := stored
		stripped.Rollup = AttestationRollup{}
		strippedRaw, err := json.Marshal(stripped)
		if err != nil {
			t.Fatalf("marshal stripped: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`UPDATE report_snapshots SET content = $2::jsonb WHERE id = $1`,
			rep.ID, string(strippedRaw)); err != nil {
			t.Fatalf("store pre-rollup content: %v", err)
		}

		// Driven through the RENDER path, so the call site's own choice of
		// population is what is under test. Calling the rollup helper directly
		// with a hardcoded argument proved nothing about how it is invoked.
		recompute := func(label string) (float64, int) {
			t.Helper()
			if _, err := pool.Exec(ctx,
				`DELETE FROM report_faces WHERE snapshot_id = $1`, rep.ID); err != nil {
				t.Fatalf("%s: clear cached face: %v", label, err)
			}
			fresh, err := svc.Get(ctx, rep.ID)
			if err != nil {
				t.Fatalf("%s: get: %v", label, err)
			}
			var c AttestationContent
			if err := json.Unmarshal(fresh.Content, &c); err != nil {
				t.Fatalf("%s: decode stored: %v", label, err)
			}
			if c.Rollup.TotalChecks != 0 {
				t.Fatalf("%s: the stored artifact still carries a rollup, so the "+
					"back-compat path is not exercised", label)
			}
			// The production function the render path calls, so a change at
			// that call site is what this catches.
			rollup, err := svc.legacyRollupFor(ctx, c)
			if err != nil {
				t.Fatalf("%s: recompute: %v", label, err)
			}
			if rollup.ScorePct == nil {
				t.Fatalf("%s: recomputed score is null", label)
			}
			if rollup.Provenance == nil {
				t.Fatalf("%s: recomputed rollup carries no provenance", label)
			}
			// And the real face renders without error on the same content.
			if _, _, err := svc.Export(ctx, rep.ID, FacePDF); err != nil {
				t.Fatalf("%s: export pdf: %v", label, err)
			}
			return *rollup.ScorePct, rollup.Provenance.HostsTotal
		}

		beforeScore, beforeTotal := recompute("before")
		if beforeScore != exp.Num("score_pct_before") {
			t.Errorf("score before deletion = %v, want %v", beforeScore, exp.Num("score_pct_before"))
		}
		if beforeTotal != exp.Int("hosts_total_before") {
			t.Errorf("hosts_total before = %d, want %d", beforeTotal, exp.Int("hosts_total_before"))
		}

		// Soft-delete an attested host AFTER signing.
		if _, err := pool.Exec(ctx,
			`UPDATE hosts SET deleted_at = now() WHERE id = $1`,
			ids["deleted_after_signing"]); err != nil {
			t.Fatalf("soft delete: %v", err)
		}

		afterScore, afterTotal := recompute("after")
		if afterScore != exp.Num("score_pct_after") {
			t.Errorf("score after deletion = %v, want %v; a signed artifact records what was "+
				"true when it was signed, and the current deletion state of a host is not "+
				"part of that record", afterScore, exp.Num("score_pct_after"))
		}
		if afterTotal != exp.Int("hosts_total_after") {
			t.Errorf("hosts_total after = %d, want %d; the population came from the hosts "+
				"table rather than from the artifact's own frozen ids",
				afterTotal, exp.Int("hosts_total_after"))
		}
		if !exp.Bool("identical_after_deletion") {
			t.Fatal("fixture must require identical numbers")
		}
		if beforeScore != afterScore || beforeTotal != afterTotal {
			t.Errorf("the rendered artifact moved: %v/%d became %v/%d",
				beforeScore, beforeTotal, afterScore, afterTotal)
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}
