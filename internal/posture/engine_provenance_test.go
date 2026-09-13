// @spec system-scan-runs
//
// Where a snapshot's engine version comes from. It lives in package posture
// because the property spans two packages: the worker stamps the run, and the
// rollup copies it. Testing either half alone would miss the journey.
package posture

import (
	"context"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/scanruns"
	"github.com/Hanalyx/openwatch/internal/specfixture"
	"github.com/Hanalyx/openwatch/internal/version"
	"github.com/google/uuid"
)

// @ac AC-10
// AC-10: engine provenance is COPIED from the producing scan, never stamped by
// the reading process.
//
// The seeded run carries a version no running process reports. That is the
// whole design of the fixture: if the two agreed, a rollup that stamped its own
// version would pass and the bug would survive the test.
func TestRollup_EngineVersionComesFromTheProducingScan(t *testing.T) {
	t.Run("system-scan-runs/AC-10", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		user := seedUser(t, pool)
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/system/scan-runs.spec.yaml", "system-scan-runs"), "AC-10")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		producer := in.Str("producer_engine_version")
		if !exp.Bool("differs_from_reporting_process") {
			t.Fatal("fixture must make the producer differ from the reading process")
		}
		if producer == version.Kensa() {
			t.Fatalf("fixture engine version %q equals this process's; the two must differ or a "+
				"rollup stamping its own version would pass", producer)
		}

		h := seedHost(t, pool, user)
		seedRuleState(t, pool, h, "r1", "pass", "low")

		// The PRODUCTION writer stamps the run. Asserting this here rather than
		// restamping the row means the criterion covers both halves of the
		// journey: what the worker writes, and what the rollup copies.
		if !exp.Bool("mark_completed_stamps_worker_version") {
			t.Fatal("fixture must require MarkCompleted to stamp the worker's version")
		}
		markRun, _ := uuid.NewV7()
		if err := scanruns.MarkRunning(ctx, pool, markRun, h, ""); err != nil {
			t.Fatalf("MarkRunning: %v", err)
		}
		if err := scanruns.MarkCompleted(ctx, pool, markRun, scanruns.Counts{Pass: 1}); err != nil {
			t.Fatalf("MarkCompleted: %v", err)
		}
		var stamped *string
		if err := pool.QueryRow(ctx,
			`SELECT engine_version FROM scan_runs WHERE id = $1`, markRun).Scan(&stamped); err != nil {
			t.Fatalf("read stamped run: %v", err)
		}
		if stamped == nil || *stamped != version.Kensa() {
			t.Errorf("MarkCompleted stamped engine_version %v, want the worker's own %q",
				stamped, version.Kensa())
		}
		// That run is now the host's latest, so remove it and restamp the run
		// the rule state actually belongs to with the producer's version.
		if _, err := pool.Exec(ctx, `DELETE FROM scan_runs WHERE id = $1`, markRun); err != nil {
			t.Fatalf("drop the marker run: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`UPDATE scan_runs SET engine_version = $2 WHERE host_id = $1`, h, producer); err != nil {
			t.Fatalf("stamp producer engine: %v", err)
		}

		// A host whose run predates migration 0063: no engine recorded.
		in.IsNull("legacy_run_engine_version")
		legacy := seedHost(t, pool, user)
		seedRuleState(t, pool, legacy, "r1", "pass", "low")
		if _, err := pool.Exec(ctx,
			`UPDATE scan_runs SET engine_version = NULL WHERE host_id = $1`, legacy); err != nil {
			t.Fatalf("clear legacy engine: %v", err)
		}

		if _, err := Rollup(ctx, pool, time.Now()); err != nil {
			t.Fatalf("Rollup: %v", err)
		}

		read := func(host uuid.UUID) *string {
			t.Helper()
			var got *string
			if err := pool.QueryRow(ctx, `
				SELECT engine_version FROM posture_snapshots
				 WHERE host_id = $1 AND snapshot_date = current_date AND framework = ''`, host).
				Scan(&got); err != nil {
				t.Fatalf("read snapshot: %v", err)
			}
			return got
		}

		got := read(h)
		if got == nil || *got != exp.Str("snapshot_engine_version") {
			t.Errorf("snapshot engine_version = %v, want %q copied from the producing scan",
				got, exp.Str("snapshot_engine_version"))
		}
		// The discriminating assertion. The rollup's own linked version is what
		// this used to record.
		_ = exp.Str("forbidden_snapshot_engine_version")
		if got != nil && *got == version.Kensa() {
			t.Errorf("snapshot engine_version = %q, which is the ROLLUP process's own version, "+
				"not the engine that produced the outcomes", *got)
		}

		exp.IsNull("legacy_snapshot_engine_version")
		if legacyGot := read(legacy); legacyGot != nil {
			t.Errorf("legacy snapshot engine_version = %q, want null; nothing recorded which "+
				"engine produced that run and this process is not evidence", *legacyGot)
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}
