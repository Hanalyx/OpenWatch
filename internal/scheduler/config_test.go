// @spec system-scheduler
//
// v3.0.0 config-sourced ladder + five-band + persist tests:
//
//	AC-01  TestLoadFromConfig_LadderAndVersion
//	AC-10  TestReload_PausedDispatchesNothing (DSN)
//	AC-12  TestScanConfigNormalize_ClampsFloorCeilingAndRateLimit
//	AC-14  TestStateFromScore_FiveBands_AndAllStates
//	AC-08  TestPersistAfterScan_UpsertsScheduleRow (DSN)
package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/systemconfig"
)

// @ac AC-01
// AC-01 (v3.0.0): LoadFromConfig maps all six state minutes through
// the clamp pipeline and derives the version snapshot from the ladder
// values — same ladder, same version; changed interval, changed version.
func TestLoadFromConfig_LadderAndVersion(t *testing.T) {
	t.Run("system-scheduler/AC-01", func(t *testing.T) {
		cfg := systemconfig.DefaultScan()
		load := LoadFromConfig(cfg)

		want := TierLadder{
			StateUnknown:         360 * time.Minute,
			StateCritical:        240 * time.Minute,
			StateNonCompliant:    480 * time.Minute,
			StatePartial:         720 * time.Minute,
			StateMostlyCompliant: 1440 * time.Minute,
			StateCompliant:       2880 * time.Minute,
		}
		for st, d := range want {
			if load.Ladder[st] != d {
				t.Errorf("ladder[%s] = %v, want %v", st, load.Ladder[st], d)
			}
		}
		if len(load.Ladder) != 6 {
			t.Errorf("ladder size = %d, want 6", len(load.Ladder))
		}
		if len(load.Clamps) != 0 {
			t.Errorf("default config produced clamps: %#v", load.Clamps)
		}

		// Version: stable for identical ladders, changes with any edit.
		if v2 := LoadFromConfig(cfg).PolicyVersion; v2 != load.PolicyVersion {
			t.Errorf("same config produced different versions: %q vs %q", load.PolicyVersion, v2)
		}
		edited := cfg
		edited.CriticalMins = 60
		if v3 := LoadFromConfig(edited).PolicyVersion; v3 == load.PolicyVersion {
			t.Errorf("interval edit did not change the version snapshot (%q)", v3)
		}
	})
}

// @ac AC-12
// AC-12 (write-time half): Normalize clamps every ladder value into
// [5m, 48h] and the rate limit into [1, 100] instead of rejecting.
func TestScanConfigNormalize_ClampsFloorCeilingAndRateLimit(t *testing.T) {
	t.Run("system-scheduler/AC-12", func(t *testing.T) {
		raw := systemconfig.ScanConfig{
			Enabled:             true,
			UnknownMins:         0,     // below floor -> 5
			CriticalMins:        1,     // below floor -> 5
			NonCompliantMins:    99999, // above cap -> 2880
			PartialMins:         720,   // in budget, untouched
			MostlyCompliantMins: -10,   // below floor -> 5
			CompliantMins:       2881,  // above cap -> 2880
			RateLimit:           0,     // -> 1
		}
		n := raw.Normalize()
		if n.UnknownMins != 5 || n.CriticalMins != 5 || n.MostlyCompliantMins != 5 {
			t.Errorf("floor clamp failed: %+v", n)
		}
		if n.NonCompliantMins != 2880 || n.CompliantMins != 2880 {
			t.Errorf("ceiling clamp failed: %+v", n)
		}
		if n.PartialMins != 720 {
			t.Errorf("in-budget value mutated: %d", n.PartialMins)
		}
		if n.RateLimit != 1 {
			t.Errorf("rate limit floor failed: %d", n.RateLimit)
		}
		raw.RateLimit = 5000
		if got := raw.Normalize().RateLimit; got != 100 {
			t.Errorf("rate limit ceiling = %d, want 100", got)
		}
		if err := n.Validate(); err != nil {
			t.Errorf("normalized config failed validation: %v", err)
		}
		// LoadFromConfig of an un-normalized config still clamps (the
		// load-time half) and records the clamp.
		load := LoadFromConfig(systemconfig.ScanConfig{CriticalMins: 1, UnknownMins: 360,
			NonCompliantMins: 480, PartialMins: 720, MostlyCompliantMins: 1440, CompliantMins: 2880})
		if load.Ladder[StateCritical] != MinIntervalFloor {
			t.Errorf("load-time floor clamp failed: %v", load.Ladder[StateCritical])
		}
		if len(load.Clamps) == 0 {
			t.Errorf("no ClampRecord for below-floor tier")
		}
	})
}

// @ac AC-14
// AC-14 (v3.0.0): five score bands with the hasCritical override, and
// AllStates lists exactly the six states in ladder order.
func TestStateFromScore_FiveBands_AndAllStates(t *testing.T) {
	t.Run("system-scheduler/AC-14", func(t *testing.T) {
		cases := []struct {
			score float64
			want  ComplianceState
		}{
			{95, StateCompliant},
			{90, StateCompliant},
			{89.999, StateMostlyCompliant},
			{70, StateMostlyCompliant},
			{69.999, StatePartial},
			{50, StatePartial},
			{49.999, StateNonCompliant},
			{20, StateNonCompliant},
			{19.999, StateCritical},
			{0, StateCritical},
		}
		for _, c := range cases {
			if got := StateFromScore(c.score, false); got != c.want {
				t.Errorf("StateFromScore(%v) = %q, want %q", c.score, got, c.want)
			}
		}
		// hasCritical forces critical at any score.
		if got := StateFromScore(100, true); got != StateCritical {
			t.Errorf("hasCritical override failed: %q", got)
		}

		want := []ComplianceState{StateCritical, StateNonCompliant, StatePartial,
			StateMostlyCompliant, StateCompliant, StateUnknown}
		got := AllStates()
		if len(got) != len(want) {
			t.Fatalf("AllStates len = %d, want %d", len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("AllStates[%d] = %q, want %q", i, got[i], want[i])
			}
		}
	})
}

// @ac AC-10
// AC-10 (v3.0.0, DSN): a paused scheduler dispatches nothing even with
// a due row; un-pausing resumes on the next Dispatch.
func TestReload_PausedDispatchesNothing(t *testing.T) {
	t.Run("system-scheduler/AC-10", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		h := seedHost(t, pool, user)
		seedSchedule(t, pool, h)

		var calls []emitCall
		svc := NewService(pool, LoadFromConfig(systemconfig.DefaultScan()), testKey(), fakeEmitter(&calls))

		// Paused (config disabled): zero dispatched, row untouched.
		svc.Reload(LoadFromConfig(systemconfig.DefaultScan()), 25, true)
		ctx := withCorrelation(context.Background(), "tick-test-pause")
		n, err := svc.Dispatch(ctx)
		if err != nil {
			t.Fatalf("paused Dispatch: %v", err)
		}
		if n != 0 {
			t.Errorf("paused Dispatch dispatched %d, want 0", n)
		}
		var queued int
		_ = pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM job_queue WHERE job_type = 'scan'`).Scan(&queued)
		if queued != 0 {
			t.Errorf("paused Dispatch enqueued %d jobs, want 0", queued)
		}

		// Un-pause: the due host dispatches.
		svc.Reload(LoadFromConfig(systemconfig.DefaultScan()), 25, false)
		n, err = svc.Dispatch(ctx)
		if err != nil {
			t.Fatalf("resumed Dispatch: %v", err)
		}
		if n != 1 {
			t.Errorf("resumed Dispatch dispatched %d, want 1", n)
		}
	})
}

// @ac AC-08
// AC-08 (v3.0.0 persistence half, DSN): PersistAfterScan UPSERTs the
// schedule row with the classified state (including the NEW
// mostly_compliant band — proves migration 0024's widened CHECK),
// anchors next_scheduled_scan at completion + ladder interval, and
// emits scheduler.schedule.updated.
func TestPersistAfterScan_UpsertsScheduleRow(t *testing.T) {
	t.Run("system-scheduler/AC-08", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		h := seedHost(t, pool, user)
		// No pre-existing schedule row: the upsert inserts (covers the
		// on-demand-scan-before-seeding shape).

		var calls []emitCall
		svc := NewService(pool, LoadFromConfig(systemconfig.DefaultScan()), testKey(), fakeEmitter(&calls))
		svc.Reload(LoadFromConfig(systemconfig.DefaultScan()), 25, false)

		completed := time.Now().UTC().Truncate(time.Second)
		ctx := withCorrelation(context.Background(), "persist-test")
		res, err := svc.PersistAfterScan(ctx, h, 75, false, completed)
		if err != nil {
			t.Fatalf("PersistAfterScan: %v", err)
		}
		if res.State != StateMostlyCompliant {
			t.Fatalf("state = %q, want mostly_compliant (score 75)", res.State)
		}
		wantNext := completed.Add(1440 * time.Minute)
		if !res.NextScheduled.Equal(wantNext) {
			t.Errorf("next = %v, want %v", res.NextScheduled, wantNext)
		}

		var state string
		var score float64
		var nextAt, lastAt time.Time
		var intervalMins int
		err = pool.QueryRow(context.Background(), `
			SELECT compliance_state, compliance_score, next_scheduled_scan,
			       last_scan_completed_at, current_interval_minutes
			  FROM host_compliance_schedule WHERE host_id = $1`, h).
			Scan(&state, &score, &nextAt, &lastAt, &intervalMins)
		if err != nil {
			t.Fatalf("read row: %v", err)
		}
		if state != "mostly_compliant" || score != 75 || intervalMins != 1440 {
			t.Errorf("row = %s/%v/%dm, want mostly_compliant/75/1440m", state, score, intervalMins)
		}
		if !nextAt.UTC().Equal(wantNext) || !lastAt.UTC().Equal(completed) {
			t.Errorf("times: next=%v last=%v, want %v / %v", nextAt.UTC(), lastAt.UTC(), wantNext, completed)
		}

		// Second persist (worse score) UPDATEs the same row.
		if _, err := svc.PersistAfterScan(ctx, h, 10, false, completed.Add(time.Hour)); err != nil {
			t.Fatalf("second PersistAfterScan: %v", err)
		}
		_ = pool.QueryRow(context.Background(),
			`SELECT compliance_state FROM host_compliance_schedule WHERE host_id = $1`, h).Scan(&state)
		if state != "critical" {
			t.Errorf("after rescan state = %q, want critical (score 10)", state)
		}

		// schedule.updated emitted (change_kind scan_completed).
		found := false
		for _, c := range calls {
			if string(c.Code) == "scheduler.schedule.updated" {
				found = true
			}
		}
		if !found {
			t.Errorf("no scheduler.schedule.updated emission; calls = %d", len(calls))
		}
	})
}
