// @spec system-liveness-loop
//
// AC traceability (this file):
//
//	AC-24  TestBandIntervalFor_MapsStateAndConsecutiveToBand
//	AC-25  TestPersist_WritesNextProbeAtFromBand
//	AC-26  TestListProbeTargets_FiltersByNextProbeAt

package liveness

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/systemconfig"
)

// @ac AC-24
// AC-24: bandIntervalFor maps (status, consec, cfg) to the right band.
// Pure function — no DB.
func TestBandIntervalFor_MapsStateAndConsecutiveToBand(t *testing.T) {
	t.Run("system-liveness-loop/AC-24", func(t *testing.T) {
		cfg := systemconfig.ConnectivityConfig{
			OnlineSec:            900,
			DegradedSec:          300,
			CriticalSec:          120,
			DownSec:              1800,
			MaintenanceSec:       3600,
			UnreachableThreshold: 2,
		}
		cases := []struct {
			name        string
			status      Status
			consecutive int
			want        time.Duration
		}{
			{"reachable consec=0 → online", StatusReachable, 0, 900 * time.Second},
			{"reachable consec=1 → degraded", StatusReachable, 1, 300 * time.Second},
			{"unreachable consec=1 → critical", StatusUnreachable, 1, 120 * time.Second},
			{"unreachable consec=threshold → down", StatusUnreachable, 2, 1800 * time.Second},
			{"reachable consec≥threshold → down still", StatusReachable, 3, 1800 * time.Second},
			{"unknown → online default", StatusUnknown, 0, 900 * time.Second},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if got := bandIntervalFor(tc.status, tc.consecutive, cfg); got != tc.want {
					t.Errorf("bandIntervalFor(%s, consec=%d) = %v, want %v",
						tc.status, tc.consecutive, got, tc.want)
				}
			})
		}
	})
}

// @ac AC-25
// AC-25: persist() writes next_probe_at = now + bandIntervalFor(...).
// A first-seen reachable host (consec=0) lands at OnlineSec.
func TestPersist_WritesNextProbeAtFromBand(t *testing.T) {
	t.Run("system-liveness-loop/AC-25", func(t *testing.T) {
		pool := freshPool(t)
		userID := seedUser(t, pool)
		hostID := seedHost(t, pool, userID)

		// Pin clock so the assertion is deterministic.
		fixed := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
		svc := NewService(pool, noopEmit, nil)
		svc.clock = func() time.Time { return fixed }

		// Use defaults (Online=900s).
		if _, err := svc.ProbeHost(
			context.Background(),
			hostID,
			"127.0.0.1:1", // refused; we don't care, persist runs either way
		); err != nil {
			// Persist may have its own error path — we still expect the row.
			t.Logf("ProbeHost: %v (expected for refused connection)", err)
		}

		var nextProbeAt time.Time
		err := pool.QueryRow(context.Background(),
			`SELECT next_probe_at FROM host_liveness WHERE host_id = $1`, hostID,
		).Scan(&nextProbeAt)
		if err != nil {
			t.Fatalf("read next_probe_at: %v", err)
		}
		// A refused first probe → unreachable + consec=1. With threshold=2,
		// that's Critical (CriticalSec=120s).
		wantBand := time.Duration(systemconfig.DefaultConnectivity().CriticalSec) * time.Second
		got := nextProbeAt.Sub(fixed)
		// Allow 1s skew for the clock returning between persist read + write.
		if got < wantBand-time.Second || got > wantBand+time.Second {
			t.Errorf("next_probe_at offset = %v, want ~%v (Critical band)", got, wantBand)
		}
	})
}

// @ac AC-26
// AC-26: listProbeTargets seeds three hosts (next_probe_at = NULL,
// past, future) — returns the first two.
func TestListProbeTargets_FiltersByNextProbeAt(t *testing.T) {
	t.Run("system-liveness-loop/AC-26", func(t *testing.T) {
		pool := freshPool(t)
		userID := seedUser(t, pool)

		hNull := seedHost(t, pool, userID)
		hPast := seedHost(t, pool, userID)
		hFuture := seedHost(t, pool, userID)

		past := time.Now().Add(-1 * time.Minute).UTC()
		future := time.Now().Add(1 * time.Hour).UTC()
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO host_liveness (host_id, reachability_status, next_probe_at)
			 VALUES ($1, 'reachable', $2)`, hPast, past); err != nil {
			t.Fatalf("seed hPast: %v", err)
		}
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO host_liveness (host_id, reachability_status, next_probe_at)
			 VALUES ($1, 'reachable', $2)`, hFuture, future); err != nil {
			t.Fatalf("seed hFuture: %v", err)
		}
		// hNull intentionally has no host_liveness row → next_probe_at IS NULL → due.

		svc := NewService(pool, noopEmit, nil)
		hosts, err := svc.listProbeTargets(context.Background())
		if err != nil {
			t.Fatalf("listProbeTargets: %v", err)
		}

		ids := map[uuid.UUID]bool{}
		for _, h := range hosts {
			ids[h.HostID] = true
		}
		if !ids[hNull] {
			t.Errorf("expected hNull (no host_liveness row) to be due")
		}
		if !ids[hPast] {
			t.Errorf("expected hPast (next_probe_at in past) to be due")
		}
		if ids[hFuture] {
			t.Errorf("expected hFuture (next_probe_at in future) to be skipped, got it back")
		}
	})
}

// noopEmit is a no-op audit emit for tests that don't assert on audits.
func noopEmit(_ context.Context, _ audit.Code, _ audit.Event) {}
