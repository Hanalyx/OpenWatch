// @spec system-alerts
//
// AC traceability (this file):
//
//	AC-01  TestMigration0021_LifecycleColumnsAndIndex
//	AC-02  TestService_Acknowledge_FromActive
//	AC-03  TestService_Silence_WithFutureUntil
//	AC-04  TestService_Silence_PastUntil_RejectsAndNoop
//	AC-05  TestService_Silence_IndefiniteThenSweep
//	AC-06  TestService_Resolve_FromActive
//	AC-07  TestService_Dismiss_FromActive
//	AC-08  TestService_Acknowledge_OnResolved_InvalidTransition
//	AC-09  TestService_Acknowledge_Concurrent_ExactlyOneSuccess
//	AC-10  TestService_SweepExpiredSilences
//	AC-11  TestService_AutoResolve_HostRecoveredClosesUnreachable
//	AC-12  TestService_List_FilterByStateHostSeverity
//	AC-13  TestService_List_CursorPagination
//	AC-14  TestService_Get_UnknownAndResolved

package alerts

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/alertrouter"
	"github.com/Hanalyx/openwatch/internal/db/dbtest"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// freshDB spins up a clean migrated DB and seeds one user.
func freshDB(t *testing.T) (*pgxpool.Pool, uuid.UUID) {
	t.Helper()
	pool := dbtest.Pool(t)
	ctx := context.Background()
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE alerts")
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE audit_events")
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE users CASCADE")
	actor, _ := uuid.NewV7()
	hash, _ := identity.HashPassword("seed-pw-12345-aa")
	_, _ = pool.Exec(ctx,
		`INSERT INTO users (id, username, email, password_hash) VALUES ($1, $2, $3, $4)`,
		actor, "alerts-actor", "alerts@example.com", hash)
	return pool, actor
}

// seedAlert inserts one row in the alerts table via the router's
// PgxStore — same code path production uses.
func seedAlert(t *testing.T, pool *pgxpool.Pool, atype alertrouter.AlertType, sev alertrouter.Severity, hostID uuid.UUID, occurredAt time.Time) uuid.UUID {
	t.Helper()
	store := alertrouter.NewPgxStore(pool)
	a := alertrouter.Alert{
		Type:       atype,
		Severity:   sev,
		HostID:     hostID,
		OccurredAt: occurredAt,
		Title:      string(atype) + " seed",
		Body:       "seeded",
		Tags:       map[string]string{"severity": string(sev)},
	}
	id, err := store.Insert(context.Background(), a)
	if err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	return id
}

// readAlertState returns (state, acknowledged_by, silenced_until,
// resolved_at, dismissed_at) — all the lifecycle scalar fields a test
// might want to assert.
type alertSnap struct {
	State          string
	AcknowledgedBy *uuid.UUID
	AcknowledgedAt *time.Time
	SilencedUntil  *time.Time
	ResolvedAt     *time.Time
	DismissedAt    *time.Time
}

func readAlertSnap(t *testing.T, pool *pgxpool.Pool, id uuid.UUID) alertSnap {
	t.Helper()
	var s alertSnap
	err := pool.QueryRow(context.Background(), `
		SELECT state, acknowledged_by, acknowledged_at, silenced_until, resolved_at, dismissed_at
		  FROM alerts WHERE id = $1`,
		id).Scan(&s.State, &s.AcknowledgedBy, &s.AcknowledgedAt, &s.SilencedUntil, &s.ResolvedAt, &s.DismissedAt)
	if err != nil {
		t.Fatalf("read alert snap: %v", err)
	}
	return s
}

// @ac AC-01
// AC-01: Migration 0021 adds the six lifecycle columns + the
// partial index for the sweeper.
func TestMigration0021_LifecycleColumnsAndIndex(t *testing.T) {
	t.Run("system-alerts/AC-01", func(t *testing.T) {
		_, file, _, _ := runtime.Caller(0)
		dir := filepath.Dir(file)
		var migPath string
		for i := 0; i < 8; i++ {
			cand := filepath.Join(dir, "db", "migrations", "0021_alerts_lifecycle.sql")
			if _, err := os.Stat(cand); err == nil {
				migPath = cand
				break
			}
			dir = filepath.Dir(dir)
		}
		if migPath == "" {
			t.Fatalf("migration 0021 not located")
		}
		raw, err := os.ReadFile(migPath)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		s := string(raw)
		want := []string{
			"acknowledged_by",
			"acknowledged_at",
			"silenced_by",
			"silenced_until",
			"resolved_by",
			"resolved_at",
			"dismissed_by",
			"dismissed_at",
			"CREATE INDEX idx_alerts_silenced",
			"WHERE state = 'silenced'",
		}
		for _, w := range want {
			if !strings.Contains(s, w) {
				t.Errorf("migration 0021 missing %q", w)
			}
		}
	})
}

// @ac AC-02
// AC-02: Acknowledge advances state, populates metadata, emits audit.
func TestService_Acknowledge_FromActive(t *testing.T) {
	t.Run("system-alerts/AC-02", func(t *testing.T) {
		pool, actor := freshDB(t)
		id := seedAlert(t, pool, alertrouter.AlertTypeHostUnreachable,
			alertrouter.SeverityHigh, uuid.Nil, time.Now().UTC().Add(-1*time.Minute))

		emits := newAuditCounter()
		svc := NewService(pool, emits.Emit)
		err := svc.Acknowledge(context.Background(), id, actor, "saw it")
		if err != nil {
			t.Fatalf("Acknowledge: %v", err)
		}

		snap := readAlertSnap(t, pool, id)
		if snap.State != "acknowledged" {
			t.Errorf("state=%q, want acknowledged", snap.State)
		}
		if snap.AcknowledgedBy == nil || *snap.AcknowledgedBy != actor {
			t.Errorf("acknowledged_by=%v, want %v", snap.AcknowledgedBy, actor)
		}
		if snap.AcknowledgedAt == nil {
			t.Errorf("acknowledged_at is NULL after Acknowledge")
		}
		if got := emits.CountFor("alert.acknowledged"); got != 1 {
			t.Errorf("audit alert.acknowledged = %d, want 1", got)
		}
	})
}

// @ac AC-03
// AC-03: Silence with future until populates state + silenced_until,
// emits alert.silenced.
func TestService_Silence_WithFutureUntil(t *testing.T) {
	t.Run("system-alerts/AC-03", func(t *testing.T) {
		pool, actor := freshDB(t)
		id := seedAlert(t, pool, alertrouter.AlertTypeDriftMajor,
			alertrouter.SeverityHigh, uuid.Nil, time.Now().UTC())

		emits := newAuditCounter()
		svc := NewService(pool, emits.Emit)
		until := time.Now().UTC().Add(1 * time.Hour)
		err := svc.Silence(context.Background(), id, actor, &until, "noise")
		if err != nil {
			t.Fatalf("Silence: %v", err)
		}

		snap := readAlertSnap(t, pool, id)
		if snap.State != "silenced" {
			t.Errorf("state=%q, want silenced", snap.State)
		}
		if snap.SilencedUntil == nil || snap.SilencedUntil.Unix() != until.Unix() {
			t.Errorf("silenced_until=%v, want ~%v", snap.SilencedUntil, until)
		}
		if got := emits.CountFor("alert.silenced"); got != 1 {
			t.Errorf("audit alert.silenced = %d, want 1", got)
		}
	})
}

// @ac AC-04
// AC-04: Past until → ErrInvalidSilenceWindow, no mutation, no audit.
func TestService_Silence_PastUntil_RejectsAndNoop(t *testing.T) {
	t.Run("system-alerts/AC-04", func(t *testing.T) {
		pool, actor := freshDB(t)
		id := seedAlert(t, pool, alertrouter.AlertTypeDriftMinor,
			alertrouter.SeverityMedium, uuid.Nil, time.Now().UTC())

		emits := newAuditCounter()
		svc := NewService(pool, emits.Emit)
		past := time.Now().UTC().Add(-1 * time.Hour)
		err := svc.Silence(context.Background(), id, actor, &past, "")
		if !errors.Is(err, ErrInvalidSilenceWindow) {
			t.Errorf("err=%v, want ErrInvalidSilenceWindow", err)
		}

		snap := readAlertSnap(t, pool, id)
		if snap.State != "active" {
			t.Errorf("state=%q, want active (unchanged)", snap.State)
		}
		if emits.CountFor("alert.silenced") != 0 {
			t.Errorf("audit emitted on rejected silence")
		}
	})
}

// @ac AC-05
// AC-05: until=nil → silenced indefinite; sweep does NOT re-arm.
func TestService_Silence_IndefiniteThenSweep(t *testing.T) {
	t.Run("system-alerts/AC-05", func(t *testing.T) {
		pool, actor := freshDB(t)
		id := seedAlert(t, pool, alertrouter.AlertTypeDriftMinor,
			alertrouter.SeverityLow, uuid.Nil, time.Now().UTC())

		emits := newAuditCounter()
		svc := NewService(pool, emits.Emit)
		err := svc.Silence(context.Background(), id, actor, nil, "")
		if err != nil {
			t.Fatalf("Silence: %v", err)
		}
		snap := readAlertSnap(t, pool, id)
		if snap.State != "silenced" {
			t.Errorf("state=%q, want silenced", snap.State)
		}
		if snap.SilencedUntil != nil {
			t.Errorf("silenced_until=%v, want NULL", snap.SilencedUntil)
		}

		// Sweep should NOT touch indefinite-silence rows.
		n, err := svc.SweepExpiredSilences(context.Background())
		if err != nil {
			t.Fatalf("Sweep: %v", err)
		}
		if n != 0 {
			t.Errorf("sweep re-armed %d, want 0 (indefinite never elapses)", n)
		}
		snap2 := readAlertSnap(t, pool, id)
		if snap2.State != "silenced" {
			t.Errorf("indefinite silence flipped to %q after sweep — should stay silenced", snap2.State)
		}
	})
}

// @ac AC-06
// AC-06: Resolve from active, audit emitted.
func TestService_Resolve_FromActive(t *testing.T) {
	t.Run("system-alerts/AC-06", func(t *testing.T) {
		pool, actor := freshDB(t)
		id := seedAlert(t, pool, alertrouter.AlertTypeHostUnreachable,
			alertrouter.SeverityHigh, uuid.Nil, time.Now().UTC())

		emits := newAuditCounter()
		svc := NewService(pool, emits.Emit)
		if err := svc.Resolve(context.Background(), id, actor, "host back"); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		snap := readAlertSnap(t, pool, id)
		if snap.State != "resolved" {
			t.Errorf("state=%q, want resolved", snap.State)
		}
		if snap.ResolvedAt == nil {
			t.Errorf("resolved_at NULL after Resolve")
		}
		if emits.CountFor("alert.resolved") != 1 {
			t.Errorf("audit alert.resolved missing")
		}
	})
}

// @ac AC-07
// AC-07: Dismiss from active, audit emitted.
func TestService_Dismiss_FromActive(t *testing.T) {
	t.Run("system-alerts/AC-07", func(t *testing.T) {
		pool, actor := freshDB(t)
		id := seedAlert(t, pool, alertrouter.AlertTypeDriftMinor,
			alertrouter.SeverityLow, uuid.Nil, time.Now().UTC())
		emits := newAuditCounter()
		svc := NewService(pool, emits.Emit)
		if err := svc.Dismiss(context.Background(), id, actor, "not real"); err != nil {
			t.Fatalf("Dismiss: %v", err)
		}
		snap := readAlertSnap(t, pool, id)
		if snap.State != "dismissed" {
			t.Errorf("state=%q, want dismissed", snap.State)
		}
		if emits.CountFor("alert.dismissed") != 1 {
			t.Errorf("audit alert.dismissed missing")
		}
	})
}

// @ac AC-08
// AC-08: Acknowledge on a resolved alert returns ErrInvalidTransition.
func TestService_Acknowledge_OnResolved_InvalidTransition(t *testing.T) {
	t.Run("system-alerts/AC-08", func(t *testing.T) {
		pool, actor := freshDB(t)
		id := seedAlert(t, pool, alertrouter.AlertTypeHostUnreachable,
			alertrouter.SeverityHigh, uuid.Nil, time.Now().UTC())
		svc := NewService(pool, nil)
		_ = svc.Resolve(context.Background(), id, actor, "")
		err := svc.Acknowledge(context.Background(), id, actor, "")
		if !errors.Is(err, ErrInvalidTransition) {
			t.Errorf("err=%v, want ErrInvalidTransition", err)
		}
		snap := readAlertSnap(t, pool, id)
		if snap.State != "resolved" {
			t.Errorf("state=%q after rejected ack, want resolved (unchanged)", snap.State)
		}
	})
}

// @ac AC-09
// AC-09: concurrent Acknowledge -> exactly one success + one audit.
func TestService_Acknowledge_Concurrent_ExactlyOneSuccess(t *testing.T) {
	t.Run("system-alerts/AC-09", func(t *testing.T) {
		pool, actor := freshDB(t)
		id := seedAlert(t, pool, alertrouter.AlertTypeHostUnreachable,
			alertrouter.SeverityHigh, uuid.Nil, time.Now().UTC())
		emits := newAuditCounter()
		svc := NewService(pool, emits.Emit)

		var wg sync.WaitGroup
		errs := make([]error, 2)
		start := make(chan struct{})
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				<-start
				errs[idx] = svc.Acknowledge(context.Background(), id, actor, "")
			}(i)
		}
		close(start)
		wg.Wait()

		successes := 0
		for _, e := range errs {
			if e == nil {
				successes++
			} else if !errors.Is(e, ErrInvalidTransition) {
				t.Errorf("unexpected err: %v", e)
			}
		}
		if successes != 1 {
			t.Errorf("concurrent acks succeeded %d times, want 1", successes)
		}
		if got := emits.CountFor("alert.acknowledged"); got != 1 {
			t.Errorf("audit alert.acknowledged = %d, want 1", got)
		}
	})
}

// @ac AC-10
// AC-10: SweepExpiredSilences re-arms only past silences.
func TestService_SweepExpiredSilences(t *testing.T) {
	t.Run("system-alerts/AC-10", func(t *testing.T) {
		pool, actor := freshDB(t)
		past := seedAlert(t, pool, alertrouter.AlertTypeDriftMinor,
			alertrouter.SeverityLow, uuid.Nil, time.Now().UTC().Add(-2*time.Hour))
		future := seedAlert(t, pool, alertrouter.AlertTypeDriftMinor,
			alertrouter.SeverityLow, uuid.Nil, time.Now().UTC().Add(-1*time.Hour))

		emits := newAuditCounter()
		svc := NewService(pool, emits.Emit)
		futureUntil := time.Now().UTC().Add(1 * time.Hour)
		// Silence both with future until so state advances to silenced
		// (Silence rejects past timestamps via ErrInvalidSilenceWindow).
		if err := svc.Silence(context.Background(), past, actor, &futureUntil, ""); err != nil {
			t.Fatalf("Silence past seed: %v", err)
		}
		if err := svc.Silence(context.Background(), future, actor, &futureUntil, ""); err != nil {
			t.Fatalf("Silence future seed: %v", err)
		}
		// Simulate the first row's silenced_until having elapsed.
		_, err := pool.Exec(context.Background(),
			`UPDATE alerts SET silenced_until = now() - interval '1 minute' WHERE id = $1`,
			past)
		if err != nil {
			t.Fatalf("simulate elapsed: %v", err)
		}
		// Reset the audit counter so we only count the sweep's emission,
		// not the two Silence calls above.
		emits.Reset("alert.unsilenced.auto")

		n, err := svc.SweepExpiredSilences(context.Background())
		if err != nil {
			t.Fatalf("Sweep: %v", err)
		}
		if n != 1 {
			t.Errorf("sweep re-armed %d, want 1", n)
		}
		if readAlertSnap(t, pool, past).State != "active" {
			t.Errorf("past silence not re-armed to active")
		}
		if readAlertSnap(t, pool, future).State != "silenced" {
			t.Errorf("future silence wrongly re-armed")
		}
		if got := emits.CountFor("alert.unsilenced.auto"); got != 1 {
			t.Errorf("audit alert.unsilenced.auto = %d, want 1", got)
		}
	})
}

// @ac AC-11
// AC-11: a host_recovered alert auto-resolves matching open
// host_unreachable alerts for the same host.
func TestService_AutoResolve_HostRecoveredClosesUnreachable(t *testing.T) {
	t.Run("system-alerts/AC-11", func(t *testing.T) {
		pool, actor := freshDB(t)
		hostID, _ := uuid.NewV7()
		_, _ = pool.Exec(context.Background(),
			`INSERT INTO hosts (id, hostname, ip_address, created_by)
			 VALUES ($1, $2, '192.0.2.40'::inet, $3)`,
			hostID, "h-"+hostID.String(), actor)

		now := time.Now().UTC()
		u1 := seedAlert(t, pool, alertrouter.AlertTypeHostUnreachable,
			alertrouter.SeverityHigh, hostID, now.Add(-1*time.Hour))
		u2 := seedAlert(t, pool, alertrouter.AlertTypeHostUnreachable,
			alertrouter.SeverityHigh, hostID, now.Add(-30*time.Minute))

		svc := NewService(pool, nil)
		_ = svc.Acknowledge(context.Background(), u2, actor, "")

		// "Persist" the host_recovered alert.
		recovered := seedAlert(t, pool, alertrouter.AlertTypeHostRecovered,
			alertrouter.SeverityInfo, hostID, now)

		n, err := svc.AutoResolveFor(context.Background(), recovered)
		if err != nil {
			t.Fatalf("AutoResolveFor: %v", err)
		}
		if n != 2 {
			t.Errorf("AutoResolveFor closed %d, want 2", n)
		}
		if readAlertSnap(t, pool, u1).State != "resolved" {
			t.Errorf("u1 not auto-resolved")
		}
		if readAlertSnap(t, pool, u2).State != "resolved" {
			t.Errorf("u2 not auto-resolved")
		}
	})
}

// @ac AC-12
// AC-12: List filter state + host_id + severity narrows correctly.
func TestService_List_FilterByStateHostSeverity(t *testing.T) {
	t.Run("system-alerts/AC-12", func(t *testing.T) {
		pool, _ := freshDB(t)
		h1, _ := uuid.NewV7()
		h2, _ := uuid.NewV7()
		_, _ = pool.Exec(context.Background(),
			`INSERT INTO hosts (id, hostname, ip_address, created_by) VALUES
			 ($1, $2, '192.0.2.50'::inet, (SELECT id FROM users LIMIT 1)),
			 ($3, $4, '192.0.2.51'::inet, (SELECT id FROM users LIMIT 1))`,
			h1, "h1-"+h1.String(), h2, "h2-"+h2.String())

		now := time.Now().UTC()
		seedAlert(t, pool, alertrouter.AlertTypeHostUnreachable, alertrouter.SeverityHigh, h1, now.Add(-3*time.Minute))
		seedAlert(t, pool, alertrouter.AlertTypeHostUnreachable, alertrouter.SeverityMedium, h1, now.Add(-2*time.Minute))
		seedAlert(t, pool, alertrouter.AlertTypeHostUnreachable, alertrouter.SeverityHigh, h2, now.Add(-1*time.Minute))

		svc := NewService(pool, nil)
		state := "active"
		high := "high"
		got, _, err := svc.List(context.Background(), ListFilter{
			State: &state, HostID: &h1, Severity: &high, Limit: 50,
		})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(got) != 1 {
			t.Errorf("List returned %d, want 1", len(got))
		}
		if len(got) > 0 && got[0].HostID != h1 {
			t.Errorf("List host_id=%s, want %s", got[0].HostID, h1)
		}
	})
}

// @ac AC-13
// AC-13: cursor pagination — limit=2 of 5 returns 2 + cursor; next call returns 2 more.
func TestService_List_CursorPagination(t *testing.T) {
	t.Run("system-alerts/AC-13", func(t *testing.T) {
		pool, _ := freshDB(t)
		base := time.Now().UTC().Add(-1 * time.Hour)
		for i := 0; i < 5; i++ {
			seedAlert(t, pool, alertrouter.AlertTypeDriftMinor,
				alertrouter.SeverityLow, uuid.Nil, base.Add(time.Duration(i)*time.Minute))
		}
		svc := NewService(pool, nil)

		first, cur1, err := svc.List(context.Background(), ListFilter{Limit: 2})
		if err != nil {
			t.Fatalf("List page1: %v", err)
		}
		if len(first) != 2 {
			t.Errorf("page1 len=%d, want 2", len(first))
		}
		if cur1 == "" {
			t.Errorf("page1 cursor empty despite full page")
		}

		second, _, err := svc.List(context.Background(), ListFilter{Limit: 2, Cursor: cur1})
		if err != nil {
			t.Fatalf("List page2: %v", err)
		}
		if len(second) != 2 {
			t.Errorf("page2 len=%d, want 2", len(second))
		}
	})
}

// @ac AC-14
// AC-14: Get(unknown) returns ErrAlertNotFound; Get(resolved) returns row.
func TestService_Get_UnknownAndResolved(t *testing.T) {
	t.Run("system-alerts/AC-14", func(t *testing.T) {
		pool, actor := freshDB(t)
		svc := NewService(pool, nil)

		missing, _ := uuid.NewV7()
		if _, err := svc.Get(context.Background(), missing); !errors.Is(err, ErrAlertNotFound) {
			t.Errorf("Get(unknown) err=%v, want ErrAlertNotFound", err)
		}

		id := seedAlert(t, pool, alertrouter.AlertTypeHostUnreachable,
			alertrouter.SeverityHigh, uuid.Nil, time.Now().UTC())
		_ = svc.Resolve(context.Background(), id, actor, "")
		got, err := svc.Get(context.Background(), id)
		if err != nil {
			t.Fatalf("Get(resolved): %v", err)
		}
		if got.State != "resolved" {
			t.Errorf("Get(resolved).State=%q", got.State)
		}
	})
}
