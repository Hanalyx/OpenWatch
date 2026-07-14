// @spec api-compliance-exceptions
//
// Service-level AC coverage (DSN-gated). Endpoint AC-06 lives in
// internal/server.
//
//	AC-01  TestRequest_InsertDuplicateInvalidReopen
//	AC-02  TestLifecycle_Transitions
//	AC-03  TestSeparationOfDuties
//	AC-04  TestActiveQueries_OverlayNeverMutatesRuleState
//	AC-05  TestExpireSweep_FlipsAndIdempotent
//	AC-07  TestListHostNameJoin
//	AC-08  TestApprove_RejectsLapsedRequest
package exception

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/db/dbtest"
)

type emitCall struct {
	Code audit.Code
}

func fakeEmitter(calls *[]emitCall) EmitFunc {
	return func(ctx context.Context, code audit.Code, ev audit.Event) {
		*calls = append(*calls, emitCall{Code: code})
	}
}

func freshPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := dbtest.Pool(t)
	ctx := context.Background()
	for _, stmt := range []string{
		"TRUNCATE TABLE compliance_exceptions CASCADE",
		"TRUNCATE TABLE host_rule_state CASCADE",
		"TRUNCATE TABLE hosts CASCADE",
		"TRUNCATE TABLE users CASCADE",
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Logf("truncate (ok if benign): %v", err)
		}
	}
	return pool
}

func seedUser(t *testing.T, pool *pgxpool.Pool, name string) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO users (id, username, email, password_hash)
		 VALUES ($1, $2, $3, $4)`,
		id, name+"-"+id.String(), name+"@example.com", "argon2id$dummy") // pragma: allowlist secret
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

func seedHost(t *testing.T, pool *pgxpool.Pool, createdBy uuid.UUID) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO hosts (id, hostname, ip_address, created_by)
		 VALUES ($1, $2, '192.0.2.30'::inet, $3)`,
		id, "exc-"+id.String(), createdBy)
	if err != nil {
		t.Fatalf("seed host: %v", err)
	}
	return id
}

// @ac AC-01
func TestRequest_InsertDuplicateInvalidReopen(t *testing.T) {
	t.Run("api-compliance-exceptions/AC-01", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		user := seedUser(t, pool, "requester")
		hostID := seedHost(t, pool, user)
		var calls []emitCall
		svc := NewService(pool, fakeEmitter(&calls))

		e, err := svc.Request(ctx, hostID, "ssh-kex-fips", "accepted risk pending hardware refresh", user, nil)
		if err != nil {
			t.Fatalf("Request: %v", err)
		}
		if e.Status != StatusRequested || e.RuleID != "ssh-kex-fips" {
			t.Errorf("requested exception = %+v", e)
		}
		if len(calls) != 1 || calls[0].Code != audit.ComplianceExceptionRequested {
			t.Errorf("audit calls = %+v, want one requested", calls)
		}

		// Duplicate open: rejected.
		if _, err := svc.Request(ctx, hostID, "ssh-kex-fips", "again", user, nil); !errors.Is(err, ErrDuplicateOpen) {
			t.Errorf("duplicate Request err = %v, want ErrDuplicateOpen", err)
		}

		// Invalid input.
		if _, err := svc.Request(ctx, hostID, "", "reason", user, nil); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("empty rule err = %v, want ErrInvalidInput", err)
		}
		if _, err := svc.Request(ctx, hostID, "r", "", user, nil); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("empty reason err = %v, want ErrInvalidInput", err)
		}

		// Reopen after the prior is rejected: a fresh request succeeds.
		reviewer := seedUser(t, pool, "reviewer")
		if _, err := svc.Reject(ctx, e.ID, reviewer, "denied"); err != nil {
			t.Fatalf("Reject: %v", err)
		}
		if _, err := svc.Request(ctx, hostID, "ssh-kex-fips", "second attempt", user, nil); err != nil {
			t.Errorf("reopen after reject failed: %v", err)
		}
	})
}

// @ac AC-02
func TestLifecycle_Transitions(t *testing.T) {
	t.Run("api-compliance-exceptions/AC-02", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		requester := seedUser(t, pool, "req")
		reviewer := seedUser(t, pool, "rev")
		hostID := seedHost(t, pool, requester)
		var calls []emitCall
		svc := NewService(pool, fakeEmitter(&calls))

		// approve path
		a, _ := svc.Request(ctx, hostID, "rule-a", "reason", requester, nil)
		got, err := svc.Approve(ctx, a.ID, reviewer, "ok")
		if err != nil || got.Status != StatusApproved || got.ReviewedBy == nil || *got.ReviewedBy != reviewer {
			t.Fatalf("Approve = %+v, err %v", got, err)
		}
		// revoke the approved
		got, err = svc.Revoke(ctx, a.ID, reviewer, "no longer needed")
		if err != nil || got.Status != StatusRevoked {
			t.Fatalf("Revoke = %+v, err %v", got, err)
		}
		// revoking a non-approved (now revoked) row: wrong state
		if _, err := svc.Revoke(ctx, a.ID, reviewer, "again"); !errors.Is(err, ErrWrongState) {
			t.Errorf("re-revoke err = %v, want ErrWrongState", err)
		}

		// reject path
		b, _ := svc.Request(ctx, hostID, "rule-b", "reason", requester, nil)
		if got, err := svc.Reject(ctx, b.ID, reviewer, "no"); err != nil || got.Status != StatusRejected {
			t.Fatalf("Reject = %+v, err %v", got, err)
		}
		// approving a rejected row: wrong state
		if _, err := svc.Approve(ctx, b.ID, reviewer, "x"); !errors.Is(err, ErrWrongState) {
			t.Errorf("approve-rejected err = %v, want ErrWrongState", err)
		}

		// audit codes seen: requested x2, approved, revoked, rejected
		seen := map[audit.Code]int{}
		for _, c := range calls {
			seen[c.Code]++
		}
		if seen[audit.ComplianceExceptionApproved] != 1 || seen[audit.ComplianceExceptionRevoked] != 1 ||
			seen[audit.ComplianceExceptionRejected] != 1 {
			t.Errorf("audit codes = %v", seen)
		}
	})
}

// @ac AC-03
func TestSeparationOfDuties(t *testing.T) {
	t.Run("api-compliance-exceptions/AC-03", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		user := seedUser(t, pool, "selfreq")
		hostID := seedHost(t, pool, user)
		svc := NewService(pool, fakeEmitter(&[]emitCall{}))

		e, _ := svc.Request(ctx, hostID, "rule-s", "reason", user, nil)
		// self-approve blocked
		if _, err := svc.Approve(ctx, e.ID, user, "me"); !errors.Is(err, ErrSelfReview) {
			t.Errorf("self-approve err = %v, want ErrSelfReview", err)
		}
		// self-reject blocked
		if _, err := svc.Reject(ctx, e.ID, user, "me"); !errors.Is(err, ErrSelfReview) {
			t.Errorf("self-reject err = %v, want ErrSelfReview", err)
		}
		// row unchanged (still requested)
		got, _ := svc.ListForHost(ctx, hostID, false)
		if len(got) != 1 || got[0].Status != StatusRequested {
			t.Errorf("row mutated by blocked self-review: %+v", got)
		}
		// self-revoke allowed: approve with a different reviewer first,
		// then the requester revokes their own (now-active) exception.
		reviewer := seedUser(t, pool, "rev2")
		if _, err := svc.Approve(ctx, e.ID, reviewer, "ok"); err != nil {
			t.Fatalf("approve: %v", err)
		}
		if _, err := svc.Revoke(ctx, e.ID, user, "self revoke ok"); err != nil {
			t.Errorf("self-revoke should be allowed: %v", err)
		}
	})
}

// @ac AC-04
func TestActiveQueries_OverlayNeverMutatesRuleState(t *testing.T) {
	t.Run("api-compliance-exceptions/AC-04", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		requester := seedUser(t, pool, "req")
		reviewer := seedUser(t, pool, "rev")
		hostID := seedHost(t, pool, requester)
		svc := NewService(pool, fakeEmitter(&[]emitCall{}))

		// A failing rule row in host_rule_state (the overlay target).
		if _, err := pool.Exec(ctx, `
			INSERT INTO host_rule_state
				(host_id, rule_id, current_status, severity, last_checked_at,
				 check_count, last_scan_id, first_seen_at, last_changed_at)
			VALUES ($1, 'rule-active', 'fail', 'high', now(), 1, $2, now(), now())`,
			hostID, uuid.Must(uuid.NewV7())); err != nil {
			t.Fatalf("seed rule state: %v", err)
		}

		// approved + active -> counted
		active, _ := svc.Request(ctx, hostID, "rule-active", "reason", requester, nil)
		_, _ = svc.Approve(ctx, active.ID, reviewer, "ok")
		// approved but already expired -> NOT counted
		past := time.Now().Add(-time.Hour)
		expired, _ := svc.Request(ctx, hostID, "rule-expired", "reason", requester, &past)
		_, _ = svc.Approve(ctx, expired.ID, reviewer, "ok")
		// requested-only -> NOT counted
		_, _ = svc.Request(ctx, hostID, "rule-pending", "reason", requester, nil)

		n, err := svc.ActiveCountForHost(ctx, hostID)
		if err != nil || n != 1 {
			t.Errorf("ActiveCountForHost = %d (err %v), want 1 (active only)", n, err)
		}
		ids, err := svc.ActiveRuleIDsForHost(ctx, hostID)
		if err != nil || !ids["rule-active"] || ids["rule-expired"] || ids["rule-pending"] || len(ids) != 1 {
			t.Errorf("ActiveRuleIDsForHost = %v, want {rule-active}", ids)
		}

		// Overlay invariant: host_rule_state.current_status untouched.
		var status string
		_ = pool.QueryRow(ctx, `SELECT current_status FROM host_rule_state
			WHERE host_id = $1 AND rule_id = 'rule-active'`, hostID).Scan(&status)
		if status != "fail" {
			t.Errorf("exception mutated host_rule_state: status = %q, want fail", status)
		}
	})
}

// @ac AC-05
func TestExpireSweep_FlipsAndIdempotent(t *testing.T) {
	t.Run("api-compliance-exceptions/AC-05", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		requester := seedUser(t, pool, "req")
		reviewer := seedUser(t, pool, "rev")
		hostID := seedHost(t, pool, requester)
		var calls []emitCall
		svc := NewService(pool, fakeEmitter(&calls))

		past := time.Now().Add(-time.Hour)
		future := time.Now().Add(time.Hour)

		// approved + past: approve with a FUTURE expiry, then age it into the
		// past via SQL. (Approve now rejects a past expiry, AC-08, so we cannot
		// request-past-then-approve to build this row.)
		eAppPast, _ := svc.Request(ctx, hostID, "rule-app-past", "reason", requester, &future)
		if _, err := svc.Approve(ctx, eAppPast.ID, reviewer, "ok"); err != nil {
			t.Fatalf("approve rule-app-past: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`UPDATE compliance_exceptions SET expires_at = $2 WHERE id = $1`, eAppPast.ID, past); err != nil {
			t.Fatalf("age approved row: %v", err)
		}
		// requested + past: a request whose requested end passed while pending.
		if _, err := svc.Request(ctx, hostID, "rule-req-past", "reason", requester, &past); err != nil {
			t.Fatalf("request rule-req-past: %v", err)
		}
		// approved + future and approved + null: both must survive the sweep.
		eFut, _ := svc.Request(ctx, hostID, "rule-fut", "reason", requester, &future)
		_, _ = svc.Approve(ctx, eFut.ID, reviewer, "ok")
		eNull, _ := svc.Request(ctx, hostID, "rule-null", "reason", requester, nil)
		_, _ = svc.Approve(ctx, eNull.ID, reviewer, "ok")

		calls = nil
		n, err := svc.ExpireSweep(ctx)
		if err != nil || n != 2 {
			t.Fatalf("ExpireSweep = %d (err %v), want 2 (approved-past + requested-past)", n, err)
		}
		if len(calls) != 2 {
			t.Fatalf("sweep audit = %+v, want two expired", calls)
		}
		for _, c := range calls {
			if c.Code != audit.ComplianceExceptionExpired {
				t.Errorf("sweep audit code = %v, want expired", c.Code)
			}
		}
		// future + null expiry (both approved) untouched.
		if c, _ := svc.ActiveCountForHost(ctx, hostID); c != 2 {
			t.Errorf("active after sweep = %d, want 2", c)
		}
		// idempotent.
		if n2, _ := svc.ExpireSweep(ctx); n2 != 0 {
			t.Errorf("second sweep = %d, want 0", n2)
		}
	})
}

// @ac AC-08
// AC-08: a lapsed request cannot be approved into an immediately-dead waiver.
func TestApprove_RejectsLapsedRequest(t *testing.T) {
	t.Run("api-compliance-exceptions/AC-08", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		requester := seedUser(t, pool, "req")
		reviewer := seedUser(t, pool, "rev")
		hostID := seedHost(t, pool, requester)
		svc := NewService(pool, nil)

		// A request whose expires_at is already in the past (it lapsed while
		// pending). Approve must refuse it and leave the row unchanged.
		past := time.Now().Add(-time.Hour)
		e, err := svc.Request(ctx, hostID, "rule-lapsed", "reason", requester, &past)
		if err != nil {
			t.Fatalf("Request: %v", err)
		}
		if _, err := svc.Approve(ctx, e.ID, reviewer, "ok"); !errors.Is(err, ErrExpired) {
			t.Fatalf("Approve(lapsed) err = %v, want ErrExpired", err)
		}
		var status string
		if err := pool.QueryRow(ctx,
			`SELECT status FROM compliance_exceptions WHERE id = $1`, e.ID).Scan(&status); err != nil {
			t.Fatalf("read status: %v", err)
		}
		if Status(status) != StatusRequested {
			t.Errorf("status after refused approve = %q, want requested", status)
		}

		// A future-dated request approves fine: the guard is specific to a
		// past expiry, not to having an expiry at all.
		future := time.Now().Add(time.Hour)
		e2, _ := svc.Request(ctx, hostID, "rule-ok", "reason", requester, &future)
		if _, err := svc.Approve(ctx, e2.ID, reviewer, "ok"); err != nil {
			t.Errorf("Approve(future) err = %v, want nil", err)
		}
	})
}

// @ac AC-07
// AC-07 (v1.1.0): the list queries join hosts and populate HostName so
// the approver queue is readable; the fleet list excludes soft-deleted
// hosts; single-row lifecycle results leave HostName empty.
func TestListHostNameJoin(t *testing.T) {
	t.Run("api-compliance-exceptions/AC-07", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		user := seedUser(t, pool, "req")
		hostID := seedHost(t, pool, user)

		// Name the host so the join has something to return.
		if _, err := pool.Exec(ctx,
			`UPDATE hosts SET hostname = 'queue-host-01' WHERE id = $1`, hostID); err != nil {
			t.Fatalf("name host: %v", err)
		}

		svc := NewService(pool, fakeEmitter(&[]emitCall{}))

		// Single-row result (Request) leaves HostName empty.
		e, err := svc.Request(ctx, hostID, "rule-x", "reason", user, nil)
		if err != nil {
			t.Fatalf("Request: %v", err)
		}
		if e.HostName != "" {
			t.Errorf("Request HostName = %q, want empty (single-row path)", e.HostName)
		}

		// List paths populate HostName via the join.
		forHost, err := svc.ListForHost(ctx, hostID, false)
		if err != nil || len(forHost) != 1 || forHost[0].HostName != "queue-host-01" {
			t.Errorf("ListForHost HostName = %+v, want queue-host-01", forHost)
		}
		fleet, err := svc.ListFleet(ctx, StatusRequested, 50)
		if err != nil || len(fleet) != 1 || fleet[0].HostName != "queue-host-01" {
			t.Errorf("ListFleet HostName = %+v, want queue-host-01", fleet)
		}

		// Soft-deleted host drops out of the fleet list.
		if _, err := pool.Exec(ctx, `UPDATE hosts SET deleted_at = now() WHERE id = $1`, hostID); err != nil {
			t.Fatalf("soft delete: %v", err)
		}
		if fleet, _ := svc.ListFleet(ctx, StatusRequested, 50); len(fleet) != 0 {
			t.Errorf("fleet after soft-delete = %d rows, want 0", len(fleet))
		}
	})
}
