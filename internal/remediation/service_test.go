// @spec api-remediation
//
// Service-level AC coverage (DSN-gated). Endpoint AC-05 and the license-gate
// AC-06 live in internal/server.
//
//	AC-01  TestRequest_InsertDuplicateInvalidReopen
//	AC-02  TestLifecycle_Transitions
//	AC-03  TestSeparationOfDuties
//	AC-04  TestProjectLift_AndOverlayNeverMutatesRuleState
package remediation

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/db/dbtest"
)

type emitCall struct {
	Code   audit.Code
	Detail string
}

func fakeEmitter(calls *[]emitCall) EmitFunc {
	return func(ctx context.Context, code audit.Code, ev audit.Event) {
		*calls = append(*calls, emitCall{Code: code, Detail: string(ev.Detail)})
	}
}

func freshPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := dbtest.Pool(t)
	ctx := context.Background()
	for _, stmt := range []string{
		"TRUNCATE TABLE remediation_transactions CASCADE",
		"TRUNCATE TABLE remediation_requests CASCADE",
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
		 VALUES ($1, $2, '192.0.2.40'::inet, $3)`,
		id, "rem-"+id.String(), createdBy)
	if err != nil {
		t.Fatalf("seed host: %v", err)
	}
	return id
}

// seedRuleState inserts one host_rule_state row with the given status and
// framework_refs JSON (e.g. `{"cis_rhel9_v2":["1.1"]}`).
func seedRuleState(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, ruleID, status, refsJSON string) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO host_rule_state
			(host_id, rule_id, current_status, severity, last_checked_at,
			 check_count, last_scan_id, evidence, framework_refs, first_seen_at, last_changed_at)
		VALUES ($1, $2, $3, 'high', now(), 1, $4, '{}'::jsonb, $5::jsonb, now(), now())`,
		hostID, ruleID, status, uuid.Must(uuid.NewV7()), refsJSON)
	if err != nil {
		t.Fatalf("seed rule state %s: %v", ruleID, err)
	}
}

// @ac AC-01
func TestRequest_InsertDuplicateInvalidReopen(t *testing.T) {
	t.Run("api-remediation/AC-01", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		user := seedUser(t, pool, "requester")
		hostID := seedHost(t, pool, user)
		var calls []emitCall
		svc := NewService(pool, fakeEmitter(&calls))

		// Free-core single-rule remediation (requiresApproval=false) is
		// AUTO-APPROVED on creation.
		rq, err := svc.Request(ctx, hostID, "sshd-permit-root-no", nil, user, false)
		if err != nil {
			t.Fatalf("Request: %v", err)
		}
		if rq.Status != StatusApproved || rq.RuleID != "sshd-permit-root-no" {
			t.Errorf("requested remediation = %+v, want status=approved", rq)
		}
		if rq.ReviewedAt == nil || rq.ReviewedBy != nil {
			t.Errorf("auto-approved: want reviewed_at set + reviewed_by nil, got reviewed_at=%v reviewed_by=%v", rq.ReviewedAt, rq.ReviewedBy)
		}
		if !strings.Contains(rq.ReviewNote, "auto-approved") {
			t.Errorf("auto-approved review_note = %q, want an auto-approved note", rq.ReviewNote)
		}
		// Auto-approve emits remediation.requested then remediation.approved.
		if len(calls) != 2 || calls[0].Code != audit.RemediationRequested || calls[1].Code != audit.RemediationApproved {
			t.Errorf("audit calls = %+v, want requested + approved", calls)
		}

		// Duplicate open (the auto-approved request is still open): rejected.
		if _, err := svc.Request(ctx, hostID, "sshd-permit-root-no", nil, user, false); !errors.Is(err, ErrDuplicateOpen) {
			t.Errorf("duplicate Request err = %v, want ErrDuplicateOpen", err)
		}

		// Invalid input (empty rule).
		if _, err := svc.Request(ctx, hostID, "  ", nil, user, false); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("empty rule err = %v, want ErrInvalidInput", err)
		}

		// Approval-required (requiresApproval=true) inserts pending_approval and
		// reopens after a terminal state: reject -> a fresh request succeeds.
		reviewer := seedUser(t, pool, "reviewer")
		pend, err := svc.Request(ctx, hostID, "needs-approval", nil, user, true)
		if err != nil {
			t.Fatalf("approval-required Request: %v", err)
		}
		if pend.Status != StatusPendingApproval {
			t.Errorf("approval-required status = %v, want pending_approval", pend.Status)
		}
		if _, err := svc.Reject(ctx, pend.ID, reviewer, "not now"); err != nil {
			t.Fatalf("Reject: %v", err)
		}
		if _, err := svc.Request(ctx, hostID, "needs-approval", nil, user, true); err != nil {
			t.Errorf("reopen after reject failed: %v", err)
		}
	})
}

// @ac AC-02
func TestLifecycle_Transitions(t *testing.T) {
	t.Run("api-remediation/AC-02", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		requester := seedUser(t, pool, "req")
		reviewer := seedUser(t, pool, "rev")
		hostID := seedHost(t, pool, requester)
		var calls []emitCall
		svc := NewService(pool, fakeEmitter(&calls))

		// approve path
		a, _ := svc.Request(ctx, hostID, "rule-a", nil, requester, true)
		got, err := svc.Approve(ctx, a.ID, reviewer, "ok")
		if err != nil || got.Status != StatusApproved || got.ReviewedBy == nil || *got.ReviewedBy != reviewer {
			t.Fatalf("Approve = %+v, err %v", got, err)
		}
		// approving an already-approved row: wrong state
		if _, err := svc.Approve(ctx, a.ID, reviewer, "again"); !errors.Is(err, ErrWrongState) {
			t.Errorf("re-approve err = %v, want ErrWrongState", err)
		}

		// reject path
		b, _ := svc.Request(ctx, hostID, "rule-b", nil, requester, true)
		if got, err := svc.Reject(ctx, b.ID, reviewer, "no"); err != nil || got.Status != StatusRejected {
			t.Fatalf("Reject = %+v, err %v", got, err)
		}
		// approving a rejected row: wrong state
		if _, err := svc.Approve(ctx, b.ID, reviewer, "x"); !errors.Is(err, ErrWrongState) {
			t.Errorf("approve-rejected err = %v, want ErrWrongState", err)
		}

		// Reject emits remediation.approved with detail.outcome=rejected (no
		// separate rejected code in the registered taxonomy).
		seen := map[audit.Code]int{}
		var rejectDetail string
		for _, c := range calls {
			seen[c.Code]++
			if c.Code == audit.RemediationApproved && strings.Contains(c.Detail, `"outcome":"rejected"`) {
				rejectDetail = c.Detail
			}
		}
		if seen[audit.RemediationApproved] != 2 {
			t.Errorf("approved-code count = %d, want 2 (approve + reject)", seen[audit.RemediationApproved])
		}
		if rejectDetail == "" {
			t.Errorf("reject did not emit remediation.approved with outcome=rejected; calls=%+v", calls)
		}
		// missing-row transition -> ErrNotFound
		if _, err := svc.Approve(ctx, uuid.Must(uuid.NewV7()), reviewer, ""); !errors.Is(err, ErrNotFound) {
			t.Errorf("approve-missing err = %v, want ErrNotFound", err)
		}
	})
}

// @ac AC-03
func TestSeparationOfDuties(t *testing.T) {
	t.Run("api-remediation/AC-03", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		user := seedUser(t, pool, "selfreq")
		hostID := seedHost(t, pool, user)
		svc := NewService(pool, fakeEmitter(&[]emitCall{}))

		rq, _ := svc.Request(ctx, hostID, "rule-s", nil, user, true)
		// self-approve blocked
		if _, err := svc.Approve(ctx, rq.ID, user, "me"); !errors.Is(err, ErrSelfReview) {
			t.Errorf("self-approve err = %v, want ErrSelfReview", err)
		}
		// self-reject blocked
		if _, err := svc.Reject(ctx, rq.ID, user, "me"); !errors.Is(err, ErrSelfReview) {
			t.Errorf("self-reject err = %v, want ErrSelfReview", err)
		}
		// row unchanged (still pending_approval)
		got, _ := svc.Get(ctx, rq.ID)
		if got.Status != StatusPendingApproval {
			t.Errorf("row mutated by blocked self-review: %+v", got)
		}
	})
}

// @ac AC-04
func TestProjectLift_AndOverlayNeverMutatesRuleState(t *testing.T) {
	t.Run("api-remediation/AC-04", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		requester := seedUser(t, pool, "req")
		reviewer := seedUser(t, pool, "rev")
		hostID := seedHost(t, pool, requester)
		svc := NewService(pool, fakeEmitter(&[]emitCall{}))

		// Framework participation on the host:
		//   cis : active, b, c           -> N=3 -> delta 33.33
		//   stig: active, e              -> N=2 -> delta 50.0
		//   nist: d                      -> N=1 (active does not map nist)
		seedRuleState(t, pool, hostID, "rule-active", "fail", `{"cis_rhel9_v2":["1.1"],"stig_rhel9_v2r7":["V-1"]}`)
		seedRuleState(t, pool, hostID, "rule-b", "pass", `{"cis_rhel9_v2":["1.2"]}`)
		seedRuleState(t, pool, hostID, "rule-c", "fail", `{"cis_rhel9_v2":["1.3"]}`)
		seedRuleState(t, pool, hostID, "rule-d", "fail", `{"nist_800_53_r5":["AC-6"]}`)
		seedRuleState(t, pool, hostID, "rule-e", "pass", `{"stig_rhel9_v2r7":["V-2"]}`)

		// ProjectLift for the failing, cis+stig-mapped rule.
		lift, err := svc.ProjectLift(ctx, hostID, "rule-active")
		if err != nil {
			t.Fatalf("ProjectLift: %v", err)
		}
		if lift.CIS == nil || *lift.CIS != 33.33 {
			t.Errorf("CIS lift = %v, want 33.33", lift.CIS)
		}
		if lift.STIG == nil || *lift.STIG != 50.0 {
			t.Errorf("STIG lift = %v, want 50.0", lift.STIG)
		}
		if lift.NIST != nil {
			t.Errorf("NIST lift = %v, want nil (rule does not map nist)", lift.NIST)
		}

		// A passing rule has no lift to gain.
		if l, _ := svc.ProjectLift(ctx, hostID, "rule-b"); l.CIS != nil || l.STIG != nil || l.NIST != nil {
			t.Errorf("passing-rule lift = %+v, want empty", l)
		}
		// An unknown rule degrades to an empty projection (no error).
		if l, err := svc.ProjectLift(ctx, hostID, "rule-unknown"); err != nil || l.CIS != nil {
			t.Errorf("unknown-rule lift = %+v err %v, want empty/no-error", l, err)
		}

		// Request persists the projection snapshot.
		rq, err := svc.Request(ctx, hostID, "rule-active", nil, requester, false)
		if err != nil {
			t.Fatalf("Request: %v", err)
		}
		if rq.Projected.CIS == nil || *rq.Projected.CIS != 33.33 {
			t.Errorf("persisted CIS projection = %v, want 33.33", rq.Projected.CIS)
		}
		_, _ = svc.Approve(ctx, rq.ID, reviewer, "ok")

		// Overlay invariant: no remediation path mutated host_rule_state, and
		// the journal stays empty in the free build.
		var status string
		_ = pool.QueryRow(ctx, `SELECT current_status FROM host_rule_state
			WHERE host_id = $1 AND rule_id = 'rule-active'`, hostID).Scan(&status)
		if status != "fail" {
			t.Errorf("remediation mutated host_rule_state: status = %q, want fail", status)
		}
		steps, _ := svc.ListSteps(ctx, rq.ID)
		if len(steps) != 0 {
			t.Errorf("free build wrote %d journal steps, want 0", len(steps))
		}
	})
}
