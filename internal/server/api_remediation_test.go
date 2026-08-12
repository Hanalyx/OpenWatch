// @spec api-remediation
//
// Endpoint AC (DSN-gated). Service-level AC-01..04 live in
// internal/remediation.
//
//	AC-05  TestAPI_Remediation_LifecycleAndRBAC
//	AC-06  TestAPI_Remediation_ExecuteFreeCore
//	AC-09  TestAPI_Remediation_RollbackAcceptsStaged
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/auth"
)

type apiRem struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	RuleID   string `json:"rule_id"`
	HostName string `json:"host_name"`
}

// @ac AC-05
// AC-05: RBAC bars on the endpoints + a full request->approve happy path
// through HTTP; ops_lead (request, no approve) is 403 on :approve;
// security_admin approves (different user); separation of duties holds at the
// HTTP layer; reads (get, steps, list) require remediation:read.
func TestAPI_Remediation_LifecycleAndRBAC(t *testing.T) {
	t.Run("api-remediation/AC-05", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)

		base := url + "/api/v1/remediation/requests"
		reqBody := map[string]any{"host_id": hostID.String(), "rule_id": "sshd-permit-root-no"}

		// --- request: ops_lead can, viewer cannot, unknown host 404 ---
		vr := doReq(t, asRole(t, "POST", base, auth.RoleViewer, reqBody))
		vr.Body.Close()
		if vr.StatusCode != http.StatusForbidden {
			t.Fatalf("viewer request status = %d, want 403", vr.StatusCode)
		}

		ghostBody := map[string]any{"host_id": uuid.Must(uuid.NewV7()).String(), "rule_id": "r"}
		gr := doReq(t, asRole(t, "POST", base, auth.RoleOpsLead, ghostBody))
		gr.Body.Close()
		if gr.StatusCode != http.StatusNotFound {
			t.Fatalf("unknown-host request status = %d, want 404", gr.StatusCode)
		}

		or := doReq(t, asRole(t, "POST", base, auth.RoleOpsLead, reqBody))
		defer or.Body.Close()
		if or.StatusCode != http.StatusCreated {
			t.Fatalf("ops_lead request status = %d, want 201", or.StatusCode)
		}
		var created apiRem
		if err := json.NewDecoder(or.Body).Decode(&created); err != nil {
			t.Fatalf("decode created: %v", err)
		}
		// Free core: a single-rule request is auto-approved on creation (no
		// separate approver). See remediation_governance_adr.md.
		if created.Status != "approved" || created.RuleID != "sshd-permit-root-no" {
			t.Errorf("created = %+v, want status=approved (auto-approved free core)", created)
		}

		// --- duplicate open -> 409 ---
		dr := doReq(t, asRole(t, "POST", base, auth.RoleOpsLead, reqBody))
		dr.Body.Close()
		if dr.StatusCode != http.StatusConflict {
			t.Errorf("duplicate request status = %d, want 409", dr.StatusCode)
		}

		// --- anonymous list rejected ---
		anon, _ := http.NewRequest("GET", base, nil)
		ar, _ := http.DefaultClient.Do(anon)
		ar.Body.Close()
		if ar.StatusCode != http.StatusUnauthorized && ar.StatusCode != http.StatusForbidden {
			t.Errorf("anonymous list status = %d, want 401/403", ar.StatusCode)
		}

		// --- approve endpoint RBAC + separation of duties. The free-core POST
		// above auto-approves, so it never yields a pending row; seed an
		// approval-required (pending_approval) request directly to exercise the
		// approve endpoint (this is the licensed bulk/auto track's shape). ---
		pendID := seedPendingRemediation(t, pool, hostID, roleUserIDs[auth.RoleOpsLead], "needs-approval")
		pendPath := base + "/" + pendID.String()

		// ops_lead (the requester; no remediation:approve) -> 403
		oa := doReq(t, asRole(t, "POST", pendPath+":approve", auth.RoleOpsLead, map[string]any{}))
		oa.Body.Close()
		if oa.StatusCode != http.StatusForbidden {
			t.Fatalf("ops_lead approve status = %d, want 403", oa.StatusCode)
		}

		// security_admin (different user from the requester) approves -> 200
		sa := doReq(t, asRole(t, "POST", pendPath+":approve",
			auth.RoleSecurityAdmin, map[string]any{"note": "reviewed"}))
		defer sa.Body.Close()
		if sa.StatusCode != http.StatusOK {
			t.Fatalf("security_admin approve status = %d, want 200", sa.StatusCode)
		}
		var approved apiRem
		_ = json.NewDecoder(sa.Body).Decode(&approved)
		if approved.Status != "approved" {
			t.Errorf("approved status = %q, want approved", approved.Status)
		}

		// re-approve -> 409 wrong state
		ra := doReq(t, asRole(t, "POST", pendPath+":approve", auth.RoleSecurityAdmin, map[string]any{}))
		ra.Body.Close()
		if ra.StatusCode != http.StatusConflict {
			t.Errorf("re-approve status = %d, want 409", ra.StatusCode)
		}

		// separation of duties at the HTTP layer: the security_admin requester
		// cannot approve their own pending request -> 409 self_review.
		selfID := seedPendingRemediation(t, pool, hostID, roleUserIDs[auth.RoleSecurityAdmin], "self-rule")
		selfAp := doReq(t, asRole(t, "POST", base+"/"+selfID.String()+":approve", auth.RoleSecurityAdmin, map[string]any{}))
		selfAp.Body.Close()
		if selfAp.StatusCode != http.StatusConflict {
			t.Errorf("self-approve status = %d, want 409 (separation of duties)", selfAp.StatusCode)
		}

		// --- reads: get + steps require remediation:read (viewer has it) ---
		g := doReq(t, asRole(t, "GET", base+"/"+created.ID, auth.RoleViewer, nil))
		g.Body.Close()
		if g.StatusCode != http.StatusOK {
			t.Errorf("get status = %d, want 200", g.StatusCode)
		}
		st := doReq(t, asRole(t, "GET", base+"/"+created.ID+"/steps", auth.RoleViewer, nil))
		defer st.Body.Close()
		var steps struct {
			Steps []any `json:"steps"`
		}
		_ = json.NewDecoder(st.Body).Decode(&steps)
		if st.StatusCode != http.StatusOK || len(steps.Steps) != 0 {
			t.Errorf("steps status = %d len = %d, want 200 / 0 (empty in free build)", st.StatusCode, len(steps.Steps))
		}

		// --- list: remediation:read, host_name joined ---
		lr := doReq(t, asRole(t, "GET", base, auth.RoleViewer, nil))
		defer lr.Body.Close()
		var list struct {
			Requests []apiRem `json:"requests"`
		}
		_ = json.NewDecoder(lr.Body).Decode(&list)
		if len(list.Requests) < 1 {
			t.Errorf("list len = %d, want >= 1", len(list.Requests))
		}
		if list.Requests[0].HostName == "" {
			t.Errorf("list request host_name empty; want the joined hostname")
		}
	})
}

// @ac AC-06
// AC-06: execute/rollback are FREE core (no license). A holder of
// remediation:execute executing an APPROVED request gets 202 and enqueues a
// remediation job; a caller lacking remediation:execute is 403; executing a
// non-approved (pending) request is 409; rolling back a request that is not
// rollback-eligible is 409 (see AC-09 for the staged case). No act endpoint
// returns 402.
func TestAPI_Remediation_ExecuteFreeCore(t *testing.T) {
	t.Run("api-remediation/AC-06", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)
		base := url + "/api/v1/remediation/requests"

		// ops_lead requests; security_admin approves (separation of duties).
		or := doReq(t, asRole(t, "POST", base, auth.RoleOpsLead,
			map[string]any{"host_id": hostID.String(), "rule_id": "rule-x"}))
		var created apiRem
		_ = json.NewDecoder(or.Body).Decode(&created)
		or.Body.Close()
		execURL := base + "/" + created.ID + ":execute"

		// viewer has remediation:read but NOT remediation:execute -> 403 (RBAC).
		o := doReq(t, asRole(t, "POST", execURL, auth.RoleViewer, map[string]any{}))
		o.Body.Close()
		if o.StatusCode != http.StatusForbidden {
			t.Fatalf("viewer execute status = %d, want 403", o.StatusCode)
		}

		// Executing a NON-approved (pending) request -> 409 wrong_state, NOT 402
		// (free core, no license gate). The free-core request above auto-approves,
		// so seed a pending row to exercise this path.
		pendID := seedPendingRemediation(t, pool, hostID, roleUserIDs[auth.RoleOpsLead], "rule-pending")
		pre := doReq(t, asRole(t, "POST", base+"/"+pendID.String()+":execute", auth.RoleSecurityAdmin, map[string]any{}))
		pre.Body.Close()
		if pre.StatusCode != http.StatusConflict {
			t.Fatalf("execute-before-approve status = %d, want 409", pre.StatusCode)
		}

		// The free-core request is already approved (auto). Execute it directly
		// -> 202 Accepted, a remediation job enqueued.
		ex := doReq(t, asRole(t, "POST", execURL, auth.RoleSecurityAdmin, map[string]any{}))
		var acc struct {
			RequestID string `json:"request_id"`
			JobID     string `json:"job_id"`
			Status    string `json:"status"`
		}
		_ = json.NewDecoder(ex.Body).Decode(&acc)
		ex.Body.Close()
		if ex.StatusCode != http.StatusAccepted {
			t.Fatalf("execute status = %d, want 202", ex.StatusCode)
		}
		if acc.Status != "queued" || acc.JobID == "" {
			t.Errorf("execute body = %+v, want queued + job_id", acc)
		}
		if n := countRemediationJobs(t, pool); n != 1 {
			t.Errorf("enqueued remediation jobs = %d, want 1", n)
		}

		// rollback on a not-executed request -> 409 (still approved/executing).
		rb := doReq(t, asRole(t, "POST", base+"/"+created.ID+":rollback",
			auth.RoleSecurityAdmin, map[string]any{}))
		rb.Body.Close()
		if rb.StatusCode != http.StatusConflict {
			t.Errorf("rollback-before-execute status = %d, want 409", rb.StatusCode)
		}
	})
}

// @ac AC-09
// AC-09: the :rollback PRECONDITION accepts staged, not just executed.
//
// WHY THIS EXISTS, at the HTTP layer specifically. AC-09 was already annotated
// on internal/remediation.TestOutcome_Staged, which asserts
// Status("staged").RollbackEligible() == true. That is the enum in isolation.
// The handler did not call RollbackEligible; it compared `rq.Status !=
// StatusExecuted` literally, so every staged rollback 409'd while the type
// test, the worker, and the UI all agreed it should be allowed. Coverage was
// 100% and the AC was still unmet, because the annotation sat on a unit test of
// a predicate rather than on the precondition the AC describes.
//
// Found by running the release verification against a real immutable-audit host
// (auditctl `enabled 2`), where the Roll back button the UI offers on a staged
// remediation failed and stranded the change on the host.
func TestAPI_Remediation_RollbackAcceptsStaged(t *testing.T) {
	t.Run("api-remediation/AC-09", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)
		base := url + "/api/v1/remediation/requests"

		// A staged request: the persist layer is written and the host HAS
		// changed, so the change is reversible and rollback must be reachable.
		stagedID := seedRemediationInStatus(t, pool, hostID,
			roleUserIDs[auth.RoleOpsLead], "rule-staged", "staged")
		rb := doReq(t, asRole(t, "POST", base+"/"+stagedID.String()+":rollback",
			auth.RoleSecurityAdmin, map[string]any{}))
		rb.Body.Close()
		if rb.StatusCode != http.StatusAccepted {
			t.Errorf("rollback of a staged request = %d, want 202; the handler "+
				"must use Status.RollbackEligible, not a literal StatusExecuted "+
				"comparison", rb.StatusCode)
		}

		// The negative direction still holds: an outcome that mutated nothing
		// has nothing to reverse.
		for _, st := range []string{"not_applied", "reverted", "failed"} {
			id := seedRemediationInStatus(t, pool, hostID,
				roleUserIDs[auth.RoleOpsLead], "rule-"+st, st)
			r := doReq(t, asRole(t, "POST", base+"/"+id.String()+":rollback",
				auth.RoleSecurityAdmin, map[string]any{}))
			r.Body.Close()
			if r.StatusCode != http.StatusConflict {
				t.Errorf("rollback of a %s request = %d, want 409", st, r.StatusCode)
			}
		}
	})
}

// seedRemediationInStatus inserts a remediation request already in a terminal
// status, so the HTTP preconditions can be exercised without driving a real
// Kensa transaction.
func seedRemediationInStatus(t *testing.T, pool *pgxpool.Pool, hostID, requestedBy uuid.UUID, ruleID, status string) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO remediation_requests (id, host_id, rule_id, status, requested_by)
		 VALUES ($1, $2, $3, $4, $5)`,
		id, hostID, ruleID, status, requestedBy); err != nil {
		t.Fatalf("seed %s remediation: %v", status, err)
	}
	return id
}

// seedPendingRemediation inserts a pending_approval remediation request
// directly (the approval-required / licensed track's shape). The free-core HTTP
// POST auto-approves, so this is how the approve-endpoint and pending-execute
// paths are exercised at the HTTP layer.
func seedPendingRemediation(t *testing.T, pool *pgxpool.Pool, hostID, requestedBy uuid.UUID, ruleID string) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO remediation_requests (id, host_id, rule_id, status, requested_by)
		 VALUES ($1, $2, $3, 'pending_approval', $4)`,
		id, hostID, ruleID, requestedBy); err != nil {
		t.Fatalf("seed pending remediation: %v", err)
	}
	return id
}

// countRemediationJobs counts pending remediation jobs on the queue.
func countRemediationJobs(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM job_queue WHERE job_type = 'remediation'`).Scan(&n); err != nil {
		t.Fatalf("count remediation jobs: %v", err)
	}
	return n
}
