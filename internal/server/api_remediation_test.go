// @spec api-remediation
//
// Endpoint AC (DSN-gated). Service-level AC-01..04 live in
// internal/remediation.
//
//	AC-05  TestAPI_Remediation_LifecycleAndRBAC
//	AC-06  TestAPI_Remediation_ExecuteFreeCore
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
		if created.Status != "pending_approval" || created.RuleID != "sshd-permit-root-no" {
			t.Errorf("created = %+v", created)
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

		// --- approve: ops_lead is 403 (no remediation:approve) ---
		oa := doReq(t, asRole(t, "POST", base+"/"+created.ID+":approve", auth.RoleOpsLead, map[string]any{}))
		oa.Body.Close()
		if oa.StatusCode != http.StatusForbidden {
			t.Fatalf("ops_lead approve status = %d, want 403", oa.StatusCode)
		}

		// --- approve: security_admin (different user from the ops_lead
		// requester) succeeds ---
		sa := doReq(t, asRole(t, "POST", base+"/"+created.ID+":approve",
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

		// --- re-approve -> 409 wrong state ---
		ra := doReq(t, asRole(t, "POST", base+"/"+created.ID+":approve", auth.RoleSecurityAdmin, map[string]any{}))
		ra.Body.Close()
		if ra.StatusCode != http.StatusConflict {
			t.Errorf("re-approve status = %d, want 409", ra.StatusCode)
		}

		// --- separation of duties at the HTTP layer: a security_admin
		// requests, then tries to approve their own -> 409 self_review ---
		selfReq := doReq(t, asRole(t, "POST", base, auth.RoleSecurityAdmin,
			map[string]any{"host_id": hostID.String(), "rule_id": "self-rule"}))
		defer selfReq.Body.Close()
		var selfRR apiRem
		_ = json.NewDecoder(selfReq.Body).Decode(&selfRR)
		selfAp := doReq(t, asRole(t, "POST", base+"/"+selfRR.ID+":approve", auth.RoleSecurityAdmin, map[string]any{}))
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
// non-approved (pending) request is 409; rolling back a non-executed request
// is 409. No act endpoint returns 402.
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

		// security_admin has the perm, but the request is still pending
		// (not approved) -> 409 wrong_state. NOT 402.
		pre := doReq(t, asRole(t, "POST", execURL, auth.RoleSecurityAdmin, map[string]any{}))
		pre.Body.Close()
		if pre.StatusCode != http.StatusConflict {
			t.Fatalf("execute-before-approve status = %d, want 409", pre.StatusCode)
		}

		// Approve it (security_admin != ops_lead requester).
		ap := doReq(t, asRole(t, "POST", base+"/"+created.ID+":approve",
			auth.RoleSecurityAdmin, map[string]any{"note": "ok"}))
		ap.Body.Close()
		if ap.StatusCode != http.StatusOK {
			t.Fatalf("approve status = %d, want 200", ap.StatusCode)
		}

		// Now execute -> 202 Accepted, a remediation job enqueued.
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
