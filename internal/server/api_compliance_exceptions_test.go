// @spec api-compliance-exceptions
//
// Endpoint AC (DSN-gated). Service-level AC-01..05 live in
// internal/exception.
//
//	AC-06  TestAPI_Exceptions_LifecycleAndRBAC
//	AC-07  (service-level; see internal/exception TestListHostNameJoin)
package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/auth"
)

// @ac AC-06
// AC-06: RBAC bars on all six endpoints + a full request->approve->
// revoke happy path through HTTP; ops_lead (request, no approve) is
// 403 on :approve; separation of duties holds at the HTTP layer.
func TestAPI_Exceptions_LifecycleAndRBAC(t *testing.T) {
	t.Run("api-compliance-exceptions/AC-06", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)

		type exc struct {
			ID       string `json:"id"`
			Status   string `json:"status"`
			RuleID   string `json:"rule_id"`
			HostName string `json:"host_name"`
		}

		// --- request: ops_lead can, viewer cannot, unknown host 404 ---
		reqBody := map[string]any{"rule_id": "ssh-kex-fips", "reason": "accepted risk"}

		viewerReq := asRole(t, "POST", url+"/api/v1/hosts/"+hostID.String()+"/exceptions",
			auth.RoleViewer, reqBody)
		vr := doReq(t, viewerReq)
		vr.Body.Close()
		if vr.StatusCode != http.StatusForbidden {
			t.Fatalf("viewer request status = %d, want 403", vr.StatusCode)
		}

		ghost := uuid.Must(uuid.NewV7())
		ghostReq := asRole(t, "POST", url+"/api/v1/hosts/"+ghost.String()+"/exceptions",
			auth.RoleOpsLead, reqBody)
		gr := doReq(t, ghostReq)
		gr.Body.Close()
		if gr.StatusCode != http.StatusNotFound {
			t.Fatalf("unknown-host request status = %d, want 404", gr.StatusCode)
		}

		opsReq := asRole(t, "POST", url+"/api/v1/hosts/"+hostID.String()+"/exceptions",
			auth.RoleOpsLead, reqBody)
		or := doReq(t, opsReq)
		defer or.Body.Close()
		if or.StatusCode != http.StatusCreated {
			t.Fatalf("ops_lead request status = %d, want 201", or.StatusCode)
		}
		var created exc
		if err := json.NewDecoder(or.Body).Decode(&created); err != nil {
			t.Fatalf("decode created: %v", err)
		}
		if created.Status != "requested" || created.RuleID != "ssh-kex-fips" {
			t.Errorf("created = %+v", created)
		}

		// --- duplicate open -> 409 ---
		dupReq := asRole(t, "POST", url+"/api/v1/hosts/"+hostID.String()+"/exceptions",
			auth.RoleOpsLead, reqBody)
		dr := doReq(t, dupReq)
		dr.Body.Close()
		if dr.StatusCode != http.StatusConflict {
			t.Errorf("duplicate request status = %d, want 409", dr.StatusCode)
		}

		// --- list: exception:read; anonymous rejected ---
		anon, _ := http.NewRequest("GET", url+"/api/v1/hosts/"+hostID.String()+"/exceptions", nil)
		ar, _ := http.DefaultClient.Do(anon)
		ar.Body.Close()
		if ar.StatusCode != http.StatusUnauthorized && ar.StatusCode != http.StatusForbidden {
			t.Errorf("anonymous list status = %d, want 401/403", ar.StatusCode)
		}
		listReq := asRole(t, "GET", url+"/api/v1/hosts/"+hostID.String()+"/exceptions",
			auth.RoleViewer, nil)
		lr := doReq(t, listReq)
		defer lr.Body.Close()
		var list struct {
			Exceptions []exc `json:"exceptions"`
		}
		_ = json.NewDecoder(lr.Body).Decode(&list)
		if len(list.Exceptions) != 1 {
			t.Errorf("list len = %d, want 1", len(list.Exceptions))
		}

		// --- approve: ops_lead is 403 (no exception:approve) ---
		opsApprove := asRole(t, "POST", url+"/api/v1/exceptions/"+created.ID+":approve",
			auth.RoleOpsLead, map[string]any{})
		oar := doReq(t, opsApprove)
		oar.Body.Close()
		if oar.StatusCode != http.StatusForbidden {
			t.Fatalf("ops_lead approve status = %d, want 403", oar.StatusCode)
		}

		// --- approve: auditor (has approve, different user from the
		// ops_lead requester) succeeds ---
		audApprove := asRole(t, "POST", url+"/api/v1/exceptions/"+created.ID+":approve",
			auth.RoleAuditor, map[string]any{"note": "risk accepted"})
		aar := doReq(t, audApprove)
		defer aar.Body.Close()
		if aar.StatusCode != http.StatusOK {
			t.Fatalf("auditor approve status = %d, want 200", aar.StatusCode)
		}
		var approved exc
		_ = json.NewDecoder(aar.Body).Decode(&approved)
		if approved.Status != "approved" {
			t.Errorf("approved status = %q, want approved", approved.Status)
		}

		// --- re-approve -> 409 wrong state ---
		reApprove := asRole(t, "POST", url+"/api/v1/exceptions/"+created.ID+":approve",
			auth.RoleAuditor, map[string]any{})
		rar := doReq(t, reApprove)
		rar.Body.Close()
		if rar.StatusCode != http.StatusConflict {
			t.Errorf("re-approve status = %d, want 409", rar.StatusCode)
		}

		// --- revoke: auditor lacks exception:revoke -> 403; security_admin OK ---
		audRevoke := asRole(t, "POST", url+"/api/v1/exceptions/"+created.ID+":revoke",
			auth.RoleAuditor, map[string]any{})
		avr := doReq(t, audRevoke)
		avr.Body.Close()
		if avr.StatusCode != http.StatusForbidden {
			t.Fatalf("auditor revoke status = %d, want 403", avr.StatusCode)
		}
		secRevoke := asRole(t, "POST", url+"/api/v1/exceptions/"+created.ID+":revoke",
			auth.RoleSecurityAdmin, map[string]any{"note": "no longer needed"})
		svr := doReq(t, secRevoke)
		defer svr.Body.Close()
		if svr.StatusCode != http.StatusOK {
			t.Fatalf("security_admin revoke status = %d, want 200", svr.StatusCode)
		}
		var revoked exc
		_ = json.NewDecoder(svr.Body).Decode(&revoked)
		if revoked.Status != "revoked" {
			t.Errorf("revoked status = %q, want revoked", revoked.Status)
		}

		// --- separation of duties at the HTTP layer: a security_admin
		// requests, then tries to approve their own -> 409 self_review ---
		selfReqBody := map[string]any{"rule_id": "self-rule", "reason": "mine"}
		selfReq := asRole(t, "POST", url+"/api/v1/hosts/"+hostID.String()+"/exceptions",
			auth.RoleSecurityAdmin, selfReqBody)
		sr := doReq(t, selfReq)
		defer sr.Body.Close()
		var selfExc exc
		_ = json.NewDecoder(sr.Body).Decode(&selfExc)
		selfApprove := asRole(t, "POST", url+"/api/v1/exceptions/"+selfExc.ID+":approve",
			auth.RoleSecurityAdmin, map[string]any{})
		sar := doReq(t, selfApprove)
		sar.Body.Close()
		if sar.StatusCode != http.StatusConflict {
			t.Errorf("self-approve status = %d, want 409 (separation of duties)", sar.StatusCode)
		}

		// --- fleet queue: exception:read, status filter works ---
		fleetReq := asRole(t, "GET", url+"/api/v1/compliance/exceptions?status=revoked",
			auth.RoleViewer, nil)
		fr := doReq(t, fleetReq)
		defer fr.Body.Close()
		var fleet struct {
			Exceptions []exc `json:"exceptions"`
		}
		_ = json.NewDecoder(fr.Body).Decode(&fleet)
		if len(fleet.Exceptions) != 1 || fleet.Exceptions[0].Status != "revoked" {
			t.Errorf("fleet revoked filter = %+v, want 1 revoked", fleet.Exceptions)
		}
		// v1.1.0: list responses carry the joined hostname (AC-07,
		// covered by the dedicated service test).
		if fleet.Exceptions[0].HostName == "" {
			t.Errorf("fleet exception host_name empty; want the joined hostname")
		}
	})
}
