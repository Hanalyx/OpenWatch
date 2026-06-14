// @spec api-groups
//
// Endpoint AC (DSN-gated). Service-level AC-01..08 live in
// internal/group.
//
//	AC-09  TestAPI_Groups_RBACAndStatusMapping
package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/auth"
)

// @ac AC-09
// AC-09: GET /groups needs host:read (viewer ok); every mutation needs
// host:write (viewer 403, ops_lead ok); anonymous is rejected; and the
// service sentinels map to 400 / 404 / 409 at the HTTP layer.
func TestAPI_Groups_RBACAndStatusMapping(t *testing.T) {
	t.Run("api-groups/AC-09", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)

		type grp struct {
			ID         string `json:"id"`
			Kind       string `json:"kind"`
			Membership string `json:"membership"`
		}

		// --- anonymous is rejected on GET and on a mutation ---
		anon, _ := http.NewRequest("GET", url+"/api/v1/groups", nil)
		ar, _ := http.DefaultClient.Do(anon)
		ar.Body.Close()
		if ar.StatusCode != http.StatusUnauthorized && ar.StatusCode != http.StatusForbidden {
			t.Errorf("anonymous GET status = %d, want 401/403", ar.StatusCode)
		}
		anonPost, _ := http.NewRequest("POST", url+"/api/v1/groups", http.NoBody)
		apr, _ := http.DefaultClient.Do(anonPost)
		apr.Body.Close()
		if apr.StatusCode != http.StatusUnauthorized && apr.StatusCode != http.StatusForbidden {
			t.Errorf("anonymous POST status = %d, want 401/403", apr.StatusCode)
		}

		// --- GET: viewer (host:read) succeeds ---
		listReq := asRole(t, "GET", url+"/api/v1/groups", auth.RoleViewer, nil)
		lr := doReq(t, listReq)
		defer lr.Body.Close()
		if lr.StatusCode != http.StatusOK {
			t.Fatalf("viewer GET status = %d, want 200", lr.StatusCode)
		}

		// --- POST: viewer (no host:write) is 403 ---
		createBody := map[string]any{"name": "Production", "kind": "site", "membership": "manual"}
		viewerCreate := asRole(t, "POST", url+"/api/v1/groups", auth.RoleViewer, createBody)
		vc := doReq(t, viewerCreate)
		vc.Body.Close()
		if vc.StatusCode != http.StatusForbidden {
			t.Fatalf("viewer create status = %d, want 403", vc.StatusCode)
		}

		// --- POST: ops_lead (host:write) creates ---
		opsCreate := asRole(t, "POST", url+"/api/v1/groups", auth.RoleOpsLead, createBody)
		oc := doReq(t, opsCreate)
		defer oc.Body.Close()
		if oc.StatusCode != http.StatusCreated {
			t.Fatalf("ops_lead create status = %d, want 201", oc.StatusCode)
		}
		var site grp
		if err := json.NewDecoder(oc.Body).Decode(&site); err != nil {
			t.Fatalf("decode created: %v", err)
		}
		if site.Kind != "site" || site.Membership != "manual" {
			t.Errorf("created = %+v", site)
		}

		// --- Create validation sentinel -> 400 (site cannot be auto) ---
		badBody := map[string]any{"name": "Bad", "kind": "site", "membership": "auto", "match_family": "rhel"}
		badReq := asRole(t, "POST", url+"/api/v1/groups", auth.RoleOpsLead, badBody)
		br := doReq(t, badReq)
		br.Body.Close()
		if br.StatusCode != http.StatusBadRequest {
			t.Errorf("invalid create status = %d, want 400", br.StatusCode)
		}

		// --- Duplicate auto family -> 409 ---
		autoBody := map[string]any{"name": "RHEL", "kind": "os_category", "membership": "auto", "match_family": "rhel"}
		first := asRole(t, "POST", url+"/api/v1/groups", auth.RoleOpsLead, autoBody)
		fr := doReq(t, first)
		fr.Body.Close()
		if fr.StatusCode != http.StatusCreated {
			t.Fatalf("first auto create status = %d, want 201", fr.StatusCode)
		}
		dup := asRole(t, "POST", url+"/api/v1/groups", auth.RoleOpsLead, autoBody)
		dr := doReq(t, dup)
		dr.Body.Close()
		if dr.StatusCode != http.StatusConflict {
			t.Errorf("duplicate auto create status = %d, want 409", dr.StatusCode)
		}

		// --- PATCH/DELETE/:maintenance on an unknown id -> 404 ---
		ghost := uuid.Must(uuid.NewV7()).String()
		patchGhost := asRole(t, "PATCH", url+"/api/v1/groups/"+ghost, auth.RoleOpsLead,
			map[string]any{"name": "x"})
		pg := doReq(t, patchGhost)
		pg.Body.Close()
		if pg.StatusCode != http.StatusNotFound {
			t.Errorf("patch unknown status = %d, want 404", pg.StatusCode)
		}
		delGhost := asRole(t, "DELETE", url+"/api/v1/groups/"+ghost, auth.RoleOpsLead, nil)
		dg := doReq(t, delGhost)
		dg.Body.Close()
		if dg.StatusCode != http.StatusNotFound {
			t.Errorf("delete unknown status = %d, want 404", dg.StatusCode)
		}
		maintGhost := asRole(t, "POST", url+"/api/v1/groups/"+ghost+":maintenance", auth.RoleOpsLead,
			map[string]any{"on": true})
		mg := doReq(t, maintGhost)
		mg.Body.Close()
		if mg.StatusCode != http.StatusNotFound {
			t.Errorf("maintenance unknown status = %d, want 404", mg.StatusCode)
		}

		// --- maintenance toggle: viewer 403, ops_lead 200 ---
		viewerMaint := asRole(t, "POST", url+"/api/v1/groups/"+site.ID+":maintenance",
			auth.RoleViewer, map[string]any{"on": true})
		vm := doReq(t, viewerMaint)
		vm.Body.Close()
		if vm.StatusCode != http.StatusForbidden {
			t.Errorf("viewer maintenance status = %d, want 403", vm.StatusCode)
		}
		opsMaint := asRole(t, "POST", url+"/api/v1/groups/"+site.ID+":maintenance",
			auth.RoleOpsLead, map[string]any{"on": true})
		om := doReq(t, opsMaint)
		om.Body.Close()
		if om.StatusCode != http.StatusOK {
			t.Errorf("ops_lead maintenance status = %d, want 200", om.StatusCode)
		}

		// --- members: add a host to the manual site (ops_lead) -> 204 ---
		addReq := asRole(t, "POST", url+"/api/v1/groups/"+site.ID+"/members",
			auth.RoleOpsLead, map[string]any{"host_id": hostID.String()})
		add := doReq(t, addReq)
		add.Body.Close()
		if add.StatusCode != http.StatusNoContent {
			t.Errorf("add member status = %d, want 204", add.StatusCode)
		}
		// viewer cannot remove.
		viewerDel := asRole(t, "DELETE", url+"/api/v1/groups/"+site.ID+"/members/"+hostID.String(),
			auth.RoleViewer, nil)
		vd := doReq(t, viewerDel)
		vd.Body.Close()
		if vd.StatusCode != http.StatusForbidden {
			t.Errorf("viewer remove member status = %d, want 403", vd.StatusCode)
		}
		opsDel := asRole(t, "DELETE", url+"/api/v1/groups/"+site.ID+"/members/"+hostID.String(),
			auth.RoleOpsLead, nil)
		od := doReq(t, opsDel)
		od.Body.Close()
		if od.StatusCode != http.StatusNoContent {
			t.Errorf("ops_lead remove member status = %d, want 204", od.StatusCode)
		}
	})
}
