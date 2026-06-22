package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/auth"
)

// @spec system-report-schedule
// @ac AC-04
// The CRUD surface: list (host:read), create/patch/delete (host:write).
// A host:read caller cannot create; create -> list -> toggle -> delete
// round-trips; RBAC is enforced.
func TestAPI_ReportSchedules(t *testing.T) {
	t.Run("system-report-schedule/AC-04", func(t *testing.T) {
		url, pool := freshAPIServer(t)

		// A real email channel for the schedule's FK + delivery transport.
		chID := uuid.New()
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO notification_channels (id, type, name, enabled, config_ciphertext)
			 VALUES ($1, 'email', 'auditors', true, $2)`, chID, []byte("x")); err != nil {
			t.Fatalf("seed channel: %v", err)
		}

		body := map[string]any{
			"name":       "weekly cis attestation",
			"kind":       "attestation",
			"framework":  "cis_rhel9",
			"frequency":  "daily",
			"channel_id": chID.String(),
		}

		// host:read may not create.
		ro := doReq(t, asRole(t, "POST", url+"/api/v1/reports/schedules", auth.RoleViewer, body))
		ro.Body.Close()
		if ro.StatusCode != http.StatusForbidden {
			t.Fatalf("create as viewer status = %d, want 403", ro.StatusCode)
		}

		// host:write creates.
		cr := doReq(t, asRole(t, "POST", url+"/api/v1/reports/schedules", auth.RoleOpsLead, body))
		defer cr.Body.Close()
		if cr.StatusCode != http.StatusCreated {
			t.Fatalf("create status = %d, want 201", cr.StatusCode)
		}
		var created struct {
			ID        string `json:"id"`
			Enabled   bool   `json:"enabled"`
			NextRunAt string `json:"next_run_at"`
		}
		if err := json.NewDecoder(cr.Body).Decode(&created); err != nil {
			t.Fatalf("decode created: %v", err)
		}
		// The create emits a report.schedule.created audit event. audit.Emit is
		// async (background writer), so poll briefly for the row to land.
		var auditCount int
		for i := 0; i < 30; i++ {
			if err := pool.QueryRow(context.Background(),
				`SELECT count(*) FROM audit_events WHERE action = 'report.schedule.created' AND resource_id = $1`,
				created.ID).Scan(&auditCount); err != nil {
				t.Fatalf("audit query: %v", err)
			}
			if auditCount > 0 {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if auditCount != 1 {
			t.Errorf("report.schedule.created audit events = %d, want 1", auditCount)
		}

		// A non-email channel is rejected at create (only email carries the PDF).
		whID := uuid.New()
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO notification_channels (id, type, name, enabled, config_ciphertext)
			 VALUES ($1, 'webhook', 'ops-hook', true, $2)`, whID, []byte("x")); err != nil {
			t.Fatalf("seed webhook channel: %v", err)
		}
		whBody := map[string]any{"name": "bad", "kind": "executive", "frequency": "daily", "channel_id": whID.String()}
		wr := doReq(t, asRole(t, "POST", url+"/api/v1/reports/schedules", auth.RoleOpsLead, whBody))
		wr.Body.Close()
		if wr.StatusCode != http.StatusBadRequest {
			t.Errorf("create with webhook channel status = %d, want 400", wr.StatusCode)
		}

		if created.ID == "" || !created.Enabled || created.NextRunAt == "" {
			t.Fatalf("created schedule malformed: %+v", created)
		}

		// list (host:read) returns it.
		lr := doReq(t, asRole(t, "GET", url+"/api/v1/reports/schedules", auth.RoleViewer, nil))
		defer lr.Body.Close()
		if lr.StatusCode != http.StatusOK {
			t.Fatalf("list status = %d, want 200", lr.StatusCode)
		}
		var list struct {
			Schedules []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"schedules"`
		}
		if err := json.NewDecoder(lr.Body).Decode(&list); err != nil {
			t.Fatalf("decode list: %v", err)
		}
		if len(list.Schedules) != 1 || list.Schedules[0].ID != created.ID {
			t.Fatalf("list = %+v, want the created schedule", list.Schedules)
		}

		// toggle disabled (host:write).
		pr := doReq(t, asRole(t, "PATCH", url+"/api/v1/reports/schedules/"+created.ID, auth.RoleOpsLead, map[string]any{"enabled": false}))
		defer pr.Body.Close()
		if pr.StatusCode != http.StatusOK {
			t.Fatalf("patch status = %d, want 200", pr.StatusCode)
		}
		var patched struct {
			Enabled bool `json:"enabled"`
		}
		_ = json.NewDecoder(pr.Body).Decode(&patched)
		if patched.Enabled {
			t.Errorf("schedule should be disabled after patch")
		}

		// delete (host:write).
		dr := doReq(t, asRole(t, "DELETE", url+"/api/v1/reports/schedules/"+created.ID, auth.RoleOpsLead, nil))
		dr.Body.Close()
		if dr.StatusCode != http.StatusNoContent {
			t.Fatalf("delete status = %d, want 204", dr.StatusCode)
		}

		// gone.
		lr2 := doReq(t, asRole(t, "GET", url+"/api/v1/reports/schedules", auth.RoleViewer, nil))
		defer lr2.Body.Close()
		var list2 struct {
			Schedules []json.RawMessage `json:"schedules"`
		}
		_ = json.NewDecoder(lr2.Body).Decode(&list2)
		if len(list2.Schedules) != 0 {
			t.Errorf("schedules after delete = %d, want 0", len(list2.Schedules))
		}
	})
}
