// @spec api-host-scan
//
// AC traceability (DSN-gated like every api_*_test in this package):
//
//	AC-01  TestHostScan_Returns202_AndRecordsRun
//	AC-02  TestHostScan_WorkerClaimsAndTerminates
//	AC-03  TestHostScan_UnknownHost404_NoSideEffects
//	AC-04  TestHostScan_MissingIdempotencyKey400
//	AC-05  TestHostScan_RBAC_ViewerAndAnonymousRejected
//	AC-06  TestHostScan_ActiveRun409_NoSecondJob
//	AC-07  TestHostScan_EmitsScanQueuedAudit
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/scanruns"
)

func postScan(t *testing.T, url string, role auth.RoleID, hostID string, withKey bool) *http.Response {
	t.Helper()
	req := asRole(t, "POST", url+"/api/v1/hosts/"+hostID+"/scans", role, nil)
	if withKey {
		req.Header.Set("Idempotency-Key", "scan-"+uuid.NewString())
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST scans: %v", err)
	}
	return resp
}

// @ac AC-01
func TestHostScan_Returns202_AndRecordsRun(t *testing.T) {
	t.Run("api-host-scan/AC-01", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)

		resp := postScan(t, url, auth.RoleOpsLead, hostID.String(), true)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("status = %d, want 202", resp.StatusCode)
		}
		var body struct {
			ScanID   uuid.UUID `json:"scan_id"`
			Status   string    `json:"status"`
			QueuedAt time.Time `json:"queued_at"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.Status != "queued" || body.ScanID == uuid.Nil || body.QueuedAt.IsZero() {
			t.Errorf("body = %+v", body)
		}

		run, err := scanruns.Get(context.Background(), pool, body.ScanID)
		if err != nil {
			t.Fatalf("scan_runs row missing: %v", err)
		}
		if run.TriggerSource != scanruns.TriggerOnDemand {
			t.Errorf("trigger = %s, want on_demand", run.TriggerSource)
		}
		if run.RequestedBy == nil || *run.RequestedBy != roleUserIDs[auth.RoleOpsLead] {
			t.Errorf("requested_by = %v, want operator %s", run.RequestedBy, roleUserIDs[auth.RoleOpsLead])
		}
		if run.HostID != hostID {
			t.Errorf("host_id = %s, want %s", run.HostID, hostID)
		}

		// The queue job exists under the SAME id (C-01). It may already
		// be claimed/processed by the in-process worker, so assert on
		// row existence, not status.
		var jobCount int
		_ = pool.QueryRow(context.Background(),
			`SELECT count(*) FROM job_queue WHERE id = $1 AND job_type = 'scan'`,
			body.ScanID).Scan(&jobCount)
		if jobCount != 1 {
			t.Errorf("job_queue rows for scan id = %d, want 1", jobCount)
		}
	})
}

// @ac AC-02
func TestHostScan_WorkerClaimsAndTerminates(t *testing.T) {
	t.Run("api-host-scan/AC-02", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)

		resp := postScan(t, url, auth.RoleOpsLead, hostID.String(), true)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("status = %d, want 202", resp.StatusCode)
		}
		var body struct {
			ScanID uuid.UUID `json:"scan_id"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)

		// The harness worker has no live Kensa wiring, so the run must
		// reach FAILED (never stuck queued/running) — proving the HMAC
		// verified, the job was claimed, and the logbook pairing held.
		deadline := time.Now().Add(10 * time.Second)
		for {
			run, err := scanruns.Get(context.Background(), pool, body.ScanID)
			if err == nil && (run.Status == scanruns.StatusFailed || run.Status == scanruns.StatusCompleted) {
				if run.Status == scanruns.StatusFailed && run.FailureReason == "hmac_rejected" {
					t.Fatalf("worker rejected the HMAC — endpoint key derivation diverged from the worker's")
				}
				break
			}
			if time.Now().After(deadline) {
				status := "<missing>"
				if err == nil {
					status = string(run.Status)
				}
				t.Fatalf("run never reached a terminal status (last=%s) — worker did not claim/process the job", status)
			}
			time.Sleep(100 * time.Millisecond)
		}
	})
}

// @ac AC-03
func TestHostScan_UnknownHost404_NoSideEffects(t *testing.T) {
	t.Run("api-host-scan/AC-03", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ghost := uuid.Must(uuid.NewV7())

		resp := postScan(t, url, auth.RoleOpsLead, ghost.String(), true)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", resp.StatusCode)
		}

		var runs, jobs int
		_ = pool.QueryRow(context.Background(),
			`SELECT count(*) FROM scan_runs WHERE host_id = $1`, ghost).Scan(&runs)
		_ = pool.QueryRow(context.Background(),
			`SELECT count(*) FROM job_queue WHERE job_type = 'scan'`).Scan(&jobs)
		if runs != 0 || jobs != 0 {
			t.Errorf("side effects for unknown host: runs=%d jobs=%d", runs, jobs)
		}
	})
}

// @ac AC-04
func TestHostScan_MissingIdempotencyKey400(t *testing.T) {
	t.Run("api-host-scan/AC-04", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)

		resp := postScan(t, url, auth.RoleOpsLead, hostID.String(), false)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want 400 (Idempotency-Key required)", resp.StatusCode)
		}
	})
}

// @ac AC-05
func TestHostScan_RBAC_ViewerAndAnonymousRejected(t *testing.T) {
	t.Run("api-host-scan/AC-05", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)

		// Viewer: host:read only -> 403.
		resp := postScan(t, url, auth.RoleViewer, hostID.String(), true)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("viewer status = %d, want 403", resp.StatusCode)
		}

		// Anonymous: no session cookie at all.
		req, _ := http.NewRequest("POST", url+"/api/v1/hosts/"+hostID.String()+"/scans", nil)
		req.Header.Set("Idempotency-Key", "scan-anon")
		anonResp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("anon POST: %v", err)
		}
		anonResp.Body.Close()
		if anonResp.StatusCode != http.StatusUnauthorized && anonResp.StatusCode != http.StatusForbidden {
			t.Errorf("anonymous status = %d, want 401/403", anonResp.StatusCode)
		}

		var runs int
		_ = pool.QueryRow(context.Background(),
			`SELECT count(*) FROM scan_runs WHERE host_id = $1`, hostID).Scan(&runs)
		if runs != 0 {
			t.Errorf("denied callers created %d scan_runs rows", runs)
		}
	})
}

// @ac AC-06
func TestHostScan_ActiveRun409_NoSecondJob(t *testing.T) {
	t.Run("api-host-scan/AC-06", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)

		// Seed an active (running) run directly — deterministic, no
		// race with the in-process worker.
		existing := uuid.Must(uuid.NewV7())
		if err := scanruns.MarkRunning(context.Background(), pool, existing, hostID, ""); err != nil {
			t.Fatalf("seed running run: %v", err)
		}

		resp := postScan(t, url, auth.RoleOpsLead, hostID.String(), true)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("status = %d, want 409", resp.StatusCode)
		}

		var jobs int
		_ = pool.QueryRow(context.Background(),
			`SELECT count(*) FROM job_queue WHERE job_type = 'scan'`).Scan(&jobs)
		if jobs != 0 {
			t.Errorf("409 path enqueued %d jobs; want 0", jobs)
		}
	})
}

// @ac AC-07
func TestHostScan_EmitsScanQueuedAudit(t *testing.T) {
	t.Run("api-host-scan/AC-07", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)

		resp := postScan(t, url, auth.RoleOpsLead, hostID.String(), true)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("status = %d, want 202", resp.StatusCode)
		}
		var body struct {
			ScanID uuid.UUID `json:"scan_id"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)

		// The audit writer flushes every 20ms in the fixture; poll.
		deadline := time.Now().Add(3 * time.Second)
		for {
			var n int
			_ = pool.QueryRow(context.Background(), `
				SELECT count(*) FROM audit_events
				WHERE action = 'scan.queued'
				  AND detail->>'scan_id' = $1
				  AND detail->>'host_id' = $2
				  AND detail->>'trigger' = 'on_demand'`,
				body.ScanID.String(), hostID.String()).Scan(&n)
			if n == 1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("scan.queued audit rows = %d, want 1", n)
			}
			time.Sleep(50 * time.Millisecond)
		}
	})
}
