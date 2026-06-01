// @spec system-host-discovery
//
// AC traceability (this file):
//
//	AC-09  TestAPI_HostDiscovery_Run_RBACDenied_Returns403
//	AC-10  TestAPI_HostDiscovery_Run_UnknownHost_Returns404
//	AC-13  TestAPI_HostDiscovery_HostCreate_AutoEnqueuesJob
//
// AC-08 (200 happy path) requires a real SSH dial path that the API
// test stack can't easily fake (the Discovery service holds a real
// credential resolver + SSH transport). Spec AC-08 is covered by the
// service-level tests in app/internal/intelligence/discovery/.

package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/intelligence/discovery"
)

// @ac AC-09
// AC-09: viewer role lacks host:write; POST returns 403
// authz.permission_denied with NO Discovery attempted.
func TestAPI_HostDiscovery_Run_RBACDenied_Returns403(t *testing.T) {
	t.Run("system-host-discovery/AC-09", func(t *testing.T) {
		url, pool := freshAPIServer(t)

		// Seed a host so the 403 fires *before* we'd hit the 404 branch.
		uid := firstSeededUserID(t, pool)
		hostID, _ := uuid.NewV7()
		_, err := pool.Exec(context.Background(),
			`INSERT INTO hosts (id, hostname, ip_address, created_by)
			 VALUES ($1, $2, $3::inet, $4)`,
			hostID, "h-"+hostID.String(), "192.0.2.10", uid)
		if err != nil {
			t.Fatalf("seed host: %v", err)
		}

		// Viewer = host:read only, no host:write.
		req := asRole(t, "POST",
			url+"/api/v1/hosts/"+hostID.String()+"/discovery:run",
			auth.RoleViewer, nil)
		req.Header.Set("Idempotency-Key", "test-403-"+hostID.String())
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 for viewer (no host:write), got %d", resp.StatusCode)
		}
	})
}

// @ac AC-10
// AC-10: POST against an unknown host id returns 404 hosts.not_found
// even when the caller has host:write.
func TestAPI_HostDiscovery_Run_UnknownHost_Returns404(t *testing.T) {
	t.Run("system-host-discovery/AC-10", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		missing, _ := uuid.NewV7()
		req := asRole(t, "POST",
			url+"/api/v1/hosts/"+missing.String()+"/discovery:run",
			auth.RoleAdmin, nil)
		req.Header.Set("Idempotency-Key", "test-404-"+missing.String())
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("expected 404 for unknown host, got %d", resp.StatusCode)
		}
	})
}

// @ac AC-13
// AC-13: Host creation MUST enqueue a host.discovery job in
// job_queue before returning the 201 response. The worker (already
// running per the fixture) drains it asynchronously; we just assert
// the row exists.
func TestAPI_HostDiscovery_HostCreate_AutoEnqueuesJob(t *testing.T) {
	t.Run("system-host-discovery/AC-13", func(t *testing.T) {
		url, pool := freshAPIServer(t)

		body := []byte(`{"hostname":"disc-auto","ip_address":"192.0.2.42"}`)
		req := asRole(t, "POST", url+"/api/v1/hosts", auth.RoleAdmin, body)
		req.Header.Set("Idempotency-Key", "create-disc-auto")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST /hosts: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("expected 201, got %d", resp.StatusCode)
		}

		// At least one host.discovery job MUST exist in job_queue. The
		// worker may have already processed it (status='completed' or
		// 'failed') by the time we read — we count regardless of status
		// because the spec contract is "enqueued before return", not
		// "still pending."
		var count int
		err = pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM job_queue WHERE job_type = $1`,
			discovery.JobKindHostDiscovery).Scan(&count)
		if err != nil {
			t.Fatalf("count host.discovery jobs: %v", err)
		}
		if count < 1 {
			t.Errorf("host.discovery jobs in job_queue = %d, want >= 1 (per AC-13)", count)
		}
	})
}
