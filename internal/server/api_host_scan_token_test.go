// @spec api-host-scan
//
// AC traceability (DSN-gated like every api_*_test in this package):
//
//	AC-08  TestHostScan_TokenStarted_RecordsOwnerAsRequester
//	AC-09  TestHostScan_FailedRunRecord_LeavesNoQueuedWork
//
// bugs/OW-097: a scan started with an owk_ token answered 500 while the
// scan ran, because the handler wrote the token's own id into
// scan_runs.requested_by (a users FK) after the job was already queued.
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/scanruns"
	"github.com/Hanalyx/openwatch/internal/server/api"
)

// mintScanToken issues a real owk_ token through the API, created by the
// admin fixture user, carrying role. Returns the raw secret and the token id.
func mintScanToken(t *testing.T, url string, role auth.RoleID) (string, uuid.UUID) {
	t.Helper()
	resp := doReq(t, asRole(t, "POST", url+"/api/v1/tokens", auth.RoleAdmin,
		map[string]any{"name": "scan-automation", "role_id": string(role)}))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create token = %d, want 201", resp.StatusCode)
	}
	var created api.ApiTokenCreated
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode token: %v", err)
	}
	return created.Token, uuid.UUID(created.ApiToken.Id)
}

func postScanBearer(t *testing.T, url, bearer, hostID string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("POST", url+"/api/v1/hosts/"+hostID+"/scans", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Idempotency-Key", "scan-"+uuid.NewString())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST scans: %v", err)
	}
	return resp
}

// scanQueuedRows counts scan.queued events for one scan id, filtered by the
// actor and the detail's requested_by. The writer is batched, so it polls
// until the count holds steady across consecutive readings, not until the
// first non-zero one.
func scanQueuedRows(t *testing.T, pool *pgxpool.Pool, scanID uuid.UUID, actorID, requestedBy string) int {
	t.Helper()
	read := func() int {
		var n int
		if err := pool.QueryRow(context.Background(), `
			SELECT count(*) FROM audit_events
			WHERE action = 'scan.queued'
			  AND detail->>'scan_id' = $1
			  AND actor_id = $2
			  AND detail->>'requested_by' = $3
			  AND detail->>'trigger' = 'on_demand'`,
			scanID.String(), actorID, requestedBy).Scan(&n); err != nil {
			t.Fatalf("count scan.queued: %v", err)
		}
		return n
	}
	deadline := time.Now().Add(3 * time.Second)
	last, steady := -1, 0
	for time.Now().Before(deadline) {
		n := read()
		if n == last && n > 0 {
			steady++
			if steady >= 3 {
				return n
			}
		} else {
			steady = 0
		}
		last = n
		time.Sleep(50 * time.Millisecond)
	}
	return read()
}

// @ac AC-08
func TestHostScan_TokenStarted_RecordsOwnerAsRequester(t *testing.T) {
	t.Run("api-host-scan/AC-08", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)
		raw, tokenID := mintScanToken(t, url, auth.RoleOpsLead)
		owner := roleUserIDs[auth.RoleAdmin]

		resp := postScanBearer(t, url, raw, hostID.String())
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("token-started scan = %d, want 202 (OW-097 answered 500)", resp.StatusCode)
		}
		var body struct {
			ScanID uuid.UUID `json:"scan_id"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || body.ScanID == uuid.Nil {
			t.Fatalf("decode 202 body: %v (scan_id %s)", err, body.ScanID)
		}

		run, err := scanruns.Get(context.Background(), pool, body.ScanID)
		if err != nil {
			t.Fatalf("scan_runs row missing: %v", err)
		}
		if run.TriggerSource != scanruns.TriggerOnDemand {
			t.Errorf("trigger = %s, want on_demand (OW-097 left 'scheduled')", run.TriggerSource)
		}
		if run.RequestedBy == nil || *run.RequestedBy != owner {
			t.Errorf("requested_by = %v, want the token owner %s", run.RequestedBy, owner)
		}
		if run.RequestedBy != nil && *run.RequestedBy == tokenID {
			t.Errorf("requested_by is the token's own id %s; it must be the owning user", tokenID)
		}
		if run.CorrelationID == "" {
			t.Error("correlation_id is empty; the run lost its request")
		}

		var jobs int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM job_queue WHERE id = $1 AND job_type = 'scan'`,
			body.ScanID).Scan(&jobs); err != nil {
			t.Fatalf("count jobs: %v", err)
		}
		if jobs != 1 {
			t.Errorf("job_queue rows for scan id = %d, want 1", jobs)
		}

		// Attribution: the actor is the token (the principal), and the
		// detail names the owner, the same value as the run row.
		if n := scanQueuedRows(t, pool, body.ScanID, tokenID.String(), owner.String()); n != 1 {
			t.Errorf("scan.queued rows with actor=token and requested_by=owner = %d, want 1", n)
		}
	})
}

// @ac AC-09
func TestHostScan_FailedRunRecord_LeavesNoQueuedWork(t *testing.T) {
	t.Run("api-host-scan/AC-09", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)
		ctx := context.Background()

		// Make the scan_runs insert fail for this host only, after the job
		// insert has already run in the same request. This is the position
		// OW-097's foreign-key failure occupied.
		if _, err := pool.Exec(ctx, `
			CREATE FUNCTION ow097_refuse_run() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN RAISE EXCEPTION 'ow097 test: refuse scan_runs insert'; END $$`); err != nil {
			t.Fatalf("create function: %v", err)
		}
		if _, err := pool.Exec(ctx, `
			CREATE TRIGGER ow097_refuse_run BEFORE INSERT ON scan_runs
			FOR EACH ROW WHEN (NEW.host_id = '`+hostID.String()+`'::uuid)
			EXECUTE FUNCTION ow097_refuse_run()`); err != nil {
			t.Fatalf("create trigger: %v", err)
		}
		t.Cleanup(func() {
			_, _ = pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS ow097_refuse_run ON scan_runs`)
			_, _ = pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS ow097_refuse_run()`)
		})

		for _, arm := range []string{"session", "token"} {
			var resp *http.Response
			if arm == "session" {
				resp = postScan(t, url, auth.RoleOpsLead, hostID.String(), true)
			} else {
				raw, _ := mintScanToken(t, url, auth.RoleOpsLead)
				resp = postScanBearer(t, url, raw, hostID.String())
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusInternalServerError {
				t.Fatalf("%s: status = %d, want 500 from the refused run insert", arm, resp.StatusCode)
			}
		}

		// The instrument can see a job for this host: the payload carries
		// host_id, and the failure test would otherwise pass vacuously.
		// Give the worker time to have claimed anything that leaked.
		time.Sleep(500 * time.Millisecond)
		var jobs, runs, queued int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM job_queue WHERE job_type = 'scan' AND payload->>'host_id' = $1`,
			hostID.String()).Scan(&jobs); err != nil {
			t.Fatalf("count jobs: %v", err)
		}
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM scan_runs WHERE host_id = $1`, hostID).Scan(&runs); err != nil {
			t.Fatalf("count runs: %v", err)
		}
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM audit_events WHERE action = 'scan.queued' AND detail->>'host_id' = $1`,
			hostID.String()).Scan(&queued); err != nil {
			t.Fatalf("count audit: %v", err)
		}
		if jobs != 0 || runs != 0 || queued != 0 {
			t.Errorf("after a refused run insert: job_queue=%d scan_runs=%d scan.queued=%d, want 0/0/0 "+
				"(OW-097 left a queued job that the worker ran)", jobs, runs, queued)
		}

		// Positive control on the same instrument: with the trigger gone,
		// the same request queues exactly one job for this host.
		if _, err := pool.Exec(ctx, `DROP TRIGGER ow097_refuse_run ON scan_runs`); err != nil {
			t.Fatalf("drop trigger: %v", err)
		}
		ok := postScan(t, url, auth.RoleOpsLead, hostID.String(), true)
		ok.Body.Close()
		if ok.StatusCode != http.StatusAccepted {
			t.Fatalf("control: status = %d, want 202", ok.StatusCode)
		}
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM job_queue WHERE job_type = 'scan' AND payload->>'host_id' = $1`,
			hostID.String()).Scan(&jobs); err != nil {
			t.Fatalf("count jobs: %v", err)
		}
		if jobs != 1 {
			t.Errorf("control: job_queue rows for host = %d, want 1; the count cannot see a job", jobs)
		}
	})
}
