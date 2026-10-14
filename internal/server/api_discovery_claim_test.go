// @spec system-host-discovery

package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/correlation"
	"github.com/Hanalyx/openwatch/internal/credential"
	"github.com/Hanalyx/openwatch/internal/intelligence/discovery"
	"github.com/Hanalyx/openwatch/internal/queue"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// countingTransport answers every probe command with empty output and
// counts dials.
type countingTransport struct{ dials atomic.Int32 }

func (c *countingTransport) Dial(context.Context, string, int, *credential.Credential) (discovery.SSHSession, error) {
	c.dials.Add(1)
	return emptySession{}, nil
}

type emptySession struct{}

func (emptySession) Run(context.Context, string) ([]byte, int, error) { return nil, 0, nil }
func (emptySession) RunWithStdin(context.Context, string, []byte) ([]byte, int, error) {
	return nil, 0, nil
}
func (emptySession) Close() error { return nil }

func postDiscoveryRun(t *testing.T, url string, host uuid.UUID) (int, string) {
	t.Helper()
	req := asRole(t, "POST", url+"/api/v1/hosts/"+host.String()+"/discovery:run", auth.RoleAdmin, nil)
	req.Header.Set("Idempotency-Key", "ac29-"+uuid.NewString())
	resp := doReq(t, req)
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &env)
	return resp.StatusCode, env.Error.Code
}

func discoveryJobCount(t *testing.T, pool *pgxpool.Pool, host uuid.UUID, status string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*) FROM job_queue
		 WHERE job_type = 'host.discovery' AND payload->>'host_id' = $1
		   AND ($2 = '' OR status = $2)`, host.String(), status).Scan(&n); err != nil {
		t.Fatalf("count jobs: %v", err)
	}
	return n
}

// @ac AC-29
// AC-29: a synchronous run holds the host's discovery slot.
func TestAPI_HostDiscovery_Run_HoldsTheHostSlot(t *testing.T) {
	t.Run("system-host-discovery/AC-29", func(t *testing.T) {
		url, pool, srv := freshAPIServerWithHandles(t)
		ctx := correlation.Set(context.Background(), "req-ac29")
		tr := &countingTransport{}
		srv.handlers.discoSvc.WithSSHTransport(tr)
		if _, err := credential.NewService(pool).NewCredential(ctx, credential.NewParams{
			Scope: credential.ScopeSystem, Name: "ac29", Username: "ops", IsDefault: true,
			AuthMethod: credential.AuthPassword, Password: "ac29-password", // pragma: allowlist secret
			CreatedBy: roleUserIDs[auth.RoleAdmin],
		}); err != nil {
			t.Fatalf("seed credential: %v", err)
		}
		host := seedAPIHost(t, pool)

		// A pending job the in-process worker cannot claim yet.
		pending, err := queue.EnqueueAfter(ctx, pool, discovery.JobKindHostDiscovery,
			discovery.HostDiscoveryJobPayload{HostID: host}, time.Hour)
		if err != nil {
			t.Fatalf("enqueue delayed job: %v", err)
		}
		if status, code := postDiscoveryRun(t, url, host); status != http.StatusConflict || code != "discovery.in_progress" {
			t.Fatalf("run with a pending job = %d %s, want 409 discovery.in_progress", status, code)
		}
		if n := tr.dials.Load(); n != 0 {
			t.Fatalf("a refused run dialed %d times", n)
		}
		if n := discoveryJobCount(t, pool, host, ""); n != 1 {
			t.Fatalf("jobs after a refused run = %d, want 1", n)
		}

		// With no active job the run claims one, runs and completes it.
		if _, err := pool.Exec(ctx, `UPDATE job_queue SET status = 'completed' WHERE id = $1`, pending); err != nil {
			t.Fatalf("finish pending job: %v", err)
		}
		if status, code := postDiscoveryRun(t, url, host); status != http.StatusOK {
			t.Fatalf("run with no active job = %d %s, want 200", status, code)
		}
		if n := tr.dials.Load(); n != 1 {
			t.Fatalf("successful run dialed %d times, want 1", n)
		}
		if n := discoveryJobCount(t, pool, host, "completed"); n != 2 {
			t.Fatalf("completed jobs = %d, want 2 (the finished one and the run's own)", n)
		}
		if n := discoveryJobCount(t, pool, host, "processing") + discoveryJobCount(t, pool, host, "pending"); n != 0 {
			t.Fatalf("active jobs after the run = %d, want 0", n)
		}

		// An unknown host is 404 and leaves no job.
		unknown := uuid.New()
		if status, code := postDiscoveryRun(t, url, unknown); status != http.StatusNotFound || code != "hosts.not_found" {
			t.Fatalf("unknown host = %d %s, want 404 hosts.not_found", status, code)
		}
		if n := discoveryJobCount(t, pool, unknown, ""); n != 0 {
			t.Fatalf("unknown host left %d jobs", n)
		}
	})
}
