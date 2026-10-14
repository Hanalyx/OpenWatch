// @spec system-discovery-scheduler

package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/correlation"
	"github.com/Hanalyx/openwatch/internal/intelligence/discovery"
	"github.com/Hanalyx/openwatch/internal/queue"
	"github.com/google/uuid"
)

// @ac AC-16
// AC-16 (sweep half): the manual sweep skips a host with an active job or
// in backoff, and counts only jobs it newly enqueued.
func TestAPI_DiscoverySweep_SkipsActiveAndBackedOffHosts(t *testing.T) {
	t.Run("system-discovery-scheduler/AC-16", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := correlation.Set(context.Background(), "req-sweep")
		if _, err := pool.Exec(ctx, `UPDATE hosts SET os_discovered_at = now()`); err != nil {
			t.Fatalf("mark existing hosts discovered: %v", err)
		}
		seed := func(name string) uuid.UUID {
			t.Helper()
			id := uuid.New()
			if _, err := pool.Exec(ctx,
				`INSERT INTO hosts (id, hostname, ip_address, created_by) VALUES ($1, $2, '192.0.2.30'::inet, $3)`,
				id, "sweep-"+name+"-"+id.String(), roleUserIDs[auth.RoleAdmin]); err != nil {
				t.Fatalf("seed host %s: %v", name, err)
			}
			return id
		}
		active, backedOff, fresh := seed("active"), seed("backoff"), seed("fresh")

		if _, err := queue.EnqueueAfter(ctx, pool, discovery.JobKindHostDiscovery,
			discovery.HostDiscoveryJobPayload{HostID: active}, time.Hour); err != nil {
			t.Fatalf("enqueue delayed job: %v", err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO host_discovery_backoff (host_id, consecutive_failures, last_failure_at, next_attempt_at)
			VALUES ($1, 1, now(), now() + interval '1 hour')`, backedOff); err != nil {
			t.Fatalf("seed backoff: %v", err)
		}

		req := asRole(t, "POST", url+"/api/v1/system/discovery/sweep", auth.RoleAdmin, nil)
		req.Header.Set("Idempotency-Key", "sweep-ac16")
		resp := doReq(t, req)
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("sweep = %d %s", resp.StatusCode, raw)
		}
		var out struct {
			Enqueued int `json:"enqueued"`
		}
		_ = json.Unmarshal(raw, &out)
		if out.Enqueued != 1 {
			t.Fatalf("sweep enqueued %d, want 1 (only the fresh host)", out.Enqueued)
		}
		for name, h := range map[string]uuid.UUID{"active": active, "backed off": backedOff, "fresh": fresh} {
			var n int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM job_queue WHERE job_type = 'host.discovery' AND payload->>'host_id' = $1`,
				h.String()).Scan(&n); err != nil {
				t.Fatalf("count: %v", err)
			}
			want := 1
			if name == "backed off" {
				want = 0
			}
			if n != want {
				t.Errorf("%s host has %d discovery jobs, want %d", name, n, want)
			}
		}
	})
}
