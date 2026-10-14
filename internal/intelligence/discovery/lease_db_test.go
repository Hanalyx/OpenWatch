// @spec system-host-discovery

package discovery

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/credential"
	"github.com/Hanalyx/openwatch/internal/queue"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// retiringTransport retires the run's job when it is dialed, then hands
// out a working session, so the run reaches persist holding a lease that
// is no longer current.
type retiringTransport struct {
	*stubSSHTransport
	retire func()
}

func (r *retiringTransport) Dial(ctx context.Context, host string, port int, cred *credential.Credential) (SSHSession, error) {
	r.retire()
	return r.stubSSHTransport.Dial(ctx, host, port, cred)
}

type refusingTransport struct{ dials int }

func (r *refusingTransport) Dial(context.Context, string, int, *credential.Credential) (SSHSession, error) {
	r.dials++
	return nil, errors.New("dial refused")
}

func jobState(t *testing.T, pool *pgxpool.Pool, id uuid.UUID) (status, lastErr string) {
	t.Helper()
	if err := pool.QueryRow(context.Background(),
		`SELECT status, COALESCE(last_error, '') FROM job_queue WHERE id = $1`, id).Scan(&status, &lastErr); err != nil {
		t.Fatalf("read job: %v", err)
	}
	return status, lastErr
}

func backoffCount(t *testing.T, pool *pgxpool.Pool, host uuid.UUID) int {
	t.Helper()
	var n int
	err := pool.QueryRow(context.Background(),
		`SELECT consecutive_failures FROM host_discovery_backoff WHERE host_id = $1`, host).Scan(&n)
	if err != nil {
		return 0
	}
	return n
}

// @ac AC-30
// AC-30: Discover runs only under a current lease, and records its outcome
// under it.
func TestDiscover_RunsUnderItsLease(t *testing.T) {
	t.Run("system-host-discovery/AC-30", func(t *testing.T) {
		pool, hostID, credSvc := freshDBHost(t)
		ctx := context.Background()
		if _, err := pool.Exec(ctx, "TRUNCATE TABLE job_queue"); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		emits := newAuditRecorder()
		newSvc := func(tr SSHTransport) *Service {
			return NewService(pool, emits.Emit, newStubBus()).
				WithHostLookup(PoolHostLookup{Pool: pool}).
				WithCredentialService(credSvc).
				WithSSHTransport(tr)
		}

		// No lease: nothing is dialed.
		stub := newStubSSHTransport()
		stub.SeedAll()
		if _, err := newSvc(stub).Discover(ctx, hostID, queue.Lease{}); !errors.Is(err, ErrNoLease) {
			t.Fatalf("Discover without a lease: %v, want ErrNoLease", err)
		}
		if stub.DialCount() != 0 {
			t.Fatalf("Discover without a lease dialed %d times", stub.DialCount())
		}

		// A failed run fails its job and backs the host off once.
		refuse := &refusingTransport{}
		l := claimLease(t, pool, hostID)
		if _, err := newSvc(refuse).Discover(ctx, hostID, l); err == nil {
			t.Fatalf("Discover with a refusing transport succeeded")
		}
		if st, msg := jobState(t, pool, l.JobID); st != "failed" || msg == "" {
			t.Fatalf("failed run left its job %s %q, want failed with a message", st, msg)
		}
		if n := backoffCount(t, pool, hostID); n != 1 {
			t.Fatalf("backoff after one failure = %d, want 1", n)
		}

		// A run whose lease is retired between dial and persist writes
		// nothing and adds no backoff of its own.
		l = claimLease(t, pool, hostID)
		emitted := emits.CountFor(string(audit.HostDiscoveryCompleted))
		retiring := &retiringTransport{stubSSHTransport: stub, retire: func() {
			if _, err := pool.Exec(ctx,
				`UPDATE job_queue SET locked_at = now() - make_interval(secs => $2) WHERE id = $1`,
				l.JobID, (StaleDeadline + time.Minute).Seconds()); err != nil {
				t.Errorf("backdate: %v", err)
			}
			if n, err := RetireStaleJobs(ctx, pool, time.Now()); err != nil || n != 1 {
				t.Errorf("retire: n=%d err=%v, want 1", n, err)
			}
		}}
		if _, err := newSvc(retiring).Discover(ctx, hostID, l); !errors.Is(err, queue.ErrLeaseLost) {
			t.Fatalf("Discover with a retired lease: %v, want queue.ErrLeaseLost", err)
		}
		var rows int
		var discovered *time.Time
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM host_system_info WHERE host_id = $1`, hostID).Scan(&rows); err != nil {
			t.Fatalf("count host_system_info: %v", err)
		}
		if err := pool.QueryRow(ctx, `SELECT os_discovered_at FROM hosts WHERE id = $1`, hostID).Scan(&discovered); err != nil {
			t.Fatalf("read os_discovered_at: %v", err)
		}
		if rows != 0 || discovered != nil {
			t.Fatalf("retired run wrote results: %d host_system_info rows, os_discovered_at %v", rows, discovered)
		}
		if n := backoffCount(t, pool, hostID); n != 2 {
			t.Fatalf("backoff after the retirement = %d, want 2 (the retirement only)", n)
		}
		if got := emits.CountFor(string(audit.HostDiscoveryCompleted)); got != emitted {
			t.Fatalf("retired run emitted %d audit events", got-emitted)
		}

		// A successful run completes its job and clears the backoff.
		l = claimLease(t, pool, hostID)
		if _, err := newSvc(stub).Discover(ctx, hostID, l); err != nil {
			t.Fatalf("successful Discover: %v", err)
		}
		if st, _ := jobState(t, pool, l.JobID); st != "completed" {
			t.Fatalf("successful run left its job %s, want completed", st)
		}
		if n := backoffCount(t, pool, hostID); n != 0 {
			t.Fatalf("backoff after success = %d, want cleared", n)
		}
	})
}
