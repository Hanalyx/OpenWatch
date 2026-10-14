// @spec system-discovery-scheduler
//
// Discovery job deduplication, stale retirement and failure backoff
// (bugs/OW-120).
//
// AC traceability (this file):
//
//	AC-12  TestDiscoveryJobs_OneActiveJobPerHost
//	AC-13  TestDiscoveryJobs_CompetingSchedulers
//	AC-15  TestDiscoveryJobs_StaleClaimRetired
//	AC-16  TestDiscoveryJobs_BackoffWithControlledClock
//	AC-18  TestDiscoveryJobs_FailureAfterSelection

package scheduler

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/correlation"
	"github.com/Hanalyx/openwatch/internal/credential"
	"github.com/Hanalyx/openwatch/internal/intelligence/discovery"
	"github.com/Hanalyx/openwatch/internal/queue"
	"github.com/Hanalyx/openwatch/internal/secretkey"
	"github.com/Hanalyx/openwatch/internal/systemconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func ow120Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := freshPool(t)
	if _, err := pool.Exec(context.Background(), "TRUNCATE TABLE job_queue"); err != nil {
		t.Fatalf("truncate job_queue: %v", err)
	}
	return pool
}

func reqCtx() context.Context {
	return correlation.Set(context.Background(), correlation.Generate(correlation.PrefixRequest))
}

type activeCounts struct{ pending, processing, total int }

func discoveryJobs(t *testing.T, pool *pgxpool.Pool, host uuid.UUID) activeCounts {
	t.Helper()
	var c activeCounts
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*) FILTER (WHERE status = 'pending'),
		       count(*) FILTER (WHERE status = 'processing'),
		       count(*)
		  FROM job_queue
		 WHERE job_type = 'host.discovery' AND payload->>'host_id' = $1`, host.String()).
		Scan(&c.pending, &c.processing, &c.total); err != nil {
		t.Fatalf("count jobs: %v", err)
	}
	return c
}

func backoffRow(t *testing.T, pool *pgxpool.Pool, host uuid.UUID) (n int, next time.Time, ok bool) {
	t.Helper()
	err := pool.QueryRow(context.Background(),
		`SELECT consecutive_failures, next_attempt_at FROM host_discovery_backoff WHERE host_id = $1`, host).
		Scan(&n, &next)
	if err != nil {
		return 0, time.Time{}, false
	}
	return n, next, true
}

// @ac AC-12
// AC-12: one active discovery job per host, whatever path starts it.
func TestDiscoveryJobs_OneActiveJobPerHost(t *testing.T) {
	t.Run("system-discovery-scheduler/AC-12", func(t *testing.T) {
		pool := ow120Pool(t)
		ctx := reqCtx()
		user := seedUser(t, pool)
		host := seedHost(t, pool, user, hostSeed{name: "ac12"})
		svc := NewService(pool)

		svc.tickOnce(ctx)
		svc.tickOnce(ctx)
		if ok, err := discovery.Enqueue(ctx, pool, host, time.Now()); err != nil || ok {
			t.Fatalf("Enqueue with a pending job: ok=%v err=%v, want false, nil", ok, err)
		}
		if _, ok, err := discovery.ClaimRun(ctx, pool, host); err != nil || ok {
			t.Fatalf("ClaimRun with a pending job: ok=%v err=%v, want false, nil", ok, err)
		}
		if c := discoveryJobs(t, pool, host); c.pending != 1 || c.total != 1 {
			t.Fatalf("after two ticks, Enqueue and ClaimRun: %+v, want exactly one pending job", c)
		}

		// Processing: still nothing added.
		j, _, err := queue.Dequeue(ctx, pool)
		if err != nil {
			t.Fatalf("dequeue: %v", err)
		}
		svc.tickOnce(ctx)
		if ok, _ := discovery.Enqueue(ctx, pool, host, time.Now()); ok {
			t.Fatalf("Enqueue added a job while one was processing")
		}
		if c := discoveryJobs(t, pool, host); c.processing != 1 || c.total != 1 {
			t.Fatalf("while processing: %+v, want one processing job and nothing else", c)
		}

		// A host with an active job does not use up the per-tick limit:
		// with RateLimit 1, a second host is still enqueued (C-12).
		// The busy host (never discovered) sorts first; the other was last
		// discovered two days ago, so it is due but sorts second.
		twoDaysAgo := time.Now().UTC().Add(-48 * time.Hour)
		other := seedHost(t, pool, user, hostSeed{name: "ac12-other", osDiscoveredAt: &twoDaysAgo})
		limited := NewService(pool).WithConfigLoader(func(context.Context) (systemconfig.DiscoveryConfig, error) {
			cfg := systemconfig.DefaultDiscovery()
			cfg.RateLimit = 1
			return cfg, nil
		})
		limited.tickOnce(ctx)
		if c := discoveryJobs(t, pool, other); c.pending != 1 {
			t.Fatalf("with RateLimit 1 and the first host busy, second host jobs = %+v, want one pending", c)
		}

		// Finished: the next tick enqueues one again.
		if err := queue.CompleteLeased(ctx, pool, j.Lease()); err != nil {
			t.Fatalf("complete: %v", err)
		}
		svc.tickOnce(ctx)
		if c := discoveryJobs(t, pool, host); c.pending != 1 || c.total != 2 {
			t.Fatalf("after completion and a tick: %+v, want one new pending job", c)
		}
	})
}

// @ac AC-13
// AC-13: concurrent schedulers still leave one active job per host.
func TestDiscoveryJobs_CompetingSchedulers(t *testing.T) {
	t.Run("system-discovery-scheduler/AC-13", func(t *testing.T) {
		pool := ow120Pool(t)
		user := seedUser(t, pool)
		var hosts []uuid.UUID
		for i := 0; i < 20; i++ {
			hosts = append(hosts, seedHost(t, pool, user, hostSeed{name: "ac13-" + uuid.NewString()[:8]}))
		}
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				svc := NewService(pool)
				for k := 0; k < 3; k++ {
					svc.tickOnce(reqCtx())
				}
			}()
		}
		wg.Wait()
		for _, h := range hosts {
			if c := discoveryJobs(t, pool, h); c.pending != 1 || c.total != 1 {
				t.Errorf("host %s: %+v, want exactly one pending job", h, c)
			}
		}
	})
}

// @ac AC-15
// AC-15: a stale claim is retired once and its lease no longer works.
func TestDiscoveryJobs_StaleClaimRetired(t *testing.T) {
	t.Run("system-discovery-scheduler/AC-15", func(t *testing.T) {
		pool := ow120Pool(t)
		ctx := reqCtx()
		user := seedUser(t, pool)
		staleHost := seedHost(t, pool, user, hostSeed{name: "ac15-stale"})
		liveHost := seedHost(t, pool, user, hostSeed{name: "ac15-live"})

		staleLease, ok, err := discovery.ClaimRun(ctx, pool, staleHost)
		if err != nil || !ok {
			t.Fatalf("claim stale: %v", err)
		}
		liveLease, ok, err := discovery.ClaimRun(ctx, pool, liveHost)
		if err != nil || !ok {
			t.Fatalf("claim live: %v", err)
		}
		older := discovery.StaleDeadline + time.Minute
		if _, err := pool.Exec(ctx,
			`UPDATE job_queue SET locked_at = now() - make_interval(secs => $2) WHERE id = $1`,
			staleLease.JobID, older.Seconds()); err != nil {
			t.Fatalf("backdate: %v", err)
		}
		younger := discovery.StaleDeadline - time.Minute
		if _, err := pool.Exec(ctx,
			`UPDATE job_queue SET locked_at = now() - make_interval(secs => $2) WHERE id = $1`,
			liveLease.JobID, younger.Seconds()); err != nil {
			t.Fatalf("age live claim: %v", err)
		}

		svc := NewService(pool)
		svc.tickOnce(ctx)

		var status, lastErr string
		if err := pool.QueryRow(ctx, `SELECT status, COALESCE(last_error, '') FROM job_queue WHERE id = $1`,
			staleLease.JobID).Scan(&status, &lastErr); err != nil {
			t.Fatalf("read stale job: %v", err)
		}
		if status != "failed" || lastErr != "host.discovery: stale: processing deadline exceeded" {
			t.Fatalf("stale job = %s %q, want failed with the stale message", status, lastErr)
		}
		if n, _, ok := backoffRow(t, pool, staleHost); !ok || n != 1 {
			t.Fatalf("stale host backoff = %d (present %v), want 1", n, ok)
		}
		if c := discoveryJobs(t, pool, liveHost); c.processing != 1 {
			t.Fatalf("live claim = %+v, want still processing", c)
		}
		if _, _, ok := backoffRow(t, pool, liveHost); ok {
			t.Fatalf("live host was backed off")
		}

		// The retired claim can neither complete nor fail its job, and its
		// failure is not counted again.
		if err := queue.CompleteLeased(ctx, pool, staleLease); !errors.Is(err, queue.ErrLeaseLost) {
			t.Fatalf("complete with the retired lease: %v, want ErrLeaseLost", err)
		}
		if err := queue.FailLeased(ctx, pool, staleLease, "late"); !errors.Is(err, queue.ErrLeaseLost) {
			t.Fatalf("fail with the retired lease: %v, want ErrLeaseLost", err)
		}
		svc.tickOnce(ctx)
		if n, _, _ := backoffRow(t, pool, staleHost); n != 1 {
			t.Fatalf("stale host backoff after another tick = %d, want still 1", n)
		}
	})
}

// failingTransport refuses every dial; okTransport answers every command
// with empty output, which Discover treats as a partial success.
type failingTransport struct{ dials int }

func (f *failingTransport) Dial(context.Context, string, int, *credential.Credential) (discovery.SSHSession, error) {
	f.dials++
	return nil, errors.New("dial refused")
}

type okTransport struct{ dials int }

func (o *okTransport) Dial(context.Context, string, int, *credential.Credential) (discovery.SSHSession, error) {
	o.dials++
	return okSession{}, nil
}

type okSession struct{}

func (okSession) Run(context.Context, string) ([]byte, int, error) { return nil, 0, nil }
func (okSession) RunWithStdin(context.Context, string, []byte) ([]byte, int, error) {
	return nil, 0, nil
}
func (okSession) Close() error { return nil }

// @ac AC-16
// AC-16: failure backoff, driven by a controlled clock.
func TestDiscoveryJobs_BackoffWithControlledClock(t *testing.T) {
	t.Run("system-discovery-scheduler/AC-16", func(t *testing.T) {
		for n, want := range map[int]time.Duration{
			0: 5 * time.Minute, 1: 5 * time.Minute, 2: 10 * time.Minute, 3: 20 * time.Minute,
			9: 1280 * time.Minute, 10: 24 * time.Hour, 50: 24 * time.Hour,
		} {
			if got := discovery.BackoffFor(n); got != want {
				t.Errorf("BackoffFor(%d) = %s, want %s", n, got, want)
			}
		}

		pool := ow120Pool(t)
		ctx := reqCtx()
		if err := secretkey.SetEphemeral(); err != nil {
			t.Fatalf("SetEphemeral: %v", err)
		}
		user := seedUser(t, pool)
		host := seedHost(t, pool, user, hostSeed{name: "ac16"})
		credSvc := credential.NewService(pool)
		if _, err := credSvc.NewCredential(ctx, credential.NewParams{
			Scope: credential.ScopeHost, ScopeID: &host, Name: "ac16", Username: "ops",
			AuthMethod: credential.AuthPassword, Password: "ac16-password", CreatedBy: user, // pragma: allowlist secret
		}); err != nil {
			t.Fatalf("seed credential: %v", err)
		}

		clock := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
		now := func() time.Time { return clock }
		sched := NewService(pool).WithClock(now)
		failing := &failingTransport{}
		disc := discovery.NewService(pool, nil, nil).
			WithHostLookup(discovery.PoolHostLookup{Pool: pool}).
			WithCredentialService(credSvc).
			WithSSHTransport(failing).
			WithClock(now)

		isTarget := func(at time.Time) bool {
			t.Helper()
			ids, err := sched.listDiscoveryTargets(ctx, 86400, at)
			if err != nil {
				t.Fatalf("list targets: %v", err)
			}
			for _, id := range ids {
				if id == host {
					return true
				}
			}
			return false
		}
		run := func() error {
			t.Helper()
			l, ok, err := discovery.ClaimRun(ctx, pool, host)
			if err != nil || !ok {
				t.Fatalf("claim: ok=%v err=%v", ok, err)
			}
			_, err = disc.Discover(ctx, host, l)
			return err
		}

		if !isTarget(clock) {
			t.Fatalf("a never-discovered host without backoff is not a target")
		}
		if err := run(); err == nil {
			t.Fatalf("discovery with a refusing transport succeeded")
		}
		if n, next, _ := backoffRow(t, pool, host); n != 1 || !next.Equal(clock.Add(5*time.Minute)) {
			t.Fatalf("after one failure: n=%d next=%s, want 1 and %s", n, next, clock.Add(5*time.Minute))
		}
		if isTarget(clock.Add(5*time.Minute - time.Second)) {
			t.Fatalf("host is a target before its backoff ends")
		}
		if !isTarget(clock.Add(5 * time.Minute)) {
			t.Fatalf("host is not a target when its backoff ends")
		}
		// The tick itself reads the scheduler's clock.
		saved := clock
		clock = saved.Add(5*time.Minute - time.Second)
		sched.tickOnce(ctx)
		if c := discoveryJobs(t, pool, host); c.pending != 0 {
			t.Fatalf("a tick before the backoff ended enqueued: %+v", c)
		}
		clock = saved.Add(5 * time.Minute)
		sched.tickOnce(ctx)
		if c := discoveryJobs(t, pool, host); c.pending != 1 {
			t.Fatalf("a tick when the backoff ended did not enqueue: %+v", c)
		}
		if _, err := pool.Exec(ctx, `UPDATE job_queue SET status = 'completed' WHERE status = 'pending'`); err != nil {
			t.Fatalf("clear the tick's job: %v", err)
		}
		clock = saved

		clock = clock.Add(5 * time.Minute)
		if err := run(); err == nil {
			t.Fatalf("second discovery succeeded")
		}
		if n, next, _ := backoffRow(t, pool, host); n != 2 || !next.Equal(clock.Add(10*time.Minute)) {
			t.Fatalf("after two failures: n=%d next=%s, want 2 and %s", n, next, clock.Add(10*time.Minute))
		}
		if isTarget(clock.Add(10*time.Minute - time.Second)) {
			t.Fatalf("host is a target before its second backoff ends")
		}

		// A success clears the backoff.
		ok := &okTransport{}
		disc.WithSSHTransport(ok)
		if err := run(); err != nil {
			t.Fatalf("discovery with a working transport: %v", err)
		}
		if _, _, present := backoffRow(t, pool, host); present {
			t.Fatalf("backoff survived a successful run")
		}
		if ok.dials != 1 || failing.dials != 2 {
			t.Fatalf("dials = %d ok, %d failing; want 1 and 2", ok.dials, failing.dials)
		}
	})
}

// interleavedEnqueuer runs between a tick's target selection and its
// enqueue, so the test can put another scheduler's failed run there.
type interleavedEnqueuer struct {
	between func(context.Context, uuid.UUID)
	next    Enqueuer
}

func (e interleavedEnqueuer) Enqueue(ctx context.Context, id uuid.UUID) (uuid.UUID, error) {
	e.between(ctx, id)
	return e.next.Enqueue(ctx, id)
}

// @ac AC-18
// AC-18 (scheduler half): a host chosen by a tick, whose discovery then
// fails elsewhere and backs off, is not queued by that tick.
func TestDiscoveryJobs_FailureAfterSelection(t *testing.T) {
	t.Run("system-discovery-scheduler/AC-18", func(t *testing.T) {
		pool := ow120Pool(t)
		ctx := reqCtx()
		if err := secretkey.SetEphemeral(); err != nil {
			t.Fatalf("SetEphemeral: %v", err)
		}
		user := seedUser(t, pool)
		host := seedHost(t, pool, user, hostSeed{name: "ac18"})
		credSvc := credential.NewService(pool)
		if _, err := credSvc.NewCredential(ctx, credential.NewParams{
			Scope: credential.ScopeHost, ScopeID: &host, Name: "ac18", Username: "ops",
			AuthMethod: credential.AuthPassword, Password: "ac18-password", CreatedBy: user, // pragma: allowlist secret
		}); err != nil {
			t.Fatalf("seed credential: %v", err)
		}
		disc := discovery.NewService(pool, nil, nil).
			WithHostLookup(discovery.PoolHostLookup{Pool: pool}).
			WithCredentialService(credSvc).
			WithSSHTransport(&failingTransport{})

		sched := NewService(pool)
		ran := false
		sched.enqueuer = interleavedEnqueuer{
			next: sched.enqueuer,
			between: func(c context.Context, id uuid.UUID) {
				ran = true
				// Another scheduler queues the host, a worker runs it, and
				// the run fails: the host is now backing off.
				if _, err := (PoolEnqueuer{Pool: pool}).Enqueue(c, id); err != nil {
					t.Fatalf("other scheduler enqueue: %v", err)
				}
				j, _, err := queue.Dequeue(c, pool)
				if err != nil {
					t.Fatalf("dequeue: %v", err)
				}
				if _, err := disc.Discover(c, id, j.Lease()); err == nil {
					t.Fatalf("discovery against a refusing transport succeeded")
				}
				if n, _, ok := backoffRow(t, pool, id); !ok || n != 1 {
					t.Fatalf("backoff not recorded: n=%d ok=%v", n, ok)
				}
			},
		}
		sched.tickOnce(ctx)
		if !ran {
			t.Fatalf("the interleaving did not run")
		}
		if c := discoveryJobs(t, pool, host); c.pending != 0 {
			t.Fatalf("the tick queued %d jobs for a host that had just backed off", c.pending)
		}
	})
}
