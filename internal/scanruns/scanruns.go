// Package scanruns owns the scan_runs table — the operational record
// ("logbook") of compliance-scan attempts.
//
// One row per scan attempt, keyed by the job_queue job id, which is
// also the value the worker passes to transactionlog as ScanID — so
// scan_runs.id correlates 1:1 with transactions.scan_id and with the
// scan.* audit events' scan_id detail.
//
// Lifecycle writes:
//
//	Insert        — at enqueue (on-demand endpoint or scheduler):
//	                status 'queued', trigger_source + requested_by set.
//	MarkRunning   — by the worker after HMAC verification, before the
//	                executor runs. UPSERTs so a job enqueued without a
//	                row (legacy/hand-enqueued) still gets a record,
//	                attributed to 'scheduled'.
//	MarkCompleted — by the worker after transactionlog.Writer.Apply
//	                succeeds; records per-outcome counts.
//	MarkFailed    — by the worker on any failure path; records the
//	                typed failure reason.
//
// MarkCompleted / MarkFailed never overwrite a terminal status, so a
// late duplicate write cannot flip a finished run.
//
// Spec: system-scan-runs v1.0.0.
package scanruns

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TriggerSource records who initiated a scan run.
type TriggerSource string

const (
	TriggerOnDemand  TriggerSource = "on_demand"
	TriggerScheduled TriggerSource = "scheduled"
)

// Status is the run lifecycle state.
type Status string

const (
	StatusQueued    Status = "queued"
	StatusRunning   Status = "running"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
)

// ErrNotFound is returned by Get when no run exists for the id.
var ErrNotFound = errors.New("scanruns: run not found")

// Run is one scan_runs row.
type Run struct {
	ID            uuid.UUID
	HostID        uuid.UUID
	TriggerSource TriggerSource
	RequestedBy   *uuid.UUID // nil for scheduled runs
	Status        Status
	QueuedAt      time.Time
	StartedAt     *time.Time
	FinishedAt    *time.Time
	PolicyVersion string
	Counts        *Counts // nil until completed
	FailureReason string
	CorrelationID string
}

// Counts are the per-outcome rule totals recorded on completion.
type Counts struct {
	Pass    int
	Fail    int
	Skipped int
	Error   int
}

// Insert records a freshly-enqueued run (status 'queued'). The id MUST
// be the queue job id so the run correlates with transactions.scan_id.
func Insert(ctx context.Context, pool *pgxpool.Pool, r Run) error {
	if r.TriggerSource == "" {
		return errors.New("scanruns: TriggerSource is required")
	}
	_, err := pool.Exec(ctx, `
		INSERT INTO scan_runs
			(id, host_id, trigger_source, requested_by, status,
			 policy_version, correlation_id)
		VALUES ($1, $2, $3, $4, 'queued', NULLIF($5, ''), NULLIF($6, ''))`,
		r.ID, r.HostID, string(r.TriggerSource), r.RequestedBy,
		r.PolicyVersion, r.CorrelationID)
	if err != nil {
		return fmt.Errorf("scanruns: insert: %w", err)
	}
	return nil
}

// MarkRunning flips the run to 'running' with started_at = now().
// UPSERT: a job that was enqueued without an Insert (legacy or
// hand-enqueued) gets a row attributed to the scheduler.
func MarkRunning(ctx context.Context, pool *pgxpool.Pool, id, hostID uuid.UUID, policyVersion string) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO scan_runs (id, host_id, trigger_source, status, started_at, policy_version)
		VALUES ($1, $2, 'scheduled', 'running', now(), NULLIF($3, ''))
		ON CONFLICT (id) DO UPDATE
		SET status = 'running', started_at = now()
		WHERE scan_runs.status IN ('queued', 'running')`,
		id, hostID, policyVersion)
	if err != nil {
		return fmt.Errorf("scanruns: mark running: %w", err)
	}
	return nil
}

// MarkCompleted records a successful run with its outcome counts.
// Terminal statuses are never overwritten.
func MarkCompleted(ctx context.Context, pool *pgxpool.Pool, id uuid.UUID, c Counts) error {
	_, err := pool.Exec(ctx, `
		UPDATE scan_runs
		SET status = 'completed', finished_at = now(),
		    rules_pass = $2, rules_fail = $3, rules_skipped = $4, rules_error = $5
		WHERE id = $1 AND status NOT IN ('completed', 'failed')`,
		id, c.Pass, c.Fail, c.Skipped, c.Error)
	if err != nil {
		return fmt.Errorf("scanruns: mark completed: %w", err)
	}
	return nil
}

// MarkFailed records a failed run with its typed reason. Terminal
// statuses are never overwritten.
func MarkFailed(ctx context.Context, pool *pgxpool.Pool, id uuid.UUID, reason string) error {
	_, err := pool.Exec(ctx, `
		UPDATE scan_runs
		SET status = 'failed', finished_at = now(), failure_reason = NULLIF($2, '')
		WHERE id = $1 AND status NOT IN ('completed', 'failed')`,
		id, reason)
	if err != nil {
		return fmt.Errorf("scanruns: mark failed: %w", err)
	}
	return nil
}

// Get returns one run by id. Returns ErrNotFound when absent.
func Get(ctx context.Context, pool *pgxpool.Pool, id uuid.UUID) (*Run, error) {
	row := pool.QueryRow(ctx, `
		SELECT id, host_id, trigger_source, requested_by, status,
		       queued_at, started_at, finished_at,
		       COALESCE(policy_version, ''),
		       rules_pass, rules_fail, rules_skipped, rules_error,
		       COALESCE(failure_reason, ''), COALESCE(correlation_id, '')
		FROM scan_runs WHERE id = $1`, id)
	return scanRun(row)
}

// LatestForHost returns the most recent run for a host (by queued_at),
// or ErrNotFound when the host has never been scanned.
func LatestForHost(ctx context.Context, pool *pgxpool.Pool, hostID uuid.UUID) (*Run, error) {
	row := pool.QueryRow(ctx, `
		SELECT id, host_id, trigger_source, requested_by, status,
		       queued_at, started_at, finished_at,
		       COALESCE(policy_version, ''),
		       rules_pass, rules_fail, rules_skipped, rules_error,
		       COALESCE(failure_reason, ''), COALESCE(correlation_id, '')
		FROM scan_runs WHERE host_id = $1
		ORDER BY queued_at DESC LIMIT 1`, hostID)
	return scanRun(row)
}

// ActiveForHost returns the host's queued-or-running run, or
// ErrNotFound when none is active. Backs the on-demand endpoint's 409.
func ActiveForHost(ctx context.Context, pool *pgxpool.Pool, hostID uuid.UUID) (*Run, error) {
	row := pool.QueryRow(ctx, `
		SELECT id, host_id, trigger_source, requested_by, status,
		       queued_at, started_at, finished_at,
		       COALESCE(policy_version, ''),
		       rules_pass, rules_fail, rules_skipped, rules_error,
		       COALESCE(failure_reason, ''), COALESCE(correlation_id, '')
		FROM scan_runs
		WHERE host_id = $1 AND status IN ('queued', 'running')
		ORDER BY queued_at DESC LIMIT 1`, hostID)
	return scanRun(row)
}

// ActiveCount returns the number of queued + running runs (the "scan
// queue" depth on the fleet page and settings readout).
func ActiveCount(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	var n int
	err := pool.QueryRow(ctx,
		`SELECT count(*) FROM scan_runs WHERE status IN ('queued', 'running')`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("scanruns: active count: %w", err)
	}
	return n, nil
}

// ActiveBreakdown returns the queued and running run counts separately
// (the /fleet/scan-queue KPI). Terminal rows never count.
// Spec api-host-compliance AC-07.
func ActiveBreakdown(ctx context.Context, pool *pgxpool.Pool) (queued, running int, err error) {
	err = pool.QueryRow(ctx, `
		SELECT COUNT(*) FILTER (WHERE status = 'queued'),
		       COUNT(*) FILTER (WHERE status = 'running')
		FROM scan_runs
		WHERE status IN ('queued', 'running')`).Scan(&queued, &running)
	if err != nil {
		return 0, 0, fmt.Errorf("scanruns: active breakdown: %w", err)
	}
	return queued, running, nil
}

func scanRun(row pgx.Row) (*Run, error) {
	var (
		r       Run
		trigger string
		status  string
		pass    *int
		fail    *int
		skipped *int
		errCnt  *int
	)
	err := row.Scan(&r.ID, &r.HostID, &trigger, &r.RequestedBy, &status,
		&r.QueuedAt, &r.StartedAt, &r.FinishedAt, &r.PolicyVersion,
		&pass, &fail, &skipped, &errCnt, &r.FailureReason, &r.CorrelationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scanruns: scan row: %w", err)
	}
	r.TriggerSource = TriggerSource(trigger)
	r.Status = Status(status)
	if pass != nil {
		r.Counts = &Counts{Pass: *pass, Fail: *fail, Skipped: *skipped, Error: *errCnt}
	}
	return &r, nil
}
