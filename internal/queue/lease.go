package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Hanalyx/openwatch/internal/correlation"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Leased jobs. A job type whose results must not be written by a claim that
// has lost the job uses these instead of Complete and Fail: every terminal
// transition names the lease token its claim minted, and a token that is no
// longer current changes nothing. To write results under a lease, call
// CompleteLeased (or FailLeased) inside the transaction that writes them:
// the update checks the token and row-locks the job, so the results commit
// only together with the transition. Spec system-job-queue AC-14 to AC-17.

// ErrLeaseLost is returned when a lease is no longer the job's current
// claim: the job was retired as stale, completed, failed, or never existed.
var ErrLeaseLost = errors.New("queue: lease lost")

// EnqueueIfAbsent inserts a pending job unless a unique index refuses it, in
// which case it inserts nothing and reports enqueued=false. A job type that
// must have at most one active job per subject declares that with a partial
// unique index; this is how callers respect it without treating the
// conflict as an error. Same correlation guard as Enqueue.
//
// Spec system-job-queue AC-15.
func EnqueueIfAbsent(ctx context.Context, pool Execer, jobType string, payload any) (uuid.UUID, bool, error) {
	id, corrID, payloadJSON, err := newJobRow(ctx, jobType, payload)
	if err != nil {
		return uuid.Nil, false, err
	}
	const stmt = `
		INSERT INTO job_queue (id, job_type, payload, correlation_id, status, attempts, available_at)
		VALUES ($1, $2, $3::jsonb, $4, 'pending', 0, now())
		ON CONFLICT DO NOTHING`
	tag, err := pool.Exec(ctx, stmt, id, jobType, payloadJSON, corrID)
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("queue: insert: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return uuid.Nil, false, nil
	}
	return id, true, nil
}

// Claim inserts a job already claimed by the caller: status processing,
// attempts 1, a fresh lease token. It is for work run in the caller's own
// goroutine (an operator's synchronous request) that must still hold the
// job's slot. Like EnqueueIfAbsent it reports claimed=false, inserting
// nothing, when a unique index refuses the row.
//
// Spec system-job-queue AC-15.
func Claim(ctx context.Context, pool Execer, jobType string, payload any) (Lease, bool, error) {
	id, corrID, payloadJSON, err := newJobRow(ctx, jobType, payload)
	if err != nil {
		return Lease{}, false, err
	}
	token, err := uuid.NewRandom()
	if err != nil {
		return Lease{}, false, fmt.Errorf("queue: lease token: %w", err)
	}
	const stmt = `
		INSERT INTO job_queue (id, job_type, payload, correlation_id, status, attempts,
		                       available_at, locked_at, lease_token)
		VALUES ($1, $2, $3::jsonb, $4, 'processing', 1, now(), now(), $5)
		ON CONFLICT DO NOTHING`
	tag, err := pool.Exec(ctx, stmt, id, jobType, payloadJSON, corrID, token)
	if err != nil {
		return Lease{}, false, fmt.Errorf("queue: claim: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return Lease{}, false, nil
	}
	return Lease{JobID: id, Token: token}, true, nil
}

// CompleteLeased marks the job completed if the lease is still current, and
// returns ErrLeaseLost otherwise. The token is cleared, so the lease cannot
// be used again. Called in a transaction, it holds the job's row lock until
// that transaction ends, so a concurrent RetireStale waits for it.
//
// Spec system-job-queue AC-16.
func CompleteLeased(ctx context.Context, db Execer, l Lease) error {
	return finishLeased(ctx, db, l, "completed", "")
}

// FailLeased marks the job failed with errMsg if the lease is still current,
// and returns ErrLeaseLost otherwise.
//
// Spec system-job-queue AC-16.
func FailLeased(ctx context.Context, db Execer, l Lease, errMsg string) error {
	return finishLeased(ctx, db, l, "failed", errMsg)
}

func finishLeased(ctx context.Context, db Execer, l Lease, status, errMsg string) error {
	if !l.Valid() {
		return ErrLeaseLost
	}
	const stmt = `
		UPDATE job_queue
		   SET status       = $3,
		       completed_at = now(),
		       last_error   = NULLIF($4, ''),
		       lease_token  = NULL
		 WHERE id = $1 AND lease_token = $2 AND status = 'processing'`
	tag, err := db.Exec(ctx, stmt, l.JobID, l.Token, status, errMsg)
	if err != nil {
		return fmt.Errorf("queue: finish leased: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrLeaseLost
	}
	return nil
}

// StaleJob is a job RetireStale retired.
type StaleJob struct {
	ID      uuid.UUID
	Payload []byte
}

// RetireStale fails every processing job of jobType claimed more than
// deadline ago (by the database clock), clearing its lease so the claim
// that held it can no longer complete it or write results. It returns the
// retired jobs so the caller can record what their failure means in the
// same transaction.
//
// Spec system-job-queue AC-17.
func RetireStale(ctx context.Context, tx pgx.Tx, jobType string, deadline time.Duration, errMsg string) ([]StaleJob, error) {
	rows, err := tx.Query(ctx, `
		UPDATE job_queue
		   SET status       = 'failed',
		       completed_at = now(),
		       last_error   = $3,
		       lease_token  = NULL
		 WHERE job_type = $1
		   AND status = 'processing'
		   AND locked_at < now() - make_interval(secs => $2)
		 RETURNING id, payload`, jobType, deadline.Seconds(), errMsg)
	if err != nil {
		return nil, fmt.Errorf("queue: retire stale: %w", err)
	}
	defer rows.Close()
	var out []StaleJob
	for rows.Next() {
		var j StaleJob
		if err := rows.Scan(&j.ID, &j.Payload); err != nil {
			return nil, fmt.Errorf("queue: retire stale: scan: %w", err)
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// newJobRow validates and prepares the fields every insert path shares.
func newJobRow(ctx context.Context, jobType string, payload any) (uuid.UUID, string, []byte, error) {
	corrID, ok := correlation.From(ctx)
	if !ok {
		return uuid.Nil, "", nil, ErrMissingCorrelation
	}
	if jobType == "" {
		return uuid.Nil, "", nil, fmt.Errorf("queue: jobType must not be empty")
	}
	payloadJSON := []byte("{}")
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return uuid.Nil, "", nil, fmt.Errorf("queue: marshal payload: %w", err)
		}
		payloadJSON = raw
	}
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, "", nil, fmt.Errorf("queue: uuid: %w", err)
	}
	return id, corrID, payloadJSON, nil
}
