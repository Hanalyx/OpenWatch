// The sweeper: one cron tick that walks the registry and deletes what
// the registry says to delete. It is the only scheduled deletion path
// for any table in the registry (spec C-03). A single-use consume, a
// user-initiated delete, and a scheduled status transition such as the
// compliance-exception expiry flip are all outside that rule.
//
// Spec: specs/system/retention-sweeper.spec.yaml (C-03, C-05, C-06,
// C-12).
package retention

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/cron"
)

// DefaultInterval is the gap between sweeps. Retention is not urgent
// work: the shortest grace in the registry is an hour, and nothing in
// the product reads a row the sweep is about to remove.
const DefaultInterval = 6 * time.Hour

// DefaultBatchSize is how many rows one statement removes. Small enough
// that a batch holds row locks briefly, large enough that a backlog
// drains in a sane number of round trips.
const DefaultBatchSize = 1000

// EmitFunc is the audit-emission shape (matches audit.Emit). The sweeper
// takes one and never calls it. See Sweep.
type EmitFunc func(ctx context.Context, code audit.Code, ev audit.Event)

// Sweeper deletes rows past their grace for every swept entry in the
// registry. Construct with NewSweeper and start with Run.
type Sweeper struct {
	pool *pgxpool.Pool
	emit EmitFunc

	// policies overrides the package registry. nil means the real one.
	// Tests inject a registry here; production never sets it.
	policies []Policy

	batchSize int
	interval  time.Duration
}

// NewSweeper wires the sweeper. emit is audit.Emit in production, and is
// deliberately never called (spec C-12).
func NewSweeper(pool *pgxpool.Pool, emit EmitFunc) *Sweeper {
	return &Sweeper{
		pool:      pool,
		emit:      emit,
		batchSize: DefaultBatchSize,
		interval:  DefaultInterval,
	}
}

// WithBatchSize sets the rows-per-statement bound. Values below one are
// ignored, because a zero batch would loop forever.
func (s *Sweeper) WithBatchSize(n int) *Sweeper {
	if n > 0 {
		s.batchSize = n
	}
	return s
}

// WithInterval sets the tick interval, which also sets the per-tick
// deadline. Values below one are ignored.
func (s *Sweeper) WithInterval(d time.Duration) *Sweeper {
	if d > 0 {
		s.interval = d
	}
	return s
}

// WithPolicies replaces the registry this sweeper walks. For tests only:
// production reads the package registry, which is what makes a newly
// swept entry run without a change at the call site.
func (s *Sweeper) WithPolicies(p []Policy) *Sweeper {
	s.policies = p
	return s
}

// Interval is the gap between ticks.
func (s *Sweeper) Interval() time.Duration { return s.interval }

// Deadline is the per-tick context deadline. Strictly shorter than the
// interval, so a slow pass cannot overlap the next tick. cron.Scheduler
// sets no deadline of its own, so the sweeper sets this one.
func (s *Sweeper) Deadline() time.Duration { return s.interval / 2 }

// registry returns the policies this sweeper walks.
func (s *Sweeper) registry() []Policy {
	if s.policies != nil {
		return s.policies
	}
	return Registry()
}

// Run starts the sweep on a cron tick with one immediate pass, mirroring
// exception.Run and posture.Run. interval of zero keeps the configured
// one. Returns the scheduler so a caller can Stop it.
func (s *Sweeper) Run(ctx context.Context, interval time.Duration) *cron.Scheduler {
	s.WithInterval(interval)
	if err := s.sweepWithDeadline(ctx); err != nil {
		slog.WarnContext(ctx, "retention boot sweep failed", slog.String("err", err.Error()))
	}
	sched := cron.New(s.interval, s.sweepWithDeadline)
	sched.Start(ctx)
	return sched
}

// sweepWithDeadline runs one pass under the per-tick deadline. This is
// the TickFunc cron calls.
func (s *Sweeper) sweepWithDeadline(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, s.Deadline())
	defer cancel()
	return s.Sweep(ctx)
}

// Sweep runs one pass over the registry. A failure on one table does not
// stop the remaining tables: the error is collected, the pass finishes,
// and the returned error names every table that failed (spec C-12).
//
// No audit event is emitted here, for either the pass or a single
// delete. Routine expiry is not an actor's action, which is the durable
// reason and holds whatever anyone later decides about audit_events. The
// second reason is narrower but true today: audit_events grows without
// bound, so auditing retention would trade one unbounded table for
// another. s.emit is held so this note sits exactly where someone would
// otherwise add the call.
func (s *Sweeper) Sweep(ctx context.Context) error {
	_ = s.emit // Deliberately unused. See the note above and spec C-12.

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("retention: sweep not started: %w", err)
	}

	var errs []error
	for _, p := range s.registry() {
		if !p.Eligible() {
			continue
		}
		deleted, err := s.sweepTable(ctx, p)
		if err != nil {
			errs = append(errs, fmt.Errorf("retention: sweep %s: %w", p.Table, err))
			slog.WarnContext(ctx, "retention sweep failed",
				slog.String("table", p.Table),
				slog.String("err", err.Error()))
			if ctx.Err() != nil {
				// Out of time or canceled. The remaining tables wait
				// for the next tick rather than each logging the same
				// context error.
				break
			}
			continue
		}
		slog.InfoContext(ctx, "retention sweep",
			slog.String("table", p.Table),
			slog.Int64("deleted", deleted))
	}
	return errors.Join(errs...)
}

// sweepTable drains one table in batches, oldest row first, until a
// batch comes back short.
func (s *Sweeper) sweepTable(ctx context.Context, p Policy) (int64, error) {
	stmt := s.DeleteStatement(p)
	cutoff := time.Now().Add(-p.Grace)

	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		tag, err := s.pool.Exec(ctx, stmt, cutoff, s.batchSize)
		if err != nil {
			return total, err
		}
		total += tag.RowsAffected()
		if tag.RowsAffected() < int64(s.batchSize) {
			return total, nil
		}
	}
}

// DeleteStatement builds the batched delete for one policy. $1 is the
// cutoff timestamp, $2 the batch size.
//
// Postgres DELETE takes neither ORDER BY nor LIMIT, so the ordering and
// the bound live in a ctid subselect. Oldest-first is a correctness
// requirement, not a preference: refresh_tokens carries a self-
// referencing rotated_to_id with NO ACTION, and a newest-first batch
// breaks that constraint the moment the entry is promoted to swept.
//
// A Keep predicate is honored by negation, so a row matching Keep
// survives past its grace. The table and column names come from the
// registry, which is code in this package, never from a request.
func (s *Sweeper) DeleteStatement(p Policy) string {
	where := fmt.Sprintf("%s < $1", p.TTLColumn)
	if p.Keep != "" {
		where += fmt.Sprintf(" AND NOT (%s)", p.Keep)
	}
	return fmt.Sprintf(
		"DELETE FROM %s WHERE ctid IN (SELECT ctid FROM %s WHERE %s ORDER BY %s ASC LIMIT $2)",
		p.Table, p.Table, where, p.TTLColumn)
}
