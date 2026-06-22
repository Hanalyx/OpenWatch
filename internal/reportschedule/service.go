package reportschedule

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when a schedule id does not exist.
var ErrNotFound = errors.New("reportschedule: not found")

// Service owns CRUD over report_schedules.
type Service struct {
	pool *pgxpool.Pool
}

func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

const scheduleCols = `id, name, kind, scope, frequency, hour, weekday, day_of_month,
	channel_id, enabled, next_run_at, last_run_at, COALESCE(last_status, ''), created_by, created_at, updated_at`

func scanSchedule(row pgx.Row) (Schedule, error) {
	var s Schedule
	var scopeRaw []byte
	if err := row.Scan(&s.ID, &s.Name, &s.Kind, &scopeRaw, &s.Frequency, &s.Hour,
		&s.Weekday, &s.DayOfMonth, &s.ChannelID, &s.Enabled, &s.NextRunAt,
		&s.LastRunAt, &s.LastStatus, &s.CreatedBy, &s.CreatedAt, &s.UpdatedAt); err != nil {
		return Schedule{}, err
	}
	if len(scopeRaw) > 0 {
		if err := json.Unmarshal(scopeRaw, &s.Scope); err != nil {
			return Schedule{}, fmt.Errorf("reportschedule: decode scope: %w", err)
		}
	}
	return s, nil
}

// Create inserts a schedule, computing its first next_run_at from now.
func (s *Service) Create(ctx context.Context, p CreateParams) (Schedule, error) {
	scopeRaw, err := json.Marshal(p.Scope)
	if err != nil {
		return Schedule{}, fmt.Errorf("reportschedule: marshal scope: %w", err)
	}
	next := ComputeNextRun(p.Frequency, p.Hour, p.Weekday, p.DayOfMonth, time.Now().UTC())
	row := s.pool.QueryRow(ctx, `
		INSERT INTO report_schedules
			(id, name, kind, scope, frequency, hour, weekday, day_of_month, channel_id, next_run_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING `+scheduleCols,
		uuid.New(), p.Name, p.Kind, scopeRaw, p.Frequency, p.Hour, p.Weekday, p.DayOfMonth,
		p.ChannelID, next, p.CreatedBy)
	return scanSchedule(row)
}

// List returns all schedules, newest first.
func (s *Service) List(ctx context.Context) ([]Schedule, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+scheduleCols+` FROM report_schedules ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("reportschedule: list: %w", err)
	}
	defer rows.Close()
	out := []Schedule{}
	for rows.Next() {
		sch, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sch)
	}
	return out, rows.Err()
}

// Get returns one schedule by id, or ErrNotFound.
func (s *Service) Get(ctx context.Context, id uuid.UUID) (Schedule, error) {
	sch, err := scanSchedule(s.pool.QueryRow(ctx, `SELECT `+scheduleCols+` FROM report_schedules WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Schedule{}, ErrNotFound
	}
	return sch, err
}

// Delete removes a schedule. A missing id is ErrNotFound.
func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM report_schedules WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("reportschedule: delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetEnabled toggles a schedule. Re-enabling recomputes next_run_at from now
// so a long-paused schedule does not fire for every missed run.
func (s *Service) SetEnabled(ctx context.Context, id uuid.UUID, enabled bool) (Schedule, error) {
	cur, err := s.Get(ctx, id)
	if err != nil {
		return Schedule{}, err
	}
	next := cur.NextRunAt
	if enabled && !cur.Enabled {
		next = ComputeNextRun(cur.Frequency, cur.Hour, cur.Weekday, cur.DayOfMonth, time.Now().UTC())
	}
	row := s.pool.QueryRow(ctx,
		`UPDATE report_schedules SET enabled = $2, next_run_at = $3, updated_at = now() WHERE id = $1 RETURNING `+scheduleCols,
		id, enabled, next)
	return scanSchedule(row)
}

// Due returns the enabled schedules whose next_run_at has passed.
func (s *Service) Due(ctx context.Context, now time.Time) ([]Schedule, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+scheduleCols+` FROM report_schedules WHERE enabled AND next_run_at <= $1 ORDER BY next_run_at`, now)
	if err != nil {
		return nil, fmt.Errorf("reportschedule: due: %w", err)
	}
	defer rows.Close()
	out := []Schedule{}
	for rows.Next() {
		sch, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sch)
	}
	return out, rows.Err()
}

// MarkRun records a run outcome and advances next_run_at.
func (s *Service) MarkRun(ctx context.Context, id uuid.UUID, next time.Time, status string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE report_schedules SET last_run_at = now(), last_status = $2, next_run_at = $3, updated_at = now() WHERE id = $1`,
		id, status, next)
	if err != nil {
		return fmt.Errorf("reportschedule: mark run: %w", err)
	}
	return nil
}

// ComputeNextRun returns the next scheduled run strictly after `from`, at the
// configured hour (UTC), honouring the cadence (weekday for weekly, day of
// month for monthly; day_of_month is capped at 28 so every month has it).
func ComputeNextRun(freq Frequency, hour int, weekday, dom *int, from time.Time) time.Time {
	from = from.UTC()
	switch freq {
	case Weekly:
		wd := 0
		if weekday != nil {
			wd = *weekday
		}
		c := time.Date(from.Year(), from.Month(), from.Day(), hour, 0, 0, 0, time.UTC)
		c = c.AddDate(0, 0, (wd-int(c.Weekday())+7)%7)
		if !c.After(from) {
			c = c.AddDate(0, 0, 7)
		}
		return c
	case Monthly:
		d := 1
		if dom != nil {
			d = *dom
		}
		c := time.Date(from.Year(), from.Month(), d, hour, 0, 0, 0, time.UTC)
		if !c.After(from) {
			c = c.AddDate(0, 1, 0)
		}
		return c
	default: // Daily
		c := time.Date(from.Year(), from.Month(), from.Day(), hour, 0, 0, 0, time.UTC)
		if !c.After(from) {
			c = c.AddDate(0, 0, 1)
		}
		return c
	}
}
