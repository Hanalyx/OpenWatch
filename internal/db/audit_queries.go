package db

// Hand-written audit queries. Day 5's `make generate` replaces this file
// with `audit_queries.gen.go` produced by sqlc from
// internal/db/queries/audit.sql. The exported types and function
// signatures here match what sqlc would produce so callers don't change
// when the swap happens.
//
// This is a Stage-0-temporary file. The doc comment above marks it so a
// future cleanup pass can confirm it's been superseded.

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditEvent mirrors a row of the audit_events table.
type AuditEvent struct {
	ID            uuid.UUID
	CorrelationID string
	ActorType     string
	ActorID       *string
	Action        string
	ResourceType  *string
	ResourceID    *string
	Detail        json.RawMessage
	OccurredAt    time.Time
}

// InsertAuditEventParams is the input bundle for InsertAuditEvent.
type InsertAuditEventParams struct {
	ID            uuid.UUID
	CorrelationID string
	ActorType     string
	ActorID       *string
	Action        string
	ResourceType  *string
	ResourceID    *string
	Detail        json.RawMessage
}

// InsertAuditEvent inserts one event and returns the persisted row.
func InsertAuditEvent(ctx context.Context, pool *pgxpool.Pool, p InsertAuditEventParams) (AuditEvent, error) {
	const q = `
INSERT INTO audit_events (id, correlation_id, actor_type, actor_id, action, resource_type, resource_id, detail)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING id, correlation_id, actor_type, actor_id, action, resource_type, resource_id, detail, occurred_at
`
	var out AuditEvent
	err := pool.QueryRow(ctx, q,
		p.ID, p.CorrelationID, p.ActorType, p.ActorID, p.Action,
		p.ResourceType, p.ResourceID, p.Detail,
	).Scan(
		&out.ID, &out.CorrelationID, &out.ActorType, &out.ActorID, &out.Action,
		&out.ResourceType, &out.ResourceID, &out.Detail, &out.OccurredAt,
	)
	if err != nil {
		return AuditEvent{}, err
	}
	return out, nil
}

// ListAuditEventsParams is the input bundle for ListAuditEvents. Before is
// a cursor (rows STRICTLY before this timestamp); nil means "from newest."
type ListAuditEventsParams struct {
	Before *time.Time
	Limit  int32
}

// ListAuditEvents returns up to Limit rows ordered newest-first.
func ListAuditEvents(ctx context.Context, pool *pgxpool.Pool, p ListAuditEventsParams) ([]AuditEvent, error) {
	const q = `
SELECT id, correlation_id, actor_type, actor_id, action, resource_type, resource_id, detail, occurred_at
FROM audit_events
WHERE ($1::timestamptz IS NULL OR occurred_at < $1)
ORDER BY occurred_at DESC, id DESC
LIMIT $2
`
	rows, err := pool.Query(ctx, q, p.Before, p.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AuditEvent
	for rows.Next() {
		var e AuditEvent
		if err := rows.Scan(
			&e.ID, &e.CorrelationID, &e.ActorType, &e.ActorID, &e.Action,
			&e.ResourceType, &e.ResourceID, &e.Detail, &e.OccurredAt,
		); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetAuditEventByID fetches a single row. Returns pgx.ErrNoRows if missing.
func GetAuditEventByID(ctx context.Context, pool *pgxpool.Pool, id uuid.UUID) (AuditEvent, error) {
	const q = `
SELECT id, correlation_id, actor_type, actor_id, action, resource_type, resource_id, detail, occurred_at
FROM audit_events
WHERE id = $1
`
	var e AuditEvent
	err := pool.QueryRow(ctx, q, id).Scan(
		&e.ID, &e.CorrelationID, &e.ActorType, &e.ActorID, &e.Action,
		&e.ResourceType, &e.ResourceID, &e.Detail, &e.OccurredAt,
	)
	return e, err
}

// CountAuditEvents returns the total row count. Useful for tests; not
// recommended for production use against a large table.
func CountAuditEvents(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	var n int64
	err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_events`).Scan(&n)
	return n, err
}

// Suppress unused-import warning during transitions where one of these is
// only referenced by tests. Removed when sqlc-generated file lands Day 5.
var _ = pgx.ErrNoRows
