package audit

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// pgStore persists events to the audit_events table via pgxpool.
type pgStore struct {
	pool *pgxpool.Pool
}

// NewStore wraps a pgxpool.Pool for use as the audit Storage.
func NewStore(pool *pgxpool.Pool) Storage {
	return &pgStore{pool: pool}
}

// InsertEvent persists one event. Caller's responsibility to have run
// Redact already; the writer does that before calling store.
//
// Uses positional parameters ($1..$N) matching the audit_events column
// order from migrations 0001 + 0002. Day 5b's sqlc codegen replaces this
// hand-written function; signatures stay identical.
func (s *pgStore) InsertEvent(ctx Ctx, ev *Event) error {
	// Bridge our Ctx alias to context.Context for pgx.
	pgxCtx, ok := ctx.(context.Context)
	if !ok {
		return fmt.Errorf("audit: store.InsertEvent: ctx is not context.Context")
	}
	return s.insertOne(pgxCtx, ev)
}

// InsertBatch persists a slice of events in a single transaction so the
// batched writer can flush 100 events as one DB round-trip. Each row goes
// through Redact in the writer before this call.
func (s *pgStore) InsertBatch(ctx context.Context, events []*Event) error {
	if len(events) == 0 {
		return nil
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("audit: store.InsertBatch: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, ev := range events {
		if err := s.insertOneTx(ctx, tx, ev); err != nil {
			return fmt.Errorf("audit: store.InsertBatch: insert: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("audit: store.InsertBatch: commit: %w", err)
	}
	return nil
}

const insertSQL = `
INSERT INTO audit_events (
    id, correlation_id, action,
    severity, outcome,
    actor_type, actor_id, actor_label, actor_ip, actor_user_agent, actor_session_id,
    resource_type, resource_id,
    parent_event_id, policy_version,
    detail, redactions,
    occurred_at
)
VALUES (
    $1, $2, $3,
    $4, $5,
    $6, $7, $8, $9, $10, $11,
    $12, $13,
    $14, $15,
    $16, $17,
    $18
)
`

func (s *pgStore) insertOne(ctx context.Context, ev *Event) error {
	_, err := s.pool.Exec(ctx, insertSQL,
		ev.ID, ev.CorrelationID, string(ev.Action),
		nilIfEmpty(string(ev.Severity)), nilIfEmpty(string(ev.Outcome)),
		ev.ActorType, nilIfEmpty(ev.ActorID), nilIfEmpty(ev.ActorLabel),
		nilIfEmpty(ev.ActorIP), nilIfEmpty(ev.ActorUserAgent), ev.ActorSessionID,
		nilIfEmpty(ev.ResourceType), nilIfEmpty(ev.ResourceID),
		ev.ParentEventID, nilIfEmpty(ev.PolicyVersion),
		ev.Detail, ev.Redactions,
		ev.OccurredAt,
	)
	return err
}

func (s *pgStore) insertOneTx(ctx context.Context, tx pgx.Tx, ev *Event) error {
	_, err := tx.Exec(ctx, insertSQL,
		ev.ID, ev.CorrelationID, string(ev.Action),
		nilIfEmpty(string(ev.Severity)), nilIfEmpty(string(ev.Outcome)),
		ev.ActorType, nilIfEmpty(ev.ActorID), nilIfEmpty(ev.ActorLabel),
		nilIfEmpty(ev.ActorIP), nilIfEmpty(ev.ActorUserAgent), ev.ActorSessionID,
		nilIfEmpty(ev.ResourceType), nilIfEmpty(ev.ResourceID),
		ev.ParentEventID, nilIfEmpty(ev.PolicyVersion),
		ev.Detail, ev.Redactions,
		ev.OccurredAt,
	)
	return err
}

// nilIfEmpty returns nil for empty strings so PG writes NULL instead of ”.
// Several columns are nullable; this preserves the distinction between
// "not provided" and "explicitly empty."
func nilIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
