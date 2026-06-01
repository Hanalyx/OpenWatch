package alertrouter

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

// Store is the persistence seam for v1.1.0 alert persistence (spec
// C-10). Production wires PgxStore; tests fake the interface.
//
// Insert MUST be idempotent: a duplicate (dedup_key, occurred_at) MUST
// return the existing row's ID rather than failing. The DB UNIQUE
// constraint is the source of truth (C-12); the implementation uses
// ON CONFLICT DO NOTHING + a follow-up SELECT to recover the id.
type Store interface {
	// Insert persists the alert and returns the assigned id. On a
	// duplicate (dedup_key, occurred_at) it returns the existing row's
	// id (no error). Any other DB error is surfaced.
	Insert(ctx context.Context, a Alert) (uuid.UUID, error)
}

// PgxStore is the production Store backed by pgxpool. Construct with
// NewPgxStore.
type PgxStore struct {
	pool *pgxpool.Pool
}

// NewPgxStore wraps a pgxpool.Pool as a Store.
func NewPgxStore(pool *pgxpool.Pool) *PgxStore {
	return &PgxStore{pool: pool}
}

// Insert satisfies Store. UPSERT-like semantics via ON CONFLICT DO
// NOTHING + RETURNING id, falling back to SELECT on a no-row return
// (which means the conflict path fired).
func (s *PgxStore) Insert(ctx context.Context, a Alert) (uuid.UUID, error) {
	if s.pool == nil {
		return uuid.Nil, errors.New("alertrouter: store pool not wired")
	}
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, fmt.Errorf("alertrouter: uuid: %w", err)
	}

	tagsRaw, err := json.Marshal(a.Tags)
	if err != nil {
		return uuid.Nil, fmt.Errorf("alertrouter: marshal tags: %w", err)
	}

	hostID := nullableUUID(a.HostID)
	occurredAt := a.OccurredAt
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}

	const stmt = `
		INSERT INTO alerts
			(id, dedup_key, alert_type, severity, host_id, rule_id,
			 title, body, tags, state, occurred_at, created_at, updated_at)
		VALUES
			($1, $2, $3, $4, $5, $6,
			 $7, $8, $9::jsonb, 'active', $10, now(), now())
		ON CONFLICT (dedup_key, occurred_at) DO NOTHING
		RETURNING id`

	var returned uuid.UUID
	err = s.pool.QueryRow(ctx, stmt,
		id, a.DedupKey(), string(a.Type), string(a.Severity),
		hostID, a.RuleID, a.Title, a.Body, tagsRaw, occurredAt,
	).Scan(&returned)
	if err == nil {
		return returned, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, fmt.Errorf("alertrouter: insert: %w", err)
	}

	// Duplicate path — recover the existing id.
	const fetch = `SELECT id FROM alerts WHERE dedup_key = $1 AND occurred_at = $2`
	if err := s.pool.QueryRow(ctx, fetch, a.DedupKey(), occurredAt).Scan(&returned); err != nil {
		return uuid.Nil, fmt.Errorf("alertrouter: fetch existing on conflict: %w", err)
	}
	return returned, nil
}

// nullableUUID converts uuid.Nil to a typed nil so the column accepts
// NULL (HostID is optional for some alert types).
func nullableUUID(u uuid.UUID) any {
	if u == uuid.Nil {
		return nil
	}
	return u
}
