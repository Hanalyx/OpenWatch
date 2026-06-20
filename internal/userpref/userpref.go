// Package userpref owns per-user UI preferences, stored as the JSONB
// users.preferences column (migration 0040). It is intentionally tiny and
// schema-agnostic at this layer: Get returns the raw blob, Merge applies a
// shallow JSON merge. The SET of valid preference keys is governed one
// layer up by the typed api.UserPreferences contract — this package only
// guarantees the merge is atomic and scoped to a single, active user.
//
// Spec: system-user-preferences.
package userpref

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrUserNotFound is returned when the target user id is unknown, soft-
// deleted, or disabled — the same "no active user" condition the users
// service guards, kept as a distinct error so the handler maps it to 401.
var ErrUserNotFound = errors.New("userpref: user not found")

// Service reads and merges the users.preferences JSONB column.
type Service struct {
	pool *pgxpool.Pool
}

// NewService binds a Service to a DB pool.
func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool}
}

// Get returns the user's stored preferences blob, or `{}` for a user who
// has never set one (the column defaults to '{}'). ErrUserNotFound for an
// unknown / soft-deleted user.
func (s *Service) Get(ctx context.Context, userID uuid.UUID) (json.RawMessage, error) {
	const q = `SELECT preferences FROM users WHERE id = $1 AND deleted_at IS NULL`
	var raw []byte
	err := s.pool.QueryRow(ctx, q, userID).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("userpref: get: %w", err)
	}
	if len(raw) == 0 {
		return json.RawMessage("{}"), nil
	}
	return json.RawMessage(raw), nil
}

// Merge applies a shallow merge of patch onto the user's stored
// preferences (Postgres `||`: top-level keys in patch overwrite, others
// are retained) and returns the merged result. A patch of `{}` is a no-op
// read. ErrUserNotFound for an unknown / soft-deleted user.
//
// patch MUST be a JSON object; the handler validates the key set against
// the typed contract before calling Merge, so this layer trusts the shape
// but still defends against a non-object blob.
func (s *Service) Merge(ctx context.Context, userID uuid.UUID, patch json.RawMessage) (json.RawMessage, error) {
	if len(patch) == 0 {
		patch = json.RawMessage("{}")
	}
	// Defend against a non-object patch reaching the JSONB || operator
	// (which would error or, worse, replace the object with a scalar).
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(patch, &probe); err != nil {
		return nil, fmt.Errorf("userpref: patch is not a JSON object: %w", err)
	}
	const q = `
		UPDATE users
		   SET preferences = preferences || $2::jsonb, updated_at = now()
		 WHERE id = $1 AND deleted_at IS NULL
		RETURNING preferences`
	var raw []byte
	err := s.pool.QueryRow(ctx, q, userID, []byte(patch)).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("userpref: merge: %w", err)
	}
	return json.RawMessage(raw), nil
}
