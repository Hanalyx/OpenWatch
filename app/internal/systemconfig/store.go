package systemconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/audit"
)

// EmitFunc mirrors audit.Emit's signature so callers can substitute a
// no-op or capture-into-buffer for tests. Production wires audit.Emit.
type EmitFunc func(ctx context.Context, code audit.Code, ev audit.Event)

// Store reads and writes typed config from system_config.
type Store struct {
	pool *pgxpool.Pool
	emit EmitFunc
}

// NewStore returns a Store backed by the given pool. emit may be
// audit.Emit in production; tests can pass a capture function.
func NewStore(pool *pgxpool.Pool, emit EmitFunc) *Store {
	return &Store{pool: pool, emit: emit}
}

// LoadConnectivity returns the persisted ConnectivityConfig OR
// DefaultConnectivity when no row exists for KeyConnectivity. Only
// returns an error for DB / unmarshal failures — "no row" is not an
// error.
//
// Spec services-connectivity-config AC-01 / C-02.
func (s *Store) LoadConnectivity(ctx context.Context) (ConnectivityConfig, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT value FROM system_config WHERE key = $1`, KeyConnectivity).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultConnectivity(), nil
	}
	if err != nil {
		return ConnectivityConfig{}, fmt.Errorf("systemconfig: load %s: %w", KeyConnectivity, err)
	}
	// Start from defaults so any missing JSON field falls back rather
	// than zeroing out. Forward-compat: when ConnectivityConfig grows
	// new fields, old rows still hydrate sensibly.
	cfg := DefaultConnectivity()
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return ConnectivityConfig{}, fmt.Errorf("systemconfig: unmarshal %s: %w", KeyConnectivity, err)
	}
	return cfg, nil
}

// SetConnectivity validates the input, UPSERTs the row, and emits
// audit.SystemConfigChanged with the old + new snapshot captured in
// the same transaction.
//
// Spec services-connectivity-config AC-02 / C-03 / C-07.
func (s *Store) SetConnectivity(ctx context.Context, cfg ConnectivityConfig, changedBy string) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	newBytes, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("systemconfig: marshal: %w", err)
	}

	// Read the prior snapshot in the same tx so a concurrent writer
	// can't race the old_value into stale.
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("systemconfig: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var oldRaw []byte
	err = tx.QueryRow(ctx, `SELECT value FROM system_config WHERE key = $1 FOR UPDATE`, KeyConnectivity).Scan(&oldRaw)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("systemconfig: read old: %w", err)
	}
	oldCfg := DefaultConnectivity()
	if len(oldRaw) > 0 {
		_ = json.Unmarshal(oldRaw, &oldCfg) // best-effort; corrupted prior shouldn't block a new write
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO system_config (key, value, updated_at, updated_by)
		VALUES ($1, $2, now(), $3)
		ON CONFLICT (key) DO UPDATE
		   SET value      = EXCLUDED.value,
		       updated_at = EXCLUDED.updated_at,
		       updated_by = EXCLUDED.updated_by`,
		KeyConnectivity, newBytes, changedBy,
	); err != nil {
		return fmt.Errorf("systemconfig: upsert: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("systemconfig: commit: %w", err)
	}

	// Audit post-commit — the persisted state is what we want to
	// audit, and we don't want a failed audit emit to roll back the
	// write.
	if s.emit != nil {
		s.emit(ctx, audit.SystemConfigChanged, audit.Event{
			ActorType: "user",
			ActorID:   changedBy,
			Detail: audit.MakeDetail(map[string]any{
				"config_key": KeyConnectivity,
				"old_value":  oldCfg,
				"new_value":  cfg,
				"changed_by": changedBy,
			}),
		})
	}
	return nil
}
