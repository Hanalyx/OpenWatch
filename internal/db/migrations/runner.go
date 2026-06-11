package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

// Apply runs all pending Up migrations against the pool. Idempotent: applies
// only the ones not yet recorded in goose_db_version.
//
// goose wants a *sql.DB (database/sql), but the rest of the codebase uses
// pgxpool. We bridge with pgx's stdlib driver: it wraps a pgxpool.Pool into
// a *sql.DB for the duration of the migration run. This is officially
// supported by jackc/pgx.
func Apply(ctx context.Context, pool *pgxpool.Pool) error {
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()

	goose.SetBaseFS(fsys)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("migrations: set dialect: %w", err)
	}

	if err := goose.UpContext(ctx, sqlDB, "."); err != nil {
		return fmt.Errorf("migrations: up: %w", err)
	}
	return nil
}

// Status reports the currently-applied migration versions. Useful for
// diagnostics from the migrate subcommand.
func Status(ctx context.Context, pool *pgxpool.Pool) (current int64, names []string, err error) {
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()

	goose.SetBaseFS(fsys)
	if err := goose.SetDialect("postgres"); err != nil {
		return 0, nil, fmt.Errorf("migrations: set dialect: %w", err)
	}

	current, err = goose.GetDBVersionContext(ctx, sqlDB)
	if err != nil {
		return 0, nil, fmt.Errorf("migrations: get version: %w", err)
	}

	files, err := List()
	if err != nil {
		return 0, nil, err
	}
	return current, files, nil
}

// connector exists so callers can type-assert what migrations.Apply expects
// without importing goose. Currently unused outside this package.
var _ = sql.ErrNoRows // keep database/sql import for stdlib bridging
