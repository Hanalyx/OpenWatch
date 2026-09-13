package db

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// Queryer is the read subset of pgx satisfied by both *pgxpool.Pool and
// pgx.Tx.
//
// It lives here rather than in each caller because Go matches interface
// METHODS by exact parameter type. Two packages declaring structurally
// identical interfaces do not satisfy each other's method signatures, so a
// service that resolves data for another package's transaction has to name
// one shared type.
//
// The reason a caller needs this at all: content that will be SIGNED must be
// read from one snapshot. A helper that quietly used the pool would put part
// of a signed artifact on a different snapshot from the rest, and nothing in
// the artifact would record that it happened.
type Queryer interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}
