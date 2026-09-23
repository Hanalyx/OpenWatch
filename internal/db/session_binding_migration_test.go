// @spec system-auth-identity
//
// Migration 0065 introduces session-bound access tokens. Credentials
// minted before it carry no binding, so nothing can decide whether their
// session is alive. It signs everyone out rather than leave the
// guarantee silently false for up to seven days.
package db_test

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/db/dbtest"
	"github.com/Hanalyx/openwatch/internal/db/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"
)

// migrationVersionBefore is the version immediately preceding the one
// under test. Seeding happens at this version, so the rows written are
// genuinely pre-migration rather than inserted after the fact.
const (
	migrationVersionBefore = 64
	migrationVersionUnder  = 65
)

// freshDBAt creates a brand-new database, migrates it to `version`, and
// returns a pool on it. It never touches the shared template database.
func freshDBAt(t *testing.T, version int64) (*pgxpool.Pool, *sql.DB) {
	t.Helper()
	admin := dbtest.DSN(t)
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	name := "ow_mig65_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]

	ctx := context.Background()
	adminPool, err := pgxpool.New(ctx, admin)
	if err != nil {
		t.Fatalf("admin pool: %v", err)
	}
	defer adminPool.Close()
	if _, err := adminPool.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %q`, name)); err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		p, err := pgxpool.New(context.Background(), admin)
		if err != nil {
			return
		}
		defer p.Close()
		_, _ = p.Exec(context.Background(), fmt.Sprintf(`DROP DATABASE IF EXISTS %q WITH (FORCE)`, name))
	})

	u.Path = "/" + name
	pool, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatalf("target pool: %v", err)
	}
	t.Cleanup(pool.Close)

	sqlDB, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatalf("sql open: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	goose.SetBaseFS(migrations.FS())
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("dialect: %v", err)
	}
	if err := goose.UpToContext(ctx, sqlDB, ".", version); err != nil {
		t.Fatalf("migrate to %d: %v", version, err)
	}
	return pool, sqlDB
}

// @ac AC-45
// AC-45: the migration revokes every live interactive credential and
// leaves service-account tokens alone.
func TestMigration0065_SignsEveryoneOut(t *testing.T) {
	t.Run("system-auth-identity/AC-45", func(t *testing.T) {
		ctx := context.Background()
		pool, sqlDB := freshDBAt(t, migrationVersionBefore)

		// Seed at the PRIOR version, so these rows genuinely predate the
		// migration rather than being inserted after it ran.
		uid := uuid.New()
		if _, err := pool.Exec(ctx,
			`INSERT INTO users (id, username, email, password_hash) VALUES ($1,$2,$3,'x')`,
			uid, "mig65-user", "mig65@example.test"); err != nil {
			t.Fatalf("seed user: %v", err)
		}
		sessID := uuid.New()
		now := time.Now().UTC()
		if _, err := pool.Exec(ctx, `
			INSERT INTO sessions (id, user_id, token_hash, created_at, last_seen,
			                      expires_at, absolute_expires_at)
			VALUES ($1,$2,$3,$4,$4,$5,$6)`,
			sessID, uid, []byte("mig65-session-hash"), now,
			now.Add(time.Hour), now.Add(12*time.Hour)); err != nil {
			t.Fatalf("seed session: %v", err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at)
			VALUES ($1,$2,$3,$4)`,
			uuid.New(), uid, []byte("mig65-refresh-hash"), now.Add(7*24*time.Hour)); err != nil {
			t.Fatalf("seed refresh: %v", err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO api_tokens (name, token_hash, prefix, role_id, created_by)
			VALUES ('mig65', $1, 'owk_mig65', 'viewer', $2)`,
			[]byte("mig65-api-token-hash"), uid); err != nil {
			t.Fatalf("seed api token: %v", err)
		}

		count := func(q string) int {
			var n int
			if err := pool.QueryRow(ctx, q, uid).Scan(&n); err != nil {
				t.Fatalf("count: %v", err)
			}
			return n
		}
		const (
			liveSessions = `SELECT count(*) FROM sessions WHERE user_id=$1 AND revoked_at IS NULL`
			liveRefresh  = `SELECT count(*) FROM refresh_tokens WHERE user_id=$1 AND revoked_at IS NULL`
			liveTokens   = `SELECT count(*) FROM api_tokens WHERE created_by=$1 AND revoked_at IS NULL`
		)
		if count(liveSessions) != 1 || count(liveRefresh) != 1 || count(liveTokens) != 1 {
			t.Fatalf("precondition: want one live row of each kind before the migration")
		}

		// Apply the migration under test.
		if err := goose.UpToContext(ctx, sqlDB, ".", migrationVersionUnder); err != nil {
			t.Fatalf("apply migration %d: %v", migrationVersionUnder, err)
		}

		if n := count(liveSessions); n != 0 {
			t.Errorf("live sessions after the migration = %d, want 0", n)
		}
		if n := count(liveRefresh); n != 0 {
			t.Errorf("live refresh tokens after the migration = %d, want 0", n)
		}
		if n := count(liveTokens); n != 1 {
			t.Errorf("live service-account tokens = %d, want 1: the migration must not touch api_tokens", n)
		}

		// And the binding column now exists, so new credentials can carry one.
		var hasColumn bool
		if err := pool.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM information_schema.columns
			               WHERE table_name='refresh_tokens' AND column_name='session_id')`).
			Scan(&hasColumn); err != nil {
			t.Fatalf("check column: %v", err)
		}
		if !hasColumn {
			t.Error("refresh_tokens.session_id was not added")
		}
	})
}
