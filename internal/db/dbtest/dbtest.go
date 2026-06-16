// Package dbtest gives each test BINARY (i.e. each Go package's test
// process) its own isolated, freshly-migrated PostgreSQL database.
//
// Why: before this, every DB-touching package read the single
// OPENWATCH_TEST_DSN, ran migrations against that one shared database, and
// TRUNCATEd shared tables between tests. That works only when packages run
// serially — under package parallelism (`go test -p N`) two packages would
// truncate and write each other's rows mid-test. The whole suite therefore
// ran `-p 1`, serializing every DB package and dominating CI wall-clock.
//
// With dbtest, package A's tests run against `owt_<hashA>` and package B's
// against `owt_<hashB>`, so they can't see each other and `-p N` is safe.
//
// Speed: migrating ~35 migrations in every one of ~35 parallel package
// processes overwhelms Postgres. Instead dbtest migrates ONCE into a shared
// TEMPLATE database (keyed by a hash of the migration files, so it is
// rebuilt only when migrations change) and each package CLONEs it with
// `CREATE DATABASE ... TEMPLATE` — a fast file copy, no re-migration. A
// PostgreSQL advisory lock makes the one-time template build race-free
// across the parallel processes.
//
// Usage — replace a package's hand-rolled `freshPool` body:
//
//	func freshPool(t *testing.T) *pgxpool.Pool {
//		pool := dbtest.Pool(t)          // isolated, migrated, skips if no DSN
//		// ... TRUNCATE the tables this package owns, as before ...
//		return pool
//	}
//
// Pool must be called DIRECTLY from the package's own test code (so the
// runtime caller resolves to that package's directory).
package dbtest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/db/migrations"
)

// EnvDSN is the base DSN env var. It is interpreted as a connection to the
// PostgreSQL SERVER (the database in its path is only used to reach the
// server + as the per-package name prefix); dbtest creates and migrates its
// own per-package databases off it.
const EnvDSN = "OPENWATCH_TEST_DSN"

// templateLockKey is the advisory-lock key guarding the one-time template
// build. Any fixed value works as long as it is dbtest-private.
const templateLockKey int64 = 0x0_77_44_54_45_53_54 // "wDTEST"

// Resolved once per test process (one package): a test binary only ever
// contains one package, so deriving the name on the first Pool call is safe.
var (
	once    sync.Once
	pkgDSN  string
	initErr error
)

// Pool returns a pgxpool connected to this package's isolated database
// (cloned from a freshly-migrated template). It skips the test when
// OPENWATCH_TEST_DSN is unset. Each call returns a NEW pool (closed via
// t.Cleanup) against the same per-package database, matching the historical
// "new pool per freshPool call" behaviour. The database is provisioned once
// per process.
func Pool(t testing.TB) *pgxpool.Pool {
	t.Helper()
	base := os.Getenv(EnvDSN)
	if base == "" {
		t.Skipf("set %s to run DB integration tests", EnvDSN)
	}

	// Derive the per-package database name from the caller's source dir.
	_, file, _, ok := runtime.Caller(1)
	if !ok {
		t.Fatal("dbtest: cannot resolve caller for per-package DB name")
	}
	dbName := databaseName(base, filepath.Dir(file))

	once.Do(func() { pkgDSN, initErr = provision(base, dbName) })
	if initErr != nil {
		t.Fatalf("dbtest: provision %q: %v", dbName, initErr)
	}

	pool, err := pgxpool.New(context.Background(), pkgDSN)
	if err != nil {
		t.Fatalf("dbtest: connect isolated DB: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// databaseName builds a valid, stable, per-package PostgreSQL identifier:
// the base DB name (truncated) + a short hash of the package directory.
func databaseName(base, pkgDir string) string {
	sum := sha256.Sum256([]byte(pkgDir))
	short := hex.EncodeToString(sum[:])[:12]
	return basePrefix(base) + "_" + short
}

// templateName is the shared migrated template's name, keyed by a hash of
// the migration files so a migration change yields a fresh template.
func templateName(base string) string {
	return basePrefix(base) + "_tmpl_" + migrationsHash()
}

// basePrefix is a sanitized, length-bounded identifier derived from the
// base DSN's database name (e.g. "openwatch_go_test" -> "openwatch_go_test").
func basePrefix(base string) string {
	prefix := "owt"
	if u, err := url.Parse(base); err == nil {
		if b := strings.Trim(u.Path, "/"); b != "" {
			prefix = sanitizeIdent(b)
		}
	}
	if len(prefix) > 36 {
		prefix = prefix[:36]
	}
	return prefix
}

var identUnsafe = strings.NewReplacer("-", "_", ".", "_", " ", "_")

func sanitizeIdent(s string) string {
	return strings.ToLower(identUnsafe.Replace(s))
}

// migrationsHash hashes every embedded migration file (name + content) so
// the template is reused only while the schema is unchanged.
var migrationsHashOnce = sync.OnceValue(func() string {
	h := sha256.New()
	files, err := fs.Glob(migrations.FS(), "*.sql")
	if err != nil {
		return "unknown"
	}
	sort.Strings(files)
	for _, f := range files {
		b, err := fs.ReadFile(migrations.FS(), f)
		if err != nil {
			return "unknown"
		}
		h.Write([]byte(f))
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))[:10]
})

func migrationsHash() string { return migrationsHashOnce() }

// provision ensures the shared migrated template exists, then DROP+CREATEs
// this package's database as a fast clone of it.
func provision(base, dbName string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parse %s: %w", EnvDSN, err)
	}
	if !strings.HasPrefix(u.Scheme, "postgres") {
		return "", fmt.Errorf("%s must be a postgres:// URL, got scheme %q", EnvDSN, u.Scheme)
	}

	adminURL := *u
	adminURL.Path = "/postgres"
	admin, err := pgx.Connect(ctx, adminURL.String())
	if err != nil {
		return "", fmt.Errorf("connect maintenance db: %w", err)
	}
	defer func() { _ = admin.Close(ctx) }()

	tmpl := templateName(base)
	if err := ensureTemplate(ctx, admin, *u, tmpl); err != nil {
		return "", fmt.Errorf("ensure template %s: %w", tmpl, err)
	}

	// Clone the template into a clean per-package DB. WITH (FORCE) (PG13+)
	// terminates any lingering backends from a previous run.
	if _, err := admin.Exec(ctx, fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, quoteIdent(dbName))); err != nil {
		return "", fmt.Errorf("drop %s: %w", dbName, err)
	}
	if _, err := admin.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %s TEMPLATE %s`, quoteIdent(dbName), quoteIdent(tmpl))); err != nil {
		return "", fmt.Errorf("clone %s from %s: %w", dbName, tmpl, err)
	}

	pkgURL := *u
	pkgURL.Path = "/" + dbName
	return pkgURL.String(), nil
}

// ensureTemplate creates + migrates the shared template database exactly
// once across all parallel test processes, guarded by an advisory lock.
func ensureTemplate(ctx context.Context, admin *pgx.Conn, base url.URL, tmpl string) error {
	if _, err := admin.Exec(ctx, "SELECT pg_advisory_lock($1)", templateLockKey); err != nil {
		return fmt.Errorf("advisory lock: %w", err)
	}
	defer func() { _, _ = admin.Exec(ctx, "SELECT pg_advisory_unlock($1)", templateLockKey) }()

	var exists bool
	if err := admin.QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)", tmpl).Scan(&exists); err != nil {
		return fmt.Errorf("check template: %w", err)
	}
	if exists {
		return nil
	}

	if _, err := admin.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %s`, quoteIdent(tmpl))); err != nil {
		return fmt.Errorf("create template: %w", err)
	}

	tmplURL := base
	tmplURL.Path = "/" + tmpl
	mp, err := pgxpool.New(ctx, tmplURL.String())
	if err != nil {
		return fmt.Errorf("connect template: %w", err)
	}
	err = migrations.Apply(ctx, mp)
	mp.Close() // disconnect BEFORE releasing the lock so clones see 0 backends
	if err != nil {
		return fmt.Errorf("migrate template: %w", err)
	}
	return nil
}

// quoteIdent double-quotes a PostgreSQL identifier (the names here are
// hash-derived and already safe, but quoting is correct hygiene).
func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}
