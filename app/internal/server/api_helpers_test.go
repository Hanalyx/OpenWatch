// API integration test helpers: httptest.NewServer against the chi
// router with the full middleware chain. Skipped without OPENWATCH_TEST_DSN
// since idempotency + audit-events writes require Postgres.
//
// No @spec annotations here — this file holds shared fixtures only. Each
// per-spec test file declares its own @spec.

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/config"
	"github.com/Hanalyx/openwatch/internal/db"
	"github.com/Hanalyx/openwatch/internal/db/migrations"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/Hanalyx/openwatch/internal/license"
	"github.com/Hanalyx/openwatch/internal/secretkey"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Per-test fixture state. freshAPIServer seeds one user per built-in
// role, mints a real session for each, and caches the resulting cookie.
// Tests grab a request carrying a real session cookie via asRole() —
// the production identity binder threads through every layer with no
// header-based bypass.
var (
	roleCookies map[auth.RoleID]*http.Cookie
	roleUserIDs map[auth.RoleID]uuid.UUID
)

// seededRoles is the list of built-in roles for which freshAPIServer
// pre-mints a session cookie. Order is irrelevant; the cookies are
// keyed by RoleID at lookup time.
var seededRoles = []auth.RoleID{
	auth.RoleViewer,
	auth.RoleAuditor,
	auth.RoleOpsLead,
	auth.RoleSecurityAdmin,
	auth.RoleAdmin,
}

func apiTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("OPENWATCH_TEST_DSN")
	if dsn == "" {
		t.Skip("set OPENWATCH_TEST_DSN to run API integration tests")
	}
	return dsn
}

// doReq runs an http.Request against the test server and fails the test on
// transport errors. Centralizes error handling so each test can focus on
// status/body assertions instead of plumbing.
func doReq(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	return resp
}

func doGet(t *testing.T, url string) *http.Response {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return resp
}

// freshAPIServer spins up an httptest server with the production middleware
// chain (correlation + idempotency + handlers). Returns the server URL and
// the underlying pool for assertions.
func freshAPIServer(t *testing.T) (string, *pgxpool.Pool) {
	t.Helper()
	dsn := apiTestDSN(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	pool, err := db.NewPool(ctx, dsn, 5)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := migrations.Apply(ctx, pool); err != nil {
		t.Fatalf("migrations.Apply: %v", err)
	}
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE audit_events")
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE idempotency_keys")
	// Slice-A tables. Order matters: credentials FK → hosts, so clear
	// credentials first. users CASCADE clears sessions/refresh/mfa.
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE credentials")
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE hosts")
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE users CASCADE")
	// Clear custom roles only — built-in rows are seeded by migration 0006
	// and must survive between tests.
	_, _ = pool.Exec(ctx, "DELETE FROM roles WHERE is_built_in = false")

	audit.Init(audit.NewStore(pool), audit.WriterOptions{
		ChannelBuffer: 256,
		BatchSize:     50,
		FlushInterval: 20 * time.Millisecond,
	})
	t.Cleanup(func() { audit.Shutdown(2 * time.Second) })

	if err := license.Init(); err != nil {
		t.Fatalf("license.Init: %v", err)
	}
	// Guarantee a clean license slate for every server fixture. Tests that
	// install a license install on top of this baseline and Reset on cleanup.
	license.Reset()

	// Slice-A: identity needs a JWT signing key and the secret-key DEK
	// (MFA + credential encryption) loaded. Tests install ephemeral keys.
	if err := identity.SetEphemeralJWTKey(); err != nil {
		t.Fatalf("SetEphemeralJWTKey: %v", err)
	}
	if err := secretkey.SetEphemeral(); err != nil {
		t.Fatalf("secretkey.SetEphemeral: %v", err)
	}

	// Seed one user per built-in role and mint a real session for each.
	// Tests reach authenticated endpoints by attaching the cached cookie
	// via asRole(). Sessions are inserted directly via IssueSession to
	// skip the Argon2id login cost (intentional in production; wasteful
	// when the fixture runs per-test).
	roleCookies = make(map[auth.RoleID]*http.Cookie, len(seededRoles))
	roleUserIDs = make(map[auth.RoleID]uuid.UUID, len(seededRoles))
	for _, role := range seededRoles {
		uid, _ := uuid.NewV7()
		username := "fixture-" + string(role)
		_, err := pool.Exec(ctx,
			`INSERT INTO users (id, username, email, password_hash)
			 VALUES ($1, $2, $3, $4)`,
			uid, username, username+"@example.com",
			"$argon2id$v=19$m=65536,t=3,p=1$00$00",
		)
		if err != nil {
			t.Fatalf("seed user for role %s: %v", role, err)
		}
		_, err = pool.Exec(ctx,
			`INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)`,
			uid, string(role))
		if err != nil {
			t.Fatalf("assign role %s: %v", role, err)
		}
		token, _, err := identity.IssueSession(ctx, pool, uid, "127.0.0.1", "go-test-fixture")
		if err != nil {
			t.Fatalf("issue session for %s: %v", role, err)
		}
		roleCookies[role] = &http.Cookie{Name: identity.SessionCookieName, Value: token}
		roleUserIDs[role] = uid
	}

	cfg := config.Defaults()
	s := New(cfg, pool)
	// Start the in-process worker. httptest.NewServer bypasses s.Run(),
	// so the worker would never start otherwise — tests that exercise
	// the queue → worker → audit chain (release-stage-0-signoff AC-10)
	// need it running.
	workerCtx, workerCancel := context.WithCancel(context.Background())
	s.StartWorker(workerCtx)
	t.Cleanup(func() {
		workerCancel()
		s.StopWorker()
	})

	srv := httptest.NewServer(s.router)
	t.Cleanup(srv.Close)
	return srv.URL, pool
}
