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
	"strings"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/activity"
	"github.com/Hanalyx/openwatch/internal/alerts"
	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/config"
	"github.com/Hanalyx/openwatch/internal/credential"
	"github.com/Hanalyx/openwatch/internal/db/dbtest"
	"github.com/Hanalyx/openwatch/internal/exception"
	"github.com/Hanalyx/openwatch/internal/group"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/Hanalyx/openwatch/internal/intelligence/discovery"
	"github.com/Hanalyx/openwatch/internal/kensa"
	"github.com/Hanalyx/openwatch/internal/license"
	"github.com/Hanalyx/openwatch/internal/liveness"
	"github.com/Hanalyx/openwatch/internal/notification"
	"github.com/Hanalyx/openwatch/internal/scanresult"
	"github.com/Hanalyx/openwatch/internal/scheduler"
	"github.com/Hanalyx/openwatch/internal/secretkey"
	"github.com/Hanalyx/openwatch/internal/systemconfig"
	"github.com/Hanalyx/openwatch/internal/transactionlog"
	"github.com/Hanalyx/openwatch/internal/worker"
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
	// SAFETY GATE: these tests TRUNCATE the schema between cases. Refuse
	// to run against a dev / production-looking database, even if the
	// operator pointed OPENWATCH_TEST_DSN there. The DSN MUST name a
	// database whose name ends with "_test" (e.g. openwatch_go_test).
	// Override with OPENWATCH_TEST_DSN_ALLOW_NONTEST=yes at your own
	// risk; this exists for CI environments that use ephemeral DBs.
	if strings.Contains(dsn, "/openwatch_go_dev") ||
		(!strings.Contains(dsn, "_test?") && !strings.HasSuffix(dsn, "_test")) {
		if os.Getenv("OPENWATCH_TEST_DSN_ALLOW_NONTEST") != "yes" {
			t.Fatalf(
				"OPENWATCH_TEST_DSN points at a non-test database (%s) — "+
					"these tests TRUNCATE tables and would destroy real data. "+
					"Use a database whose name ends with _test, or set "+
					"OPENWATCH_TEST_DSN_ALLOW_NONTEST=yes if you know what you're doing.",
				redactDSN(dsn),
			)
		}
	}
	return dsn
}

// redactDSN strips the password from a postgres DSN for safe logging.
func redactDSN(dsn string) string {
	// Replace any "user:password@" with "user:***@".
	if i := strings.Index(dsn, "@"); i > 0 {
		if j := strings.LastIndex(dsn[:i], ":"); j > 0 {
			return dsn[:j+1] + "***" + dsn[i:]
		}
	}
	return dsn
}

// doReq runs an http.Request against the test server and fails the test on
// transport errors. Centralizes error handling so each test can focus on
// status/body assertions instead of plumbing.
func doReq(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	attachBrowserCSRF(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	return resp
}

// attachBrowserCSRF simulates a real browser's double-submit on a
// cookie-authenticated unsafe request: when the request carries the session
// cookie, uses an unsafe method, and has not already set X-CSRF-Token, it
// adds a matching XSRF-TOKEN cookie + X-CSRF-Token header. This keeps the
// whole suite green under csrfProtect without editing every call site. Tests
// that assert the CSRF deny path bypass doReq and call the client directly.
func attachBrowserCSRF(req *http.Request) {
	if isSafeMethod(req.Method) || req.Header.Get(csrfHeaderName) != "" {
		return
	}
	for _, c := range req.Cookies() {
		if c.Name == identity.SessionCookieName {
			const tok = "test-csrf-token"
			req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: tok})
			req.Header.Set(csrfHeaderName, tok)
			return
		}
	}
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
	// Safety gate: refuse a non-test DSN before we create or touch any DB.
	// dbtest.Pool gives this package its own isolated, migrated database
	// (so -p N parallel packages never share tables), but the gate still
	// guards against pointing OPENWATCH_TEST_DSN at a dev/prod server.
	_ = apiTestDSN(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	pool := dbtest.Pool(t)
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE audit_events")
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE idempotency_keys")
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE system_config")
	// Slice-B tables. Clear children before hosts to avoid FK violations.
	// transactions + host_rule_state FK to hosts ON DELETE RESTRICT;
	// host_compliance_schedule + host_backoff_state FK to hosts;
	// host_liveness FK CASCADE so it's safe at any order but explicit
	// is clearer.
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE transactions")
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE host_rule_state")
	// job_queue has no FK to hosts, so the hosts CASCADE below never
	// clears it — leftover scan jobs from earlier fixtures broke the
	// api-host-scan job-count assertions (caught by the DSN-gated CI
	// run; scan_runs IS cascaded via its hosts FK).
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE posture_snapshots")
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE compliance_exceptions")
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE job_queue")
	// SSO config + federation links (cascades to identities + auth states).
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE sso_providers CASCADE")
	// TRUNCATE…CASCADE delegates child cleanup to the schema — the
	// hosts row has 11 FK-referencing children and a hand-rolled
	// list rots every time a new FK is added. CASCADE bypasses
	// per-row ON DELETE RESTRICT. users CASCADE clears sessions /
	// refresh / mfa.
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE hosts CASCADE")
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE users CASCADE")
	// Clear custom roles only — built-in rows are seeded by migration 0006
	// and must survive between tests.
	_, _ = pool.Exec(ctx, "DELETE FROM roles WHERE is_built_in = false")
	// Re-seed the singleton auth_policy row to its defaults. The TRUNCATE
	// users CASCADE above cascades to auth_policy (its updated_by FKs
	// users), so the migration-seeded row is gone; INSERT…ON CONFLICT both
	// restores it and resets a prior test's PUT. Runs before New() primes
	// the identity windows below.
	_, _ = pool.Exec(ctx, `INSERT INTO auth_policy (id) VALUES (true)
		ON CONFLICT (id) DO UPDATE
		SET require_mfa = false, session_idle_timeout_seconds = 900,
		    session_absolute_timeout_seconds = 43200, updated_by = NULL`)

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

	// Wire the connectivity-monitor surface so the new /system/connectivity/*
	// + /fleet/connectivity/breakdown + /hosts/{id}/connectivity:check
	// endpoints have a backing store and live liveness Service. The
	// liveness service is constructed but not started (tests don't need
	// the periodic loop; they exercise endpoints directly).
	cfgStore := systemconfig.NewStore(pool, audit.Emit)
	liveSvc := liveness.NewService(pool, audit.Emit, nil).
		WithConfigLoader(cfgStore.LoadConnectivity)
	s.WithConnectivityConfig(cfgStore, liveSvc)

	// Spec system-host-discovery: wire a Discovery service so
	// /hosts/{id}/discovery:run reaches a real handler in tests. The
	// service has no SSH transport wired here — tests that exercise the
	// full Discover path inject one via the service interface; the
	// not-found path (AC-10) and RBAC denial path (AC-09) reach the
	// authz / lookup gate before SSH would matter.
	discoSvc := discovery.NewService(pool, audit.Emit, nil).
		WithHostLookup(discovery.PoolHostLookup{Pool: pool}).
		WithCredentialService(credential.NewService(pool))
	s.WithDiscovery(discoSvc)

	// Spec system-alerts + api-alerts: wire the lifecycle service.
	s.WithAlerts(alerts.NewService(pool, audit.Emit))

	// Spec system-activity + api-activity: wire the unified feed.
	s.WithActivity(activity.NewService(pool))

	// Spec api-host-scan: scan-job HMAC key from the ephemeral DEK —
	// the same derivation production uses, so enqueued payloads verify.
	dekKey, err := secretkey.Active()
	if err != nil {
		t.Fatalf("secretkey.Active: %v", err)
	}
	scanKey, err := scheduler.DeriveQueueKey(dekKey.Material())
	if err != nil {
		t.Fatalf("DeriveQueueKey: %v", err)
	}
	s.WithScanQueue(scanKey)
	s.WithExceptions(exception.NewService(pool, audit.Emit))
	// Spec api-groups: wire the host-group service so /api/v1/groups and
	// its sub-routes reach a real handler instead of the 503 not-wired
	// guard.
	s.WithGroups(group.NewService(pool))
	// Spec api-scans: wire the durable per-scan results reader so
	// /api/v1/scans and its sub-routes reach a real handler.
	s.WithScanResults(scanresult.NewReader(pool))
	// Spec api-notifications: wire the notification-channel service so
	// /api/v1/notifications/channels reaches a real handler.
	s.WithNotifications(notification.NewService(pool))
	// Variable catalog fixture: two corpus-style variables (one a
	// configure-me placeholder) so the scan-variables endpoints are
	// testable without the on-disk kensa corpus.
	s.WithVariableCatalog(kensa.NewVariableCatalogFromInfos([]kensa.VariableInfo{
		{Name: "banner_text", Default: "Authorized use only", Rules: []string{"r-banner"}, ConfigureMe: true},
		{Name: "ssh_max_auth_tries", Default: "4", Rules: []string{"r-ssh-auth", "r-ssh-tries"}},
	}))
	// Spec api-rules: wire a small fixture rule library so /api/v1/rules
	// reaches a real handler without the on-disk corpus.
	s.WithRuleLibrary(kensa.NewRuleLibraryFromItems([]kensa.RuleListItem{
		{
			ID: "sshd-root-login-disabled", Title: "Disable SSH root login",
			Description: "Root login over SSH must be disabled.", Severity: "high", Category: "network",
			Tags:          []string{"ssh"},
			FrameworkRefs: map[string][]string{"cis_rhel9": {"5.2.8"}, "nist_800_53": {"AC-6"}},
			Transactional: true,
			Remediation: kensa.RemediationSummary{
				Available: true, Mechanisms: []string{"config_set_dropin"}, RebootBehavior: "none",
			},
		},
		{
			ID: "manual-only-rule", Title: "A manual rule",
			Description: "Needs manual remediation.", Severity: "medium", Category: "audit",
			Tags:          []string{},
			FrameworkRefs: map[string][]string{"nist_800_53": {"AU-2"}},
			Transactional: false,
			Remediation:   kensa.RemediationSummary{Available: false, Mechanisms: []string{}, RebootBehavior: "none"},
		},
	}))

	// Register a ScanWorker on the in-process worker so claimed scan
	// jobs are processed (HMAC verify + scan_runs lifecycle) instead of
	// dead-ending on the nil-processor branch. No live Kensa binding:
	// the executor keeps its test fallback, so runs terminate FAILED —
	// exactly what api-host-scan AC-02 asserts.
	s.WithScanWorker(worker.NewScanWorker(worker.Config{
		Pool:     pool,
		Executor: kensa.NewExecutor(worker.NewCredentialBridge(credential.NewService(pool)), audit.Emit),
		Writer:   transactionlog.NewWriter(pool, audit.Emit),
		QueueKey: scanKey,
		Emit:     audit.Emit,
	}))

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
