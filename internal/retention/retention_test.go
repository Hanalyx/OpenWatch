// @spec system-retention-sweeper
//
// AC traceability (this file):
//   AC-01  TestRegistryEntriesAreWellFormed
//   AC-01  TestSweptTTLColumnsAreNotNull
//   AC-02  TestRegistryCoversEveryMigratedTable
//   AC-03  TestSweptEntriesAreExactlyTheThree
//   AC-04  TestNeverTablesSurviveASweep
//   AC-05  TestDeferredTablesSurviveASweep
//   AC-06  TestSweepDeletesPastGraceOnly
//   AC-07  TestSweepIsBatchedAndOldestFirst
//   AC-08  TestTickDeadlineIsShorterThanInterval
//   AC-08  TestCanceledSweepLeavesRowsInPlace
//   AC-09  TestKeepPredicateIsHonored
//   AC-10  TestSweeperIsReachableFromMain
//   AC-11  TestNoSecondSweeperInTheTree
//   AC-12  TestOrphanedPurgeFunctionsAreResolved
//   AC-13  TestOTPReplayWindowComesFromTheRegistry
//   AC-14  TestSweepLogsPerTableAndEmitsNoAudit
//   AC-15  TestOneBadTableDoesNotEndThePass
//   AC-16  TestUndecidedTablesArePinnedAndUntouched
//
// Four of these are structural rather than behavioral, and that is the
// point of the spec. A unit test of a purge function that production
// never calls is exactly the state this package replaces: the tree held
// two exported purge functions with zero callers for months. AC-02,
// AC-10 and AC-11 are the ones that make a repeat of that fail CI.

package retention

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/correlation"
	"github.com/Hanalyx/openwatch/internal/db/dbtest"
	"github.com/Hanalyx/openwatch/internal/identity"
)

// ---------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------

// repoRoot is the tree root, two levels above internal/retention.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// goSourceFiles returns every non-test .go file in the tree, as paths
// relative to the root. Vendor, node_modules and the frontend are
// skipped because none of them holds Go the server builds.
func goSourceFiles(t *testing.T, root string) []string {
	t.Helper()
	skip := map[string]bool{".git": true, "vendor": true, "node_modules": true, "frontend": true}
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skip[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	sort.Strings(out)
	if len(out) < 100 {
		t.Fatalf("found only %d Go source files under %s, the walk is broken and every scan below would pass vacuously", len(out), root)
	}
	return out
}

// ---------------------------------------------------------------------
// Migration parsing (AC-02)
// ---------------------------------------------------------------------

var (
	createTableRe = regexp.MustCompile(`(?im)^\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"?([A-Za-z_][A-Za-z0-9_]*)"?`)
	dropTableRe   = regexp.MustCompile(`(?im)^\s*DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?"?([A-Za-z_][A-Za-z0-9_]*)"?`)
	renameTableRe = regexp.MustCompile(`(?im)^\s*ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?"?([A-Za-z_][A-Za-z0-9_]*)"?\s+RENAME\s+TO\s+"?([A-Za-z_][A-Za-z0-9_]*)"?`)
)

// migratedTables returns the tables the migrations leave behind, mapped
// to the file that created each one.
//
// Only the Up section of each file is read. The Down sections are full of
// DROP TABLE statements for tables that very much exist, so parsing a
// whole file would report an empty schema.
//
// The parse follows renames and drops inside Up sections too, because a
// table created in one migration and renamed in a later one must be
// demanded under its final name and not its first one.
//
// No part of this reads a column name. That is deliberate: an earlier
// survey of this schema keyed on expires_at, missed auth_mfa_otp_uses
// (which keys on used_at), and reported the schema as covered.
func migratedTables(t *testing.T) map[string]string {
	t.Helper()
	dir := filepath.Join(repoRoot(t), "internal", "db", "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	if len(files) == 0 {
		t.Fatal("no .sql migrations found, the AC-02 guard would pass vacuously")
	}

	live := map[string]string{}
	for _, name := range files {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		src := string(b)

		// Both markers must be present. A migration written in some other
		// format would otherwise have its tables silently skipped, which
		// is the same silence this spec exists to remove.
		up := strings.Index(src, "-- +goose Up")
		down := strings.Index(src, "-- +goose Down")
		if up < 0 || down < 0 {
			t.Fatalf("%s has no goose Up/Down markers, so this guard cannot tell schema from rollback", name)
		}
		if down < up {
			t.Fatalf("%s has its Down marker before its Up marker", name)
		}
		section := src[up:down]

		for _, m := range createTableRe.FindAllStringSubmatch(section, -1) {
			live[m[1]] = name
		}
		for _, m := range renameTableRe.FindAllStringSubmatch(section, -1) {
			delete(live, m[1])
			live[m[2]] = name
		}
		for _, m := range dropTableRe.FindAllStringSubmatch(section, -1) {
			delete(live, m[1])
		}
	}

	// Floor check. If the regex above ever stops matching, every
	// "table has no entry" assertion below would pass on an empty set.
	if len(live) < 40 {
		t.Fatalf("parsed only %d tables out of %d migrations, the CREATE TABLE parser is broken", len(live), len(files))
	}
	return live
}

// ---------------------------------------------------------------------
// Database helpers
// ---------------------------------------------------------------------

// sweptAndSeedableTables are every table these tests write to. Truncated
// before each database test so one test cannot see another's rows.
var sweptAndSeedableTables = []string{
	"idempotency_keys",
	"sso_auth_states",
	"auth_mfa_otp_uses",
	"api_tokens",
	"compliance_exceptions",
	"sessions",
	"refresh_tokens",
	"auth_mfa_secrets",
	"sso_providers",
	"hosts",
	"users",
}

// freshPool returns this package's isolated database with the tables
// these tests own emptied.
func freshPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := dbtest.Pool(t)
	_, err := pool.Exec(context.Background(),
		"TRUNCATE "+strings.Join(sweptAndSeedableTables, ", ")+" RESTART IDENTITY CASCADE")
	if err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return pool
}

func seedUser(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	id := uuid.New()
	name := "ret-" + id.String()[:8]
	_, err := pool.Exec(context.Background(),
		`INSERT INTO users (id, username, email, password_hash)
		 VALUES ($1, $2, $3, 'x')`,
		id, name, name+"@example.test")
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

func seedHost(t *testing.T, pool *pgxpool.Pool, owner uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO hosts (id, hostname, ip_address, created_by)
		 VALUES ($1, $2, '192.0.2.10', $3)`,
		id, "ret-"+id.String()[:8]+".example.test", owner)
	if err != nil {
		t.Fatalf("seed host: %v", err)
	}
	return id
}

func seedSSOProvider(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO sso_providers (id, name, issuer, client_id, client_secret_enc)
		 VALUES ($1, $2, 'https://idp.example.test', 'cid', '\x00'::bytea)`,
		id, "ret-"+id.String()[:8])
	if err != nil {
		t.Fatalf("seed sso provider: %v", err)
	}
	return id
}

// fixtures holds the rows other rows point at.
type fixtures struct {
	user     uuid.UUID
	host     uuid.UUID
	provider uuid.UUID
}

func seedFixtures(t *testing.T, pool *pgxpool.Pool) fixtures {
	t.Helper()
	u := seedUser(t, pool)
	return fixtures{user: u, host: seedHost(t, pool, u), provider: seedSSOProvider(t, pool)}
}

// seedRow inserts one row into the policy's table with its TTL column set
// to ts, and returns the row's identity as a WHERE clause plus argument.
//
// The TTL column name comes from the policy, never from a literal in this
// test. That is what exercises auth_mfa_otp_uses on used_at without any
// test here having to know that it has no expires_at.
func seedRow(t *testing.T, pool *pgxpool.Pool, fx fixtures, p Policy, ts time.Time) (idWhere string, idArg any) {
	t.Helper()
	if p.TTLColumn == "" {
		t.Fatalf("policy for %s has no TTL column, cannot seed an aged row", p.Table)
	}

	var cols []string
	var vals []any
	switch p.Table {
	case "idempotency_keys":
		key := uuid.NewString()
		cols = []string{"key", "request_hash", "response_status", "response_body", "actor_id"}
		vals = []any{key, "h", 200, []byte(`{}`), "actor"}
		idWhere, idArg = "key = $1", key
	case "sso_auth_states":
		state := uuid.NewString()
		cols = []string{"state", "provider_id", "nonce", "code_verifier"}
		vals = []any{state, fx.provider, "n", "v"}
		idWhere, idArg = "state = $1", state
	case "auth_mfa_otp_uses":
		code := uuid.NewString()[:6]
		cols = []string{"user_id", "otp"}
		vals = []any{fx.user, code}
		idWhere, idArg = "otp = $1", code
	case "api_tokens":
		id := uuid.New()
		cols = []string{"id", "name", "token_hash", "prefix", "role_id", "created_by"}
		vals = []any{id, "t-" + id.String()[:8], []byte(id.String()), id.String()[:8], "admin", fx.user}
		idWhere, idArg = "id = $1", id
	case "compliance_exceptions":
		id := uuid.New()
		cols = []string{"id", "host_id", "rule_id", "reason", "requested_by"}
		vals = []any{id, fx.host, "rule-1", "because", fx.user}
		idWhere, idArg = "id = $1", id
	case "sessions":
		id := uuid.New()
		// Both timestamps are NOT NULL and either one could be the TTL
		// column, so both are seeded. Seeding only the column the policy
		// happens to name would turn a wrong-column entry into a seed
		// error instead of the assertion failure it should be.
		cols = []string{"id", "user_id", "token_hash", "expires_at", "absolute_expires_at"}
		vals = []any{id, fx.user, []byte(id.String()), ts, ts}
		idWhere, idArg = "id = $1", id
	case "refresh_tokens":
		id := uuid.New()
		cols = []string{"id", "user_id", "token_hash"}
		vals = []any{id, fx.user, []byte(id.String())}
		idWhere, idArg = "id = $1", id
	default:
		t.Fatalf("no seed recipe for table %s, add one rather than skipping the table", p.Table)
	}

	// The TTL column may already be in the recipe, because some tables
	// have a NOT NULL timestamp that is not the column the policy keys
	// on. Overwrite rather than append: listing a column twice is a SQL
	// error, and that error would fire before any assertion an entry
	// naming the wrong column was supposed to trip.
	ttlSeeded := false
	for i, c := range cols {
		if c == p.TTLColumn {
			vals[i] = ts
			ttlSeeded = true
			break
		}
	}
	if !ttlSeeded {
		cols = append(cols, p.TTLColumn)
		vals = append(vals, ts)
	}

	placeholders := make([]string, len(cols))
	for i := range cols {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
	}
	stmt := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		p.Table, strings.Join(cols, ", "), strings.Join(placeholders, ", "))
	if _, err := pool.Exec(context.Background(), stmt, vals...); err != nil {
		t.Fatalf("seed %s: %v", p.Table, err)
	}
	return idWhere, idArg
}

func rowExists(t *testing.T, pool *pgxpool.Pool, table, where string, arg any) bool {
	t.Helper()
	var n int
	err := pool.QueryRow(context.Background(),
		fmt.Sprintf("SELECT count(*) FROM %s WHERE %s", table, where), arg).Scan(&n)
	if err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n > 0
}

func countRows(t *testing.T, pool *pgxpool.Pool, table string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM "+table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// swept returns the swept policies from the real registry.
func swept() []Policy {
	var out []Policy
	for _, p := range Registry() {
		if p.State == StateSwept {
			out = append(out, p)
		}
	}
	return out
}

// ---------------------------------------------------------------------
// Statement counting (AC-07)
// ---------------------------------------------------------------------

// stmtCounter is a pgx QueryTracer that counts executions per SQL text.
// AC-07 asks how many statements one pass issued, and inferring that from
// a row count would only prove the drain, not the batching.
type stmtCounter struct {
	mu sync.Mutex
	n  map[string]int
}

func (c *stmtCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n == nil {
		c.n = map[string]int{}
	}
	c.n[data.SQL]++
	return ctx
}

func (c *stmtCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (c *stmtCounter) count(sql string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n[sql]
}

// tracedPool opens a second pool against the same database as base, with
// a tracer attached.
func tracedPool(t *testing.T, base *pgxpool.Pool) (*pgxpool.Pool, *stmtCounter) {
	t.Helper()
	counter := &stmtCounter{}
	cfg := base.Config().Copy()
	cfg.ConnConfig.Tracer = counter
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("traced pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool, counter
}

// failIfCalled is the audit emit function the sweeper must never call.
func failIfCalled(t *testing.T) EmitFunc {
	return func(_ context.Context, code audit.Code, _ audit.Event) {
		t.Errorf("the sweeper emitted audit event %q. Retention must not audit its own deletes: audit_events is itself a growing table with no retention decision, so a per-tick event trades one unbounded table for another (spec C-12)", code)
	}
}

// ---------------------------------------------------------------------
// AC-01: registry entries are well formed
// ---------------------------------------------------------------------

// @ac AC-01
// AC-01: every entry has a table, a reason, and a legal state. Swept and
// deferred entries carry a TTL column and a positive grace; never entries
// carry neither. No table appears twice.
//
// The reason is not decoration. An entry with no reason is a decision
// nobody can audit, which is how api_tokens and compliance_exceptions
// would eventually get "fixed" by a reader who assumed the omission was
// an oversight.
func TestRegistryEntriesAreWellFormed(t *testing.T) {
	t.Run("system-retention-sweeper/AC-01", func(t *testing.T) {
		reg := Registry()
		if len(reg) == 0 {
			t.Fatal("the registry is empty")
		}

		seen := map[string]int{}
		for _, p := range reg {
			seen[p.Table]++
			if p.Table == "" {
				t.Error("an entry has an empty Table")
				continue
			}
			if strings.TrimSpace(p.Reason) == "" {
				t.Errorf("%s has an empty Reason. Every entry needs one, including swept ones", p.Table)
			}
			switch p.State {
			case StateSwept, StateDeferred:
				if p.TTLColumn == "" {
					t.Errorf("%s is %s but has no TTLColumn", p.Table, p.State)
				}
				if p.Grace <= 0 {
					t.Errorf("%s is %s but its Grace is %v, which must be greater than zero", p.Table, p.State, p.Grace)
				}
			case StateNever, StateUndecided:
				if p.TTLColumn != "" {
					t.Errorf("%s is %s but carries TTLColumn %q. Neither state ages anything", p.Table, p.State, p.TTLColumn)
				}
				if p.Grace != 0 {
					t.Errorf("%s is %s but carries Grace %v. Recording a grace nothing applies would make an unused field read as intent", p.Table, p.State, p.Grace)
				}
			default:
				t.Errorf("%s has state %q, which is not swept, never, deferred or undecided", p.Table, p.State)
			}
		}

		for table, n := range seen {
			if n > 1 {
				t.Errorf("%s appears %d times in the registry. One table, one decision", table, n)
			}
		}
	})
}

// @ac AC-01
// AC-01, schema half: every swept or deferred entry names a TTL column
// the migrations declare NOT NULL.
//
// This reads the schema rather than the registry, so a well-formed entry
// naming a nullable column still fails. The delete compares that column
// against a past bound, and a NULL satisfies no comparison, so a nullable
// TTL column would make a table read as swept while every row whose
// column is NULL stayed forever. All five entries naming a column are
// fine today. The point is that the sixth is caught by CI.
func TestSweptTTLColumnsAreNotNull(t *testing.T) {
	t.Run("system-retention-sweeper/AC-01", func(t *testing.T) {
		pool := dbtest.Pool(t)

		checked := 0
		for _, p := range Registry() {
			if p.State != StateSwept && p.State != StateDeferred {
				continue
			}
			if p.TTLColumn == "" {
				continue // Already reported by the well-formed half.
			}
			var nullable string
			err := pool.QueryRow(context.Background(),
				`SELECT is_nullable FROM information_schema.columns
				 WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2`,
				p.Table, p.TTLColumn).Scan(&nullable)
			if err != nil {
				t.Errorf("%s.%s: cannot read the column from the migrated schema: %v. Either the column does not exist or the entry names it wrong", p.Table, p.TTLColumn, err)
				continue
			}
			if nullable != "NO" {
				t.Errorf("%s is %s on %s, but the migrations declare that column nullable. A NULL satisfies no comparison, so every row with a NULL there would survive the sweep forever while the table reads as covered", p.Table, p.State, p.TTLColumn)
			}
			checked++
		}
		if checked == 0 {
			t.Fatal("no swept or deferred entry named a TTL column, so this guard checked nothing")
		}
	})
}

// ---------------------------------------------------------------------
// AC-02: the registry covers the schema, both directions
// ---------------------------------------------------------------------

// @ac AC-02
// AC-02: every table the migrations create has exactly one entry, and
// every entry names a table the migrations create.
//
// This is the guard that makes a forgotten table fail CI instead of
// growing forever in silence. It enumerates tables and demands an
// explicit decision for each. It never reads a column name, because the
// survey that keyed on expires_at is the one that missed
// auth_mfa_otp_uses.
//
// goose_db_version is goose's own bookkeeping table. No migration file
// declares it, so it is correctly absent from both sides here, and adding
// an entry for it would fail the second direction.
func TestRegistryCoversEveryMigratedTable(t *testing.T) {
	t.Run("system-retention-sweeper/AC-02", func(t *testing.T) {
		tables := migratedTables(t)

		entries := map[string]int{}
		for _, p := range Registry() {
			entries[p.Table]++
		}

		var missing []string
		for table := range tables {
			if entries[table] == 0 {
				missing = append(missing, fmt.Sprintf("%s (created in %s)", table, tables[table]))
			}
		}
		sort.Strings(missing)
		for _, m := range missing {
			t.Errorf("table %s has no retention entry. Add one to internal/retention/policy.go saying swept, never or deferred, with a reason. Silence is not a decision", m)
		}

		var unknown []string
		for table := range entries {
			if _, ok := tables[table]; !ok {
				unknown = append(unknown, table)
			}
		}
		sort.Strings(unknown)
		for _, u := range unknown {
			t.Errorf("registry entry %q names a table no migration creates. Either the table was renamed or dropped and the entry is stale, or the name is a typo", u)
		}

		if len(missing) == 0 && len(unknown) == 0 && len(Registry()) != len(tables) {
			t.Errorf("registry has %d entries for %d tables with no name mismatch, so a table is entered twice", len(Registry()), len(tables))
		}
	})
}

// ---------------------------------------------------------------------
// AC-03: the three swept entries, field by field
// ---------------------------------------------------------------------

// @ac AC-03
// AC-03: the swept set is exactly idempotency_keys (expires_at, 24h),
// sso_auth_states (expires_at, 1h) and auth_mfa_otp_uses (used_at, 24h).
//
// Asserted field by field so a silent edit of a grace or a TTL column
// fails here rather than in production. The auth_mfa_otp_uses row pins
// used_at on purpose: that table has no expires_at, and assuming it did
// is the mistake this spec was written around.
func TestSweptEntriesAreExactlyTheThree(t *testing.T) {
	t.Run("system-retention-sweeper/AC-03", func(t *testing.T) {
		want := map[string]Policy{
			"idempotency_keys":  {Table: "idempotency_keys", TTLColumn: "expires_at", Grace: 24 * time.Hour},
			"sso_auth_states":   {Table: "sso_auth_states", TTLColumn: "expires_at", Grace: time.Hour},
			"auth_mfa_otp_uses": {Table: "auth_mfa_otp_uses", TTLColumn: "used_at", Grace: 24 * time.Hour},
		}

		got := map[string]Policy{}
		for _, p := range swept() {
			got[p.Table] = p
		}

		for table, w := range want {
			g, ok := got[table]
			if !ok {
				t.Errorf("%s is not swept. C-07 fixes the swept set at these three tables", table)
				continue
			}
			if g.TTLColumn != w.TTLColumn {
				t.Errorf("%s TTLColumn = %q, want %q", table, g.TTLColumn, w.TTLColumn)
			}
			if g.Grace != w.Grace {
				t.Errorf("%s Grace = %v, want %v", table, g.Grace, w.Grace)
			}
		}
		for table := range got {
			if _, ok := want[table]; !ok {
				t.Errorf("%s is swept but is not one of the three tables C-07 allows. A new swept table needs a spec bump, not just an edit", table)
			}
		}
	})
}

// ---------------------------------------------------------------------
// AC-04 and AC-05: never and deferred tables survive
// ---------------------------------------------------------------------

// @ac AC-04
// AC-04: api_tokens and compliance_exceptions are never, and a sweep
// leaves an ancient row in each of them alone.
func TestNeverTablesSurviveASweep(t *testing.T) {
	t.Run("system-retention-sweeper/AC-04", func(t *testing.T) {
		pool := freshPool(t)
		fx := seedFixtures(t, pool)
		ancient := time.Now().Add(-365 * 24 * time.Hour)

		type seeded struct {
			table string
			where string
			arg   any
		}
		var rows []seeded
		for _, table := range []string{"api_tokens", "compliance_exceptions"} {
			p, ok := Lookup(table)
			if !ok {
				t.Fatalf("%s has no registry entry", table)
			}
			if p.State != StateNever {
				t.Errorf("%s state = %q, want never", table, p.State)
			}
			if strings.TrimSpace(p.Reason) == "" {
				t.Errorf("%s is never with no reason. The reason is what stops a later reader from sweeping it", table)
			}
			// Seed on expires_at directly: a never entry carries no TTL
			// column, so the aged row is built from the schema instead.
			seedPolicy := p
			seedPolicy.TTLColumn = "expires_at"
			where, arg := seedRow(t, pool, fx, seedPolicy, ancient)
			rows = append(rows, seeded{table, where, arg})
		}

		// Reported, not fatal. A sweep that errors part way through can
		// still have deleted from a table it had no business touching,
		// and that is the assertion this test exists for.
		if err := NewSweeper(pool, failIfCalled(t)).Sweep(context.Background()); err != nil {
			t.Errorf("sweep: %v", err)
		}

		for _, r := range rows {
			if !rowExists(t, pool, r.table, r.where, r.arg) {
				t.Errorf("a %s row expired a year ago was deleted by the sweep. That table is recorded never on purpose", r.table)
			}
		}
	})
}

// @ac AC-05
// AC-05: sessions and refresh_tokens are deferred, each says what work it
// is blocked on, and a sweep leaves an aged row in each alone.
//
// Deferred is a state the registry expresses, not silence. Neither may be
// promoted without its migration, and deleting live session history is
// not reversible.
func TestDeferredTablesSurviveASweep(t *testing.T) {
	t.Run("system-retention-sweeper/AC-05", func(t *testing.T) {
		pool := freshPool(t)
		fx := seedFixtures(t, pool)
		ancient := time.Now().Add(-365 * 24 * time.Hour)

		type seeded struct {
			table string
			where string
			arg   any
		}
		var rows []seeded
		for _, table := range []string{"sessions", "refresh_tokens"} {
			p, ok := Lookup(table)
			if !ok {
				t.Fatalf("%s has no registry entry", table)
			}
			if p.State != StateDeferred {
				t.Errorf("%s state = %q, want deferred", table, p.State)
			}
			if strings.TrimSpace(p.Reason) == "" {
				t.Errorf("%s is deferred with no reason. The reason has to name the work it is blocked on", table)
			}
			where, arg := seedRow(t, pool, fx, p, ancient)
			rows = append(rows, seeded{table, where, arg})
		}

		// The parameters a promotion would use, not only the state.
		// Nothing else checks these, so a wrong column or a missing
		// safety predicate would stay green until the day someone flips
		// the state to swept, which is the worst day to find out.
		sess, _ := Lookup("sessions")
		if sess.TTLColumn != "absolute_expires_at" {
			t.Errorf("sessions TTLColumn = %q, want absolute_expires_at. expires_at slides forward on every request (internal/identity/sessions.go:245 extends it by the inactivity window), so an entry pointed there would delete the sessions of users who are merely idle rather than sessions that are finished", sess.TTLColumn)
		}
		const wantKeep = "reuse_detected_at IS NOT NULL"
		if rt, _ := Lookup("refresh_tokens"); rt.Keep != wantKeep {
			t.Errorf("refresh_tokens Keep = %q, want %q, carried now while the entry is still deferred. A row with reuse_detected_at set is the only durable artifact of a detected token theft, and adding the predicate at promotion time is one review away from being forgotten", rt.Keep, wantKeep)
		}

		if err := NewSweeper(pool, failIfCalled(t)).Sweep(context.Background()); err != nil {
			t.Errorf("sweep: %v", err)
		}

		for _, r := range rows {
			if !rowExists(t, pool, r.table, r.where, r.arg) {
				t.Errorf("an aged %s row was deleted. That table is deferred, and its sweep is blocked on a migration that has not landed", r.table)
			}
		}
	})
}

// ---------------------------------------------------------------------
// AC-06: a sweep deletes past the grace and nothing else
// ---------------------------------------------------------------------

// @ac AC-06
// AC-06: for every swept entry, a row inside the grace survives and a row
// past it goes. Both rows are seeded through the policy's own TTL column,
// so auth_mfa_otp_uses is exercised on used_at without this test naming
// that column.
func TestSweepDeletesPastGraceOnly(t *testing.T) {
	t.Run("system-retention-sweeper/AC-06", func(t *testing.T) {
		pool := freshPool(t)
		fx := seedFixtures(t, pool)

		policies := swept()
		if len(policies) == 0 {
			t.Fatal("no swept entries, this test would pass vacuously")
		}

		type pair struct {
			p                  Policy
			freshW, staleW     string
			freshArg, staleArg any
		}
		var pairs []pair
		for _, p := range policies {
			// Half a grace old: inside. A grace plus an hour: past.
			fw, fa := seedRow(t, pool, fx, p, time.Now().Add(-p.Grace/2))
			sw, sa := seedRow(t, pool, fx, p, time.Now().Add(-p.Grace-time.Hour))
			pairs = append(pairs, pair{p, fw, sw, fa, sa})
		}

		if err := NewSweeper(pool, failIfCalled(t)).Sweep(context.Background()); err != nil {
			t.Fatalf("sweep: %v", err)
		}

		for _, pr := range pairs {
			if !rowExists(t, pool, pr.p.Table, pr.freshW, pr.freshArg) {
				t.Errorf("%s: a row only half a grace old was deleted. The sweep is deleting inside the grace, and for auth_mfa_otp_uses that would reopen an OTP replay hole", pr.p.Table)
			}
			if rowExists(t, pool, pr.p.Table, pr.staleW, pr.staleArg) {
				t.Errorf("%s: a row past its %v grace on %s survived the sweep", pr.p.Table, pr.p.Grace, pr.p.TTLColumn)
			}
		}
	})
}

// ---------------------------------------------------------------------
// AC-07: batched and oldest first
// ---------------------------------------------------------------------

// @ac AC-07
// AC-07: with batch size N and 2N+1 eligible rows, one pass removes all
// 2N+1 and issues more than one statement, and the statement carries
// ORDER BY the TTL column ascending and a LIMIT.
//
// The statement count is observed through a pgx tracer rather than
// inferred from the row count, so the batching is measured and not
// assumed. Oldest first is a correctness requirement: refresh_tokens
// carries a self-referencing rotated_to_id with NO ACTION, and a
// newest-first batch breaks it the moment that entry is promoted.
func TestSweepIsBatchedAndOldestFirst(t *testing.T) {
	t.Run("system-retention-sweeper/AC-07", func(t *testing.T) {
		base := freshPool(t)
		pool, counter := tracedPool(t, base)
		fx := seedFixtures(t, base)

		policies := swept()
		if len(policies) == 0 {
			t.Fatal("no swept entries, this test would pass vacuously")
		}
		p := policies[0]

		const n = 3
		const eligible = 2*n + 1
		for i := 0; i < eligible; i++ {
			// Staggered ages, all past the grace, so ordering is
			// observable rather than a tie.
			seedRow(t, base, fx, p, time.Now().Add(-p.Grace-time.Duration(i+1)*time.Hour))
		}

		sw := NewSweeper(pool, failIfCalled(t)).WithBatchSize(n)

		stmt := sw.DeleteStatement(p)
		if !strings.Contains(stmt, "ORDER BY "+p.TTLColumn+" ASC") {
			t.Errorf("the delete for %s has no ORDER BY %s ASC. Got: %s", p.Table, p.TTLColumn, stmt)
		}
		if !strings.Contains(stmt, "LIMIT") {
			t.Errorf("the delete for %s has no LIMIT, so a batch is unbounded. Got: %s", p.Table, stmt)
		}

		if err := sw.Sweep(context.Background()); err != nil {
			t.Fatalf("sweep: %v", err)
		}

		if left := countRows(t, base, p.Table); left != 0 {
			t.Errorf("%d of %d eligible %s rows survived one pass. The sweep must repeat until a batch comes back short", left, eligible, p.Table)
		}
		if got := counter.count(stmt); got < 2 {
			t.Errorf("one pass issued %d delete statements for %d rows at batch size %d. It must batch, not delete the backlog in a single unbounded statement", got, eligible, n)
		}
	})
}

// ---------------------------------------------------------------------
// AC-08: a tick cannot outrun its interval
// ---------------------------------------------------------------------

// @ac AC-08
// AC-08: the per-tick deadline is strictly shorter than the tick
// interval, read off the sweeper rather than timed. cron.Scheduler passes
// no deadline of its own, so a pass that ran long would overlap the next
// tick and two sweeps would fight over the same rows.
func TestTickDeadlineIsShorterThanInterval(t *testing.T) {
	t.Run("system-retention-sweeper/AC-08", func(t *testing.T) {
		for _, interval := range []time.Duration{time.Minute, time.Hour, DefaultInterval} {
			sw := NewSweeper(nil, nil).WithInterval(interval)
			if sw.Interval() != interval {
				t.Fatalf("Interval() = %v, want %v", sw.Interval(), interval)
			}
			d := sw.Deadline()
			if d <= 0 {
				t.Errorf("deadline at interval %v is %v, so a tick has no time bound at all", interval, d)
			}
			if d >= interval {
				t.Errorf("deadline %v is not shorter than the %v interval, so a slow pass can overlap the next tick", d, interval)
			}
		}
	})
}

// @ac AC-08
// AC-08, second half: a sweep whose context is already canceled returns
// promptly, does not panic, and leaves every row in place.
func TestCanceledSweepLeavesRowsInPlace(t *testing.T) {
	t.Run("system-retention-sweeper/AC-08", func(t *testing.T) {
		pool := freshPool(t)
		fx := seedFixtures(t, pool)

		policies := swept()
		if len(policies) == 0 {
			t.Fatal("no swept entries, this test would pass vacuously")
		}
		before := map[string]int{}
		for _, p := range policies {
			seedRow(t, pool, fx, p, time.Now().Add(-p.Grace-time.Hour))
			before[p.Table] = countRows(t, pool, p.Table)
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		done := make(chan error, 1)
		go func() { done <- NewSweeper(pool, failIfCalled(t)).Sweep(ctx) }()

		select {
		case <-done:
			// Returning at all is the assertion. The error value is not
			// pinned: a canceled sweep may report the cancellation or
			// report nothing done.
		case <-time.After(10 * time.Second):
			t.Fatal("a sweep on an already-canceled context did not return within 10 seconds")
		}

		for _, p := range policies {
			if got := countRows(t, pool, p.Table); got != before[p.Table] {
				t.Errorf("%s went from %d rows to %d on a canceled sweep. A canceled pass must delete nothing", p.Table, before[p.Table], got)
			}
		}
	})
}

// ---------------------------------------------------------------------
// AC-09: a Keep predicate is honored
// ---------------------------------------------------------------------

// @ac AC-09
// AC-09: with a Keep predicate, a past-grace row matching Keep survives
// and a past-grace row that does not match is deleted.
//
// Tested on refresh_tokens through a test registry, before that entry is
// promoted to swept rather than with it. A row with reuse_detected_at set
// is the only durable artifact of a detected token theft, so the
// promotion is only safe if this already works.
func TestKeepPredicateIsHonored(t *testing.T) {
	t.Run("system-retention-sweeper/AC-09", func(t *testing.T) {
		pool := freshPool(t)
		fx := seedFixtures(t, pool)

		base, ok := Lookup("refresh_tokens")
		if !ok {
			t.Fatal("refresh_tokens has no registry entry")
		}
		if base.Keep == "" {
			t.Fatalf("refresh_tokens carries no Keep predicate. C-09 requires %q so a detected token theft is not swept away at promotion", "reuse_detected_at IS NOT NULL")
		}

		aged := time.Now().Add(-base.Grace - time.Hour)
		keepW, keepArg := seedRow(t, pool, fx, base, aged)
		goW, goArg := seedRow(t, pool, fx, base, aged)

		// Make one row match Keep.
		if _, err := pool.Exec(context.Background(),
			"UPDATE refresh_tokens SET reuse_detected_at = now() WHERE "+keepW, keepArg); err != nil {
			t.Fatalf("mark reuse: %v", err)
		}

		// A test registry promoting the entry to swept, Keep intact.
		promoted := base
		promoted.State = StateSwept
		sw := NewSweeper(pool, failIfCalled(t)).WithPolicies([]Policy{promoted})

		if !strings.Contains(sw.DeleteStatement(promoted), promoted.Keep) {
			t.Errorf("the generated delete does not mention the Keep predicate %q at all: %s", promoted.Keep, sw.DeleteStatement(promoted))
		}
		if err := sw.Sweep(context.Background()); err != nil {
			t.Fatalf("sweep: %v", err)
		}

		if !rowExists(t, pool, "refresh_tokens", keepW, keepArg) {
			t.Errorf("a past-grace row matching Keep (%s) was deleted. That row is the only durable record of a detected token theft", promoted.Keep)
		}
		if rowExists(t, pool, "refresh_tokens", goW, goArg) {
			t.Error("a past-grace row not matching Keep survived, so the Keep negation is swallowing everything and the sweep deletes nothing")
		}
	})
}

// ---------------------------------------------------------------------
// AC-10: the wiring guard
// ---------------------------------------------------------------------

// @ac AC-10
// AC-10: main.go reaches the sweeper, and the sweep walks the registry
// rather than a hard-coded list of tables.
//
// This is the criterion the two dead purge functions would have failed.
// internal/sso PurgeExpiredStates and internal/identity PurgeStaleOTPs
// were each written, reviewed and left with no caller for months, because
// nothing in this repo enforced that code is reachable from main. A
// sweeper that exists and is never started is the same defect wearing a
// spec.
//
// The second half matters just as much. If the sweep named its tables
// inline, a new swept entry in the registry would do nothing until
// someone remembered to edit the sweep too, and the registry would drift
// back into documentation.
//
// system-daemon-orchestration AC-12 asserts the main.go half again from
// the other side, as an AST check over cmdServe.
func TestSweeperIsReachableFromMain(t *testing.T) {
	t.Run("system-retention-sweeper/AC-10", func(t *testing.T) {
		root := repoRoot(t)

		mainPath := filepath.Join(root, "cmd", "openwatch", "main.go")
		b, err := os.ReadFile(mainPath)
		if err != nil {
			t.Fatalf("read main.go: %v", err)
		}
		main := string(b)
		if !strings.Contains(main, "retention.NewSweeper(") {
			t.Error("cmd/openwatch/main.go never calls retention.NewSweeper(. Nothing sweeps any table in production, which is the state this spec exists to end")
		} else if !sweeperIsStarted(main) {
			// Constructed and not started is the failure worth naming.
			// Both dead purge functions compiled, passed review and did
			// nothing, so "the code exists" proves nothing here. A bare
			// search for .Run(ctx would match any of the other services
			// main.go starts, so the value has to be followed.
			t.Error("cmd/openwatch/main.go constructs retention.NewSweeper( but never starts that value with a Run call taking ctx. A sweeper that is built and not run deletes nothing")
		}

		// Second half: the sweep ranges over the registry.
		pkgDir := filepath.Join(root, "internal", "retention")
		fset := token.NewFileSet()
		pkgs, err := parser.ParseDir(fset, pkgDir, func(fi fs.FileInfo) bool {
			return !strings.HasSuffix(fi.Name(), "_test.go")
		}, 0)
		if err != nil {
			t.Fatalf("parse internal/retention: %v", err)
		}

		// The range has to be inside the code a tick actually reaches.
		// Asking only whether the package contains such a range anywhere
		// is not enough: Lookup ranges over the registry too, so that
		// version stays green while the sweep itself walks a hard-coded
		// list. Start at the function handed to cron.New and follow the
		// calls from there.
		funcs := map[string]*ast.FuncDecl{}
		tick := ""
		for _, pkg := range pkgs {
			for _, f := range pkg.Files {
				for _, d := range f.Decls {
					if fn, ok := d.(*ast.FuncDecl); ok {
						funcs[fn.Name.Name] = fn
					}
				}
				ast.Inspect(f, func(n ast.Node) bool {
					if !pkgCallExpr(n, "cron", "New") {
						return true
					}
					args := n.(*ast.CallExpr).Args
					if len(args) >= 2 {
						tick = calleeName(args[1])
					}
					return true
				})
			}
		}
		if tick == "" {
			t.Fatal("internal/retention never calls cron.New with a tick function, so the sweep is not on a scheduler at all")
		}
		if _, ok := funcs[tick]; !ok {
			t.Fatalf("the tick function %q handed to cron.New is not declared in internal/retention, so this guard cannot follow it", tick)
		}

		reached := map[string]bool{}
		var walk func(name string)
		walk = func(name string) {
			fn, ok := funcs[name]
			if !ok || reached[name] {
				return
			}
			reached[name] = true
			ast.Inspect(fn, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if callee := calleeName(call.Fun); callee != "" {
						walk(callee)
					}
				}
				return true
			})
		}
		walk(tick)

		rangesOverRegistry := false
		for name := range reached {
			ast.Inspect(funcs[name], func(n ast.Node) bool {
				if rng, ok := n.(*ast.RangeStmt); ok && usesRegistry(rng.X) {
					rangesOverRegistry = true
				}
				return true
			})
		}
		if !rangesOverRegistry {
			t.Errorf("nothing reachable from the cron tick %q iterates the registry (reached: %s). The sweep must walk the registry, so a newly swept entry runs with no change at the call site. A hard-coded table list turns the registry back into documentation", tick, strings.Join(sortedKeys(reached), ", "))
		}
	})
}

// pkgCallExpr reports whether n is a call to pkg.name(...).
func pkgCallExpr(n ast.Node, pkg, name string) bool {
	call, ok := n.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == pkg
}

// calleeName is the bare function name an expression refers to, for both
// a package-level call and a method value such as s.sweepWithDeadline.
func calleeName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return v.Sel.Name
	}
	return ""
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sweeperIsStarted reports whether main.go runs the value that
// retention.NewSweeper returned, either chained straight into Run or
// bound to a name and that name run.
//
// system-daemon-orchestration AC-12 makes the same check over the AST,
// scoped to cmdServe. This one is text, matching the house style of the
// other wiring guards, and the two are meant to overlap: a wiring defect
// this important should fail twice.
func sweeperIsStarted(main string) bool {
	if regexp.MustCompile(`retention\.NewSweeper\([^\n]*\)\s*\.\s*Run\(ctx\b`).MatchString(main) {
		return true
	}
	bind := regexp.MustCompile(`(\w+)\s*:?=\s*retention\.NewSweeper\(`).FindStringSubmatch(main)
	if bind == nil || bind[1] == "_" {
		return false
	}
	return regexp.MustCompile(`\b` + regexp.QuoteMeta(bind[1]) + `\s*\.\s*Run\(ctx\b`).MatchString(main)
}

// usesRegistry reports whether expr reads the package registry, as the
// bare identifier, as a Registry() call, or through the sweeper's own
// registry accessor.
func usesRegistry(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name == "registry" || e.Name == "Registry"
	case *ast.CallExpr:
		return usesRegistry(e.Fun)
	case *ast.SelectorExpr:
		return e.Sel.Name == "registry" || e.Sel.Name == "Registry"
	}
	return false
}

// ---------------------------------------------------------------------
// AC-11: no second sweeper
// ---------------------------------------------------------------------

// pastBoundPattern is the WHERE shape of an age-based bulk delete: the
// given column compared against a past bound. now() covers the literal
// form and now() minus an interval; a bound parameter covers a cutoff
// computed in Go. A delete keyed on an identifier does not match.
func pastBoundPattern(column string) string {
	return `(?is)\b` + regexp.QuoteMeta(column) + `\s*<\s*(now\(\)|current_timestamp|\$\d)`
}

// literalText is a string literal's contents with its quotes or
// backticks removed. The delimiters have to go before fragments are
// joined, or a statement split mid-token ("DELETE FROM sso_auth_" +
// "states ...") would still not match once folded.
func literalText(lit *ast.BasicLit) string {
	s := lit.Value
	if len(s) >= 2 {
		if q := s[0]; q == '`' || q == '"' {
			s = s[1 : len(s)-1]
		}
	}
	return s
}

// foldStringConcat joins a + concatenation of string literals into the
// value it builds. Reports false if any operand is not a literal or
// another such concatenation, because a fragment joined to a variable
// cannot be read off the source at all.
func foldStringConcat(e ast.Expr) (string, bool) {
	switch v := e.(type) {
	case *ast.ParenExpr:
		return foldStringConcat(v.X)
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		return literalText(v), true
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return "", false
		}
		left, ok := foldStringConcat(v.X)
		if !ok {
			return "", false
		}
		right, ok := foldStringConcat(v.Y)
		if !ok {
			return "", false
		}
		return left + right, true
	}
	return "", false
}

// @ac AC-11
// AC-11: outside internal/retention and outside test files, no Go source
// runs an age-based bulk DELETE from a swept table.
//
// Such a delete anywhere else is a private retention policy the registry
// does not know about, and that is how this codebase reached two purge
// functions and no sweeper. There are five cron.New call sites in the
// tree, each a package owning its own scheduled work. Retention does not
// join them.
//
// The shape is what matters, not the table name. The SSO single-use
// consume (internal/sso/store.go consumeAuthState) deletes by state = $1
// and checks expiry in Go afterward, so it is not retention and does not
// match. It must keep working.
//
// Only string literals are scanned. A comment describing a delete is not
// a delete, and flagging prose would push people into writing SQL that
// reads worse to get past a test.
func TestNoSecondSweeperInTheTree(t *testing.T) {
	t.Run("system-retention-sweeper/AC-11", func(t *testing.T) {
		policies := swept()
		if len(policies) == 0 {
			t.Fatal("no swept entries, so this scan has nothing to look for and would pass vacuously")
		}

		root := repoRoot(t)
		fset := token.NewFileSet()

		for _, rel := range goSourceFiles(t, root) {
			if strings.HasPrefix(rel, "internal/retention/") {
				continue
			}
			f, err := parser.ParseFile(fset, filepath.Join(root, rel), nil, 0)
			if err != nil {
				// Generated files and build-tagged files still parse;
				// a real parse failure is worth reporting, not skipping.
				t.Errorf("parse %s: %v", rel, err)
				continue
			}
			check := func(sql string, pos token.Pos) {
				for _, p := range policies {
					deleteRe := regexp.MustCompile(`(?is)\bDELETE\s+FROM\s+` + regexp.QuoteMeta(p.Table) + `\b(.*)`)
					m := deleteRe.FindStringSubmatch(sql)
					if m == nil {
						continue
					}
					ageRe := regexp.MustCompile(pastBoundPattern(p.TTLColumn))
					if !ageRe.MatchString(m[1]) {
						continue
					}
					t.Errorf("%s:%d runs an age-based bulk DELETE from %s on %s. That is a second retention policy the registry does not know about. Move it into internal/retention or delete it (spec C-03)",
						rel, fset.Position(pos).Line, p.Table, p.TTLColumn)
				}
			}

			ast.Inspect(f, func(n ast.Node) bool {
				// A SQL string split across a + concatenation reaches the
				// AST as a BinaryExpr over separate literals. Matching one
				// literal at a time sees "DELETE FROM x " and "WHERE ttl <
				// now()" as two harmless fragments and misses the delete
				// they build. Wrapping a long statement with + is ordinary
				// Go and this repo does it constantly, so fold first.
				if bin, ok := n.(*ast.BinaryExpr); ok && bin.Op == token.ADD {
					if joined, ok := foldStringConcat(bin); ok {
						check(joined, bin.Pos())
						// Consumed. Descending would re-report each
						// fragment against the same finding.
						return false
					}
					// Not an all-literal concatenation, so fall through
					// and let the literals inside it be checked singly.
					return true
				}
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					check(literalText(lit), lit.Pos())
				}
				return true
			})
		}
	})
}

// ---------------------------------------------------------------------
// AC-12: the orphaned purges are resolved
// ---------------------------------------------------------------------

// orphanedPurges are the two functions that were exported, tested and
// never called. Each must now be gone or called from internal/retention.
var orphanedPurges = map[string]string{
	"PurgeExpiredStates": "internal/sso/store.go",
	"PurgeStaleOTPs":     "internal/identity/mfa.go",
}

// falseCallerRe matches a doc comment claiming a scheduled caller.
var falseCallerRe = regexp.MustCompile(`(?is)called\s+by\s+a\s+(periodic\s+sweeper|cron\s+tick|scheduler|sweeper)`)

// @ac AC-12
// AC-12: neither orphaned purge is left sitting beside the new sweeper,
// and no surviving function in those two files claims a scheduled caller
// it does not have.
//
// Identifiers are read from the AST, not from the file text, so prose
// that names a deleted function in a comment is not mistaken for a live
// reference to it.
//
// The doc-comment half is scoped to comments attached to a declaration.
// That is where the original defect lived: each function's own doc
// comment asserted a caller, which is why both read as live for months. A
// free-standing comment recording that a function used to exist claims
// nothing about live code and is how a deletion should be documented.
func TestOrphanedPurgeFunctionsAreResolved(t *testing.T) {
	t.Run("system-retention-sweeper/AC-12", func(t *testing.T) {
		root := repoRoot(t)
		fset := token.NewFileSet()

		// Where each name is used as a real identifier.
		uses := map[string][]string{}
		for _, rel := range goSourceFiles(t, root) {
			f, err := parser.ParseFile(fset, filepath.Join(root, rel), nil, parser.ParseComments)
			if err != nil {
				t.Errorf("parse %s: %v", rel, err)
				continue
			}
			ast.Inspect(f, func(n ast.Node) bool {
				id, ok := n.(*ast.Ident)
				if !ok {
					return true
				}
				if _, watched := orphanedPurges[id.Name]; watched {
					uses[id.Name] = append(uses[id.Name], rel)
				}
				return true
			})
		}

		referencedFromRetention := map[string]bool{}
		for name, files := range uses {
			for _, rel := range files {
				if strings.HasPrefix(rel, "internal/retention/") {
					referencedFromRetention[name] = true
				}
			}
		}

		for name := range orphanedPurges {
			files := uses[name]
			if len(files) == 0 {
				continue // Deleted from the tree. Resolved.
			}
			if !referencedFromRetention[name] {
				sort.Strings(files)
				t.Errorf("%s still exists (%s) and nothing in internal/retention calls it. It must be called from the sweeper or deleted. An exported purge with no caller is the defect this spec corrects, and golangci-lint does not report it",
					name, strings.Join(files, ", "))
			}
		}

		// Doc comments in the two original homes must not claim a
		// scheduled caller that does not exist.
		for name, rel := range orphanedPurges {
			path := filepath.Join(root, rel)
			f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if err != nil {
				t.Fatalf("parse %s: %v", rel, err)
			}
			ast.Inspect(f, func(n ast.Node) bool {
				var doc *ast.CommentGroup
				var decl string
				switch d := n.(type) {
				case *ast.FuncDecl:
					doc, decl = d.Doc, d.Name.Name
				case *ast.GenDecl:
					doc, decl = d.Doc, "a declaration"
				default:
					return true
				}
				if doc == nil || !falseCallerRe.MatchString(doc.Text()) {
					return true
				}
				if referencedFromRetention[decl] {
					return true
				}
				t.Errorf("%s:%d the doc comment on %s claims a scheduled caller, and internal/retention does not call it. That exact claim is why %s read as live for months",
					rel, fset.Position(doc.Pos()).Line, decl, name)
				return true
			})
		}
	})
}

// ---------------------------------------------------------------------
// AC-13: the OTP replay window
// ---------------------------------------------------------------------

// totpAcceptanceWindow is the TOTP window VerifyMFA accepts: period 30s
// with skew 1, so three steps. The replay grace can never be shorter,
// because a used OTP is rejected only for as long as its row survives.
const totpAcceptanceWindow = 90 * time.Second

// @ac AC-13
// AC-13: the OTP replay window comes from the registry and never drops
// below the TOTP acceptance window.
//
// This is a security parameter, not a capacity setting. VerifyMFA rejects
// a replay by inserting (user_id, otp) with ON CONFLICT DO NOTHING and
// checking whether the insert took. The check is existence-based, so
// deleting the row makes that OTP live again.
//
// The functional half is the one that bites. A future change that narrows
// the grace passes both static assertions if it also edits the constant,
// but it cannot pass a real verify, sweep, verify sequence.
//
// This is why "just call the purge function that already exists" was the
// wrong fix for OW-013. PurgeStaleOTPs deleted at 180 seconds and had no
// caller, so replay rejection was accidentally unlimited. Wiring it up as
// written would have narrowed protection from unlimited to 180 seconds.
func TestOTPReplayWindowComesFromTheRegistry(t *testing.T) {
	t.Run("system-retention-sweeper/AC-13", func(t *testing.T) {
		p, ok := Lookup("auth_mfa_otp_uses")
		if !ok {
			t.Fatal("auth_mfa_otp_uses has no registry entry")
		}
		if p.Grace < totpAcceptanceWindow {
			t.Errorf("the auth_mfa_otp_uses grace is %v, below the %v TOTP acceptance window. An OTP would become replayable while it is still valid", p.Grace, totpAcceptanceWindow)
		}

		// Any surviving OTPReplayWindow constant must equal the grace.
		// Deleting it is also fine: the registry is the single source of
		// truth, and two numbers that must agree eventually will not.
		if w, found := otpReplayWindowConstant(t); found && w != p.Grace {
			t.Errorf("identity.OTPReplayWindow is %v but the registry grace is %v. Two places state the replay window and they disagree, so one of them is lying to whoever reads it next", w, p.Grace)
		}

		// Functional: verify once, sweep, verify again.
		pool := freshPool(t)
		if err := identity.SetEphemeralMFAKey(); err != nil {
			t.Fatalf("ephemeral mfa key: %v", err)
		}
		userID := seedUser(t, pool)
		ctx := context.Background()

		uri, err := identity.EnrollMFA(ctx, pool, userID, "ret-otp-user")
		if err != nil {
			t.Fatalf("EnrollMFA: %v", err)
		}
		u, err := url.Parse(uri)
		if err != nil {
			t.Fatalf("parse provisioning uri: %v", err)
		}
		secret := u.Query().Get("secret")
		if secret == "" {
			t.Fatal("provisioning uri carries no secret")
		}
		code, err := totp.GenerateCodeCustom(secret, time.Now().UTC(), totp.ValidateOpts{
			Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil {
			t.Fatalf("generate otp: %v", err)
		}

		if err := identity.VerifyMFA(ctx, pool, userID, code); err != nil {
			t.Fatalf("first VerifyMFA: %v", err)
		}
		if n := countRows(t, pool, "auth_mfa_otp_uses"); n != 1 {
			t.Fatalf("auth_mfa_otp_uses has %d rows after one verify, want 1", n)
		}

		// Age the row by the full TOTP acceptance window before sweeping.
		//
		// Without this the row is zero seconds old and any positive grace
		// spares it, so the two assertions below would hold no matter how
		// far the grace was narrowed. Aged 90 seconds, they state the
		// security property directly and without reading the registry: a
		// used OTP must still be rejected for as long as that same OTP is
		// still valid, whatever the grace happens to say.
		if _, err := pool.Exec(ctx,
			`UPDATE auth_mfa_otp_uses SET used_at = now() - make_interval(secs => $1)`,
			totpAcceptanceWindow.Seconds()); err != nil {
			t.Fatalf("age the otp row: %v", err)
		}

		if err := NewSweeper(pool, failIfCalled(t)).Sweep(ctx); err != nil {
			t.Fatalf("sweep: %v", err)
		}

		if n := countRows(t, pool, "auth_mfa_otp_uses"); n != 1 {
			t.Errorf("the sweep deleted an OTP row used %v ago (%d rows left), while that OTP is still inside its own validation window. The registry grace is %v", totpAcceptanceWindow, n, p.Grace)
		}
		if err := identity.VerifyMFA(ctx, pool, userID, code); err != identity.ErrOTPReplayed {
			t.Errorf("after a full sweep, replaying the same OTP returned %v, want ErrOTPReplayed. The sweep reopened a replay hole, and system-auth-identity AC-16 no longer holds", err)
		}
	})
}

// otpReplayWindowConstant reads identity.OTPReplayWindow out of the
// source if it still exists. Reflection cannot see an untyped duration
// constant that the package may have deleted, and referring to it
// directly would stop this package compiling once it is gone.
func otpReplayWindowConstant(t *testing.T) (time.Duration, bool) {
	t.Helper()
	path := filepath.Join(repoRoot(t), "internal", "identity", "mfa.go")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read mfa.go: %v", err)
	}
	m := regexp.MustCompile(`OTPReplayWindow\s*=\s*([0-9]+)\s*\*\s*time\.(Second|Minute|Hour)`).FindStringSubmatch(string(b))
	if m == nil {
		return 0, false
	}
	var n time.Duration
	if _, err := fmt.Sscanf(m[1], "%d", &n); err != nil {
		t.Fatalf("parse OTPReplayWindow: %v", err)
	}
	switch m[2] {
	case "Second":
		return n * time.Second, true
	case "Minute":
		return n * time.Minute, true
	default:
		return n * time.Hour, true
	}
}

// ---------------------------------------------------------------------
// AC-14: a tick reports what it did
// ---------------------------------------------------------------------

// captureHandler collects slog records so a test can read them back,
// along with the correlation id each one was logged under. The id lives
// on the context rather than on the record, so it has to be pulled out
// here or it is gone by the time the test reads the record.
type captureHandler struct {
	mu      sync.Mutex
	records []capturedRecord
}

type capturedRecord struct {
	rec           slog.Record
	correlationID string
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *captureHandler) Handle(ctx context.Context, r slog.Record) error {
	id, _ := correlation.From(ctx)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, capturedRecord{rec: r.Clone(), correlationID: id})
	return nil
}

func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

// attrs flattens one record's attributes.
func attrsOf(r slog.Record) map[string]slog.Value {
	out := map[string]slog.Value{}
	r.Attrs(func(a slog.Attr) bool {
		out[a.Key] = a.Value
		return true
	})
	return out
}

// @ac AC-14
// AC-14: a pass that deletes rows logs one record per swept table naming
// the table and the deleted count, and emits no audit event.
//
// The audit half is asserted by passing an emit function that fails the
// test if it is called. audit_events is itself a growing table with no
// retention decision yet, so auditing retention would trade one unbounded
// table for another. Routine expiry is also not an actor's action.
func TestSweepLogsPerTableAndEmitsNoAudit(t *testing.T) {
	t.Run("system-retention-sweeper/AC-14", func(t *testing.T) {
		pool := freshPool(t)
		fx := seedFixtures(t, pool)

		policies := swept()
		if len(policies) == 0 {
			t.Fatal("no swept entries, this test would pass vacuously")
		}
		for _, p := range policies {
			seedRow(t, pool, fx, p, time.Now().Add(-p.Grace-time.Hour))
		}

		capture := &captureHandler{}
		prev := slog.Default()
		slog.SetDefault(slog.New(capture))
		t.Cleanup(func() { slog.SetDefault(prev) })

		// Sweep under a cron correlation id, the way cron.Scheduler
		// calls the tick. Without it the records would carry no id and
		// the operator could not tie a pass together.
		tickID := correlation.Generate(correlation.PrefixCron)
		ctx := correlation.Set(context.Background(), tickID)
		if err := NewSweeper(pool, failIfCalled(t)).Sweep(ctx); err != nil {
			t.Fatalf("sweep: %v", err)
		}

		capture.mu.Lock()
		records := append([]capturedRecord(nil), capture.records...)
		capture.mu.Unlock()

		if !strings.HasPrefix(tickID, "cron-") {
			t.Fatalf("correlation.Generate(PrefixCron) produced %q, which is not a cron- id, so this assertion would not mean what it says", tickID)
		}

		for _, p := range policies {
			found := false
			for _, r := range records {
				a := attrsOf(r.rec)
				table, hasTable := a["table"]
				if !hasTable || table.String() != p.Table {
					continue
				}
				deleted, hasDeleted := a["deleted"]
				if !hasDeleted {
					t.Errorf("the log record for %s names the table but carries no deleted count. An operator cannot tell a working sweep from a no-op", p.Table)
					continue
				}
				if deleted.Int64() != 1 {
					t.Errorf("the log record for %s reports %d rows deleted, want 1", p.Table, deleted.Int64())
				}
				if r.correlationID != tickID {
					t.Errorf("the log record for %s carries correlation id %q, want the tick's %q. Records that do not share the tick's id cannot be read back as one pass", p.Table, r.correlationID, tickID)
				}
				found = true
			}
			if !found {
				t.Errorf("no log record names table %s. Each tick must report one record per swept table", p.Table)
			}
		}
	})
}

// ---------------------------------------------------------------------
// AC-15: one bad table does not end the pass
// ---------------------------------------------------------------------

// @ac AC-15
// AC-15: with a first swept entry naming a table that does not exist, the
// pass still drains the remaining swept tables and returns an error
// naming the one that failed.
//
// A pass that stopped on the first error would let one broken entry hide
// every table behind it, and the growth would be silent again.
func TestOneBadTableDoesNotEndThePass(t *testing.T) {
	t.Run("system-retention-sweeper/AC-15", func(t *testing.T) {
		pool := freshPool(t)
		fx := seedFixtures(t, pool)

		kept, ok := Lookup("idempotency_keys")
		if !ok {
			t.Fatal("idempotency_keys has no registry entry")
		}
		where, arg := seedRow(t, pool, fx, kept, time.Now().Add(-kept.Grace-time.Hour))

		const missing = "table_that_does_not_exist"
		bad := Policy{
			Table:     missing,
			TTLColumn: "expires_at",
			Grace:     time.Hour,
			State:     StateSwept,
			Reason:    "test fixture",
		}

		err := NewSweeper(pool, failIfCalled(t)).
			WithPolicies([]Policy{bad, kept}).
			Sweep(context.Background())

		if err == nil {
			t.Fatalf("a pass over a table that does not exist returned no error. The failure would be invisible")
		}
		if !strings.Contains(err.Error(), missing) {
			t.Errorf("the error does not name the failing table. Got: %v", err)
		}
		if rowExists(t, pool, kept.Table, where, arg) {
			t.Errorf("the pass stopped at the broken entry: an eligible %s row behind it survived. One bad table must not hide every table after it", kept.Table)
		}
	})
}

// ---------------------------------------------------------------------
// AC-16: the undecided set is pinned by name
// ---------------------------------------------------------------------

// undecidedTables is the thirty-nine tables that carry no retention
// decision yet, pinned by name rather than counted.
//
// A count would let a promotion pay for a new undecided table and hold
// the total, so a table could arrive undecided and stay that way without
// a reviewer ever seeing it. Pinning the names means adding an undecided
// table edits this list, and promoting one edits it too. That is a
// record of the decision, not friction.
var undecidedTables = []string{
	"alerts",
	"audit_events",
	"auth_mfa_secrets",
	"auth_policy",
	"credentials",
	"group_members",
	"groups",
	"host_backoff_state",
	"host_compliance_schedule",
	"host_connection_profile",
	"host_intelligence_events",
	"host_intelligence_state",
	"host_liveness",
	"host_monitoring_history",
	"host_rule_state",
	"host_system_info",
	"hosts",
	"job_queue",
	"license_clock_watermark",
	"notification_channels",
	"notifications",
	"policy_history",
	"posture_snapshots",
	"remediation_requests",
	"remediation_transactions",
	"report_faces",
	"report_schedules",
	"report_snapshots",
	"roles",
	"scan_evidence",
	"scan_results",
	"scan_runs",
	"ssh_known_hosts",
	"sso_identities",
	"sso_providers",
	"system_config",
	"transactions",
	"user_roles",
	"users",
}

// @ac AC-16
// AC-16: the undecided set is exactly that list, and a row in an
// undecided table survives a sweep however old it is.
//
// Why the survival half is here, stated carefully, because the obvious
// version of the reasoning is wrong today.
//
// The worry is a sweep filter written as "not never and not deferred",
// which would take in all thirty-nine undecided tables. Sweeper.Eligible
// is written positively (State == StateSwept) so this does not happen,
// and neither AC-04 nor AC-05 would notice if it did: each looks only at
// the two tables it names.
//
// But writing that filter today does not delete anything. An undecided
// entry carries no TTLColumn, so the sweep builds a WHERE clause with
// nothing on its left, Postgres rejects the statement, and the pass ends
// in an error. Every test that runs a sweep goes red, on the error
// rather than on a deleted row. Verified: with the filter flipped, the
// only assertion that fires anywhere is the sweep error, and no row is
// removed from a never, deferred or undecided table.
//
// So the crash, not this assertion, is what currently stops that bug.
// That protection is an accident of AC-01 and it disappears the moment
// anyone gives an undecided entry a TTL column for documentation
// reasons. This assertion is what still holds afterward. Confirmed by
// mutating both at once, the filter and a TTL column on hosts, which
// makes it fail on its own:
//
//	a five-year-old hosts row was deleted
//
// Do not delete this as redundant on the strength of the filter mutation
// alone. That mutation goes red either way.
func TestUndecidedTablesArePinnedAndUntouched(t *testing.T) {
	t.Run("system-retention-sweeper/AC-16", func(t *testing.T) {
		want := map[string]bool{}
		for _, table := range undecidedTables {
			want[table] = true
		}
		if len(want) != len(undecidedTables) {
			t.Fatalf("the pinned list has %d names but only %d are distinct", len(undecidedTables), len(want))
		}

		got := map[string]bool{}
		for _, p := range Registry() {
			if p.State != StateUndecided {
				continue
			}
			got[p.Table] = true
			if strings.TrimSpace(p.Reason) == "" {
				t.Errorf("%s is undecided with no reason. The reason has to name the state of the decision and point at bugs/OW-013", p.Table)
			} else if !strings.Contains(p.Reason, "OW-013") {
				t.Errorf("%s is undecided but its reason does not point at bugs/OW-013, so a reader has nowhere to go to find out where the decision stands", p.Table)
			}
		}

		for table := range want {
			if !got[table] {
				t.Errorf("%s is pinned as undecided but the registry no longer says so. If it was promoted, take it out of the pinned list in the same change so the promotion is visible in review", table)
			}
		}
		for table := range got {
			if !want[table] {
				t.Errorf("%s is undecided in the registry but is not in the pinned list. A new table arriving with no retention decision has to be added here deliberately, not counted", table)
			}
		}

		// A sweep must not touch an undecided table, whatever its age.
		pool := freshPool(t)
		fx := seedFixtures(t, pool)
		if !want["hosts"] {
			t.Fatal("this test seeds hosts as its undecided sample and hosts is no longer undecided")
		}
		if _, err := pool.Exec(context.Background(),
			"UPDATE hosts SET created_at = now() - interval '5 years' WHERE id = $1", fx.host); err != nil {
			t.Fatalf("age the host row: %v", err)
		}

		if err := NewSweeper(pool, failIfCalled(t)).Sweep(context.Background()); err != nil {
			t.Errorf("sweep: %v", err)
		}
		if !rowExists(t, pool, "hosts", "id = $1", fx.host) {
			t.Error("a five-year-old hosts row was deleted. hosts is undecided, which means no retention decision has been taken for it, so a sweep must leave it alone. A filter written as \"not never and not deferred\" would do exactly this")
		}
	})
}
