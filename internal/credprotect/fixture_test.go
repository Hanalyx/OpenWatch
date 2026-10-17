package credprotect

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/credprotect/fingerprint"
	"github.com/Hanalyx/openwatch/internal/secretkey"

	"github.com/Hanalyx/openwatch/internal/db/dbtest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// fakeClock is a controlled time source.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakeProcs is a controlled process table: machine m1, with the PIDs in
// alive running.
type fakeProcs struct {
	mu    sync.Mutex
	alive map[int]string
}

func (p *fakeProcs) Machine() string { return "m1" }

func (p *fakeProcs) Alive(pid int, start string) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.alive[pid]
	return ok && s == start, nil
}

func (p *fakeProcs) kill(pid int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.alive, pid)
}

type fixture struct {
	t     *testing.T
	pool  *pgxpool.Pool
	store *Store
	clock *fakeClock
	procs *fakeProcs
	user  uuid.UUID
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pool := dbtest.Pool(t)
	ctx := context.Background()
	for _, table := range []string{
		"credprotect_verified_secrets", "credprotect_verification_requests", "credprotect_recoveries",
		"credprotect_submissions", "credprotect_restrictions", "credprotect_credential_classes",
		"credprotect_directory_bindings", "credprotect_directory_resolutions", "credprotect_identities",
	} {
		if _, err := pool.Exec(ctx, "TRUNCATE "+table+" CASCADE"); err != nil {
			t.Fatalf("truncate %s: %v", table, err)
		}
	}
	fixtureKeyring = newTestKeyring(t, pool)
	f := &fixture{
		t:     t,
		pool:  pool,
		clock: &fakeClock{t: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)},
		procs: &fakeProcs{alive: map[int]string{4242: "100"}},
	}
	f.store = New(pool, WithClock(f.clock), WithProcesses(f.procs))
	f.user = uuid.Must(uuid.NewV7())
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, username, email, password_hash) VALUES ($1, $2, $3, $4)`,
		f.user, "cp-"+f.user.String(), f.user.String()+"@example.com", "argon2id$dummy"); err != nil { // pragma: allowlist secret
		t.Fatalf("seed user: %v", err)
	}
	return f
}

func (f *fixture) host() uuid.UUID {
	f.t.Helper()
	id := uuid.Must(uuid.NewV7())
	if _, err := f.pool.Exec(context.Background(),
		`INSERT INTO hosts (id, hostname, ip_address, created_by) VALUES ($1, $2, '192.0.2.10'::inet, $3)`,
		id, "host-"+id.String(), f.user); err != nil {
		f.t.Fatalf("seed host: %v", err)
	}
	return id
}

// cred seeds a password credential for username. The stored ciphertext is
// a placeholder: this package never decrypts.
func (f *fixture) cred(username string) uuid.UUID {
	f.t.Helper()
	id := uuid.Must(uuid.NewV7())
	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO credentials (id, scope, scope_id, name, username, auth_method,
		                         encrypted_password, is_default, is_active, created_by)
		VALUES ($1, 'system', NULL, $2, $3, 'password', '\x01'::bytea, false, true, $4)`,
		id, "cred-"+id.String(), username, f.user); err != nil {
		f.t.Fatalf("seed credential: %v", err)
	}
	return id
}

// pw is a password secret whose identifier is n repeated, under key k1.
// fixtureKeyring is the real fingerprint keyring the current fixture
// built: two keys, the first current, as after a fingerprint-key rotation.
// The tests in this package do not run in parallel.
var fixtureKeyring testKeyring

type testKeyring struct {
	keyring  fingerprint.Keyring
	wrapper  *secretkey.Key
	current  string // the current key's id
	previous string // the other key's id
}

// builtKeyring is the keyring the first fixture built, and its rows, so
// every later fixture can restore the identical keyring. Its snapshot then
// stays the same, and a secret a test built before its fixture still names
// the keyring that fixture holds.
var builtKeyring *struct {
	ring       testKeyring
	rows       [][]any
	generation int64
}

// newTestKeyring returns the fixture keyring: built through fingerprint.Load
// on first use (one key, then a second added as a rotation would add it,
// then loaded again so the snapshot covers both), and restored row for row
// afterwards. Identifiers in the tests are arbitrary bytes under these real
// key ids.
func newTestKeyring(t *testing.T, pool *pgxpool.Pool) testKeyring {
	t.Helper()
	ctx := context.Background()
	if builtKeyring != nil {
		for _, q := range []string{`TRUNCATE credprotect_fingerprint_keys`, `DELETE FROM credprotect_keyring`} {
			if _, err := pool.Exec(ctx, q); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
		for _, r := range builtKeyring.rows {
			if _, err := pool.Exec(ctx, `INSERT INTO credprotect_fingerprint_keys (id, wrapped, is_current, created_at)
				VALUES ($1, $2, $3, $4)`, r...); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := pool.Exec(ctx, `INSERT INTO credprotect_keyring (singleton, initialized_at, generation)
			VALUES (true, now(), $1)`, builtKeyring.generation); err != nil {
			t.Fatal(err)
		}
		return builtKeyring.ring
	}
	for _, q := range []string{
		`TRUNCATE credprotect_fingerprint_keys`,
		`DELETE FROM credprotect_keyring`,
		`INSERT INTO credprotect_keyring (singleton) VALUES (true)`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	raw := make([]byte, secretkey.KeySize)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "credential.key")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := secretkey.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	first, err := fingerprint.Load(ctx, pool, w, time.Now())
	if err != nil {
		t.Fatalf("load keyring: %v", err)
	}
	material := make([]byte, fingerprint.KeySize)
	if _, err := rand.Read(material); err != nil {
		t.Fatal(err)
	}
	wrapped, err := w.Encrypt(material)
	if err != nil {
		t.Fatal(err)
	}
	second := uuid.Must(uuid.NewV7())
	if _, err := pool.Exec(ctx, `INSERT INTO credprotect_fingerprint_keys (id, wrapped, is_current, created_at)
		VALUES ($1, $2, false, now())`, second, wrapped); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE credprotect_keyring SET generation = generation + 1`); err != nil {
		t.Fatal(err)
	}
	kr, err := fingerprint.Load(ctx, pool, w, time.Now())
	if err != nil {
		t.Fatalf("reload keyring: %v", err)
	}
	ring := testKeyring{keyring: kr, wrapper: w, current: first.KeyIDs()[0], previous: second.String()}
	rows, err := pool.Query(ctx, `SELECT id, wrapped, is_current, created_at FROM credprotect_fingerprint_keys`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	built := &struct {
		ring       testKeyring
		rows       [][]any
		generation int64
	}{ring: ring, generation: kr.Generation}
	for rows.Next() {
		var id uuid.UUID
		var wrappedKey []byte
		var current bool
		var created time.Time
		if err := rows.Scan(&id, &wrappedKey, &current, &created); err != nil {
			t.Fatal(err)
		}
		built.rows = append(built.rows, []any{id, wrappedKey, current, created})
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	builtKeyring = built
	return ring
}

// pw is a password identified under the fixture keyring's current key,
// with an arbitrary identifier n.
func pw(n byte) Secret {
	var a Alias
	a.KeyID = fixtureKeyring.current
	for i := range a.ID {
		a.ID[i] = n
	}
	return Secret{Kind: SecretPassword, Keyring: fixtureKeyring.keyring.Snapshot(), Aliases: []Alias{a}}
}

var owner = Owner{Machine: "m1", PID: 4242, Start: "100"}

func (f *fixture) req(cred, host uuid.UUID, s Secret, kind Kind) Request {
	return Request{CredentialID: cred, HostID: host, Secret: s, Kind: kind, Stage: "ssh", Owner: owner,
		TTL: 5 * time.Minute}
}

// reserve reserves and fails the test on refusal.
func (f *fixture) reserve(cred, host uuid.UUID, s Secret, kind Kind) Submission {
	f.t.Helper()
	sub, err := f.store.Reserve(context.Background(), f.req(cred, host, s, kind))
	if err != nil {
		f.t.Fatalf("reserve %s: %v", kind, err)
	}
	return sub
}

func (f *fixture) settle(id uuid.UUID, o Outcome) Result {
	f.t.Helper()
	res, err := f.store.Settle(context.Background(), id, o)
	if err != nil {
		f.t.Fatalf("settle %s: %v", o, err)
	}
	return res
}

// activate takes a new secret through its automatic verification on the
// identity cred resolves to on host, leaving it ACTIVE there.
func (f *fixture) activate(cred, host uuid.UUID, s Secret) {
	f.t.Helper()
	sub := f.reserve(cred, host, s, KindVerification)
	if res := f.settle(sub.ID, OutcomeVerified); res.Recovery == uuid.Nil {
		f.t.Fatalf("activate: no recovery on an exact match")
	}
	f.wantMode(cred, host, s, ModeActive)
}

func (f *fixture) identity(cred, host uuid.UUID) uuid.UUID {
	f.t.Helper()
	id, err := f.store.Resolve(context.Background(), cred, host)
	if err != nil {
		f.t.Fatalf("resolve: %v", err)
	}
	return id
}

func (f *fixture) status(cred, host uuid.UUID, s Secret) Status {
	f.t.Helper()
	st, err := f.store.Status(context.Background(), cred, host, s)
	if err != nil {
		f.t.Fatalf("status: %v", err)
	}
	return st
}

func (f *fixture) mode(cred, host uuid.UUID, s Secret) Mode {
	f.t.Helper()
	return f.status(cred, host, s).Mode
}

// request asks for verification of s for cred's attempts on host.
func (f *fixture) request(cred, host uuid.UUID, s Secret) error {
	_, err := f.store.RequestVerification(context.Background(), cred, host, s, f.user)
	return err
}

// classify classifies cred, failing the test on refusal.
func (f *fixture) classify(cred uuid.UUID, to Target) {
	f.t.Helper()
	if err := f.store.Classify(context.Background(), cred, to); err != nil {
		f.t.Fatalf("classify %s: %v", to.Scope, err)
	}
}

// localCred is a credential for username classified local.
func (f *fixture) localCred(username string) uuid.UUID {
	f.t.Helper()
	c := f.cred(username)
	f.classify(c, Target{Scope: ScopeLocal})
	return c
}

// confirm confirms (host, username) as a local account.
func (f *fixture) confirm(host uuid.UUID, username string) {
	f.t.Helper()
	if err := f.store.ConfirmLocal(context.Background(), host, username, f.user, "inventory: local account"); err != nil {
		f.t.Fatalf("confirm local: %v", err)
	}
}

// directory creates a directory identity and checks its admission.
func (f *fixture) directory(name, username string, want Admission) uuid.UUID {
	f.t.Helper()
	id, adm, err := f.store.CreateDirectory(context.Background(), name, username)
	if err != nil {
		f.t.Fatalf("create directory: %v", err)
	}
	if adm != want {
		f.t.Fatalf("directory %s is %s, want %s", name, adm, want)
	}
	return id
}

// dirCred is a credential for username classified to directory d.
func (f *fixture) dirCred(username string, d uuid.UUID) uuid.UUID {
	f.t.Helper()
	c := f.cred(username)
	f.classify(c, Target{Scope: ScopeDirectory, Directory: d})
	return c
}

func (f *fixture) wantMode(cred, host uuid.UUID, s Secret, want Mode) {
	f.t.Helper()
	if got := f.mode(cred, host, s); got != want {
		f.t.Fatalf("mode = %s, want %s", got, want)
	}
}

func (f *fixture) wantRefused(err, want error) {
	f.t.Helper()
	if !errors.Is(err, want) {
		f.t.Fatalf("err = %v, want %v", err, want)
	}
}

func (f *fixture) count(query string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		f.t.Fatalf("count: %v", err)
	}
	return n
}

// block puts a block on P on the identity cred resolves to on host, by a
// rejected ordinary submission after activation.
func (f *fixture) block(cred, host uuid.UUID, s Secret) uuid.UUID {
	f.t.Helper()
	if f.mode(cred, host, s) != ModeActive {
		f.activate(cred, host, s)
	}
	sub := f.reserve(cred, host, s, KindOrdinary)
	res := f.settle(sub.ID, OutcomeRejected)
	if len(res.Blocks) != 1 {
		f.t.Fatalf("block: %d blocks", len(res.Blocks))
	}
	return res.Blocks[0]
}

// fresh is a fence read that finds c.
func fresh(c Current) func(context.Context, Reader) (Current, error) {
	return func(context.Context, Reader) (Current, error) { return c, nil }
}
