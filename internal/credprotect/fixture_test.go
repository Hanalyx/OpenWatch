package credprotect

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

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
		"credprotect_identity_edges", "credprotect_identities",
	} {
		if _, err := pool.Exec(ctx, "TRUNCATE "+table+" CASCADE"); err != nil {
			t.Fatalf("truncate %s: %v", table, err)
		}
	}
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
func pw(n byte) Secret {
	var a Alias
	a.KeyID = "k1"
	for i := range a.ID {
		a.ID[i] = n
	}
	return Secret{Kind: SecretPassword, Aliases: []Alias{a}}
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

func (f *fixture) mode(cred, host uuid.UUID, s Secret) Mode {
	f.t.Helper()
	st, err := f.store.Status(context.Background(), f.identity(cred, host), s)
	if err != nil {
		f.t.Fatalf("status: %v", err)
	}
	return st.Mode
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
