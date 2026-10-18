// @spec system-ssh-connectivity
//
// The protected dial with the real credential-protection store and a
// loaded fingerprint keyring (spec C-15). The bound is asserted by
// counting what the SSH server received, never by counting calls in
// OpenWatch.

package ssh

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/credential"
	"github.com/Hanalyx/openwatch/internal/credprotect"
	"github.com/Hanalyx/openwatch/internal/credprotect/fingerprint"
	"github.com/Hanalyx/openwatch/internal/db/dbtest"
	"github.com/Hanalyx/openwatch/internal/secretkey"
)

// protectedFixture is a store, a loaded keyring, and one credential and
// host seeded for them. The stored ciphertext is a placeholder: the dial
// takes the credential from the caller, and Current from the test.
type protectedFixture struct {
	pool    *pgxpool.Pool
	store   *credprotect.Store
	keyring fingerprint.Keyring
	credID  uuid.UUID
	hostID  uuid.UUID
}

func newProtectedFixture(t *testing.T, username string) *protectedFixture {
	t.Helper()
	pool := dbtest.Pool(t)
	ctx := context.Background()
	for _, q := range []string{
		`TRUNCATE credprotect_verified_secrets, credprotect_verification_requests, credprotect_recoveries,
		          credprotect_submissions, credprotect_restrictions, credprotect_credential_classes,
		          credprotect_directory_bindings, credprotect_directory_resolutions, credprotect_identities CASCADE`,
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
	dek, err := secretkey.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	kr, err := fingerprint.Load(ctx, pool, dek, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f := &protectedFixture{pool: pool, store: credprotect.New(pool), keyring: kr,
		credID: uuid.Must(uuid.NewV7()), hostID: uuid.Must(uuid.NewV7())}
	user := uuid.Must(uuid.NewV7())
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO users (id, username, email, password_hash) VALUES ($1, $2, $3, 'argon2id$dummy')`, // pragma: allowlist secret
			[]any{user, "pd-" + user.String(), user.String() + "@example.com"}},
		{`INSERT INTO hosts (id, hostname, ip_address, created_by) VALUES ($1, $2, '192.0.2.10'::inet, $3)`,
			[]any{f.hostID, "host-" + f.hostID.String(), user}},
		{`INSERT INTO credentials (id, scope, scope_id, name, username, auth_method,
		                           encrypted_password, is_default, is_active, created_by)
		  VALUES ($1, 'system', NULL, $2, $3, 'password', '\x01'::bytea, false, true, $4)`,
			[]any{f.credID, "cred-" + f.credID.String(), username, user}},
	} {
		if _, err := pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	return f
}

func (f *protectedFixture) opts(stored *credential.Credential, kind credprotect.Kind) ProtectedOptions {
	return ProtectedOptions{
		Mode: ModeTOFU, Timeout: 5 * time.Second,
		Protection: f.store, CredentialID: f.credID, HostID: f.hostID,
		Secret: SecretKindPassword, Keyring: f.keyring, Kind: kind,
		Current: func(context.Context, credprotect.Reader) (*credential.Credential, error) {
			c := *stored
			return &c, nil
		},
	}
}

func (f *protectedFixture) mode(t *testing.T, pw string) credprotect.Mode {
	t.Helper()
	st, err := f.store.Status(context.Background(), f.credID, f.hostID,
		credprotect.PasswordSecret(f.keyring, "ops", pw))
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode
}

// @ac AC-32
// AC-32: with the real store, reservations and the fence bound what a
// host receives. After a rotation, eight workers dialing at once with the
// old password reach the host once in total, and nothing more is sent
// until the operator acts; a fence refusal sends nothing and changes
// nothing.
func TestProtectedDial_BoundsWhatTheHostReceives(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-32", func(t *testing.T) {
		ctx := context.Background()

		t.Run("one submission of a rotated-out password, fleet-wide", func(t *testing.T) {
			f := newProtectedFixture(t, "ops")
			p1 := activePassword("ops", "P1")

			// Before the rotation: P1 is verified, so ordinary work may run.
			host, port, _ := startCountingServer(t, countingServer{password: "P1", offerPassword: true,
				kbdRounds: []kbdRound{hiddenPrompt}, kbdPassword: "P1"})
			if _, err := protectedDial(t, host, port, p1, f.opts(p1, credprotect.KindVerification)); err != nil {
				t.Fatalf("verification: %v", err)
			}
			if m := f.mode(t, "P1"); m != credprotect.ModeActive {
				t.Fatalf("after verification: %s", m)
			}

			// The host's password is rotated to P2; OpenWatch still holds P1.
			host, port, got := startCountingServer(t, countingServer{password: "P2", offerPassword: true,
				kbdRounds: []kbdRound{hiddenPrompt}, kbdPassword: "P2"})
			const workers = 8
			errs := make([]error, workers)
			var wg sync.WaitGroup
			start := make(chan struct{})
			for i := range workers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					_, errs[i] = protectedDial(t, host, port, p1, f.opts(p1, credprotect.KindOrdinary))
				}()
			}
			close(start)
			wg.Wait()
			if n := got.secretBearing(); n != 1 {
				t.Fatalf("the host received %d secret-bearing requests from %d workers, want 1", n, workers)
			}
			failed, refused := 0, 0
			for _, err := range errs {
				switch {
				case errors.Is(err, ErrAuthFailed):
					failed++
				case errors.Is(err, ErrProtected):
					refused++
				default:
					t.Errorf("unexpected error: %v", err)
				}
			}
			if failed != 1 || refused != workers-1 {
				t.Fatalf("%d failed and %d refused, want 1 and %d", failed, refused, workers-1)
			}
			if m := f.mode(t, "P1"); m != credprotect.ModeBlocked {
				t.Fatalf("after the failure: %s, want BLOCKED", m)
			}

			// Every later dial with P1 is refused before it connects.
			for range 5 {
				_, err := protectedDial(t, host, port, p1, f.opts(p1, credprotect.KindOrdinary))
				if !errors.Is(err, credprotect.ErrBlocked) {
					t.Fatalf("a later dial: %v, want ErrBlocked", err)
				}
			}
			if n := got.secretBearing(); n != 1 {
				t.Fatalf("the host received %d secret-bearing requests in all, want 1", n)
			}
		})

		t.Run("a fence refusal sends nothing and changes nothing", func(t *testing.T) {
			f := newProtectedFixture(t, "ops")
			p1 := activePassword("ops", "P1")
			host, port, got := startCountingServer(t, countingServer{password: "P1", offerPassword: true})
			if _, err := protectedDial(t, host, port, p1, f.opts(p1, credprotect.KindVerification)); err != nil {
				t.Fatalf("verification: %v", err)
			}
			for name, stored := range map[string]*credential.Credential{
				"deactivated":           {Username: "ops", Password: "P1"},
				"edited to a new value": activePassword("ops", "P2"),
			} {
				before := got.secretBearing()
				_, err := protectedDial(t, host, port, p1, f.opts(stored, credprotect.KindOrdinary))
				if !errors.Is(err, credprotect.ErrFenceRefused) {
					t.Fatalf("%s: %v, want ErrFenceRefused", name, err)
				}
				if n := got.secretBearing() - before; n != 0 {
					t.Fatalf("%s: the host received %d secret-bearing requests", name, n)
				}
				if m := f.mode(t, "P1"); m != credprotect.ModeActive {
					t.Fatalf("%s: mode %s after a refusal, want ACTIVE unchanged", name, m)
				}
			}
			var open int
			if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM credprotect_submissions WHERE slot_held`).Scan(&open); err != nil {
				t.Fatal(err)
			}
			if open != 0 {
				t.Fatalf("%d submissions still hold a slot", open)
			}
		})
	})
}

// editBeforeFence commits a credential edit through the credential service
// after the dial has asked for the fence and before the store's fence
// takes its locks, then runs the real fence.
type editBeforeFence struct {
	*credprotect.Store
	edit   func(context.Context) error
	edited bool
}

func (p *editBeforeFence) Fence(ctx context.Context, id uuid.UUID, read func(context.Context, credprotect.Reader) (credprotect.Current, error)) error {
	if err := p.edit(ctx); err != nil {
		return err
	}
	p.edited = true
	return p.Store.Fence(ctx, id, read)
}

// @ac AC-33
// AC-33: the fence checks the credential as the credential service holds
// it at the fence. A password rotation or a soft deletion committed through
// the service just before the store's fence sends nothing.
func TestProtectedDial_FenceSeesCredentialEdits(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-33", func(t *testing.T) {
		for _, which := range []string{"password rotation", "soft deletion"} {
			t.Run(which, func(t *testing.T) {
				ctx := context.Background()
				f := newProtectedFixture(t, "ops")
				if err := secretkey.SetEphemeral(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(secretkey.Reset)
				key, err := secretkey.Active()
				if err != nil {
					t.Fatal(err)
				}
				enc, err := key.Encrypt([]byte("P1"))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.pool.Exec(ctx, `UPDATE credentials SET encrypted_password = $2 WHERE id = $1`, f.credID, enc); err != nil {
					t.Fatal(err)
				}
				svc := credential.NewService(f.pool)
				p1, err := svc.GetByID(ctx, f.credID)
				if err != nil {
					t.Fatal(err)
				}
				opts := f.opts(p1, credprotect.KindVerification)
				opts.Current = func(ctx context.Context, db credprotect.Reader) (*credential.Credential, error) {
					return credential.GetByIDWith(ctx, db, f.credID)
				}
				host, port, _ := startCountingServer(t, countingServer{password: "P1", offerPassword: true})
				if _, err := protectedDial(t, host, port, p1, opts); err != nil {
					t.Fatalf("verification: %v", err)
				}

				hostPW, edit := "P1", func(ctx context.Context) error { return svc.SoftDelete(ctx, f.credID) }
				if which == "password rotation" {
					hostPW = "P2"
					edit = func(ctx context.Context) error {
						pw := "P2"
						_, err := svc.Update(ctx, credential.UpdateParams{ID: f.credID, Password: &pw})
						return err
					}
				}
				host, port, got := startCountingServer(t, countingServer{password: hostPW, offerPassword: true})
				p := &editBeforeFence{Store: f.store, edit: edit}
				opts.Protection, opts.Kind = p, credprotect.KindOrdinary
				_, err = protectedDial(t, host, port, p1, opts)
				if !p.edited {
					t.Fatal("the edit did not run")
				}
				if n := got.secretBearing(); n != 0 {
					t.Fatalf("the host received %d secret-bearing requests after the %s", n, which)
				}
				if !errors.Is(err, credprotect.ErrFenceRefused) {
					t.Fatalf("err = %v, want ErrFenceRefused", err)
				}
			})
		}
	})
}
