// @spec system-credential-protection
//
// The keyring check inside credprotect's own transactions (spec C-16), with
// real fingerprint keyrings: a password is admitted only while the keyring
// is the one its aliases were computed from, and outcomes are recorded
// under the keyring lock but never refused for an old or damaged keyring.

package credprotect

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/credprotect/fingerprint"
)

type uuidT = uuid.UUID

func keySecret(n byte) Secret {
	var a Alias
	a.ID[0] = n
	return Secret{Kind: SecretKey, Aliases: []Alias{a}}
}

// realPassword identifies a password through the fixture's real keyring.
func realPassword(password string) Secret {
	return PasswordSecret(fixtureKeyring.keyring, "ops", password)
}

// waitForLockWait waits until a backend in this database is waiting on a
// lock, as an operation blocked on the keyring row is.
func waitForLockWait(t *testing.T, f *fixture, done <-chan error) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	// A row lock waits on the holder's transaction, not on the table, so the
	// wait shows as a backend waiting for a lock.
	for f.count(`SELECT count(*) FROM pg_stat_activity
		WHERE datname = current_database() AND wait_event_type = 'Lock'`) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the operation did not wait for the keyring change")
		}
		select {
		case err := <-done:
			t.Fatalf("the operation finished while the keyring was locked: %v", err)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// @ac AC-17
func TestKeyring_AdmitsOnlyTheKeyringTheAliasesCameFrom(t *testing.T) {
	t.Run("system-credential-protection/AC-17", func(t *testing.T) {
		ctx := context.Background()
		t.Run("a real keyring's password is admitted and fenced", func(t *testing.T) {
			f := newFixture(t)
			c, h := f.cred("ops"), f.host()
			s := realPassword("synthetic-password")
			if len(s.Aliases) != 2 {
				t.Fatalf("aliases %d, want one per key", len(s.Aliases))
			}
			f.activate(c, h, s)
			sub := f.reserve(c, h, s, KindOrdinary)
			if err := f.store.Fence(ctx, sub.ID, fresh(Current{Active: true, Secret: s})); err != nil {
				t.Fatalf("fence: %v", err)
			}
		})
		// Damage after a password was identified, as a long-running process
		// holding a cached snapshot would meet it. Reserve, Status,
		// RequestVerification and an active Fence must each refuse it, and
		// nothing may be recorded.
		damage := []struct {
			name string
			q    string
			want error
		}{
			{"keys deleted", `DELETE FROM credprotect_fingerprint_keys`, ErrKeyringUnavailable},
			{"no current key", `UPDATE credprotect_fingerprint_keys SET is_current = false`, ErrKeyringUnavailable},
			// Still exactly one current key; only the snapshot shows it.
			{"the current flag moved to the other key", `UPDATE credprotect_fingerprint_keys SET is_current = NOT is_current`, ErrKeyringChanged},
			{"a wrapped key altered", `UPDATE credprotect_fingerprint_keys SET wrapped = '\x01'::bytea WHERE is_current`, ErrKeyringChanged},
			// One byte flipped, the length kept: only the bytes themselves
			// show it.
			{"a wrapped key's byte flipped", `UPDATE credprotect_fingerprint_keys
				SET wrapped = set_byte(wrapped, 20, get_byte(wrapped, 20) # 1) WHERE is_current`, ErrKeyringChanged},
			{"a key added", `INSERT INTO credprotect_fingerprint_keys (id, wrapped, is_current, created_at)
				VALUES (gen_random_uuid(), '\x02'::bytea, false, now())`, ErrKeyringChanged},
			{"the generation moved", `UPDATE credprotect_keyring SET generation = generation + 1`, ErrKeyringChanged},
			{"not initialized", `UPDATE credprotect_keyring SET initialized_at = NULL`, ErrKeyringUnavailable},
			{"the keyring row deleted", `DELETE FROM credprotect_keyring`, ErrKeyringUnavailable},
		}
		for _, d := range damage {
			t.Run(d.name, func(t *testing.T) {
				f := newFixture(t)
				c, h := f.cred("ops"), f.host()
				s := realPassword("synthetic-password")
				f.activate(c, h, s)
				sub := f.reserve(c, h, s, KindOrdinary)
				before := f.count(`SELECT count(*) FROM credprotect_submissions`)
				if _, err := f.pool.Exec(ctx, d.q); err != nil {
					t.Fatal(err)
				}
				f.wantRefused(f.store.Fence(ctx, sub.ID, fresh(Current{Active: true, Secret: s})), d.want)
				_, err := f.store.Reserve(ctx, f.req(c, h, s, KindOrdinary))
				f.wantRefused(err, d.want)
				_, err = f.store.Status(ctx, c, h, s)
				f.wantRefused(err, d.want)
				_, err = f.store.RequestVerification(ctx, c, h, s, f.user)
				f.wantRefused(err, d.want)
				if n := f.count(`SELECT count(*) FROM credprotect_submissions`); n != before {
					t.Errorf("%d submissions recorded against a damaged keyring", n-before)
				}
				if n := f.count(`SELECT count(*) FROM credprotect_verification_requests`); n != 0 {
					t.Errorf("%d verification requests recorded against a damaged keyring", n)
				}
				// A key secret is not identified through the keyring.
				if _, err := f.store.Status(ctx, c, h, keySecret(1)); errors.Is(err, ErrKeyringUnavailable) || errors.Is(err, ErrKeyringChanged) {
					t.Errorf("a key secret depends on the keyring: %v", err)
				}
			})
		}
		t.Run("an alias under a key the keyring does not hold", func(t *testing.T) {
			f := newFixture(t)
			s := pw(1)
			s.Aliases[0].KeyID = "00000000-0000-7000-8000-00000000dead"
			_, err := f.store.Reserve(ctx, f.req(f.cred("ops"), f.host(), s, KindOrdinary))
			f.wantRefused(err, ErrKeyringChanged)
		})
		t.Run("a password without a snapshot is invalid", func(t *testing.T) {
			f := newFixture(t)
			s := pw(1)
			s.Keyring = fingerprint.Snapshot{}
			_, err := f.store.Reserve(ctx, f.req(f.cred("ops"), f.host(), s, KindOrdinary))
			f.wantRefused(err, ErrInvalid)
		})
		t.Run("a keyring change and a reservation do not overlap", func(t *testing.T) {
			f := newFixture(t)
			c, h := f.cred("ops"), f.host()
			tx, err := f.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			if _, err := tx.Exec(ctx, `SELECT 1 FROM credprotect_keyring WHERE singleton FOR UPDATE`); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				_, err := f.store.Reserve(ctx, f.req(c, h, pw(1), KindOrdinary))
				done <- err
			}()
			waitForLockWait(t, f, done)
			if _, err := tx.Exec(ctx, `UPDATE credprotect_keyring SET generation = generation + 1`); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			f.wantRefused(<-done, ErrKeyringChanged)
		})
	})
}

// @ac AC-25
func TestKeyring_OutcomesWaitForAKeyringChangeAndAreAlwaysRecorded(t *testing.T) {
	t.Run("system-credential-protection/AC-25", func(t *testing.T) {
		ctx := context.Background()
		// hold takes the keyring row FOR UPDATE and moves the generation, as
		// a keyring change would, and returns its commit.
		hold := func(t *testing.T, f *fixture) func() {
			t.Helper()
			tx, err := f.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `SELECT 1 FROM credprotect_keyring WHERE singleton FOR UPDATE`); err != nil {
				t.Fatal(err)
			}
			// A test that fails before release must not leave the row
			// locked for every later fixture.
			t.Cleanup(func() { _ = tx.Rollback(ctx) })
			if _, err := tx.Exec(ctx, `UPDATE credprotect_keyring SET generation = generation + 1`); err != nil {
				t.Fatal(err)
			}
			return func() {
				if err := tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
			}
		}
		t.Run("a settlement waits, then records a rejection under the new generation", func(t *testing.T) {
			f := newFixture(t)
			c, h := f.cred("ops"), f.host()
			s := realPassword("synthetic-password")
			f.activate(c, h, s)
			sub := f.reserve(c, h, s, KindOrdinary)
			release := hold(t, f)
			done := make(chan error, 1)
			go func() {
				_, err := f.store.Settle(ctx, sub.ID, OutcomeRejected)
				done <- err
			}()
			waitForLockWait(t, f, done)
			release()
			if err := <-done; err != nil {
				t.Fatalf("the rejection was not recorded after a keyring change: %v", err)
			}
			if n := f.count(`SELECT count(*) FROM credprotect_restrictions WHERE kind = 'block' AND submission_id = $1`, sub.ID); n != 1 {
				t.Errorf("%d blocks recorded, want 1", n)
			}
		})
		t.Run("a verification's settlement waits too", func(t *testing.T) {
			// The review's reproduction: settlement used to complete while a
			// keyring change held the row.
			f := newFixture(t)
			c, h := f.cred("ops"), f.host()
			s := realPassword("synthetic-password")
			sub := f.reserve(c, h, s, KindVerification)
			release := hold(t, f)
			done := make(chan error, 1)
			go func() {
				_, err := f.store.Settle(ctx, sub.ID, OutcomeVerified)
				done <- err
			}()
			waitForLockWait(t, f, done)
			release()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
		t.Run("every path that records an outcome waits", func(t *testing.T) {
			for name, op := range map[string]func(f *fixture, id uuidT) error{
				"Settle": func(f *fixture, id uuidT) error { _, err := f.store.Settle(ctx, id, OutcomeRejected); return err },
				"Expire": func(f *fixture, _ uuidT) error { _, err := f.store.Expire(ctx); return err },
				"ReleaseIfTerminated": func(f *fixture, id uuidT) error {
					_, err := f.store.ReleaseIfTerminated(ctx, id)
					if errors.Is(err, ErrNotTerminated) {
						return nil // it waited for the lock before deciding
					}
					return err
				},
				"Override": func(f *fixture, id uuidT) error { return f.store.Override(ctx, id, f.user, "stalled", true) },
			} {
				t.Run(name, func(t *testing.T) {
					f := newFixture(t)
					c, h := f.cred("ops"), f.host()
					s := realPassword("synthetic-password")
					f.activate(c, h, s)
					sub := f.reserve(c, h, s, KindOrdinary)
					f.clock.Advance(24 * time.Hour) // so Expire has a submission to lock
					release := hold(t, f)
					done := make(chan error, 1)
					go func() { done <- op(f, sub.ID) }()
					waitForLockWait(t, f, done)
					release()
					if err := <-done; err != nil {
						t.Fatalf("%s after the keyring change: %v", name, err)
					}
				})
			}
		})
		t.Run("an expiry records unknown against a damaged keyring", func(t *testing.T) {
			f := newFixture(t)
			c, h := f.cred("ops"), f.host()
			s := realPassword("synthetic-password")
			f.activate(c, h, s)
			sub := f.reserve(c, h, s, KindOrdinary)
			if _, err := f.pool.Exec(ctx, `DELETE FROM credprotect_fingerprint_keys`); err != nil {
				t.Fatal(err)
			}
			f.clock.Advance(24 * time.Hour)
			if n, err := f.store.Expire(ctx); err != nil || n != 1 {
				t.Fatalf("expire: %d, %v", n, err)
			}
			var outcome string
			if err := f.pool.QueryRow(ctx, `SELECT coalesce(outcome, '') FROM credprotect_submissions WHERE id = $1`, sub.ID).Scan(&outcome); err != nil {
				t.Fatal(err)
			}
			if outcome != string(OutcomeUnknown) {
				t.Errorf("outcome %q, want unknown", outcome)
			}
		})
	})
}
