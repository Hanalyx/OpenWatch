// @spec system-credential-protection
//
// The keyring check inside credprotect's own transactions (spec C-16): a
// password whose aliases come from another keyring generation, or a keyring
// that is missing or uninitialized, is refused before anything is recorded.

package credprotect

import (
	"context"
	"errors"
	"testing"
	"time"
)

func keySecret(n byte) Secret {
	var a Alias
	a.ID[0] = n
	return Secret{Kind: SecretKey, Aliases: []Alias{a}}
}

func stale(s Secret) Secret {
	s.KeyringGeneration = testGeneration + 1
	return s
}

// @ac AC-17
func TestKeyring_RefusesStaleOrMissingKeyring(t *testing.T) {
	t.Run("system-credential-protection/AC-17", func(t *testing.T) {
		ctx := context.Background()
		t.Run("a stale generation is refused everywhere, recording nothing", func(t *testing.T) {
			f := newFixture(t)
			c, h := f.cred("ops"), f.host()
			_, err := f.store.Reserve(ctx, f.req(c, h, stale(pw(1)), KindOrdinary))
			f.wantRefused(err, ErrKeyringChanged)
			_, err = f.store.Status(ctx, c, h, stale(pw(1)))
			f.wantRefused(err, ErrKeyringChanged)
			_, err = f.store.RequestVerification(ctx, c, h, stale(pw(1)), f.user)
			f.wantRefused(err, ErrKeyringChanged)
			if n := f.count(`SELECT count(*) FROM credprotect_submissions`); n != 0 {
				t.Errorf("%d submissions recorded under a stale generation", n)
			}
			if n := f.count(`SELECT count(*) FROM credprotect_verification_requests`); n != 0 {
				t.Errorf("%d verification requests recorded under a stale generation", n)
			}
			// The fence refuses a stale secret before it compares it.
			f.activate(c, h, pw(1))
			sub := f.reserve(c, h, pw(1), KindOrdinary)
			f.wantRefused(f.store.Fence(ctx, sub.ID, Current{Active: true, Secret: stale(pw(1))}), ErrKeyringChanged)
			if err := f.store.Fence(ctx, sub.ID, Current{Active: true, Secret: pw(1)}); err != nil {
				t.Errorf("the fence refused the current generation: %v", err)
			}
		})
		t.Run("an uninitialized or missing keyring is unavailable", func(t *testing.T) {
			for name, change := range map[string]string{
				"uninitialized": `UPDATE credprotect_keyring SET initialized_at = NULL`,
				"row missing":   `DELETE FROM credprotect_keyring`,
			} {
				t.Run(name, func(t *testing.T) {
					f := newFixture(t)
					c, h := f.cred("ops"), f.host()
					if _, err := f.pool.Exec(ctx, change); err != nil {
						t.Fatal(err)
					}
					_, err := f.store.Reserve(ctx, f.req(c, h, pw(1), KindOrdinary))
					f.wantRefused(err, ErrKeyringUnavailable)
					_, err = f.store.Status(ctx, c, h, pw(1))
					f.wantRefused(err, ErrKeyringUnavailable)
					// A key secret is not identified through the keyring.
					if _, err := f.store.Status(ctx, c, h, keySecret(1)); errors.Is(err, ErrKeyringUnavailable) || errors.Is(err, ErrKeyringChanged) {
						t.Errorf("a key secret depends on the keyring: %v", err)
					}
				})
			}
		})
		t.Run("a password without a generation is invalid", func(t *testing.T) {
			f := newFixture(t)
			s := pw(1)
			s.KeyringGeneration = 0
			_, err := f.store.Reserve(ctx, f.req(f.cred("ops"), f.host(), s, KindOrdinary))
			f.wantRefused(err, ErrInvalid)
		})
		t.Run("a keyring change and a reservation do not overlap", func(t *testing.T) {
			// A keyring change holds the row FOR UPDATE and raises the
			// generation. A reservation that starts meanwhile waits for it,
			// then sees the new generation and is refused.
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
			deadline := time.Now().Add(5 * time.Second)
			// A row lock waits on the holder's transaction, not on the
			// table, so the wait shows as a backend waiting for a lock.
			for f.count(`SELECT count(*) FROM pg_stat_activity
				WHERE datname = current_database() AND wait_event_type = 'Lock'
				AND query LIKE '%credprotect_keyring%'`) == 0 {
				if time.Now().After(deadline) {
					t.Fatal("the reservation did not wait for the keyring change")
				}
				select {
				case err := <-done:
					t.Fatalf("the reservation finished while the keyring was locked: %v", err)
				default:
				}
				time.Sleep(10 * time.Millisecond)
			}
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
