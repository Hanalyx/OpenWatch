// @spec system-credential-protection

package credprotect

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// @ac AC-26
// AC-26: the fence reads the credential under its own lock on the
// credential row. An edit to the row waits until the fence has finished,
// and the row's own active flag refuses, whatever the read reports.
func TestFence_ReadsTheCredentialUnderItsLock(t *testing.T) {
	t.Run("system-credential-protection/AC-26", func(t *testing.T) {
		ctx := context.Background()

		t.Run("an edit waits for the fence", func(t *testing.T) {
			f := newFixture(t)
			c, h := f.cred("ops"), f.host()
			f.activate(c, h, pw(1))
			sub := f.reserve(c, h, pw(1), KindOrdinary)
			edited := make(chan error, 1)
			read := func(context.Context, Reader) (Current, error) {
				go func() {
					_, err := f.pool.Exec(ctx, `UPDATE credentials SET is_active = false WHERE id = $1`, c)
					edited <- err
				}()
				select {
				case err := <-edited:
					t.Errorf("the edit committed while the fence read the credential: %v", err)
				case <-time.After(300 * time.Millisecond):
				}
				return Current{Active: true, Secret: pw(1)}, nil
			}
			if err := f.store.Fence(ctx, sub.ID, read); err != nil {
				t.Fatalf("fence: %v", err)
			}
			select {
			case err := <-edited:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the edit did not resume after the fence")
			}
		})

		t.Run("the row's active flag refuses", func(t *testing.T) {
			f := newFixture(t)
			c, h := f.cred("ops"), f.host()
			f.activate(c, h, pw(1))
			sub := f.reserve(c, h, pw(1), KindOrdinary)
			if _, err := f.pool.Exec(ctx, `UPDATE credentials SET is_active = false WHERE id = $1`, c); err != nil {
				t.Fatal(err)
			}
			f.wantRefused(f.store.Fence(ctx, sub.ID, fresh(Current{Active: true, Secret: pw(1)})), ErrFenceRefused)
		})

		t.Run("a read that fails refuses", func(t *testing.T) {
			f := newFixture(t)
			c, h := f.cred("ops"), f.host()
			f.activate(c, h, pw(1))
			sub := f.reserve(c, h, pw(1), KindOrdinary)
			down := errors.New("store down")
			read := func(context.Context, Reader) (Current, error) { return Current{}, down }
			err := f.store.Fence(ctx, sub.ID, read)
			f.wantRefused(err, ErrFenceRefused)
			if !errors.Is(err, down) {
				t.Fatalf("the refusal does not carry the read's error: %v", err)
			}
		})
	})
}

// @ac AC-27
// AC-27: a fence takes no second connection. N fences for N healthy,
// independent credentials, on a pool of exactly N connections, each held
// inside its read until all have entered, all pass: each read goes through
// the fence's own transaction.
func TestFence_TakesNoSecondConnection(t *testing.T) {
	t.Run("system-credential-protection/AC-27", func(t *testing.T) {
		for _, conns := range []int32{1, 2, 4} {
			n := int(conns)
			t.Run(fmt.Sprintf("%d connections", conns), func(t *testing.T) {
				f := newFixture(t)
				cfg := f.pool.Config()
				cfg.MaxConns = conns
				pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer pool.Close()
				store := New(pool, WithClock(f.clock), WithProcesses(f.procs))
				creds := make([]uuid.UUID, n)
				subs := make([]Submission, n)
				for i := range n {
					creds[i] = f.cred(fmt.Sprintf("pool%d", i))
					h := f.host()
					f.activate(creds[i], h, pw(1))
					subs[i] = f.reserve(creds[i], h, pw(1), KindOrdinary)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				entered := make(chan struct{}, n)
				release := make(chan struct{})
				results := make(chan error, n)
				for i := range n {
					go func() {
						results <- store.Fence(ctx, subs[i].ID, func(ctx context.Context, db Reader) (Current, error) {
							entered <- struct{}{}
							select {
							case <-release:
							case <-ctx.Done():
								return Current{}, ctx.Err()
							}
							var active bool
							err := db.QueryRow(ctx, `SELECT is_active FROM credentials WHERE id = $1`, creds[i]).Scan(&active)
							return Current{Active: active, Secret: pw(1)}, err
						})
					}()
				}
				for range n {
					select {
					case <-entered:
					case <-ctx.Done():
						t.Fatal("the fences did not all reach their reads")
					}
				}
				if got := pool.Stat().AcquiredConns(); got != conns {
					t.Fatalf("%d connections held with every fence inside its read, want %d", got, n)
				}
				close(release)
				for range n {
					if err := <-results; err != nil {
						t.Errorf("a healthy fence failed: %v", err)
					}
				}
			})
		}
	})
}
