// @spec api-users
//
// A committed disable or enable is reported as committed, even when the
// database cannot be read after the commit (C-08, AC-21).

package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// breakReadsAfterCommit commits for real, then renames the users table on
// another connection so any read of it after the commit fails.
type breakReadsAfterCommit struct {
	inner identity.TxBeginner
	pool  *pgxpool.Pool
	t     *testing.T
}

type breakReadsTx struct {
	pgx.Tx
	b *breakReadsAfterCommit
}

func (b *breakReadsAfterCommit) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := b.inner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &breakReadsTx{Tx: tx, b: b}, nil
}

func (tx *breakReadsTx) Commit(ctx context.Context) error {
	if err := tx.Tx.Commit(ctx); err != nil {
		return err
	}
	if _, err := tx.b.pool.Exec(context.Background(), `ALTER TABLE users RENAME TO users_ac21`); err != nil {
		tx.b.t.Errorf("break reads after the commit: %v", err)
	}
	return nil
}

func restoreUsersTable(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var n int
	_ = pool.QueryRow(context.Background(), `SELECT count(*) FROM pg_class WHERE relname = 'users_ac21'`).Scan(&n)
	if n == 1 {
		if _, err := pool.Exec(context.Background(), `ALTER TABLE users_ac21 RENAME TO users`); err != nil {
			t.Fatalf("RESTORE users table: %v", err)
		}
	}
}

// @ac AC-21
// AC-21: a disable or enable that commits answers 200 with the committed
// state even when nothing can be read after the commit. It is never
// reported as not applied or not found, and nothing invites repeating it.
func TestAdminAccountChange_CommittedIsReportedAsCommitted(t *testing.T) {
	t.Run("api-users/AC-21", func(t *testing.T) {
		url, pool, srv := freshAPIServerWithHandles(t)
		ctx := context.Background()
		t.Cleanup(func() { restoreUsersTable(t, pool) })

		for _, tc := range []struct {
			name         string
			path         string
			disableFirst bool
			wantDisabled bool
		}{
			{"disable", ":disable", false, true},
			{"enable", ":enable", true, false},
		} {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				li := loginFresh(t, url, pool, "ac21"+tc.name)
				if tc.disableFirst {
					if _, err := srv.handlers.users.DisableUser(ctx, li.u.ID); err != nil {
						t.Fatalf("disable: %v", err)
					}
				}
				srv.handlers.users.UseTxSource(&breakReadsAfterCommit{inner: pool, pool: pool, t: t})
				got := doAPI(t, asRole(t, "POST", url+"/api/v1/users/"+li.u.ID.String()+tc.path, auth.RoleAdmin, nil))
				srv.handlers.users.UseTxSource(nil)
				restoreUsersTable(t, pool)

				if got.status != http.StatusOK {
					t.Fatalf("response = %d %q %q, want 200 for a committed change", got.status, got.code, got.message)
				}
				if got.retryable || got.code != "" {
					t.Errorf("the response carries an error envelope (%q retryable=%v) for a committed change", got.code, got.retryable)
				}
				if disabledAt := got.body["disabled_at"]; (disabledAt != nil) != tc.wantDisabled {
					t.Errorf("response disabled_at = %v, want set=%v", disabledAt, tc.wantDisabled)
				}
				if isDisabled(t, pool, li.u.ID) != tc.wantDisabled {
					t.Errorf("durable disabled state = %v, want %v", !tc.wantDisabled, tc.wantDisabled)
				}
				if s, r := liveCounts(t, pool, li.u.ID); s != 0 || r != 0 {
					t.Errorf("live credentials after the committed %s = %d/%d, want 0/0", tc.name, s, r)
				}
			})
		}
	})
}
