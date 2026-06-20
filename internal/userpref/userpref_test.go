// @spec system-user-preferences
//
// Service-level storage + merge semantics. DSN-gated: skipped without
// OPENWATCH_TEST_DSN.

package userpref

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/db/dbtest"
)

func freshService(t *testing.T) (*Service, *pgxpool.Pool) {
	t.Helper()
	pool := dbtest.Pool(t)
	_, _ = pool.Exec(context.Background(), "TRUNCATE TABLE users CASCADE")
	return NewService(pool), pool
}

func seedUser(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO users (id, username, email, password_hash)
		 VALUES ($1, $2, $3, $4)`,
		id, "pref-"+id.String(), id.String()+"@example.com",
		"$argon2id$v=19$m=65536,t=3,p=1$00$00")
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

// @ac AC-05
func TestUserPref_Service_GetMerge(t *testing.T) {
	t.Run("system-user-preferences/AC-05", func(t *testing.T) {
		svc, pool := freshService(t)
		ctx := context.Background()
		uid := seedUser(t, pool)

		// Default column → "{}".
		raw, err := svc.Get(ctx, uid)
		if err != nil {
			t.Fatalf("Get default: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil || len(m) != 0 {
			t.Fatalf("default prefs = %s, want empty object", raw)
		}

		// Merge two keys across two calls — shallow merge retains the first.
		if _, err := svc.Merge(ctx, uid, json.RawMessage(`{"hosts_view_default":"table"}`)); err != nil {
			t.Fatalf("Merge 1: %v", err)
		}
		merged, err := svc.Merge(ctx, uid, json.RawMessage(`{"density":"compact"}`))
		if err != nil {
			t.Fatalf("Merge 2: %v", err)
		}
		_ = json.Unmarshal(merged, &m)
		if m["hosts_view_default"] != "table" || m["density"] != "compact" {
			t.Errorf("merged = %s, want both keys retained", merged)
		}

		// Unknown user → ErrUserNotFound on both Get and Merge.
		ghost, _ := uuid.NewV7()
		if _, err := svc.Get(ctx, ghost); !errors.Is(err, ErrUserNotFound) {
			t.Errorf("Get(ghost) err = %v, want ErrUserNotFound", err)
		}
		if _, err := svc.Merge(ctx, ghost, json.RawMessage(`{"density":"compact"}`)); !errors.Is(err, ErrUserNotFound) {
			t.Errorf("Merge(ghost) err = %v, want ErrUserNotFound", err)
		}

		// A non-object patch is rejected before touching the column.
		if _, err := svc.Merge(ctx, uid, json.RawMessage(`"scalar"`)); err == nil {
			t.Error("Merge(scalar) err = nil, want rejection")
		}
	})
}
