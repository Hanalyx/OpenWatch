// @spec system-account-policy
//
// AC traceability:
//
//	AC-01  TestPwExpiryDecision (pure classification; non-DB)
//	AC-02  TestSweepOnce_EmitsForWindowAndExpired (DB integration)
package accountpolicy

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/db/dbtest"
	"github.com/Hanalyx/openwatch/internal/intelligence/collector"
	"github.com/Hanalyx/openwatch/internal/systemconfig"
	"github.com/jackc/pgx/v5/pgxpool"
)

func ptr(n int) *int { return &n }

func userWithExpiry(uid int, exp *time.Time) collector.UserSnapshot {
	u := collector.UserSnapshot{UID: uid, PasswordExpiresAt: exp}
	if exp != nil {
		u.MaxDays = ptr(90)
		u.LastChangeDays = ptr(0)
	}
	return u
}

// @ac AC-01
// AC-01: pwExpiryDecision notifies only for human accounts (UID >= 1000, not
// nobody) that have an expiry policy and are expired OR within the warn
// window; system accounts, no-policy accounts, and healthy accounts are
// skipped. daysLeft is negative-or-zero when already expired.
func TestPwExpiryDecision(t *testing.T) {
	t.Run("system-account-policy/AC-01", func(t *testing.T) {
		now := time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC)
		warn := 14
		in := func(days int) *time.Time { d := now.AddDate(0, 0, days); return &d }

		cases := []struct {
			name       string
			u          collector.UserSnapshot
			wantNotify bool
			wantExpire bool
		}{
			{"expiring within window", userWithExpiry(1000, in(9)), true, false},
			{"expired", userWithExpiry(1000, in(-3)), true, true},
			{"healthy beyond window", userWithExpiry(1000, in(40)), false, false},
			{"no policy (nil expiry)", collector.UserSnapshot{UID: 1000}, false, false},
			{"system account uid<1000", userWithExpiry(999, in(2)), false, false},
			{"nobody 65534", userWithExpiry(65534, in(2)), false, false},
			{"boundary: exactly warn days", userWithExpiry(1000, in(14)), true, false},
		}
		for _, c := range cases {
			notify, daysLeft, expired := pwExpiryDecision(c.u, now, warn)
			if notify != c.wantNotify {
				t.Errorf("%s: notify=%v, want %v", c.name, notify, c.wantNotify)
			}
			if notify && expired != c.wantExpire {
				t.Errorf("%s: expired=%v, want %v", c.name, expired, c.wantExpire)
			}
			if c.wantNotify && c.wantExpire && daysLeft > 0 {
				t.Errorf("%s: expired daysLeft=%d, want <= 0", c.name, daysLeft)
			}
		}
	})
}

// recordingNotifier captures PasswordExpiring calls.
type recordingNotifier struct {
	calls []struct {
		host    uuid.UUID
		user    string
		expired bool
	}
}

func (r *recordingNotifier) PasswordExpiring(_ context.Context, hostID uuid.UUID, user string, _ int, expired bool) error {
	r.calls = append(r.calls, struct {
		host    uuid.UUID
		user    string
		expired bool
	}{hostID, user, expired})
	return nil
}

type fixedConfig struct{ warn int }

func (f fixedConfig) LoadSecurity(context.Context) (systemconfig.SecurityConfig, error) {
	return systemconfig.SecurityConfig{WarnDaysBeforePasswordExpiry: f.warn}, nil
}

// @ac AC-02
// AC-02: SweepOnce reads every host_intelligence_state snapshot and emits one
// notification per human account that is expired or within the warn window,
// skipping system/no-policy/healthy accounts.
func TestSweepOnce_EmitsForWindowAndExpired(t *testing.T) {
	t.Run("system-account-policy/AC-02", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		hostID := seedHost(t, pool)
		now := time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC)
		in := func(days int) *time.Time { d := now.AddDate(0, 0, days); return &d }

		users := map[string]collector.UserSnapshot{
			"expiring": userWithExpiry(1000, in(5)),  // within window → notify
			"expired":  userWithExpiry(1001, in(-2)), // expired → notify
			"healthy":  userWithExpiry(1002, in(60)), // beyond window → skip
			"nopolicy": {UID: 1003},                  // no policy → skip
			"daemon":   userWithExpiry(2, in(1)),     // system account → skip
		}
		seedSnapshot(t, pool, hostID, users)

		rec := &recordingNotifier{}
		svc := New(pool, rec, fixedConfig{warn: 14})
		svc.now = func() time.Time { return now }

		n, err := svc.SweepOnce(ctx)
		if err != nil {
			t.Fatalf("SweepOnce: %v", err)
		}
		if n != 2 {
			t.Fatalf("emitted=%d, want 2 (expiring + expired)", n)
		}
		got := map[string]bool{}
		for _, c := range rec.calls {
			got[c.user] = c.expired
		}
		if _, ok := got["expiring"]; !ok {
			t.Error("expiring account not notified")
		}
		if exp, ok := got["expired"]; !ok || !exp {
			t.Error("expired account not notified with expired=true")
		}
		for _, skip := range []string{"healthy", "nopolicy", "daemon"} {
			if _, ok := got[skip]; ok {
				t.Errorf("%s should not be notified", skip)
			}
		}
	})
}

func freshPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := dbtest.Pool(t)
	ctx := context.Background()
	for _, stmt := range []string{
		"TRUNCATE TABLE host_intelligence_state CASCADE",
		"TRUNCATE TABLE hosts CASCADE",
		"TRUNCATE TABLE users CASCADE",
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Logf("truncate (ok if benign): %v", err)
		}
	}
	return pool
}

func seedHost(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	creator := uuid.Must(uuid.NewV7())
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO users (id, username, email, password_hash) VALUES ($1,$2,$3,$4)`,
		creator, "ap-user", "ap@example.com", "argon2id$dummy"); err != nil { // pragma: allowlist secret
		t.Fatalf("seed user: %v", err)
	}
	id := uuid.Must(uuid.NewV7())
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO hosts (id, hostname, ip_address, created_by) VALUES ($1,$2,$3::inet,$4)`,
		id, "ap-host", "192.0.2.40", creator); err != nil {
		t.Fatalf("seed host: %v", err)
	}
	return id
}

func seedSnapshot(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, users map[string]collector.UserSnapshot) {
	t.Helper()
	snap := collector.Snapshot{CollectedAt: time.Now().UTC(), Users: users}
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO host_intelligence_state (host_id, snapshot, collected_at, created_at, updated_at)
		 VALUES ($1, $2, now(), now(), now())`, hostID, raw); err != nil {
		t.Fatalf("seed snapshot: %v", err)
	}
}
