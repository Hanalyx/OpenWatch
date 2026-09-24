// @spec system-sso
//
// The SSO callback's issuance outcomes (C-06): success, a known rollback,
// and an unknown commit, which must read as uncertainty rather than
// failure.

package server

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// loginAuditEvents counts login success and failure events, polling until
// the reading stops changing because the audit writer batches. The SSO
// fixture truncates audit_events, so every row here belongs to this test.
func loginAuditEvents(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	start := time.Now()
	last, stable := -1, 0
	for {
		var n int
		if err := pool.QueryRow(context.Background(), `
			SELECT count(*) FROM audit_events
			WHERE action IN ('auth.login.success', 'auth.login.failure')`).Scan(&n); err != nil {
			t.Fatalf("count login events: %v", err)
		}
		if n == last {
			stable++
			if stable >= 2 && time.Since(start) > 400*time.Millisecond {
				return n
			}
		} else {
			stable, last = 0, n
		}
		if time.Since(start) > 5*time.Second {
			return n
		}
	}
}

func issuedRows(t *testing.T, pool *pgxpool.Pool, uid uuid.UUID) (sessions, refresh int) {
	t.Helper()
	if err := pool.QueryRow(context.Background(), `
		SELECT (SELECT count(*) FROM sessions WHERE user_id = $1),
		       (SELECT count(*) FROM refresh_tokens WHERE user_id = $1)`, uid).
		Scan(&sessions, &refresh); err != nil {
		t.Fatalf("count issued rows: %v", err)
	}
	return
}

func credentialCookies(res ssoCallbackResult) (set, cleared int) {
	for _, c := range res.all {
		if c.Name != identity.SessionCookieName && c.Name != identity.RefreshCookieName {
			continue
		}
		if c.Value == "" || c.MaxAge < 0 {
			cleared++
		} else {
			set++
		}
	}
	return
}

// @ac AC-11
// AC-11: the real callback reports success, a known rollback and an
// unknown commit truthfully, and the durable state confirms which variant
// the harness actually produced.
func TestSSOCallback_ReportsEachIssuanceOutcomeTruthfully(t *testing.T) {
	t.Run("system-sso/AC-11", func(t *testing.T) {
		type variant struct {
			name         string
			sub          string
			setup        func(t *testing.T, pool *pgxpool.Pool, s *Server) (counter *countingBeginner, restore func())
			wantLocation string
			wantSet      int
			wantSessions int
			unknown      bool
		}
		unknown := func(commitFirst bool) func(*testing.T, *pgxpool.Pool, *Server) (*countingBeginner, func()) {
			return func(_ *testing.T, pool *pgxpool.Pool, s *Server) (*countingBeginner, func()) {
				c := &countingBeginner{inner: &indeterminateBeginner{inner: pool, commitFirst: commitFirst}}
				s.handlers.serializer = c
				return c, func() { s.handlers.serializer = nil }
			}
		}
		variants := []variant{
			{"durable commit, acknowledgement lost", "sub-ac11-durable", unknown(true),
				"/login?sso_error=unconfirmed", 0, 1, true},
			{"non-durable, outcome unknown", "sub-ac11-lost", unknown(false),
				"/login?sso_error=unconfirmed", 0, 0, true},
			{"known rollback", "sub-ac11-rollback",
				func(t *testing.T, pool *pgxpool.Pool, _ *Server) (*countingBeginner, func()) {
					return nil, failOnWrite(t, pool, "sessions", "INSERT")
				},
				"/login?sso_error=session", 0, 0, false},
			{"successful issuance", "sub-ac11-ok",
				func(*testing.T, *pgxpool.Pool, *Server) (*countingBeginner, func()) { return nil, func() {} },
				"/dashboard", 2, 1, false},
		}

		for _, v := range variants {
			t.Run(v.name, func(t *testing.T) {
				base, pool, d, p, srv := ssoFixtureWithServer(t)
				d.sub, d.email = v.sub, v.sub+"@example.test"

				logs := &lockedBuffer{}
				prev := slog.Default()
				slog.SetDefault(slog.New(slog.NewTextHandler(logs, nil)))
				defer slog.SetDefault(prev)

				counter, restore := v.setup(t, pool, srv)
				res := ssoSignIn(t, base, pool, d, p)
				restore()

				if res.location != v.wantLocation {
					t.Errorf("location = %q, want %q", res.location, v.wantLocation)
				}
				set, cleared := credentialCookies(res)
				if set != v.wantSet {
					t.Errorf("credential cookies set = %d, want %d", set, v.wantSet)
				}

				// The federated user was provisioned before issuance, so
				// it exists in every variant.
				var uid uuid.UUID
				if err := pool.QueryRow(context.Background(),
					`SELECT user_id FROM sso_identities WHERE subject = $1`, v.sub).Scan(&uid); err != nil {
					t.Fatalf("no provisioned user: %v", err)
				}
				// Confirm the harness produced the variant it claims.
				sessions, refresh := issuedRows(t, pool, uid)
				if sessions != v.wantSessions || refresh != v.wantSessions {
					t.Errorf("issued rows sessions=%d refresh=%d, want %d/%d: the harness did not produce this variant",
						sessions, refresh, v.wantSessions, v.wantSessions)
				}

				if !v.unknown {
					return
				}
				if cleared != 0 {
					t.Errorf("an unknown outcome cleared %d credential cookie(s)", cleared)
				}
				counter.mu.Lock()
				begun := counter.n
				counter.mu.Unlock()
				if begun != 1 {
					t.Errorf("transactions begun = %d, want 1: an unknown outcome must not be replayed", begun)
				}
				log := logs.String()
				if !containsFold(log, "outcome unknown") {
					t.Errorf("the log does not record an unknown outcome:\n%s", log)
				}
				for _, claim := range []string{"rolled back", "nothing was issued", "sign-in succeeded"} {
					if containsFold(log, claim) {
						t.Errorf("the log asserts an outcome (%q) nothing here knows:\n%s", claim, log)
					}
				}
				if n := loginAuditEvents(t, pool); n != 0 {
					t.Errorf("login audit events = %d, want 0: success and failure would both assert an outcome", n)
				}
			})
		}
	})
}
