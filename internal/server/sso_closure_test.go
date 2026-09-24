// @spec system-sso
//
// SSO regressions promoted from the first integrated closure run for
// bugs/doing/OW-073 (bugs/doing/OW-062 criteria AC-78 and AC-90).

package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/users"
	"github.com/google/uuid"
)

// @ac AC-12
// AC-12: a refused federated sign-in records WHICH account state refused
// it, on the callback's own audit row, while the sign-in page stays
// generic.
func TestSSO_RefusalAuditNamesTheAccountState(t *testing.T) {
	t.Run("system-sso/AC-12", func(t *testing.T) {
		for _, tc := range []struct {
			name, subject, reason string
			transform             func(*users.Service, uuid.UUID) error
		}{
			{"disabled", "sub-ac12-disabled", "sso_account_disabled",
				func(svc *users.Service, id uuid.UUID) error { return svc.Disable(context.Background(), id) }},
			{"soft-deleted", "sub-ac12-deleted", "sso_account_deleted",
				func(svc *users.Service, id uuid.UUID) error { return svc.SoftDelete(context.Background(), id) }},
		} {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				base, pool, d, p := ssoFixture(t)
				ctx := context.Background()
				svc := users.NewService(pool, nil)
				d.sub, d.email = tc.subject, tc.subject+"@example.test"
				if first := ssoSignIn(t, base, pool, d, p); first.sessionCookie == nil {
					t.Fatalf("precondition: the first sign-in must succeed, got %q", first.location)
				}
				var uid uuid.UUID
				if err := pool.QueryRow(ctx, `SELECT user_id FROM sso_identities WHERE subject = $1`, tc.subject).Scan(&uid); err != nil {
					t.Fatalf("no federation link: %v", err)
				}
				if err := tc.transform(svc, uid); err != nil {
					t.Fatalf("%s: %v", tc.name, err)
				}
				res := ssoSignIn(t, base, pool, d, p)
				if res.location != "/login?sso_error=signin" || res.sessionCookie != nil || res.refreshCookie != nil {
					t.Errorf("refused sign-in = %q (session %v); want /login?sso_error=signin and no cookies",
						res.location, res.sessionCookie != nil)
				}
				if got := loginFailureReasonFor(t, pool, res.correlationID); got != tc.reason {
					t.Errorf("audit reason = %q, want %q", got, tc.reason)
				}
			})
		}
	})
}

// @ac AC-13
// AC-13: an account disabled between the provisioning commit and the
// issuance lock gets nothing, keeps its provisioned row, and a later
// callback reuses that row. A password reset in the same window does not
// block issuance, because a federated sign-in does not use the password.
func TestSSO_ProvisioningRace(t *testing.T) {
	t.Run("system-sso/AC-13", func(t *testing.T) {
		base, pool, d, p, srv := ssoFixtureWithServer(t)
		ctx := context.Background()
		svc := users.NewService(pool, nil)
		linkedUser := func(subject string) uuid.UUID {
			var uid uuid.UUID
			if err := pool.QueryRow(ctx, `SELECT user_id FROM sso_identities WHERE subject = $1`, subject).Scan(&uid); err != nil {
				t.Fatalf("no federation link for %s: %v", subject, err)
			}
			return uid
		}

		t.Run("disabled before the issuance lock", func(t *testing.T) {
			d.sub, d.email = "sub-ac13-disabled", "ac13-disabled@example.test"
			srv.handlers.serializer = &hookedBeginner{inner: pool, beforeBegin: func(attempt int) {
				if attempt == 1 {
					if err := svc.Disable(ctx, linkedUser(d.sub)); err != nil {
						t.Errorf("disable: %v", err)
					}
				}
			}}
			res := ssoSignIn(t, base, pool, d, p)
			srv.handlers.serializer = nil
			uid := linkedUser(d.sub)

			if res.location != "/login?sso_error=signin" || res.sessionCookie != nil || res.refreshCookie != nil {
				t.Errorf("callback = %q (session %v); want /login?sso_error=signin and no cookies", res.location, res.sessionCookie != nil)
			}
			// The user did not exist before this callback, so every
			// credential row for it would be the attempt's.
			if rows := snapshotCredentials(t, pool, uid); len(rows.sessions)+len(rows.refresh) != 0 {
				t.Errorf("rows written for the provisioned user: %d sessions, %d refresh", len(rows.sessions), len(rows.refresh))
			}
			var deleted bool
			if err := pool.QueryRow(ctx, `SELECT deleted_at IS NOT NULL FROM users WHERE id = $1`, uid).Scan(&deleted); err != nil || deleted {
				t.Errorf("the provisioned user row is not intact (deleted=%v, err=%v)", deleted, err)
			}
			if got := loginFailureReasonFor(t, pool, res.correlationID); got != "sso_account_disabled" {
				t.Errorf("audit reason = %q, want sso_account_disabled", got)
			}

			// Re-enabled, a later callback finds the same user.
			if err := svc.Enable(ctx, uid); err != nil {
				t.Fatalf("enable: %v", err)
			}
			_ = svc.AssignRole(ctx, uid, auth.RoleID("viewer"), nil)
			later := ssoSignIn(t, base, pool, d, p)
			if later.sessionCookie == nil {
				t.Errorf("later callback = %q, want a session", later.location)
			}
			var usersWithEmail, links int
			_ = pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE email = $1`, d.email).Scan(&usersWithEmail)
			_ = pool.QueryRow(ctx, `SELECT count(*) FROM sso_identities WHERE subject = $1`, d.sub).Scan(&links)
			if usersWithEmail != 1 || links != 1 {
				t.Errorf("later callback re-provisioned: %d users, %d links", usersWithEmail, links)
			}
		})

		t.Run("password reset before the issuance lock", func(t *testing.T) {
			d.sub, d.email = "sub-ac13-reset", "ac13-reset@example.test"
			if first := ssoSignIn(t, base, pool, d, p); first.sessionCookie == nil {
				t.Fatalf("precondition: provisioning sign-in must succeed, got %q", first.location)
			}
			uid := linkedUser(d.sub)
			before := snapshotCredentials(t, pool, uid)
			srv.handlers.serializer = &hookedBeginner{inner: pool, beforeBegin: func(attempt int) {
				if attempt == 1 {
					if err := svc.AdminResetPassword(ctx, uid, "ac13-reset-Passphrase-7781"); err != nil { // pragma: allowlist secret
						t.Errorf("reset: %v", err)
					}
				}
			}}
			res := ssoSignIn(t, base, pool, d, p)
			srv.handlers.serializer = nil
			if res.sessionCookie == nil {
				t.Errorf("callback after a password reset = %q, want a session", res.location)
			}
			if s, _ := snapshotCredentials(t, pool, uid).added(before); len(s) != 1 {
				t.Errorf("sessions written by the callback = %d, want 1", len(s))
			}
			if res.sessionCookie != nil && authMe(t, base, res.sessionCookie) != http.StatusOK {
				t.Error("the session issued after the reset does not authenticate")
			}
		})
	})
}
