// @spec system-auth-identity
//
// Re-enabling an account (I10). A disabled-to-enabled transition revokes
// every interactive credential the user holds, and a call on an account
// that is not disabled changes nothing.
//
// The stray credentials in AC-70 are written directly for the disabled
// user with the identity package's issue functions, bypassing every
// handler and the lock. That is deliberate: it measures what Enable does
// with state an older release or a leaked issuance path could leave, which
// no amount of issuance prevention reaches. It does not show that a
// current handler issues credentials while an account is disabled.

package server

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/apitoken"
	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/Hanalyx/openwatch/internal/users"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// strayCredentials are interactive credentials that exist for a user
// without ever having passed through a handler.
type strayCredentials struct {
	sessionID     uuid.UUID
	sessionCookie *http.Cookie
	accessToken   string
	bodyRefresh   string
	cookieRefresh *http.Cookie
}

func writeStrayCredentials(t *testing.T, pool *pgxpool.Pool, uid uuid.UUID) strayCredentials {
	t.Helper()
	ctx := context.Background()
	tok, sess, err := identity.IssueSession(ctx, pool, uid, "127.0.0.1", "stray")
	if err != nil {
		t.Fatalf("write stray session: %v", err)
	}
	access, _, err := identity.IssueJWTForSession(uid, "viewer", sess.ID)
	if err != nil {
		t.Fatalf("mint stray access token: %v", err)
	}
	body, err := identity.IssueRefreshTokenForSession(ctx, pool, uid, sess.ID, sess.AbsoluteExpiresAt)
	if err != nil {
		t.Fatalf("write stray body refresh token: %v", err)
	}
	cookie, err := identity.IssueRefreshTokenForSession(ctx, pool, uid, sess.ID, sess.AbsoluteExpiresAt)
	if err != nil {
		t.Fatalf("write stray cookie refresh token: %v", err)
	}
	return strayCredentials{
		sessionID:     sess.ID,
		sessionCookie: &http.Cookie{Name: identity.SessionCookieName, Value: tok},
		accessToken:   access,
		bodyRefresh:   body,
		cookieRefresh: &http.Cookie{Name: identity.RefreshCookieName, Value: cookie},
	}
}

func isDisabled(t *testing.T, pool *pgxpool.Pool, uid uuid.UUID) bool {
	t.Helper()
	var disabled bool
	if err := pool.QueryRow(context.Background(),
		`SELECT disabled_at IS NOT NULL FROM users WHERE id = $1`, uid).Scan(&disabled); err != nil {
		t.Fatalf("read disabled_at: %v", err)
	}
	return disabled
}

// freshLoginWorks signs in through the real login handler and proves the
// new session authenticates.
func freshLoginWorks(t *testing.T, url string, u authTestUser) bool {
	t.Helper()
	resp := login(t, url, map[string]string{"username": u.Username, "password": u.Password})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Logf("fresh login = %d", resp.StatusCode)
		return false
	}
	return getMeWithCookie(t, url, sessionCookie(resp)) == http.StatusOK
}

// @ac AC-70
// AC-70: a real enable transition revokes every interactive credential,
// including ones no revocation ever reached, atomically and under the lock.
func TestEnable_TransitionRevokesInteractiveCredentials(t *testing.T) {
	t.Run("system-auth-identity/AC-70", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()
		svc := users.NewService(pool, nil)

		t.Run("transition", func(t *testing.T) {
			li := loginFresh(t, url, pool, "enabletransition")
			if err := svc.Disable(ctx, li.u.ID); err != nil {
				t.Fatalf("disable: %v", err)
			}
			stray := writeStrayCredentials(t, pool, li.u.ID)
			if s, r := liveCounts(t, pool, li.u.ID); s != 1 || r != 2 {
				t.Fatalf("precondition: stray live credentials = %d/%d, want 1/2", s, r)
			}

			transitioned, err := svc.Enable(ctx, li.u.ID)
			if err != nil {
				t.Fatalf("enable: %v", err)
			}
			if !transitioned {
				t.Error("enable of a disabled account reported no transition")
			}
			if isDisabled(t, pool, li.u.ID) {
				t.Fatal("enable did not clear disabled_at")
			}
			// Attributed positively: the stray session row itself is revoked.
			var sessionRevoked bool
			if err := pool.QueryRow(ctx,
				`SELECT revoked_at IS NOT NULL FROM sessions WHERE id = $1`, stray.sessionID).Scan(&sessionRevoked); err != nil {
				t.Fatalf("read stray session: %v", err)
			}
			if !sessionRevoked {
				t.Error("the stray session is still live after enable")
			}
			if s, r := liveCounts(t, pool, li.u.ID); s != 0 || r != 0 {
				t.Errorf("live credentials after enable = %d/%d, want 0/0", s, r)
			}

			if code := authMe(t, url, stray.sessionCookie); code != http.StatusUnauthorized {
				t.Errorf("stray session cookie after enable = %d, want 401", code)
			}
			if code := authMeBearer(t, url, stray.accessToken); code != http.StatusUnauthorized {
				t.Errorf("stray access token after enable = %d, want 401", code)
			}
			if code, _ := refreshBody(t, url, stray.bodyRefresh); code == http.StatusOK {
				t.Error("stray body refresh token rotated after enable")
			}
			if code, sess := refreshCookie(t, url, stray.cookieRefresh); code == http.StatusOK || sess != nil {
				t.Errorf("stray refresh cookie after enable = %d (session minted: %v)", code, sess != nil)
			}
			if !freshLoginWorks(t, url, li.u) {
				t.Error("a fresh login after enable did not authenticate")
			}
		})

		t.Run("controlled failure", func(t *testing.T) {
			li := loginFresh(t, url, pool, "enablefailure")
			if err := svc.Disable(ctx, li.u.ID); err != nil {
				t.Fatalf("disable: %v", err)
			}
			writeStrayCredentials(t, pool, li.u.ID)
			restore := failOnWrite(t, pool, "refresh_tokens", "UPDATE")
			transitioned, err := svc.Enable(ctx, li.u.ID)
			restore()
			if transitioned {
				t.Error("a failed enable reported a transition")
			}
			if err == nil {
				t.Fatal("enable succeeded although its revocation failed")
			}
			if !isDisabled(t, pool, li.u.ID) {
				t.Error("disabled_at was cleared without the revocation")
			}
			if s, r := liveCounts(t, pool, li.u.ID); s != 1 || r != 2 {
				t.Errorf("live credentials after a failed enable = %d/%d, want 1/2 untouched", s, r)
			}
		})

		t.Run("serialized", func(t *testing.T) {
			li := loginFresh(t, url, pool, "enableserialized")
			if err := svc.Disable(ctx, li.u.ID); err != nil {
				t.Fatalf("disable: %v", err)
			}
			holder, err := pool.Begin(ctx)
			if err != nil {
				t.Fatalf("begin holder: %v", err)
			}
			defer func() { _ = holder.Rollback(ctx) }()
			if err := identity.LockUser(ctx, holder, li.u.ID); err != nil {
				t.Fatalf("hold lock: %v", err)
			}
			done := make(chan error, 1)
			go func() {
				_, err := svc.Enable(ctx, li.u.ID)
				done <- err
			}()
			if !waitForUserLockWaiter(t, pool) {
				t.Fatal("enable did not wait on the per-user lock")
			}
			if !isDisabled(t, pool, li.u.ID) {
				t.Error("enable changed the account while another transaction held the lock")
			}
			if err := holder.Commit(ctx); err != nil {
				t.Fatalf("release: %v", err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("enable after release: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("enable did not complete after the lock was released")
			}
			if isDisabled(t, pool, li.u.ID) {
				t.Error("enable did not clear disabled_at after the lock was released")
			}
		})
	})
}

// @ac AC-71
// AC-71: enable on an account that is not disabled is a no-op.
func TestEnable_NoOpWhenNotDisabled(t *testing.T) {
	t.Run("system-auth-identity/AC-71", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()
		svc := users.NewService(pool, nil)

		for _, calls := range []int{1, 2} {
			name := map[int]string{1: "already enabled", 2: "repeated"}[calls]
			t.Run(name, func(t *testing.T) {
				li := loginFresh(t, url, pool, "enablenoop"+map[int]string{1: "once", 2: "twice"}[calls])
				var before time.Time
				if err := pool.QueryRow(ctx, `SELECT updated_at FROM users WHERE id = $1`, li.u.ID).Scan(&before); err != nil {
					t.Fatalf("read updated_at: %v", err)
				}
				s0, r0 := liveCounts(t, pool, li.u.ID)
				for i := 0; i < calls; i++ {
					transitioned, err := svc.Enable(ctx, li.u.ID)
					if err != nil {
						t.Fatalf("enable call %d: %v", i+1, err)
					}
					if transitioned {
						t.Errorf("enable call %d on an enabled account reported a transition", i+1)
					}
				}
				var after time.Time
				if err := pool.QueryRow(ctx, `SELECT updated_at FROM users WHERE id = $1`, li.u.ID).Scan(&after); err != nil {
					t.Fatalf("read updated_at: %v", err)
				}
				if !after.Equal(before) {
					t.Errorf("updated_at changed from %v to %v on a no-op", before, after)
				}
				if s1, r1 := liveCounts(t, pool, li.u.ID); s1 != s0 || r1 != r0 {
					t.Errorf("live credentials %d/%d -> %d/%d on a no-op", s0, r0, s1, r1)
				}
				if code := authMe(t, url, li.sessionCookie); code != http.StatusOK {
					t.Errorf("session cookie after a no-op enable = %d, want 200", code)
				}
				if code := authMeBearer(t, url, li.accessToken); code != http.StatusOK {
					t.Errorf("access token after a no-op enable = %d, want 200", code)
				}
				if code, _ := refreshBody(t, url, li.bodyRefresh); code != http.StatusOK {
					t.Errorf("body refresh after a no-op enable = %d, want 200", code)
				}
			})
		}

		t.Run("unknown or soft-deleted", func(t *testing.T) {
			if _, err := svc.Enable(ctx, uuid.New()); !errors.Is(err, users.ErrUserNotFound) {
				t.Errorf("unknown user: err = %v, want ErrUserNotFound", err)
			}
			u := seedAuthUser(t, svc, "enabledeleted", false)
			if err := svc.Disable(ctx, u.ID); err != nil {
				t.Fatalf("disable: %v", err)
			}
			if err := svc.SoftDelete(ctx, u.ID); err != nil {
				t.Fatalf("soft delete: %v", err)
			}
			if _, err := svc.Enable(ctx, u.ID); !errors.Is(err, users.ErrUserNotFound) {
				t.Errorf("soft-deleted user: err = %v, want ErrUserNotFound", err)
			}
			if !isDisabled(t, pool, u.ID) {
				t.Error("enable cleared disabled_at on a soft-deleted user")
			}
		})
	})
}

// @ac AC-72
// AC-72: enable neither revokes a service-account token nor restores a
// revoked one.
func TestEnable_LeavesServiceTokensAlone(t *testing.T) {
	t.Run("system-auth-identity/AC-72", func(t *testing.T) {
		_, pool := freshAPIServer(t)
		ctx := context.Background()
		svc := users.NewService(pool, nil)
		tokens := apitoken.NewService(pool)

		u := seedAuthUser(t, svc, "enabletokens", false)
		_ = svc.AssignRole(ctx, u.ID, "viewer", nil)
		_, valid, err := tokens.Create(ctx, apitoken.CreateParams{Name: "valid", RoleID: auth.RoleID("viewer"), CreatedBy: &u.ID})
		if err != nil {
			t.Fatalf("create valid token: %v", err)
		}
		revokedRaw, revoked, err := tokens.Create(ctx, apitoken.CreateParams{Name: "revoked", RoleID: auth.RoleID("viewer"), CreatedBy: &u.ID})
		if err != nil {
			t.Fatalf("create revoked token: %v", err)
		}
		if err := tokens.Revoke(ctx, revoked.ID); err != nil {
			t.Fatalf("revoke token: %v", err)
		}
		if err := svc.Disable(ctx, u.ID); err != nil {
			t.Fatalf("disable: %v", err)
		}

		snapshot := func() string {
			var s string
			if err := pool.QueryRow(ctx, `
				SELECT string_agg(id::text || ':' || COALESCE(revoked_at::text, 'live') || ':' ||
				                  COALESCE(expires_at::text, 'none'), ',' ORDER BY id)
				FROM api_tokens WHERE created_by = $1`, u.ID).Scan(&s); err != nil {
				t.Fatalf("snapshot api_tokens: %v", err)
			}
			return s
		}
		before := snapshot()
		if _, err := svc.Enable(ctx, u.ID); err != nil {
			t.Fatalf("enable: %v", err)
		}
		if after := snapshot(); after != before {
			t.Errorf("enable changed api_tokens:\nbefore %s\nafter  %s", before, after)
		}
		var validRevoked bool
		if err := pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM api_tokens WHERE id = $1`, valid.ID).Scan(&validRevoked); err != nil {
			t.Fatalf("read valid token: %v", err)
		}
		if validRevoked {
			t.Error("enable revoked a service-account token")
		}
		if _, err := tokens.AuthenticateToken(ctx, revokedRaw); err == nil {
			t.Error("a permanently revoked token authenticates after enable")
		}
	})
}
