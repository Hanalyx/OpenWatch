// @spec system-auth-identity
//
// Blocker remediation for bugs/OW-069: an administrator's lockout must
// actually lock the account out, across every interactive credential.
//
// The shapes here are the authorized OW-069 reproduction, kept as
// regression evidence: the same sequence that demonstrated the defect
// now asserts the fixed outcome.

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/Hanalyx/openwatch/internal/users"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type credState struct {
	SessionsLive int
	RefreshLive  int
	APITokens    int
}

func readCredState(t *testing.T, pool *pgxpool.Pool, uid uuid.UUID) credState {
	t.Helper()
	var s credState
	if err := pool.QueryRow(context.Background(), `
		SELECT (SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL),
		       (SELECT count(*) FROM refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL),
		       (SELECT count(*) FROM api_tokens WHERE created_by = $1 AND revoked_at IS NULL)`,
		uid).Scan(&s.SessionsLive, &s.RefreshLive, &s.APITokens); err != nil {
		t.Fatalf("read credential state: %v", err)
	}
	return s
}

// loggedIn signs a fresh user in and returns its identifiers plus the
// credentials the login handed out.
type loggedInUser struct {
	u             authTestUser
	sessionCookie *http.Cookie
	refreshCookie *http.Cookie
	bodyRefresh   string
	accessToken   string
}

func loginFresh(t *testing.T, url string, pool *pgxpool.Pool, name string) loggedInUser {
	t.Helper()
	svc := users.NewService(pool, nil)
	u := seedAuthUser(t, svc, name, false)
	if err := svc.AssignRole(context.Background(), u.ID, "viewer", nil); err != nil {
		t.Fatalf("assign role: %v", err)
	}
	resp := login(t, url, map[string]string{"username": u.Username, "password": u.Password})
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("login %s: status %d body %s", name, resp.StatusCode, b)
	}
	var body struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	_ = json.Unmarshal(raw, &body)
	out := loggedInUser{u: u, bodyRefresh: body.RefreshToken, accessToken: body.AccessToken}
	for _, c := range resp.Cookies() {
		switch c.Name {
		case identity.SessionCookieName:
			out.sessionCookie = &http.Cookie{Name: c.Name, Value: c.Value}
		case identity.RefreshCookieName:
			out.refreshCookie = &http.Cookie{Name: c.Name, Value: c.Value}
		}
	}
	if out.sessionCookie == nil || out.refreshCookie == nil || out.bodyRefresh == "" {
		t.Fatalf("login did not return the full credential set for %s", name)
	}
	return out
}

func authMe(t *testing.T, url string, c *http.Cookie) int {
	t.Helper()
	req, _ := http.NewRequest("GET", url+"/api/v1/auth/me", nil)
	req.AddCookie(c)
	resp := doReq(t, req)
	defer resp.Body.Close()
	return resp.StatusCode
}

func authMeBearer(t *testing.T, url, token string) int {
	t.Helper()
	req, _ := http.NewRequest("GET", url+"/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp := doReq(t, req)
	defer resp.Body.Close()
	return resp.StatusCode
}

// refreshBody posts the body refresh token. Returns status and whether
// the response carried a usable access token.
func refreshBody(t *testing.T, url, token string) (int, string) {
	t.Helper()
	bs, _ := json.Marshal(map[string]string{"refresh_token": token})
	req, _ := http.NewRequest("POST", url+"/api/v1/auth/refresh", bytes.NewReader(bs))
	req.Header.Set("Content-Type", "application/json")
	resp := doReq(t, req)
	defer resp.Body.Close()
	var body struct {
		AccessToken string `json:"access_token"`
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &body)
	return resp.StatusCode, body.AccessToken
}

// refreshCookie posts the refresh cookie. Returns status and the session
// cookie the response set, if any.
func refreshCookie(t *testing.T, url string, rc *http.Cookie) (int, *http.Cookie) {
	t.Helper()
	req, _ := http.NewRequest("POST", url+"/api/v1/auth/refresh-cookie", nil)
	req.AddCookie(rc)
	req.AddCookie(&http.Cookie{Name: "XSRF-TOKEN", Value: "test-csrf-token"})
	req.Header.Set("X-CSRF-Token", "test-csrf-token")
	resp := doReq(t, req)
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)
	for _, c := range resp.Cookies() {
		if c.Name == identity.SessionCookieName && c.Value != "" {
			return resp.StatusCode, &http.Cookie{Name: c.Name, Value: c.Value}
		}
	}
	return resp.StatusCode, nil
}

// @ac AC-37
// AC-37: Disable performs user-wide INTERACTIVE revocation. Sessions and
// refresh families both go to zero, neither refresh path mints anything,
// and no credential derived from either response authenticates. The
// api_tokens row is the control that interactive revocation stays out of
// the service-token lifecycle.
//
// This is the OW-069 reproduction asserting the fixed outcome.
func TestDisable_RevokesEveryInteractiveCredential(t *testing.T) {
	t.Run("system-auth-identity/AC-37", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		li := loginFresh(t, url, pool, "ac37user")
		ctx := context.Background()

		// A service token owned by the same user. Interactive revocation
		// must not touch it.
		_, err := pool.Exec(ctx, `
			INSERT INTO api_tokens (name, token_hash, prefix, role_id, created_by)
			VALUES ('ac37', $1, 'owk_ac37', 'viewer', $2)`,
			[]byte("ac37-token-hash-not-a-real-secret"), li.u.ID)
		if err != nil {
			t.Fatalf("seed api token: %v", err)
		}

		before := readCredState(t, pool, li.u.ID)
		if before.SessionsLive == 0 || before.RefreshLive == 0 || before.APITokens != 1 {
			t.Fatalf("precondition: want live credentials and one api token, got %+v", before)
		}

		if err := users.NewService(pool, nil).Disable(ctx, li.u.ID); err != nil {
			t.Fatalf("disable: %v", err)
		}

		after := readCredState(t, pool, li.u.ID)
		if after.SessionsLive != 0 {
			t.Errorf("sessions live after disable = %d, want 0", after.SessionsLive)
		}
		if after.RefreshLive != 0 {
			t.Errorf("refresh tokens live after disable = %d, want 0 (this is the OW-069 defect)", after.RefreshLive)
		}
		if after.APITokens != 1 {
			t.Errorf("api tokens touched by interactive revocation = %d live, want 1 untouched", after.APITokens)
		}

		// The pre-existing credentials stop working.
		if code := authMe(t, url, li.sessionCookie); code != http.StatusUnauthorized {
			t.Errorf("pre-existing session cookie on /auth/me = %d, want 401", code)
		}
		if code := authMeBearer(t, url, li.accessToken); code != http.StatusUnauthorized {
			t.Errorf("pre-existing access token on /auth/me = %d, want 401", code)
		}

		// Neither refresh path mints anything usable.
		if code, access := refreshBody(t, url, li.bodyRefresh); code == http.StatusOK {
			t.Errorf("body refresh after disable = %d, want a refusal", code)
			if access != "" && authMeBearer(t, url, access) == http.StatusOK {
				t.Error("the body refresh minted a working access token for a disabled account")
			}
		}
		code, newSession := refreshCookie(t, url, li.refreshCookie)
		if code == http.StatusOK {
			t.Errorf("cookie refresh after disable = %d, want a refusal", code)
		}
		if newSession != nil && authMe(t, url, newSession) == http.StatusOK {
			t.Error("the cookie refresh minted a working session for a disabled account")
		}

		final := readCredState(t, pool, li.u.ID)
		if final.SessionsLive != 0 || final.RefreshLive != 0 {
			t.Errorf("a refresh attempt resurrected credentials: %+v", final)
		}
	})
}

// @ac AC-38
// AC-38: AdminResetPassword and SoftDelete each perform user-wide
// interactive revocation. SoftDelete revoked nothing before this change.
func TestAdminResetAndSoftDelete_RevokeInteractiveCredentials(t *testing.T) {
	t.Run("system-auth-identity/AC-38", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()
		svc := users.NewService(pool, nil)

		for _, tc := range []struct {
			name string
			user string
			act  func(uid uuid.UUID) error
		}{
			{"AdminResetPassword", "ac38reset", func(uid uuid.UUID) error {
				return svc.AdminResetPassword(ctx, uid, "a-new-strong-passphrase-Zz9")
			}},
			{"SoftDelete", "ac38delete", func(uid uuid.UUID) error {
				return svc.SoftDelete(ctx, uid)
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				li := loginFresh(t, url, pool, tc.user)
				before := readCredState(t, pool, li.u.ID)
				if before.SessionsLive == 0 || before.RefreshLive == 0 {
					t.Fatalf("precondition: want live credentials, got %+v", before)
				}
				if err := tc.act(li.u.ID); err != nil {
					t.Fatalf("%s: %v", tc.name, err)
				}
				after := readCredState(t, pool, li.u.ID)
				if after.SessionsLive != 0 {
					t.Errorf("%s: sessions live = %d, want 0", tc.name, after.SessionsLive)
				}
				if after.RefreshLive != 0 {
					t.Errorf("%s: refresh live = %d, want 0", tc.name, after.RefreshLive)
				}
				if code, _ := refreshBody(t, url, li.bodyRefresh); code == http.StatusOK {
					t.Errorf("%s: body refresh still succeeded", tc.name)
				}
				if code, _ := refreshCookie(t, url, li.refreshCookie); code == http.StatusOK {
					t.Errorf("%s: cookie refresh still succeeded", tc.name)
				}
			})
		}
	})
}

// @ac AC-41
// AC-41: both refresh paths revalidate account state inside the locked
// transaction. A disabled account is refused on both, an enabled one is
// not, and a refusal mints nothing.
func TestRefreshPaths_RevalidateAccountState(t *testing.T) {
	t.Run("system-auth-identity/AC-41", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()
		svc := users.NewService(pool, nil)

		// Controls first: an enabled account refreshes on both paths.
		ctrl := loginFresh(t, url, pool, "ac41control")
		if code, _ := refreshBody(t, url, ctrl.bodyRefresh); code != http.StatusOK {
			t.Errorf("control body refresh = %d, want 200", code)
		}
		ctrl2 := loginFresh(t, url, pool, "ac41control2")
		if code, sess := refreshCookie(t, url, ctrl2.refreshCookie); code != http.StatusOK || sess == nil {
			t.Errorf("control cookie refresh = %d (session set: %v), want 200 with a session", code, sess != nil)
		}

		// Disabled, with the refresh family LEFT LIVE. The account state
		// is set by a raw UPDATE rather than through Disable(), because
		// Disable revokes the family and a revoked token is refused by
		// rotation alone. That version of this test passed with the
		// account-state check deleted, which made it worthless. This
		// version isolates the check: the only thing wrong with the
		// credential is the account behind it.
		//
		// The state is also reachable in production: a credential issued
		// during a disabled window is never revoked by anything.
		for _, tc := range []struct {
			name string
			user string
			run  func(li loggedInUser) int
		}{
			{"body path", "ac41body", func(li loggedInUser) int {
				code, _ := refreshBody(t, url, li.bodyRefresh)
				return code
			}},
			{"cookie path", "ac41cookie", func(li loggedInUser) int {
				code, _ := refreshCookie(t, url, li.refreshCookie)
				return code
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				li := loginFresh(t, url, pool, tc.user)
				if _, err := pool.Exec(ctx,
					`UPDATE users SET disabled_at = now() WHERE id = $1`, li.u.ID); err != nil {
					t.Fatalf("set disabled_at: %v", err)
				}
				pre := readCredState(t, pool, li.u.ID)
				if pre.RefreshLive == 0 {
					t.Fatalf("precondition: the refresh family must still be live, got %+v", pre)
				}
				if code := tc.run(li); code == http.StatusOK {
					t.Errorf("%s refreshed a disabled account holding a LIVE refresh token (status %d)", tc.name, code)
				}
				// The login's own session is still in the table and
				// unrevoked (disabled_at was set directly, so nothing
				// revoked it). What must not happen is a NEW one.
				st := readCredState(t, pool, li.u.ID)
				if st.SessionsLive > pre.SessionsLive {
					t.Errorf("%s: a refused refresh minted a session (%d -> %d)",
						tc.name, pre.SessionsLive, st.SessionsLive)
				}
				if st.RefreshLive > pre.RefreshLive {
					t.Errorf("%s: a refused refresh rotated the family (%d -> %d)",
						tc.name, pre.RefreshLive, st.RefreshLive)
				}
			})
		}

		// And the same through the real Disable(), which also revokes.
		// Both refusals matter: one is the revocation, the other is the
		// account-state check that covers what revocation cannot reach.
		li := loginFresh(t, url, pool, "ac41disabled")
		if err := svc.Disable(ctx, li.u.ID); err != nil {
			t.Fatalf("disable: %v", err)
		}
		if code, _ := refreshBody(t, url, li.bodyRefresh); code == http.StatusOK {
			t.Error("body refresh succeeded after Disable()")
		}
		if code, _ := refreshCookie(t, url, li.refreshCookie); code == http.StatusOK {
			t.Error("cookie refresh succeeded after Disable()")
		}
	})
}

// @ac AC-39
// AC-39: password login runs in ONE transaction that takes the per-user
// lock first and revalidates account state inside it. A disable that
// commits while the login is waiting on that lock is observed by the
// login, which issues nothing.
//
// The ordering is imposed by the lock, not by sleeping. The disabling
// transaction holds the user row; the login blocks on it; the disable
// commits and releases. If the login had not yet reached the lock, it
// still observes the committed disable, so the assertion holds either
// way and the test cannot flake into a false pass.
func TestLogin_RevalidatesAccountStateUnderTheLock(t *testing.T) {
	t.Run("system-auth-identity/AC-39", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()
		svc := users.NewService(pool, nil)

		// Control: the same credentials succeed with no disable in flight.
		ctrl := seedAuthUser(t, svc, "ac39control", false)
		_ = svc.AssignRole(ctx, ctrl.ID, "viewer", nil)
		resp := login(t, url, map[string]string{"username": ctrl.Username, "password": ctrl.Password})
		gotCtrl := resp.StatusCode
		resp.Body.Close()
		if gotCtrl != http.StatusOK {
			t.Fatalf("control login = %d, want 200", gotCtrl)
		}

		u := seedAuthUser(t, svc, "ac39race", false)
		_ = svc.AssignRole(ctx, u.ID, "viewer", nil)

		// Hold the user row, so a login reaching the lock blocks here.
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		var one int
		if err := tx.QueryRow(ctx,
			`SELECT 1 FROM users WHERE id = $1 FOR NO KEY UPDATE`, u.ID).Scan(&one); err != nil {
			t.Fatalf("hold lock: %v", err)
		}

		type loginResult struct {
			status int
		}
		done := make(chan loginResult, 1)
		go func() {
			r := login(t, url, map[string]string{"username": u.Username, "password": u.Password})
			r.Body.Close()
			done <- loginResult{status: r.StatusCode}
		}()

		// Commit the disable while the login is waiting on the row.
		if _, err := tx.Exec(ctx,
			`UPDATE users SET disabled_at = now() WHERE id = $1`, u.ID); err != nil {
			t.Fatalf("disable in tx: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit disable: %v", err)
		}

		res := <-done
		if res.status == http.StatusOK {
			t.Errorf("login = %d: a disable committed before the login's lock was not observed", res.status)
		}
		st := readCredState(t, pool, u.ID)
		if st.SessionsLive != 0 || st.RefreshLive != 0 {
			t.Errorf("the refused login issued credentials: %+v", st)
		}
	})
}
