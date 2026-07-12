// @spec api-auth
//
// Auth HTTP integration tests against an httptest server with the
// full middleware chain (correlation → identity binder → idempotency →
// handler). Skipped without OPENWATCH_TEST_DSN.

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/Hanalyx/openwatch/internal/users"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
)

// authTestUser seeds a fresh user via the users service and returns
// the user + plaintext password (so login tests can present it).
type authTestUser struct {
	ID       uuid.UUID
	Username string
	Email    string
	Password string
}

// seedAuthUser creates a user. The adminPolicy flag selects which
// password-strength policy is applied at creation; pass true when the
// caller's test will assign the admin role to mirror production.
func seedAuthUser(t *testing.T, svc *users.Service, username string, adminPolicy bool) authTestUser {
	t.Helper()
	pw := "test-passphrase-strong-zZ-" + username
	u, err := svc.CreateUser(context.Background(), users.CreateParams{
		Username:    username,
		Email:       username + "@example.com",
		Password:    pw,
		AdminPolicy: adminPolicy,
	})
	if err != nil {
		t.Fatalf("seedAuthUser %s: %v", username, err)
	}
	return authTestUser{
		ID:       u.ID,
		Username: u.Username,
		Email:    u.Email,
		Password: pw,
	}
}

// login posts to /auth/login with the supplied body and returns the
// raw response. Tests check status + body shape.
func login(t *testing.T, url string, body any) *http.Response {
	t.Helper()
	bs, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", url+"/api/v1/auth/login", bytes.NewReader(bs))
	req.Header.Set("Content-Type", "application/json")
	return doReq(t, req)
}

// @ac AC-01
// AC-01: Valid login (no MFA) returns 200 + access + refresh + cookie + audit.
func TestAuthLogin_HappyPath(t *testing.T) {
	t.Run("api-auth/AC-01", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		usrSvc := users.NewService(pool, nil)
		u := seedAuthUser(t, usrSvc, "ac01", false)
		_ = usrSvc.AssignRole(context.Background(), u.ID, "viewer", nil)

		resp := login(t, url, map[string]string{
			"username": u.Username, "password": u.Password,
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d body=%s", resp.StatusCode, b)
		}
		var got struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			User         struct {
				Username string `json:"username"`
			} `json:"user"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&got)
		if got.AccessToken == "" || got.RefreshToken == "" {
			t.Errorf("tokens missing")
		}
		if got.User.Username != u.Username {
			t.Errorf("user.username = %q, want %q", got.User.Username, u.Username)
		}
		// Cookie set.
		var found bool
		for _, c := range resp.Cookies() {
			if c.Name == identity.SessionCookieName {
				found = true
				if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode {
					t.Errorf("cookie attrs HttpOnly=%v Secure=%v SameSite=%v", c.HttpOnly, c.Secure, c.SameSite)
				}
			}
		}
		if !found {
			t.Error("openwatch_session cookie not set")
		}
	})
}

// @ac AC-02
// AC-02: Wrong password → 401 auth.invalid_credentials.
func TestAuthLogin_WrongPassword(t *testing.T) {
	t.Run("api-auth/AC-02", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		usrSvc := users.NewService(pool, nil)
		u := seedAuthUser(t, usrSvc, "ac02", false)

		resp := login(t, url, map[string]string{
			"username": u.Username, "password": "wrong-password-12345",
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d", resp.StatusCode)
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "auth.invalid_credentials") {
			t.Errorf("body lacks auth.invalid_credentials: %s", b)
		}
	})
}

// @ac AC-03
// AC-03: Unknown username → same response shape as wrong password (no oracle).
func TestAuthLogin_UnknownUsername(t *testing.T) {
	t.Run("api-auth/AC-03", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		resp := login(t, url, map[string]string{
			"username": "does-not-exist", "password": "anything",
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d", resp.StatusCode)
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "auth.invalid_credentials") {
			t.Errorf("body lacks auth.invalid_credentials: %s", b)
		}
	})
}

// @ac AC-04
// AC-04: MFA enrolled + missing otp → 401 auth.mfa_required.
func TestAuthLogin_MFARequired(t *testing.T) {
	t.Run("api-auth/AC-04", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		usrSvc := users.NewService(pool, nil)
		u := seedAuthUser(t, usrSvc, "ac04", false)
		_, err := identity.EnrollMFA(context.Background(), pool, u.ID, u.Username)
		if err != nil {
			t.Fatalf("EnrollMFA: %v", err)
		}
		// Mark the enrollment verified — only a verified secret gates login.
		// EnrollMFA alone leaves last_verified_at NULL (see AC-13).
		if _, err := pool.Exec(context.Background(),
			`UPDATE auth_mfa_secrets SET last_verified_at = now() WHERE user_id = $1`, u.ID); err != nil {
			t.Fatalf("mark verified: %v", err)
		}
		resp := login(t, url, map[string]string{
			"username": u.Username, "password": u.Password,
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d", resp.StatusCode)
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "auth.mfa_required") {
			t.Errorf("body lacks auth.mfa_required: %s", b)
		}
	})
}

// @ac AC-13
// AC-13: an unverified MFA enrollment (secret written by EnrollMFA but never
// confirmed via VerifyMFA, so last_verified_at IS NULL) must NOT require an OTP
// at sign-in — the user logs in normally (200) and can re-attempt enrollment.
// Regression guard for the lockout where a begun-but-abandoned enrollment
// stranded the user behind an OTP they could not produce.
func TestAuthLogin_UnverifiedMFA_DoesNotGate(t *testing.T) {
	t.Run("api-auth/AC-13", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		usrSvc := users.NewService(pool, nil)
		u := seedAuthUser(t, usrSvc, "ac12", false)
		// Begin enrollment only — no VerifyMFA, so last_verified_at stays NULL.
		if _, err := identity.EnrollMFA(context.Background(), pool, u.ID, u.Username); err != nil {
			t.Fatalf("EnrollMFA: %v", err)
		}
		resp := login(t, url, map[string]string{
			"username": u.Username, "password": u.Password,
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d (want 200; unverified enrollment must not gate login): %s", resp.StatusCode, b)
		}
	})
}

// @ac AC-05
// AC-05: Valid creds + valid otp → 200.
func TestAuthLogin_MFASucceeds(t *testing.T) {
	t.Run("api-auth/AC-05", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		usrSvc := users.NewService(pool, nil)
		u := seedAuthUser(t, usrSvc, "ac05", false)
		// EnrollMFA returns the otpauth URI; pull the secret out so we
		// can generate a current OTP without needing a real authenticator app.
		uri, err := identity.EnrollMFA(context.Background(), pool, u.ID, u.Username)
		if err != nil {
			t.Fatalf("EnrollMFA: %v", err)
		}
		// Mark verified so the secret gates login (only verified MFA does; AC-13).
		if _, err := pool.Exec(context.Background(),
			`UPDATE auth_mfa_secrets SET last_verified_at = now() WHERE user_id = $1`, u.ID); err != nil {
			t.Fatalf("mark verified: %v", err)
		}
		secret := otpSecretFromURI(t, uri)
		otp, _ := totp.GenerateCode(secret, time.Now().UTC())
		resp := login(t, url, map[string]any{
			"username": u.Username, "password": u.Password, "otp": otp,
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d body=%s", resp.StatusCode, b)
		}
	})
}

// @ac AC-06
// AC-06: Valid creds + WRONG otp → 401 auth.mfa_invalid.
func TestAuthLogin_MFAInvalid(t *testing.T) {
	t.Run("api-auth/AC-06", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		usrSvc := users.NewService(pool, nil)
		u := seedAuthUser(t, usrSvc, "ac06", false)
		_, _ = identity.EnrollMFA(context.Background(), pool, u.ID, u.Username)
		// Mark verified so the secret gates login (only verified MFA does; AC-13).
		if _, err := pool.Exec(context.Background(),
			`UPDATE auth_mfa_secrets SET last_verified_at = now() WHERE user_id = $1`, u.ID); err != nil {
			t.Fatalf("mark verified: %v", err)
		}
		resp := login(t, url, map[string]any{
			"username": u.Username, "password": u.Password, "otp": "000000",
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d", resp.StatusCode)
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "auth.mfa_invalid") {
			t.Errorf("body lacks auth.mfa_invalid: %s", b)
		}
	})
}

// @ac AC-07
// AC-07: Logout revokes the session; subsequent /auth/me returns 401.
func TestAuthLogout_RevokesSession(t *testing.T) {
	t.Run("api-auth/AC-07", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		usrSvc := users.NewService(pool, nil)
		u := seedAuthUser(t, usrSvc, "ac07", false)
		_ = usrSvc.AssignRole(context.Background(), u.ID, "viewer", nil)

		// Login → get cookie.
		resp := login(t, url, map[string]string{"username": u.Username, "password": u.Password})
		cookie := pickSessionCookie(resp)
		resp.Body.Close()
		if cookie == nil {
			t.Fatal("no session cookie")
		}

		// /auth/me with cookie → 200.
		req, _ := http.NewRequest("GET", url+"/api/v1/auth/me", nil)
		req.AddCookie(cookie)
		resp = doReq(t, req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("pre-logout me status = %d", resp.StatusCode)
		}

		// Logout with cookie.
		req, _ = http.NewRequest("POST", url+"/api/v1/auth/logout", nil)
		req.AddCookie(cookie)
		resp = doReq(t, req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("logout status = %d", resp.StatusCode)
		}

		// /auth/me with same cookie now → 401 (session revoked).
		req, _ = http.NewRequest("GET", url+"/api/v1/auth/me", nil)
		req.AddCookie(cookie)
		resp = doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("post-logout me status = %d, want 401", resp.StatusCode)
		}
	})
}

// @ac AC-14
// AC-14: PATCH /auth/me applies a partial self-profile update and returns
// the updated identity; changing email to one another active user already
// holds returns 409. /auth/* is CSRF-exempt, so the cookie alone authorizes.
func TestAuthPatchMe_UpdatesProfileAndEmailConflict(t *testing.T) {
	t.Run("api-auth/AC-14", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		usrSvc := users.NewService(pool, nil)
		u := seedAuthUser(t, usrSvc, "ac14", false)
		_ = usrSvc.AssignRole(context.Background(), u.ID, "viewer", nil)
		other := seedAuthUser(t, usrSvc, "ac14other", false)

		resp := login(t, url, map[string]string{"username": u.Username, "password": u.Password})
		cookie := pickSessionCookie(resp)
		resp.Body.Close()
		if cookie == nil {
			t.Fatal("no session cookie")
		}

		// Partial profile update → 200 with the new fields echoed, email intact.
		body, _ := json.Marshal(map[string]any{"full_name": "AC Fourteen", "job_title": "SecOps", "timezone": "UTC"})
		req, _ := http.NewRequest("PATCH", url+"/api/v1/auth/me", bytes.NewReader(body))
		req.AddCookie(cookie)
		req.Header.Set("Content-Type", "application/json")
		resp = doReq(t, req)
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			t.Fatalf("patch status = %d, want 200", resp.StatusCode)
		}
		var me struct {
			FullName string `json:"full_name"`
			JobTitle string `json:"job_title"`
			Email    string `json:"email"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&me)
		resp.Body.Close()
		if me.FullName != "AC Fourteen" || me.JobTitle != "SecOps" {
			t.Errorf("profile not updated: %+v", me)
		}
		if me.Email != u.Email {
			t.Errorf("email changed unexpectedly to %q", me.Email)
		}

		// Email collision with the other active user → 409.
		body, _ = json.Marshal(map[string]any{"email": other.Email})
		req, _ = http.NewRequest("PATCH", url+"/api/v1/auth/me", bytes.NewReader(body))
		req.AddCookie(cookie)
		req.Header.Set("Content-Type", "application/json")
		resp = doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusConflict {
			t.Errorf("email-conflict status = %d, want 409", resp.StatusCode)
		}
	})
}

// @ac AC-08
// AC-08: Refresh rotates; old refresh token is invalid for subsequent calls.
func TestAuthRefresh_Rotates(t *testing.T) {
	t.Run("api-auth/AC-08", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		usrSvc := users.NewService(pool, nil)
		u := seedAuthUser(t, usrSvc, "ac08", false)
		_ = usrSvc.AssignRole(context.Background(), u.ID, "viewer", nil)

		resp := login(t, url, map[string]string{"username": u.Username, "password": u.Password})
		var loginResp struct {
			RefreshToken string `json:"refresh_token"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&loginResp)
		resp.Body.Close()

		// First refresh — succeeds.
		bs, _ := json.Marshal(map[string]string{"refresh_token": loginResp.RefreshToken})
		req, _ := http.NewRequest("POST", url+"/api/v1/auth/refresh", bytes.NewReader(bs))
		req.Header.Set("Content-Type", "application/json")
		resp = doReq(t, req)
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("first refresh status = %d body=%s", resp.StatusCode, b)
		}
		var pair struct {
			RefreshToken string `json:"refresh_token"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&pair)
		resp.Body.Close()
		if pair.RefreshToken == loginResp.RefreshToken {
			t.Error("refresh token was not rotated")
		}
	})
}

// @ac AC-09
// AC-09: Reused refresh token → 401 auth.refresh_reused; cascade revoke.
func TestAuthRefresh_ReuseCascadeRevokes(t *testing.T) {
	t.Run("api-auth/AC-09", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		usrSvc := users.NewService(pool, nil)
		u := seedAuthUser(t, usrSvc, "ac09", false)
		_ = usrSvc.AssignRole(context.Background(), u.ID, "viewer", nil)

		resp := login(t, url, map[string]string{"username": u.Username, "password": u.Password})
		var loginResp struct {
			RefreshToken string `json:"refresh_token"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&loginResp)
		resp.Body.Close()

		// Consume once.
		bs, _ := json.Marshal(map[string]string{"refresh_token": loginResp.RefreshToken})
		req, _ := http.NewRequest("POST", url+"/api/v1/auth/refresh", bytes.NewReader(bs))
		req.Header.Set("Content-Type", "application/json")
		resp = doReq(t, req)
		resp.Body.Close()

		// Consume again — reuse.
		bs, _ = json.Marshal(map[string]string{"refresh_token": loginResp.RefreshToken})
		req, _ = http.NewRequest("POST", url+"/api/v1/auth/refresh", bytes.NewReader(bs))
		req.Header.Set("Content-Type", "application/json")
		resp = doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("reuse status = %d, want 401", resp.StatusCode)
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "auth.refresh_reused") {
			t.Errorf("body lacks auth.refresh_reused: %s", b)
		}
		// Cascade: every active session for the user is revoked.
		var active int64
		_ = pool.QueryRow(context.Background(),
			`SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL`,
			u.ID,
		).Scan(&active)
		if active != 0 {
			t.Errorf("active sessions after reuse = %d, want 0", active)
		}
	})
}

// @ac AC-10
// AC-10: GET /auth/me requires a valid session/bearer.
func TestAuthMe_RequiresIdentity(t *testing.T) {
	t.Run("api-auth/AC-10", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		usrSvc := users.NewService(pool, nil)
		u := seedAuthUser(t, usrSvc, "ac10", false)
		_ = usrSvc.AssignRole(context.Background(), u.ID, "auditor", nil)

		// Anonymous → 401.
		resp := doGet(t, url+"/api/v1/auth/me")
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("anonymous status = %d, want 401", resp.StatusCode)
		}

		// With cookie → 200 + identity body.
		resp = login(t, url, map[string]string{"username": u.Username, "password": u.Password})
		cookie := pickSessionCookie(resp)
		resp.Body.Close()
		req, _ := http.NewRequest("GET", url+"/api/v1/auth/me", nil)
		req.AddCookie(cookie)
		resp = doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("me status = %d", resp.StatusCode)
		}
		var got struct {
			Username string `json:"username"`
			Role     string `json:"role"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&got)
		if got.Username != u.Username {
			t.Errorf("username = %q, want %q", got.Username, u.Username)
		}
		if got.Role != "auditor" {
			t.Errorf("role = %q, want auditor", got.Role)
		}
	})
}

// @ac AC-11
// AC-11: POST /auth/mfa:enroll returns a provisioning URI.
func TestAuthMFA_Enroll(t *testing.T) {
	t.Run("api-auth/AC-11", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		usrSvc := users.NewService(pool, nil)
		u := seedAuthUser(t, usrSvc, "ac11", false)
		_ = usrSvc.AssignRole(context.Background(), u.ID, "viewer", nil)

		resp := login(t, url, map[string]string{"username": u.Username, "password": u.Password})
		cookie := pickSessionCookie(resp)
		resp.Body.Close()

		req, _ := http.NewRequest("POST", url+"/api/v1/auth/mfa:enroll", nil)
		req.AddCookie(cookie)
		resp = doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("enroll status = %d body=%s", resp.StatusCode, b)
		}
		var got struct {
			ProvisioningURI string `json:"provisioning_uri"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&got)
		if !strings.HasPrefix(got.ProvisioningURI, "otpauth://totp/") {
			t.Errorf("provisioning_uri = %q, want otpauth://totp/...", got.ProvisioningURI)
		}
	})
}

// @ac AC-12
// AC-12: Password change validates current pw, applies new pw, emits audit;
// wrong current pw → 401.
func TestAuthPasswordChange(t *testing.T) {
	t.Run("api-auth/AC-12", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		usrSvc := users.NewService(pool, nil)
		u := seedAuthUser(t, usrSvc, "ac12", false)
		_ = usrSvc.AssignRole(context.Background(), u.ID, "viewer", nil)

		resp := login(t, url, map[string]string{"username": u.Username, "password": u.Password})
		cookie := pickSessionCookie(resp)
		resp.Body.Close()

		// Wrong current_password → 401.
		bs, _ := json.Marshal(map[string]string{
			"current_password": "wrong-pw",
			"new_password":     "new-passphrase-strong-zZ",
		})
		req, _ := http.NewRequest("POST", url+"/api/v1/auth/password:change", bytes.NewReader(bs))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		resp = doReq(t, req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("wrong-cur status = %d, want 401", resp.StatusCode)
		}

		// Right current_password → 204 + new password works.
		newPW := "new-passphrase-strong-zZ"
		bs, _ = json.Marshal(map[string]string{
			"current_password": u.Password,
			"new_password":     newPW,
		})
		req, _ = http.NewRequest("POST", url+"/api/v1/auth/password:change", bytes.NewReader(bs))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		resp = doReq(t, req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("change status = %d, want 204", resp.StatusCode)
		}
		// Verify new password works for fresh login.
		resp = login(t, url, map[string]string{"username": u.Username, "password": newPW})
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("login with new pw status = %d", resp.StatusCode)
		}
	})
}

// pickSessionCookie returns the openwatch_session cookie from a response,
// or nil if not present.
func pickSessionCookie(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == identity.SessionCookieName {
			return c
		}
	}
	return nil
}

// pickRefreshCookie returns the openwatch_refresh cookie from a
// response, or nil if not present.
func pickRefreshCookie(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == identity.RefreshCookieName {
			return c
		}
	}
	return nil
}

// @spec system-auth-identity
// @ac AC-22
// AC-22: Login Set-Cookies openwatch_refresh (HttpOnly + Secure +
// SameSite=Lax + Path=/ + MaxAge ≈ 7d) carrying the same refresh
// presentation token returned in the response body.
func TestAuthLogin_SetsRefreshCookie(t *testing.T) {
	t.Run("system-auth-identity/AC-22", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		usrSvc := users.NewService(pool, nil)
		u := seedAuthUser(t, usrSvc, "ac22", false)
		_ = usrSvc.AssignRole(context.Background(), u.ID, "viewer", nil)

		resp := login(t, url, map[string]string{"username": u.Username, "password": u.Password})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("login status = %d body=%s", resp.StatusCode, b)
		}
		var body struct {
			RefreshToken string `json:"refresh_token"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)

		rc := pickRefreshCookie(resp)
		if rc == nil {
			t.Fatal("openwatch_refresh cookie not set on login")
		}
		if !rc.HttpOnly {
			t.Error("refresh cookie HttpOnly = false")
		}
		if !rc.Secure {
			t.Error("refresh cookie Secure = false")
		}
		if rc.SameSite != http.SameSiteLaxMode {
			t.Errorf("refresh cookie SameSite = %v, want Lax", rc.SameSite)
		}
		if rc.Path != "/" {
			t.Errorf("refresh cookie Path = %q, want /", rc.Path)
		}
		// ~7 days; allow ±5s clock skew. Browsers floor sub-second values so an
		// exact match isn't required, just being in the right ballpark.
		want := int(identity.RefreshTokenWindow.Seconds())
		if rc.MaxAge < want-5 || rc.MaxAge > want+5 {
			t.Errorf("refresh cookie MaxAge = %d, want ~%d (7d)", rc.MaxAge, want)
		}
		if rc.Value != body.RefreshToken {
			t.Errorf("cookie value != body.refresh_token (cookie=%q body=%q)", rc.Value, body.RefreshToken)
		}
	})
}

// @spec system-auth-identity
// @ac AC-23
// AC-23: POST /auth/refresh-cookie consumes the refresh cookie, rotates
// the refresh token, mints a new session, Set-Cookies both, and returns
// 200 with the identity body.
func TestAuthRefreshCookie_Rotates(t *testing.T) {
	t.Run("system-auth-identity/AC-23", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		usrSvc := users.NewService(pool, nil)
		u := seedAuthUser(t, usrSvc, "ac23", false)
		_ = usrSvc.AssignRole(context.Background(), u.ID, "viewer", nil)

		// Login.
		resp := login(t, url, map[string]string{"username": u.Username, "password": u.Password})
		sessCookie := pickSessionCookie(resp)
		refrCookie := pickRefreshCookie(resp)
		resp.Body.Close()
		if sessCookie == nil || refrCookie == nil {
			t.Fatal("login did not set both cookies")
		}

		// Call refresh-cookie with the refresh cookie present.
		req, _ := http.NewRequest("POST", url+"/api/v1/auth/refresh-cookie", nil)
		req.AddCookie(refrCookie)
		// Include the (possibly stale) session cookie too — production
		// browsers present whatever they hold.
		req.AddCookie(sessCookie)
		resp = doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("refresh-cookie status = %d body=%s", resp.StatusCode, b)
		}

		newSess := pickSessionCookie(resp)
		newRefr := pickRefreshCookie(resp)
		if newSess == nil {
			t.Error("refresh-cookie did not Set-Cookie a new openwatch_session")
		}
		if newRefr == nil {
			t.Error("refresh-cookie did not Set-Cookie a new openwatch_refresh")
		}
		if newSess != nil && newSess.Value == sessCookie.Value {
			t.Error("session cookie value unchanged after refresh")
		}
		if newRefr != nil && newRefr.Value == refrCookie.Value {
			t.Error("refresh cookie value unchanged after refresh — rotation broken")
		}

		// Identity body shape — username present.
		var me struct {
			Username string `json:"username"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&me)
		if me.Username != u.Username {
			t.Errorf("identity body username = %q, want %q", me.Username, u.Username)
		}
	})
}

// @spec system-auth-identity
// @ac AC-23
// AC-23 reject path: no refresh cookie → 401 auth.refresh_invalid +
// both cookies cleared (MaxAge=-1). Browser strips them so a known-bad
// state doesn't keep re-presenting.
func TestAuthRefreshCookie_MissingCookie_Clears(t *testing.T) {
	t.Run("system-auth-identity/AC-23", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		req, _ := http.NewRequest("POST", url+"/api/v1/auth/refresh-cookie", nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", resp.StatusCode)
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "auth.refresh_invalid") {
			t.Errorf("body lacks auth.refresh_invalid: %s", b)
		}
		// Both cookies cleared (MaxAge < 0).
		gotSession, gotRefresh := false, false
		for _, c := range resp.Cookies() {
			if c.Name == identity.SessionCookieName && c.MaxAge < 0 {
				gotSession = true
			}
			if c.Name == identity.RefreshCookieName && c.MaxAge < 0 {
				gotRefresh = true
			}
		}
		if !gotSession {
			t.Error("openwatch_session cookie not cleared on rejection")
		}
		if !gotRefresh {
			t.Error("openwatch_refresh cookie not cleared on rejection")
		}
	})
}

// @spec system-auth-identity
// @ac AC-24
// AC-24: Logout clears BOTH cookies (MaxAge=-1) and revokes the
// refresh token row so the value can't be redeemed afterwards.
func TestAuthLogout_ClearsBothCookiesAndRevokesRefresh(t *testing.T) {
	t.Run("system-auth-identity/AC-24", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		usrSvc := users.NewService(pool, nil)
		u := seedAuthUser(t, usrSvc, "ac24", false)
		_ = usrSvc.AssignRole(context.Background(), u.ID, "viewer", nil)

		resp := login(t, url, map[string]string{"username": u.Username, "password": u.Password})
		sessCookie := pickSessionCookie(resp)
		refrCookie := pickRefreshCookie(resp)
		resp.Body.Close()
		if sessCookie == nil || refrCookie == nil {
			t.Fatal("login did not set both cookies")
		}

		// Logout with both cookies.
		req, _ := http.NewRequest("POST", url+"/api/v1/auth/logout", nil)
		req.AddCookie(sessCookie)
		req.AddCookie(refrCookie)
		resp = doReq(t, req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("logout status = %d", resp.StatusCode)
		}

		// Both cookies cleared.
		gotSession, gotRefresh := false, false
		for _, c := range resp.Cookies() {
			if c.Name == identity.SessionCookieName && c.MaxAge < 0 {
				gotSession = true
			}
			if c.Name == identity.RefreshCookieName && c.MaxAge < 0 {
				gotRefresh = true
			}
		}
		if !gotSession {
			t.Error("logout did not clear openwatch_session cookie")
		}
		if !gotRefresh {
			t.Error("logout did not clear openwatch_refresh cookie")
		}

		// Calling refresh-cookie with the now-revoked refresh token → 401.
		req, _ = http.NewRequest("POST", url+"/api/v1/auth/refresh-cookie", nil)
		req.AddCookie(refrCookie)
		resp = doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("refresh-cookie after logout: status = %d, want 401", resp.StatusCode)
		}
	})
}

// otpSecretFromURI parses an otpauth:// provisioning URI and returns
// the embedded shared secret. The authenticator app would do this off
// a QR code; tests do it inline.
func otpSecretFromURI(t *testing.T, uri string) string {
	t.Helper()
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("parse uri: %v", err)
	}
	s := u.Query().Get("secret")
	if s == "" {
		t.Fatalf("uri missing secret: %s", uri)
	}
	return s
}
