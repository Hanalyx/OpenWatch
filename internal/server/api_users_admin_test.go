// @spec api-users
//
// Admin user-management endpoint coverage (DSN-gated): reset-password +
// disable/enable. Exercises the full stack — RBAC, real login, and session
// revocation.
//
//	AC-14  TestAPI_AdminResetPassword
//	AC-15  TestAPI_AdminResetOwnPassword
//	AC-16  TestAPI_AdminDisableEnable (disable half)
//	AC-17  TestAPI_AdminDisableEnable (enable half)
//	AC-18  TestAPI_AdminDisableEnable (self-disable guard)
//	AC-19  TestAPI_AdminUserMgmt_NotFoundAndRBAC
package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/Hanalyx/openwatch/internal/users"
)

// getMe issues GET /auth/me carrying the given session cookie; returns the
// status. Used to prove a session is live (200) or revoked (401).
func getMeWithCookie(t *testing.T, url, cookie string) int {
	t.Helper()
	req, _ := http.NewRequest("GET", url+"/api/v1/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: identity.SessionCookieName, Value: cookie})
	resp := doReq(t, req)
	resp.Body.Close()
	return resp.StatusCode
}

func sessionCookie(resp *http.Response) string {
	for _, c := range resp.Cookies() {
		if c.Name == identity.SessionCookieName {
			return c.Value
		}
	}
	return ""
}

// @ac AC-14
func TestAPI_AdminResetPassword(t *testing.T) {
	t.Run("api-users/AC-14", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		svc := users.NewService(pool, nil)
		target := seedAuthUser(t, svc, "resettarget", false)
		_ = svc.AssignRole(context.Background(), target.ID, "viewer", nil)
		base := url + "/api/v1/users/" + target.ID.String() + ":reset-password"

		// non-admin (viewer) cannot reset -> 403
		vr := doReq(t, asRole(t, "POST", base, auth.RoleViewer, map[string]any{"new_password": "whatever-strong-9Z"}))
		vr.Body.Close()
		if vr.StatusCode != http.StatusForbidden {
			t.Fatalf("viewer reset = %d, want 403", vr.StatusCode)
		}

		// admin resets to a strong new password -> 204
		newPw := "brand-new-strong-pass-9Z"
		ar := doReq(t, asRole(t, "POST", base, auth.RoleAdmin, map[string]any{"new_password": newPw}))
		ar.Body.Close()
		if ar.StatusCode != http.StatusNoContent {
			t.Fatalf("admin reset = %d, want 204", ar.StatusCode)
		}

		// old password rejected, new password authenticates
		oldResp := login(t, url, map[string]string{"username": target.Username, "password": target.Password})
		oldResp.Body.Close()
		if oldResp.StatusCode != http.StatusUnauthorized {
			t.Errorf("login with old password = %d, want 401", oldResp.StatusCode)
		}
		newResp := login(t, url, map[string]string{"username": target.Username, "password": newPw})
		newResp.Body.Close()
		if newResp.StatusCode != http.StatusOK {
			t.Errorf("login with new password = %d, want 200", newResp.StatusCode)
		}

		// a password that fails policy -> 400, old (new) password still works
		short := doReq(t, asRole(t, "POST", base, auth.RoleAdmin, map[string]any{"new_password": "abc"}))
		short.Body.Close()
		if short.StatusCode != http.StatusBadRequest {
			t.Errorf("too-short reset = %d, want 400", short.StatusCode)
		}
	})
}

// @ac AC-15
func TestAPI_AdminResetOwnPassword(t *testing.T) {
	t.Run("api-users/AC-15", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		adminID := roleUserIDs[auth.RoleAdmin]
		base := url + "/api/v1/users/" + adminID.String() + ":reset-password"

		// admin resets their OWN password without a current password -> 204
		r := doReq(t, asRole(t, "POST", base, auth.RoleAdmin, map[string]any{"new_password": "my-own-fresh-pass-15chars"}))
		r.Body.Close()
		if r.StatusCode != http.StatusNoContent {
			t.Fatalf("admin self-reset = %d, want 204", r.StatusCode)
		}
	})
}

// @ac AC-16
// @ac AC-17
// @ac AC-18
func TestAPI_AdminDisableEnable(t *testing.T) {
	t.Run("api-users/AC-16", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		svc := users.NewService(pool, nil)
		target := seedAuthUser(t, svc, "disabletarget", false)
		_ = svc.AssignRole(context.Background(), target.ID, "viewer", nil)

		// target logs in -> live session cookie
		lr := login(t, url, map[string]string{"username": target.Username, "password": target.Password})
		lr.Body.Close()
		if lr.StatusCode != http.StatusOK {
			t.Fatalf("target login = %d, want 200", lr.StatusCode)
		}
		cookie := sessionCookie(lr)
		if cookie == "" {
			t.Fatal("no session cookie from target login")
		}
		if code := getMeWithCookie(t, url, cookie); code != http.StatusOK {
			t.Fatalf("target /me before disable = %d, want 200", code)
		}

		// admin disables target -> 200, disabled_at set
		dr := doReq(t, asRole(t, "POST", url+"/api/v1/users/"+target.ID.String()+":disable", auth.RoleAdmin, nil))
		defer dr.Body.Close()
		if dr.StatusCode != http.StatusOK {
			t.Fatalf("disable = %d, want 200", dr.StatusCode)
		}

		// AC-16: existing session revoked + login now blocked
		if code := getMeWithCookie(t, url, cookie); code != http.StatusUnauthorized {
			t.Errorf("target /me after disable = %d, want 401 (session revoked)", code)
		}
		blocked := login(t, url, map[string]string{"username": target.Username, "password": target.Password})
		blocked.Body.Close()
		if blocked.StatusCode != http.StatusUnauthorized {
			t.Errorf("disabled login = %d, want 401", blocked.StatusCode)
		}

		// AC-17: enable -> can authenticate again
		er := doReq(t, asRole(t, "POST", url+"/api/v1/users/"+target.ID.String()+":enable", auth.RoleAdmin, nil))
		er.Body.Close()
		if er.StatusCode != http.StatusOK {
			t.Fatalf("enable = %d, want 200", er.StatusCode)
		}
		reLogin := login(t, url, map[string]string{"username": target.Username, "password": target.Password})
		reLogin.Body.Close()
		if reLogin.StatusCode != http.StatusOK {
			t.Errorf("login after enable = %d, want 200", reLogin.StatusCode)
		}

		// AC-18: admin cannot disable their own account -> 409
		self := doReq(t, asRole(t, "POST", url+"/api/v1/users/"+roleUserIDs[auth.RoleAdmin].String()+":disable", auth.RoleAdmin, nil))
		self.Body.Close()
		if self.StatusCode != http.StatusConflict {
			t.Errorf("self-disable = %d, want 409", self.StatusCode)
		}
	})
}

// @ac AC-19
func TestAPI_AdminUserMgmt_NotFoundAndRBAC(t *testing.T) {
	t.Run("api-users/AC-19", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		ghost := uuid.Must(uuid.NewV7()).String()

		// unknown user -> 404 on all three
		for _, action := range []string{":reset-password", ":disable", ":enable"} {
			body := map[string]any(nil)
			if action == ":reset-password" {
				body = map[string]any{"new_password": "some-strong-pass-9Z"}
			}
			r := doReq(t, asRole(t, "POST", url+"/api/v1/users/"+ghost+action, auth.RoleAdmin, body))
			r.Body.Close()
			if r.StatusCode != http.StatusNotFound {
				t.Errorf("%s unknown user = %d, want 404", action, r.StatusCode)
			}
		}

		// non-admin (security_admin has user:write but NOT admin:user_manage) -> 403
		for _, action := range []string{":reset-password", ":disable", ":enable"} {
			body := map[string]any(nil)
			if action == ":reset-password" {
				body = map[string]any{"new_password": "some-strong-pass-9Z"}
			}
			r := doReq(t, asRole(t, "POST", url+"/api/v1/users/"+ghost+action, auth.RoleSecurityAdmin, body))
			r.Body.Close()
			if r.StatusCode != http.StatusForbidden {
				t.Errorf("%s as security_admin = %d, want 403 (lacks admin:user_manage)", action, r.StatusCode)
			}
		}
	})
}
