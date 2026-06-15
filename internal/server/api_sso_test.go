// @spec api-sso
//
// Provider CRUD RBAC, secret-free responses, the anonymous enabled list,
// and the anonymous redirect endpoints.

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/server/api"
)

// httpClientNoRedirect is a client that does NOT follow redirects, so the
// SSO login/callback 302s can be asserted directly.
func doNoRedirect(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	return resp
}

// @ac AC-01
func TestSSO_ListRBAC(t *testing.T) {
	t.Run("api-sso/AC-01", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		if r := doReq(t, asRole(t, "GET", url+"/api/v1/sso/providers", "", nil)); r.StatusCode != http.StatusUnauthorized && r.StatusCode != http.StatusForbidden {
			t.Errorf("anon list = %d, want 401/403", r.StatusCode)
		}
		if r := doReq(t, asRole(t, "GET", url+"/api/v1/sso/providers", auth.RoleViewer, nil)); r.StatusCode != http.StatusForbidden {
			t.Errorf("viewer list = %d, want 403", r.StatusCode)
		}
		if r := doReq(t, asRole(t, "GET", url+"/api/v1/sso/providers", auth.RoleAdmin, nil)); r.StatusCode != http.StatusOK {
			t.Errorf("admin list = %d, want 200", r.StatusCode)
		}
	})
}

// @ac AC-02
func TestSSO_CreateRBACAndValidation(t *testing.T) {
	t.Run("api-sso/AC-02", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		good := map[string]any{
			"name": "Acme", "issuer": "https://idp.example.com",
			"client_id": "abc", "client_secret": "shh", "default_role": "viewer",
		}
		// Viewer denied.
		if r := doReq(t, asRole(t, "POST", url+"/api/v1/sso/providers", auth.RoleViewer, good)); r.StatusCode != http.StatusForbidden {
			t.Errorf("viewer create = %d, want 403", r.StatusCode)
		}
		// Admin creates; response carries no secret.
		r := doReq(t, asRole(t, "POST", url+"/api/v1/sso/providers", auth.RoleAdmin, good))
		if r.StatusCode != http.StatusCreated {
			t.Fatalf("admin create = %d, want 201", r.StatusCode)
		}
		body := readBody(t, r)
		if strings.Contains(body, "shh") || strings.Contains(strings.ToLower(body), "client_secret") {
			t.Errorf("create response leaked the secret: %s", body)
		}
		// Non-https issuer → 400.
		bad := map[string]any{"name": "x", "issuer": "http://idp", "client_id": "a", "client_secret": "s"}
		if r := doReq(t, asRole(t, "POST", url+"/api/v1/sso/providers", auth.RoleAdmin, bad)); r.StatusCode != http.StatusBadRequest {
			t.Errorf("http issuer create = %d, want 400", r.StatusCode)
		}
	})
}

// @ac AC-03
// @ac AC-04
func TestSSO_UpdateDeleteRBAC(t *testing.T) {
	t.Run("api-sso/AC-03", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		r := doReq(t, asRole(t, "POST", url+"/api/v1/sso/providers", auth.RoleAdmin, map[string]any{
			"name": "Acme", "issuer": "https://idp.example.com", "client_id": "abc", "client_secret": "shh",
		}))
		var created api.SSOProvider
		_ = json.NewDecoder(r.Body).Decode(&created)
		id := created.Id.String()

		upd := map[string]any{"name": "Acme2", "issuer": "https://idp.example.com", "client_id": "abc"}
		if dr := doReq(t, asRole(t, "PUT", url+"/api/v1/sso/providers/"+id, auth.RoleViewer, upd)); dr.StatusCode != http.StatusForbidden {
			t.Errorf("viewer update = %d, want 403", dr.StatusCode)
		}
		if dr := doReq(t, asRole(t, "PUT", url+"/api/v1/sso/providers/"+id, auth.RoleAdmin, upd)); dr.StatusCode != http.StatusOK {
			t.Errorf("admin update = %d, want 200", dr.StatusCode)
		}
		// Unknown id → 404.
		if dr := doReq(t, asRole(t, "PUT", url+"/api/v1/sso/providers/11111111-1111-1111-1111-111111111111", auth.RoleAdmin, upd)); dr.StatusCode != http.StatusNotFound {
			t.Errorf("update unknown = %d, want 404", dr.StatusCode)
		}
	})
	t.Run("api-sso/AC-04", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		r := doReq(t, asRole(t, "POST", url+"/api/v1/sso/providers", auth.RoleAdmin, map[string]any{
			"name": "Acme", "issuer": "https://idp.example.com", "client_id": "abc", "client_secret": "shh",
		}))
		var created api.SSOProvider
		_ = json.NewDecoder(r.Body).Decode(&created)
		id := created.Id.String()
		if dr := doReq(t, asRole(t, "DELETE", url+"/api/v1/sso/providers/"+id, auth.RoleViewer, nil)); dr.StatusCode != http.StatusForbidden {
			t.Errorf("viewer delete = %d, want 403", dr.StatusCode)
		}
		if dr := doReq(t, asRole(t, "DELETE", url+"/api/v1/sso/providers/"+id, auth.RoleAdmin, nil)); dr.StatusCode != http.StatusNoContent {
			t.Errorf("admin delete = %d, want 204", dr.StatusCode)
		}
		if dr := doReq(t, asRole(t, "DELETE", url+"/api/v1/sso/providers/"+id, auth.RoleAdmin, nil)); dr.StatusCode != http.StatusNotFound {
			t.Errorf("delete again = %d, want 404", dr.StatusCode)
		}
	})
}

// @ac AC-05
func TestSSO_EnabledListAnonymous(t *testing.T) {
	t.Run("api-sso/AC-05", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		// Create one enabled + one disabled provider.
		_ = doReq(t, asRole(t, "POST", url+"/api/v1/sso/providers", auth.RoleAdmin, map[string]any{
			"name": "EnabledCo", "issuer": "https://e.example.com", "client_id": "a", "client_secret": "s", "enabled": true,
		}))
		_ = doReq(t, asRole(t, "POST", url+"/api/v1/sso/providers", auth.RoleAdmin, map[string]any{
			"name": "DisabledCo", "issuer": "https://d.example.com", "client_id": "b", "client_secret": "s", "enabled": false,
		}))
		// Anonymous GET succeeds and lists only the enabled one, id+name only.
		r := doReq(t, asRole(t, "GET", url+"/api/v1/sso/providers/enabled", "", nil))
		if r.StatusCode != http.StatusOK {
			t.Fatalf("anon enabled = %d, want 200", r.StatusCode)
		}
		body := readBody(t, r)
		if !strings.Contains(body, "EnabledCo") || strings.Contains(body, "DisabledCo") {
			t.Errorf("enabled list wrong: %s", body)
		}
		if strings.Contains(body, "issuer") || strings.Contains(body, "client_id") {
			t.Errorf("enabled list leaked non-public fields: %s", body)
		}
	})
}

// @ac AC-06
func TestSSO_LoginCallbackRedirects(t *testing.T) {
	t.Run("api-sso/AC-06", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		// Unknown provider login → 302 to /login?sso_error.
		req := mustGet(t, url+"/api/v1/auth/sso/11111111-1111-1111-1111-111111111111/login")
		r := doNoRedirect(t, req)
		if r.StatusCode != http.StatusFound {
			t.Fatalf("login redirect = %d, want 302", r.StatusCode)
		}
		if loc := r.Header.Get("Location"); !strings.Contains(loc, "/login") || !strings.Contains(loc, "sso_error") {
			t.Errorf("login redirect Location = %q, want /login?sso_error", loc)
		}
		// Callback with missing code/state → 302 to /login?sso_error.
		req2 := mustGet(t, url+"/api/v1/auth/sso/11111111-1111-1111-1111-111111111111/callback")
		r2 := doNoRedirect(t, req2)
		if r2.StatusCode != http.StatusFound {
			t.Fatalf("callback redirect = %d, want 302", r2.StatusCode)
		}
		if loc := r2.Header.Get("Location"); !strings.Contains(loc, "sso_error") {
			t.Errorf("callback redirect Location = %q, want sso_error", loc)
		}
	})
}

func mustGet(t *testing.T, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	return req
}
