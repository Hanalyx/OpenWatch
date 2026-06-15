// @spec api-tokens
//
// CRUD-lite + RBAC + once-only secret for /api/v1/tokens, plus an
// end-to-end proof that an issued token authenticates a real request.

package server

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/server/api"
)

// @ac AC-01
func TestTokens_ListRBAC(t *testing.T) {
	t.Run("api-tokens/AC-01", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		// Anonymous denied.
		if r := doReq(t, asRole(t, "GET", url+"/api/v1/tokens", "", nil)); r.StatusCode != http.StatusUnauthorized && r.StatusCode != http.StatusForbidden {
			t.Errorf("anon list = %d, want 401/403", r.StatusCode)
		}
		// Viewer lacks token:read → 403.
		if r := doReq(t, asRole(t, "GET", url+"/api/v1/tokens", auth.RoleViewer, nil)); r.StatusCode != http.StatusForbidden {
			t.Errorf("viewer list = %d, want 403", r.StatusCode)
		}
		// Admin → 200.
		if r := doReq(t, asRole(t, "GET", url+"/api/v1/tokens", auth.RoleAdmin, nil)); r.StatusCode != http.StatusOK {
			t.Errorf("admin list = %d, want 200", r.StatusCode)
		}
	})
}

// @ac AC-02
func TestTokens_CreateReturnsSecretOnce(t *testing.T) {
	t.Run("api-tokens/AC-02", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := map[string]any{"name": "ci-deploy", "role_id": "auditor"}
		r := doReq(t, asRole(t, "POST", url+"/api/v1/tokens", auth.RoleAdmin, body))
		if r.StatusCode != http.StatusCreated {
			t.Fatalf("create = %d, want 201", r.StatusCode)
		}
		var created api.ApiTokenCreated
		if err := json.NewDecoder(r.Body).Decode(&created); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !strings.HasPrefix(created.Token, auth.APITokenPrefix) {
			t.Errorf("created.token %q lacks owk_ prefix", created.Token)
		}
		if !strings.HasPrefix(created.ApiToken.Prefix, auth.APITokenPrefix) {
			t.Errorf("metadata prefix wrong: %q", created.ApiToken.Prefix)
		}
		// The raw secret appears in NO list entry.
		lr := doReq(t, asRole(t, "GET", url+"/api/v1/tokens", auth.RoleAdmin, nil))
		listRaw := readBody(t, lr)
		if strings.Contains(listRaw, created.Token) {
			t.Errorf("list leaked the raw token: %s", listRaw)
		}
		if !strings.Contains(listRaw, created.ApiToken.Prefix) {
			t.Errorf("list missing the token prefix: %s", listRaw)
		}
	})
}

// @ac AC-03
func TestTokens_DeleteRBACAndBadRole(t *testing.T) {
	t.Run("api-tokens/AC-03", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		// Unknown role → 400.
		if r := doReq(t, asRole(t, "POST", url+"/api/v1/tokens", auth.RoleAdmin,
			map[string]any{"name": "x", "role_id": "not_a_role"})); r.StatusCode != http.StatusBadRequest {
			t.Errorf("unknown role create = %d, want 400", r.StatusCode)
		}
		// Create a valid one, then test delete RBAC.
		r := doReq(t, asRole(t, "POST", url+"/api/v1/tokens", auth.RoleAdmin,
			map[string]any{"name": "del", "role_id": "viewer"}))
		var created api.ApiTokenCreated
		_ = json.NewDecoder(r.Body).Decode(&created)
		id := created.ApiToken.Id.String()
		if dr := doReq(t, asRole(t, "DELETE", url+"/api/v1/tokens/"+id, auth.RoleViewer, nil)); dr.StatusCode != http.StatusForbidden {
			t.Errorf("viewer delete = %d, want 403", dr.StatusCode)
		}
		if dr := doReq(t, asRole(t, "DELETE", url+"/api/v1/tokens/"+id, auth.RoleAdmin, nil)); dr.StatusCode != http.StatusNoContent {
			t.Errorf("admin delete = %d, want 204", dr.StatusCode)
		}
	})
}

// @ac AC-04
func TestTokens_ResponseHasNoSecretField(t *testing.T) {
	t.Run("api-tokens/AC-04", func(t *testing.T) {
		rt := reflect.TypeOf(api.ApiToken{})
		for _, banned := range []string{"Token", "Hash", "TokenHash", "Secret"} {
			if _, ok := rt.FieldByName(banned); ok {
				t.Errorf("ApiToken response exposes secret field %q", banned)
			}
		}
	})
}

// End-to-end: an issued token authenticates a real request as its role.
// A security_admin token (which holds token:read) can list tokens; after
// revocation the same bearer is rejected.
func TestTokens_BearerAuthenticatesRequest(t *testing.T) {
	t.Run("api-tokens/AC-02", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		r := doReq(t, asRole(t, "POST", url+"/api/v1/tokens", auth.RoleAdmin,
			map[string]any{"name": "automation", "role_id": "security_admin"}))
		var created api.ApiTokenCreated
		if err := json.NewDecoder(r.Body).Decode(&created); err != nil {
			t.Fatalf("decode: %v", err)
		}
		// Use the raw token as a bearer to list tokens → 200 (token acts as
		// security_admin, which holds token:read).
		req, _ := http.NewRequest("GET", url+"/api/v1/tokens", nil)
		req.Header.Set("Authorization", "Bearer "+created.Token)
		if br := doReq(t, req); br.StatusCode != http.StatusOK {
			t.Fatalf("bearer-token list = %d, want 200", br.StatusCode)
		}
		// Revoke it, then the same bearer is rejected (401/403).
		if dr := doReq(t, asRole(t, "DELETE", url+"/api/v1/tokens/"+created.ApiToken.Id.String(), auth.RoleAdmin, nil)); dr.StatusCode != http.StatusNoContent {
			t.Fatalf("revoke = %d, want 204", dr.StatusCode)
		}
		req2, _ := http.NewRequest("GET", url+"/api/v1/tokens", nil)
		req2.Header.Set("Authorization", "Bearer "+created.Token)
		if br := doReq(t, req2); br.StatusCode != http.StatusUnauthorized && br.StatusCode != http.StatusForbidden {
			t.Errorf("revoked bearer list = %d, want 401/403", br.StatusCode)
		}
	})
}
