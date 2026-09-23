// @spec system-rbac
//
// A custom role confers its stored permission set when a request is bound
// (C-11, 2.3.0), through the real binder on real sessions and API tokens,
// and primary-role binding is unchanged.
//
//	AC-27  TestRBAC_CustomRoleGrantsItsPermissionsAtBindTime
//	AC-28  TestRBAC_BuiltInRolePrecedenceIsPreservedOverCustom
package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/Hanalyx/openwatch/internal/server/api"
)

func createCustomRole(t *testing.T, url, id string, perms []string) {
	t.Helper()
	req := asRole(t, "POST", url+"/api/v1/roles:create", auth.RoleAdmin, map[string]any{
		"id": id, "description": "custom role for binding tests", "permissions": perms,
	})
	resp := doReq(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("roles:create %s = %d body=%s", id, resp.StatusCode, b)
	}
}

func assignRole(t *testing.T, url string, uid uuid.UUID, role string) {
	t.Helper()
	req := asRole(t, "POST", url+"/api/v1/users/"+uid.String()+"/roles:assign", auth.RoleAdmin, map[string]string{"role_id": role})
	resp := doReq(t, req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("roles:assign %s = %d, want 204", role, resp.StatusCode)
	}
}

func sessionCookieFor(t *testing.T, pool *pgxpool.Pool, uid uuid.UUID) *http.Cookie {
	t.Helper()
	tok, _, err := identity.IssueSession(context.Background(), pool, uid, "127.0.0.1", "custom-role-test")
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}
	return &http.Cookie{Name: identity.SessionCookieName, Value: tok}
}

// mePermissions decodes GET /api/v1/auth/me/permissions for a request
// carrying the given credential.
func mePermissions(t *testing.T, url string, decorate func(*http.Request)) (role string, perms []string) {
	t.Helper()
	req, _ := http.NewRequest("GET", url+"/api/v1/auth/me/permissions", nil)
	decorate(req)
	resp := doReq(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("me/permissions = %d body=%s", resp.StatusCode, b)
	}
	var got struct {
		Identity struct {
			Role string `json:"role"`
		} `json:"identity"`
		Permissions []string `json:"permissions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return got.Identity.Role, got.Permissions
}

func statusFor(t *testing.T, method, url string, decorate func(*http.Request), body any) int {
	t.Helper()
	var req *http.Request
	if body != nil {
		req = asRole(t, method, url, "", body) // no fixture cookie; decorate adds the credential
	} else {
		req, _ = http.NewRequest(method, url, nil)
	}
	decorate(req)
	if !isSafeMethod(method) {
		const tok = "test-csrf-token"
		req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: tok})
		req.Header.Set(csrfHeaderName, tok)
	}
	resp := doReq(t, req)
	resp.Body.Close()
	return resp.StatusCode
}

// @ac AC-27
func TestRBAC_CustomRoleGrantsItsPermissionsAtBindTime(t *testing.T) {
	t.Run("system-rbac/AC-27", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		createCustomRole(t, url, "host_reader", []string{"host:read"})
		created := createUser(t, url, "customonly")
		uid := uuid.MustParse(created["id"].(string))
		assignRole(t, url, uid, "host_reader")

		cookie := sessionCookieFor(t, pool, uid)
		withCookie := func(r *http.Request) { r.AddCookie(cookie) }

		if got := statusFor(t, "GET", url+"/api/v1/hosts", withCookie, nil); got != http.StatusOK {
			t.Errorf("custom-only user GET /hosts = %d, want 200 (host:read granted by the custom role)", got)
		}
		if got := statusFor(t, "POST", url+"/api/v1/hosts", withCookie, map[string]any{"hostname": "x", "ip_address": "10.0.0.9"}); got != http.StatusForbidden {
			t.Errorf("custom-only user POST /hosts = %d, want 403 (host:write not granted)", got)
		}
		role, perms := mePermissions(t, url, withCookie)
		if role != "host_reader" || len(perms) != 1 || perms[0] != "host:read" {
			t.Errorf("me/permissions = role %q perms %v, want host_reader [host:read]", role, perms)
		}

		// An API token minted for the custom role binds the same grants.
		req := asRole(t, "POST", url+"/api/v1/tokens", auth.RoleAdmin, map[string]any{"name": "custom-bot", "role_id": "host_reader"})
		resp := doReq(t, req)
		if resp.StatusCode != http.StatusCreated {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("tokens create = %d body=%s", resp.StatusCode, b)
		}
		var tokenCreated api.ApiTokenCreated
		_ = json.NewDecoder(resp.Body).Decode(&tokenCreated)
		resp.Body.Close()
		withToken := func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tokenCreated.Token) }
		if got := statusFor(t, "GET", url+"/api/v1/hosts", withToken, nil); got != http.StatusOK {
			t.Errorf("custom-role API token GET /hosts = %d, want 200", got)
		}
		if _, perms := mePermissions(t, url, withToken); len(perms) != 1 || perms[0] != "host:read" {
			t.Errorf("token me/permissions = %v, want [host:read]", perms)
		}

		// A session JWT minted while the role existed outlives the role: the
		// user_roles and api_tokens rows are FK-restricted, so a deleted role
		// can only be met through a stale JWT claim. The credential is valid,
		// the role resolves to nothing, and the answer is 403, not 401.
		// Bound to a live session: an unbound access token is refused
		// outright (C-38), which would mask what this case is about.
		_, jwtSess, err := identity.IssueSession(context.Background(), pool, uid, "127.0.0.1", "go-test")
		if err != nil {
			t.Fatalf("issue session for jwt: %v", err)
		}
		jwtTok, _, err := identity.IssueJWTForSession(uid, "host_reader", jwtSess.ID)
		if err != nil {
			t.Fatalf("issue jwt: %v", err)
		}
		withJWT := func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+jwtTok) }
		if got := statusFor(t, "GET", url+"/api/v1/hosts", withJWT, nil); got != http.StatusOK {
			t.Fatalf("custom-role JWT GET /hosts before deletion = %d, want 200", got)
		}
		for _, q := range []string{
			`DELETE FROM user_roles WHERE role_id = 'host_reader'`,
			`DELETE FROM api_tokens WHERE role_id = 'host_reader'`,
			`DELETE FROM roles WHERE id = 'host_reader'`,
		} {
			if _, err := pool.Exec(context.Background(), q); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
		if got := statusFor(t, "GET", url+"/api/v1/hosts", withJWT, nil); got != http.StatusForbidden {
			t.Errorf("JWT for a deleted custom role GET /hosts = %d, want 403 (valid credential, no permissions)", got)
		}
	})
}

// @ac AC-28
func TestRBAC_BuiltInRolePrecedenceIsPreservedOverCustom(t *testing.T) {
	t.Run("system-rbac/AC-28", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		createCustomRole(t, url, "host_writer", []string{"host:write"})
		created := createUser(t, url, "viewerpluscustom")
		uid := uuid.MustParse(created["id"].(string))
		assignRole(t, url, uid, "viewer")
		assignRole(t, url, uid, "host_writer")

		cookie := sessionCookieFor(t, pool, uid)
		withCookie := func(r *http.Request) { r.AddCookie(cookie) }
		role, perms := mePermissions(t, url, withCookie)
		if role != string(auth.RoleViewer) {
			t.Errorf("bound role = %q, want viewer (system-user-management C-06)", role)
		}
		want := auth.BuiltInRoles[auth.RoleViewer].Permissions
		if len(perms) != len(want) {
			t.Errorf("permissions = %d entries, want the viewer set (%d); the custom grant must not be added", len(perms), len(want))
		}
		for _, p := range perms {
			if p == "host:write" {
				t.Errorf("host:write present in the bound set; union of roles is features/OW-007, not this contract")
			}
		}
		if got := statusFor(t, "POST", url+"/api/v1/hosts", withCookie, map[string]any{"hostname": "x", "ip_address": "10.0.0.8"}); got != http.StatusForbidden {
			t.Errorf("viewer+custom POST /hosts = %d, want 403", got)
		}
	})
}
