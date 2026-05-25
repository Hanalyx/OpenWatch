// @spec api-users
//
// User CRUD + custom-role administration HTTP integration tests.
// Skipped without OPENWATCH_TEST_DSN.

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/google/uuid"
)

// asRole builds a request carrying the session cookie of the fixture
// user pre-seeded for that role. The production identity binder reads
// the cookie, looks up the user in the sessions table, and attaches a
// real Identity on the request — no header-based bypass.
//
// Pass auth.RoleID("") (or omit) to produce an unauthenticated
// request.
func asRole(t *testing.T, method, url string, role auth.RoleID, body any) *http.Request {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		bs, _ := json.Marshal(body)
		rdr = bytes.NewReader(bs)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if role != "" {
		cookie, ok := roleCookies[role]
		if !ok {
			t.Fatalf("asRole: no fixture session for role %q (seeded: %v)", role, seededRoles)
		}
		req.AddCookie(cookie)
	}
	return req
}

// createUser is the canonical happy-path POST /admin/users helper used
// by setup in multiple AC tests.
func createUser(t *testing.T, srvURL, username string) map[string]any {
	t.Helper()
	body := map[string]any{
		"username": username,
		"email":    username + "@example.com",
		"password": "test-passphrase-strong-zZ-" + username,
	}
	req := asRole(t, "POST", srvURL+"/api/v1/admin/users", auth.RoleAdmin, body)
	resp := doReq(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("seed createUser %s: status=%d body=%s", username, resp.StatusCode, b)
	}
	var got map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode createUser: %v", err)
	}
	return got
}

// @ac AC-01
// AC-01: POST /admin/users with admin caller and valid body returns 201
// with the new user JSON; response body does NOT contain password_hash.
func TestUsers_Create_Success(t *testing.T) {
	t.Run("api-users/AC-01", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := map[string]any{
			"username": "ac01user",
			"email":    "ac01@example.com",
			"password": "test-passphrase-strong-zZ-ac01",
		}
		req := asRole(t, "POST", url+"/api/v1/admin/users", auth.RoleAdmin, body)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d body=%s", resp.StatusCode, b)
		}
		raw, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(raw), "password_hash") {
			t.Errorf("response leaks password_hash: %s", raw)
		}
		var got map[string]any
		_ = json.Unmarshal(raw, &got)
		if got["username"] != "ac01user" || got["email"] != "ac01@example.com" {
			t.Errorf("unexpected body: %s", raw)
		}
		if _, ok := got["id"].(string); !ok {
			t.Errorf("missing id in body: %s", raw)
		}
	})
}

// @ac AC-02
// AC-02: POST /admin/users with a caller missing user:write returns 403
// authz.permission_denied; no user is inserted.
func TestUsers_Create_DeniedWithoutPermission(t *testing.T) {
	t.Run("api-users/AC-02", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		body := map[string]any{
			"username": "ac02user",
			"email":    "ac02@example.com",
			"password": "test-passphrase-strong-zZ-ac02",
		}
		// viewer lacks user:write.
		req := asRole(t, "POST", url+"/api/v1/admin/users", auth.RoleViewer, body)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "authz.permission_denied") {
			t.Errorf("body lacks authz.permission_denied: %s", b)
		}
		// Confirm no user was inserted.
		var count int64
		_ = pool.QueryRow(context.Background(),
			`SELECT count(*) FROM users WHERE username = $1`, "ac02user").Scan(&count)
		if count != 0 {
			t.Errorf("user count = %d, want 0", count)
		}
	})
}

// @ac AC-03
// AC-03: POST /admin/users with a weak password (fails NIST policy)
// returns 400; no user inserted.
func TestUsers_Create_WeakPasswordRejected(t *testing.T) {
	t.Run("api-users/AC-03", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		body := map[string]any{
			"username": "ac03user",
			"email":    "ac03@example.com",
			"password": "short", // way below NIST 800-63B minimum length.
		}
		req := asRole(t, "POST", url+"/api/v1/admin/users", auth.RoleAdmin, body)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d, want 400; body=%s", resp.StatusCode, b)
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "auth.password_policy") {
			t.Errorf("body lacks auth.password_policy: %s", b)
		}
		var count int64
		_ = pool.QueryRow(context.Background(),
			`SELECT count(*) FROM users WHERE username = $1`, "ac03user").Scan(&count)
		if count != 0 {
			t.Errorf("user count = %d, want 0", count)
		}
	})
}

// @ac AC-04
// AC-04: GET /admin/users with auth.UserRead returns 200 with a JSON
// array of users; each item lacks password_hash.
func TestUsers_List_Success(t *testing.T) {
	t.Run("api-users/AC-04", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		_ = createUser(t, url, "ac04a")
		_ = createUser(t, url, "ac04b")

		req := asRole(t, "GET", url+"/api/v1/admin/users", auth.RoleAdmin, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d body=%s", resp.StatusCode, b)
		}
		raw, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(raw), "password_hash") {
			t.Errorf("list leaks password_hash: %s", raw)
		}
		var body struct {
			Users []map[string]any `json:"users"`
		}
		_ = json.Unmarshal(raw, &body)
		if len(body.Users) < 2 {
			t.Errorf("users len = %d, want >= 2", len(body.Users))
		}
	})
}

// @ac AC-05
// AC-05: GET /admin/users with a caller missing user:read returns 403.
func TestUsers_List_DeniedWithoutPermission(t *testing.T) {
	t.Run("api-users/AC-05", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		// ops_lead lacks user:read.
		req := asRole(t, "GET", url+"/api/v1/admin/users", auth.RoleOpsLead, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
	})
}

// @ac AC-06
// AC-06: GET /admin/users/{id} with admin caller returns 200 with the
// user; unknown id returns 404.
func TestUsers_Get_HappyAndNotFound(t *testing.T) {
	t.Run("api-users/AC-06", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		created := createUser(t, url, "ac06user")
		uid := created["id"].(string)

		req := asRole(t, "GET", url+"/api/v1/admin/users/"+uid, auth.RoleAdmin, nil)
		resp := doReq(t, req)
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get status = %d body=%s", resp.StatusCode, b)
		}
		var got map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&got)
		resp.Body.Close()
		if got["username"] != "ac06user" {
			t.Errorf("username = %v, want ac06user", got["username"])
		}

		// Unknown id → 404.
		other := uuid.New().String()
		req = asRole(t, "GET", url+"/api/v1/admin/users/"+other, auth.RoleAdmin, nil)
		resp = doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("unknown status = %d, want 404", resp.StatusCode)
		}
	})
}

// @ac AC-07
// AC-07: DELETE /admin/users/{id} with auth.UserDelete returns 204;
// subsequent GET returns 404.
func TestUsers_Delete(t *testing.T) {
	t.Run("api-users/AC-07", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		created := createUser(t, url, "ac07user")
		uid := created["id"].(string)

		req := asRole(t, "DELETE", url+"/api/v1/admin/users/"+uid, auth.RoleAdmin, nil)
		resp := doReq(t, req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("delete status = %d, want 204", resp.StatusCode)
		}

		// Get returns 404.
		req = asRole(t, "GET", url+"/api/v1/admin/users/"+uid, auth.RoleAdmin, nil)
		resp = doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("get-after-delete status = %d, want 404", resp.StatusCode)
		}
	})
}

// @ac AC-08
// AC-08: POST /admin/users/{id}/roles:assign with body {role_id: "viewer"}
// returns 204; user_roles row created; role:assign permission enforced.
func TestUsers_AssignRole(t *testing.T) {
	t.Run("api-users/AC-08", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		created := createUser(t, url, "ac08user")
		uid := created["id"].(string)

		req := asRole(t, "POST", url+"/api/v1/admin/users/"+uid+"/roles:assign", auth.RoleAdmin,
			map[string]string{"role_id": "viewer"})
		resp := doReq(t, req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("assign status = %d, want 204", resp.StatusCode)
		}

		var count int64
		_ = pool.QueryRow(context.Background(),
			`SELECT count(*) FROM user_roles WHERE user_id = $1 AND role_id = $2`,
			uid, "viewer").Scan(&count)
		if count != 1 {
			t.Errorf("user_roles count = %d, want 1", count)
		}

		// Caller without role:assign → 403.
		req = asRole(t, "POST", url+"/api/v1/admin/users/"+uid+"/roles:assign", auth.RoleViewer,
			map[string]string{"role_id": "auditor"})
		resp = doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("denied status = %d, want 403", resp.StatusCode)
		}
	})
}

// @ac AC-09
// AC-09: POST /admin/users/{id}/roles:assign with unknown role id returns
// 400 with error.code = "users.unknown_role".
func TestUsers_AssignRole_Unknown(t *testing.T) {
	t.Run("api-users/AC-09", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		created := createUser(t, url, "ac09user")
		uid := created["id"].(string)

		req := asRole(t, "POST", url+"/api/v1/admin/users/"+uid+"/roles:assign", auth.RoleAdmin,
			map[string]string{"role_id": "does_not_exist"})
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d, want 400; body=%s", resp.StatusCode, b)
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "users.unknown_role") {
			t.Errorf("body lacks users.unknown_role: %s", b)
		}
	})
}

// @ac AC-10
// AC-10: POST /admin/users/{id}/roles:unassign returns 204; idempotent
// (second call also 204).
func TestUsers_UnassignRole_Idempotent(t *testing.T) {
	t.Run("api-users/AC-10", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		created := createUser(t, url, "ac10user")
		uid := created["id"].(string)

		// Assign first.
		req := asRole(t, "POST", url+"/api/v1/admin/users/"+uid+"/roles:assign", auth.RoleAdmin,
			map[string]string{"role_id": "viewer"})
		resp := doReq(t, req)
		resp.Body.Close()

		// Unassign once.
		req = asRole(t, "POST", url+"/api/v1/admin/users/"+uid+"/roles:unassign", auth.RoleAdmin,
			map[string]string{"role_id": "viewer"})
		resp = doReq(t, req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("first unassign status = %d, want 204", resp.StatusCode)
		}

		// Unassign again — still 204.
		req = asRole(t, "POST", url+"/api/v1/admin/users/"+uid+"/roles:unassign", auth.RoleAdmin,
			map[string]string{"role_id": "viewer"})
		resp = doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Errorf("second unassign status = %d, want 204", resp.StatusCode)
		}
	})
}

// @ac AC-11
// AC-11: POST /admin/roles:create with a fresh id and valid permissions
// returns 201; roles.permissions TEXT[] column populated.
func TestUsers_CreateCustomRole(t *testing.T) {
	t.Run("api-users/AC-11", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		body := map[string]any{
			"id":          "field_auditor",
			"description": "read-only host + scan auditor",
			"permissions": []string{"host:read", "scan:read"},
		}
		req := asRole(t, "POST", url+"/api/v1/admin/roles:create", auth.RoleAdmin, body)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d body=%s", resp.StatusCode, b)
		}
		var got map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&got)
		if got["id"] != "field_auditor" {
			t.Errorf("id = %v, want field_auditor", got["id"])
		}
		if isBuiltIn, _ := got["is_built_in"].(bool); isBuiltIn {
			t.Errorf("is_built_in = true, want false")
		}

		// Check the row landed with permissions[].
		var perms []string
		err := pool.QueryRow(context.Background(),
			`SELECT permissions FROM roles WHERE id = $1`, "field_auditor").Scan(&perms)
		if err != nil {
			t.Fatalf("role lookup: %v", err)
		}
		if len(perms) != 2 {
			t.Errorf("perms = %v, want 2 entries", perms)
		}
	})
}

// @ac AC-12
// AC-12: POST /admin/roles:create with id="admin" (built-in collision)
// returns 409 with error.code = "users.role_id_taken"; POST with unknown
// permission returns 400 with error.code = "users.unknown_permission" and
// detail.invalid_permissions listing them.
func TestUsers_CreateCustomRole_Conflicts(t *testing.T) {
	t.Run("api-users/AC-12", func(t *testing.T) {
		url, _ := freshAPIServer(t)

		// Built-in collision.
		body := map[string]any{
			"id":          "admin",
			"description": "would clash with built-in",
			"permissions": []string{"host:read"},
		}
		req := asRole(t, "POST", url+"/api/v1/admin/roles:create", auth.RoleAdmin, body)
		resp := doReq(t, req)
		if resp.StatusCode != http.StatusConflict {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("collision status = %d, want 409; body=%s", resp.StatusCode, b)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(b), "users.role_id_taken") {
			t.Errorf("body lacks users.role_id_taken: %s", b)
		}

		// Unknown permission.
		body = map[string]any{
			"id":          "broken_role",
			"description": "grants a fictional permission",
			"permissions": []string{"host:read", "doesnt:exist"},
		}
		req = asRole(t, "POST", url+"/api/v1/admin/roles:create", auth.RoleAdmin, body)
		resp = doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("unknown-perm status = %d, want 400", resp.StatusCode)
		}
		b, _ = io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "users.unknown_permission") {
			t.Errorf("body lacks users.unknown_permission: %s", b)
		}
		// detail.invalid_permissions must list the offender.
		var envelope struct {
			Error struct {
				Detail map[string]any `json:"detail"`
			} `json:"error"`
		}
		_ = json.Unmarshal(b, &envelope)
		invalid, _ := envelope.Error.Detail["invalid_permissions"].([]any)
		if len(invalid) != 1 || invalid[0] != "doesnt:exist" {
			t.Errorf("invalid_permissions = %v, want [doesnt:exist]", invalid)
		}
	})
}
