// @spec release-admin-signoff
//
// End-to-end admin-flow test. Drives the full admin surface through the
// production identity binder: an admin user is created via the API,
// logs in, and uses the resulting session cookie to register a host,
// register credentials, resolve credentials, and soft-delete. No
// header-based identity bypass exists in the binary — the cookie path
// is the only path.

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

// @ac AC-09
// AC-09: end-to-end admin-flow test. Proves the full admin surface
// holds together via real identity. The flow:
//  1. Bootstrap an admin user via the asRole helper, which carries the
//     fixture's pre-minted admin session cookie.
//  2. Login as the newly-created user via /auth/login to mint a fresh
//     session cookie tied to that user's id.
//  3. Subsequent admin calls use ONLY that cookie.
//  4. Exercise host + credential + resolve + soft-delete with real
//     identity threading through every layer.
func TestAdminE2E_RealIdentity(t *testing.T) {
	t.Run("release-admin-signoff/AC-09", func(t *testing.T) {
		url, pool := freshAPIServer(t)

		// Step 1 — Bootstrap. Use the fixture's pre-seeded admin session
		// cookie (no plaintext password is stored for the fixture admin)
		// to create a fresh admin user via the API, then assign that
		// user the admin role.
		realPw := "admin-flow-pw-zZ-12345"
		body := map[string]any{
			"username": "e2e-admin",
			"email":    "e2e-admin@example.com",
			"password": realPw,
			"is_admin": true,
		}
		req := asRole(t, "POST", url+"/api/v1/admin/users", "admin", body)
		resp := doReq(t, req)
		if resp.StatusCode != http.StatusCreated {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("bootstrap user create: status=%d body=%s", resp.StatusCode, b)
		}
		var createdUser map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&createdUser)
		resp.Body.Close()
		uid := createdUser["id"].(string)

		req = asRole(t, "POST",
			url+"/api/v1/admin/users/"+uid+"/roles:assign", "admin",
			map[string]string{"role_id": "admin"})
		resp = doReq(t, req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("bootstrap role assign: status=%d", resp.StatusCode)
		}

		// Step 2 — Login as the new admin via the real /auth/login path.
		loginBody, _ := json.Marshal(map[string]string{
			"username": "e2e-admin", "password": realPw,
		})
		req, _ = http.NewRequest("POST", url+"/api/v1/auth/login", bytes.NewReader(loginBody))
		req.Header.Set("Content-Type", "application/json")
		resp = doReq(t, req)
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("login: status=%d body=%s", resp.StatusCode, b)
		}
		cookie := pickSessionCookie(resp)
		resp.Body.Close()
		if cookie == nil {
			t.Fatal("login returned no session cookie")
		}

		// Helper: build a request that carries only the session cookie
		// for the newly-logged-in user.
		realReq := func(method, path string, payload any) *http.Request {
			t.Helper()
			var rdr io.Reader
			if payload != nil {
				bs, _ := json.Marshal(payload)
				rdr = bytes.NewReader(bs)
			}
			r, err := http.NewRequest(method, url+path, rdr)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			if payload != nil {
				r.Header.Set("Content-Type", "application/json")
			}
			r.AddCookie(cookie)
			return r
		}

		// Step 3 — GET /auth/me confirms the session resolved to the
		// real user and the real role.
		resp = doReq(t, realReq("GET", "/api/v1/auth/me", nil))
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("auth/me: status=%d body=%s", resp.StatusCode, b)
		}
		var me struct {
			Username string `json:"username"`
			Role     string `json:"role"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&me)
		resp.Body.Close()
		if me.Username != "e2e-admin" {
			t.Errorf("auth/me username = %q, want e2e-admin", me.Username)
		}
		if me.Role != "admin" {
			t.Errorf("auth/me role = %q, want admin", me.Role)
		}

		// Step 4 — Create a host through real identity.
		resp = doReq(t, realReq("POST", "/api/v1/admin/hosts", map[string]any{
			"hostname":    "e2e-host",
			"ip_address":  "192.0.2.77",
			"environment": "production",
			"tags":        []string{"critical"},
		}))
		if resp.StatusCode != http.StatusCreated {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("create host: status=%d body=%s", resp.StatusCode, b)
		}
		var createdHost map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&createdHost)
		resp.Body.Close()
		hostID := createdHost["hostname"]
		if hostID != "e2e-host" {
			t.Errorf("hostname = %v, want e2e-host", hostID)
		}
		// The host's created_by MUST be the logged-in user's id.
		if createdHost["created_by"] != uid {
			t.Errorf("created_by = %v, want %v (real user)", createdHost["created_by"], uid)
		}
		hid := createdHost["id"].(string)

		// Step 5 — Create a system-default credential.
		resp = doReq(t, realReq("POST", "/api/v1/admin/credentials", map[string]any{
			"scope": "system", "name": "e2e-sys", "username": "sysuser",
			"auth_method": "password", "password": "sys-pw", "is_default": true,
		}))
		if resp.StatusCode != http.StatusCreated {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("create sys cred: status=%d body=%s", resp.StatusCode, b)
		}
		resp.Body.Close()

		// Step 6 — Resolve credential for the host: with no host-scope
		// row, we should get the system default.
		resp = doReq(t, realReq("POST",
			"/api/v1/admin/hosts/"+hid+"/credentials:resolve", nil))
		var resolved map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&resolved)
		resp.Body.Close()
		if resolved["scope"] != "system" || resolved["username"] != "sysuser" {
			t.Errorf("resolve (no host-scope) = %v, want system/sysuser", resolved)
		}

		// Step 7 — Create a host-scope credential and re-resolve. It
		// must shadow the system default per spec C-06.
		resp = doReq(t, realReq("POST", "/api/v1/admin/credentials", map[string]any{
			"scope": "host", "scope_id": hid,
			"name": "e2e-host-override", "username": "hostuser",
			"auth_method": "password", "password": "host-pw",
		}))
		if resp.StatusCode != http.StatusCreated {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("create host cred: status=%d body=%s", resp.StatusCode, b)
		}
		var hostCred map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&hostCred)
		resp.Body.Close()
		hcid := hostCred["id"].(string)

		resp = doReq(t, realReq("POST",
			"/api/v1/admin/hosts/"+hid+"/credentials:resolve", nil))
		_ = json.NewDecoder(resp.Body).Decode(&resolved)
		resp.Body.Close()
		if resolved["scope"] != "host" || resolved["username"] != "hostuser" {
			t.Errorf("resolve (host-scope) = %v, want host/hostuser", resolved)
		}

		// Step 8 — Soft-delete the host-scope cred. Resolver must fall
		// back to system default.
		resp = doReq(t, realReq("DELETE", "/api/v1/admin/credentials/"+hcid, nil))
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("delete host cred: status=%d", resp.StatusCode)
		}
		resp = doReq(t, realReq("POST",
			"/api/v1/admin/hosts/"+hid+"/credentials:resolve", nil))
		_ = json.NewDecoder(resp.Body).Decode(&resolved)
		resp.Body.Close()
		if resolved["scope"] != "system" {
			t.Errorf("post-delete resolve scope = %v, want system fallback", resolved["scope"])
		}

		// Step 9 — Soft-delete the host. GET must 404.
		resp = doReq(t, realReq("DELETE", "/api/v1/admin/hosts/"+hid, nil))
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("delete host: status=%d", resp.StatusCode)
		}
		resp = doReq(t, realReq("GET", "/api/v1/admin/hosts/"+hid, nil))
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("post-delete host get: status=%d, want 404", resp.StatusCode)
		}

		// Step 10 — Anonymous (no cookie) hits /auth/me → 401. Verifies
		// the real identity binder rejects the unbound case.
		anonReq, _ := http.NewRequest("GET", url+"/api/v1/auth/me", nil)
		resp = doReq(t, anonReq)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("anonymous /auth/me status = %d, want 401", resp.StatusCode)
		}

		// Step 11 — Audit trail check. host.created, host.deleted,
		// credential.created, credential.deleted should be present.
		// The writer flushes on a 20ms batch interval — sleep past it.
		time.Sleep(250 * time.Millisecond)
		var audited int64
		_ = pool.QueryRow(context.Background(),
			`SELECT count(*) FROM audit_events
			 WHERE action IN ('host.created','host.deleted','credential.created','credential.deleted')`,
		).Scan(&audited)
		if audited < 4 {
			t.Errorf("audit events = %d, want >= 4 (host x2 + cred x2)", audited)
		}
	})
}
