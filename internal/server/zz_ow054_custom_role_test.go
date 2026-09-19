package server

import (
	"context"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/google/uuid"
)

// Diagnostic reproduction for CP bugs/OW-054. Not a regression test yet:
// it records what the shipped binder does with a custom role.
func TestZZOW054CustomRoleBinding(t *testing.T) {
	if os.Getenv("OW054") == "" {
		t.Skip()
	}
	url, pool := freshAPIServer(t)
	ctx := context.Background()

	// 1. A custom role that grants host:read only, created through the API.
	req := asRole(t, "POST", url+"/api/v1/roles:create", auth.RoleAdmin, map[string]any{
		"id": "host_reader", "description": "custom", "permissions": []string{"host:read"},
	})
	resp := doReq(t, req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("roles:create = %d", resp.StatusCode)
	}

	// 2. A user whose ONLY role is that custom role, assigned through the API.
	created := createUser(t, url, "customonly")
	uid := uuid.MustParse(created["id"].(string))
	req = asRole(t, "POST", url+"/api/v1/users/"+uid.String()+"/roles:assign", auth.RoleAdmin, map[string]string{"role_id": "host_reader"})
	resp = doReq(t, req)
	resp.Body.Close()
	t.Logf("roles:assign custom role -> %d", resp.StatusCode)

	sessionFor := func(id uuid.UUID) *http.Cookie {
		tok, _, err := identity.IssueSession(ctx, pool, id, "127.0.0.1", "ow054")
		if err != nil {
			t.Fatal(err)
		}
		return &http.Cookie{Name: identity.SessionCookieName, Value: tok}
	}
	get := func(cookie *http.Cookie, path string) (int, string) {
		r, _ := http.NewRequest("GET", url+path, nil)
		r.AddCookie(cookie)
		rs := doReq(t, r)
		defer rs.Body.Close()
		b, _ := io.ReadAll(rs.Body)
		return rs.StatusCode, string(b)
	}

	c := sessionFor(uid)
	code, body := get(c, "/api/v1/hosts")
	t.Logf("custom-only user GET /hosts (needs host:read, which the role grants) -> %d %s", code, body)
	code, body = get(c, "/api/v1/auth/me/permissions")
	t.Logf("custom-only user GET /auth/me/permissions -> %d %s", code, body)

	// 3. A user holding viewer AND the custom role: is the custom grant added?
	req = asRole(t, "POST", url+"/api/v1/roles:create", auth.RoleAdmin, map[string]any{
		"id": "host_writer", "description": "custom", "permissions": []string{"host:write"},
	})
	resp = doReq(t, req)
	resp.Body.Close()
	both := createUser(t, url, "viewerpluscustom")
	bid := uuid.MustParse(both["id"].(string))
	for _, role := range []string{"viewer", "host_writer"} {
		req = asRole(t, "POST", url+"/api/v1/users/"+bid.String()+"/roles:assign", auth.RoleAdmin, map[string]string{"role_id": role})
		resp = doReq(t, req)
		resp.Body.Close()
		t.Logf("assign %s -> %d", role, resp.StatusCode)
	}
	code, body = get(sessionFor(bid), "/api/v1/auth/me/permissions")
	t.Logf("viewer+custom(host:write) GET /auth/me/permissions -> %d %s", code, body)

	// 4. Built-in non-nesting: auditor + ops_lead binds as ops_lead.
	ao := createUser(t, url, "auditoropslead")
	aid := uuid.MustParse(ao["id"].(string))
	for _, role := range []string{"auditor", "ops_lead"} {
		req = asRole(t, "POST", url+"/api/v1/users/"+aid.String()+"/roles:assign", auth.RoleAdmin, map[string]string{"role_id": role})
		resp = doReq(t, req)
		resp.Body.Close()
	}
	code, body = get(sessionFor(aid), "/api/v1/audit/events/export?format=json")
	t.Logf("auditor+ops_lead GET /audit/events/export (needs audit:export, held by auditor) -> %d %.200s", code, body)
}
