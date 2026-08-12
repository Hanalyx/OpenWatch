// @spec system-rbac
//
// API integration tests for the RBAC demo endpoints. Verifies the
// full middleware chain: correlation → identity binder → idempotency →
// handler-level EnforcePermission. The middleware checks RBAC only; a
// route that needs an entitlement calls license.EnforceFeature inside the
// handler, which is why the 402 case here goes through the handler rather
// than the middleware. Skipped without OPENWATCH_TEST_DSN since the audit
// writer needs Postgres.

package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/license"
)

// @ac AC-08
// AC-08: a caller whose role grants the permission reaches the handler.
// RBAC is the only stage the middleware runs.
func TestAPI_RBAC_AllowsWithPermission(t *testing.T) {
	t.Run("system-rbac/AC-08", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := strings.NewReader(`{"message":"rbac-allow"}`)
		req, _ := http.NewRequest("POST", url+"/api/v1/diagnostics:require-host-read", body)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "rbac-allow-key")
		req.AddCookie(roleCookies[auth.RoleViewer])
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, b)
		}
	})
}

// @ac AC-09
// AC-09: an anonymous caller gets 401 auth.required, and an authenticated
// caller whose role lacks the permission gets 403 authz.permission_denied.
func TestAPI_RBAC_DeniesWithoutPermission(t *testing.T) {
	t.Run("system-rbac/AC-09", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := strings.NewReader(`{"message":"rbac-deny"}`)
		req, _ := http.NewRequest("POST", url+"/api/v1/diagnostics:require-host-read", body)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "rbac-deny-key")
		// No session cookie → anonymous.
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("anonymous status = %d, want 401; body=%s", resp.StatusCode, b)
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "auth.required") {
			t.Errorf("anonymous body lacks auth.required: %s", b)
		}

		// Authenticated caller whose role lacks the permission still gets 403
		// authz.permission_denied (a viewer holds host:read but not host:write).
		vreq := asRole(t, "POST", url+"/api/v1/diagnostics:require-host-write", auth.RoleViewer,
			map[string]any{"message": "rbac-deny-authed"})
		vreq.Header.Set("Idempotency-Key", "rbac-deny-authed-key")
		vresp := doReq(t, vreq)
		defer vresp.Body.Close()
		if vresp.StatusCode != http.StatusForbidden {
			vb, _ := io.ReadAll(vresp.Body)
			t.Fatalf("authenticated viewer status = %d, want 403; body=%s", vresp.StatusCode, vb)
		}
		vb, _ := io.ReadAll(vresp.Body)
		if !strings.Contains(string(vb), "authz.permission_denied") {
			t.Errorf("authenticated-denial body lacks authz.permission_denied: %s", vb)
		}
	})
}

// @ac AC-10
// AC-10: RBAC passes (security_admin has remediation:execute), then the
// route-level feature gate fails because no license is installed → 402
// license.feature_unavailable. The 402 comes from license.EnforceFeature
// inside the handler, not from the RBAC middleware. Confirms the ordering
// holds: an anonymous caller would have been stopped at 401/403 first and
// never reached the feature check.
func TestAPI_RBAC_RBACPassesLicenseFails(t *testing.T) {
	t.Run("system-rbac/AC-10", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := strings.NewReader(`{"message":"license-deny"}`)
		req, _ := http.NewRequest("POST", url+"/api/v1/diagnostics:require-remediation-execute", body)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "license-deny-key")
		req.AddCookie(roleCookies[auth.RoleSecurityAdmin])
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusPaymentRequired {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d, want 402; body=%s", resp.StatusCode, b)
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "license.feature_unavailable") {
			t.Errorf("body lacks license.feature_unavailable: %s", b)
		}
	})
}

// AC-10 corollary: viewer + no license on the same endpoint → 403, NOT
// 402. RBAC fails first, because the handler that runs the feature check
// cannot be reached until the permission check passes.
func TestAPI_RBAC_RBACFirstWhenBothFail(t *testing.T) {
	t.Run("system-rbac/AC-10/rbac-first", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := strings.NewReader(`{"message":"both-fail"}`)
		req, _ := http.NewRequest("POST", url+"/api/v1/diagnostics:require-remediation-execute", body)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "both-fail-key")
		req.AddCookie(roleCookies[auth.RoleViewer]) // viewer lacks remediation:execute
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403 (RBAC fails first)", resp.StatusCode)
		}
	})
}

// @ac AC-11
// AC-11: 403 denial emits authz.permission.denied audit event with
// detail.required_permission set to the permission id.
func TestAPI_RBAC_DenialEmitsAudit(t *testing.T) {
	t.Run("system-rbac/AC-11", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		body := strings.NewReader(`{"message":"audit-deny"}`)
		req, _ := http.NewRequest("POST", url+"/api/v1/diagnostics:require-host-read", body)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "audit-deny-key")
		req.Header.Set("X-Correlation-Id", "rbac-audit-corr")
		// No role → 403
		resp := doReq(t, req)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		time.Sleep(150 * time.Millisecond) // let writer flush

		var count int64
		var detail string
		err := pool.QueryRow(context.Background(),
			`SELECT count(*), COALESCE(MAX(detail::text), '') FROM audit_events
			   WHERE action = 'authz.permission.denied'
			     AND correlation_id = 'rbac-audit-corr'`,
		).Scan(&count, &detail)
		if err != nil {
			t.Fatalf("query audit: %v", err)
		}
		if count != 1 {
			t.Errorf("authz.permission.denied audit count = %d, want 1", count)
		}
		if !strings.Contains(detail, "host:read") {
			t.Errorf("audit detail missing required_permission=host:read: %s", detail)
		}
	})
}

// @ac AC-13
// AC-13: GET /auth/me/permissions returns the calling identity's
// effective permission list.
func TestAPI_RBAC_GetAuthMePermissions(t *testing.T) {
	t.Run("system-rbac/AC-13", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		req, _ := http.NewRequest("GET", url+"/api/v1/auth/me/permissions", nil)
		req.AddCookie(roleCookies[auth.RoleOpsLead])
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		var got struct {
			Identity struct {
				ID          string `json:"id"`
				Role        string `json:"role"`
				IsAnonymous bool   `json:"is_anonymous"`
			} `json:"identity"`
			Permissions []string `json:"permissions"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&got)
		if got.Identity.Role != string(auth.RoleOpsLead) {
			t.Errorf("identity.role = %q, want ops_lead", got.Identity.Role)
		}
		if got.Identity.IsAnonymous {
			t.Error("is_anonymous = true; expected role-bound identity")
		}
		hasHostRead := false
		hasHostDelete := false
		for _, p := range got.Permissions {
			if p == "host:read" {
				hasHostRead = true
			}
			if p == "host:delete" {
				hasHostDelete = true
			}
		}
		if !hasHostRead {
			t.Error("ops_lead must include host:read")
		}
		if hasHostDelete {
			t.Error("ops_lead must NOT include host:delete (admin-only)")
		}
	})
}

// @ac AC-14
// AC-14: GET /auth/permissions:registry returns the full registry.
func TestAPI_RBAC_GetPermissionsRegistry(t *testing.T) {
	t.Run("system-rbac/AC-14", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		resp := doGet(t, url+"/api/v1/auth/permissions:registry")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		var got struct {
			Categories []struct {
				ID          string `json:"id"`
				Description string `json:"description"`
			} `json:"categories"`
			Permissions []map[string]any `json:"permissions"`
			Roles       []struct {
				ID          string   `json:"id"`
				Permissions []string `json:"permissions"`
			} `json:"roles"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&got)
		if len(got.Categories) == 0 {
			t.Error("categories empty")
		}
		if len(got.Permissions) < 50 {
			t.Errorf("permissions = %d, want >= 50", len(got.Permissions))
		}
		if len(got.Roles) != 5 {
			t.Errorf("roles = %d, want 5", len(got.Roles))
		}
		// The registry surfaces the permission and its dangerous marker, and
		// NO entitlement state. Decoding into a map rather than a struct is
		// deliberate: a struct would silently drop a reintroduced field, so
		// the map is what makes the negative assertion real.
		found := false
		for _, p := range got.Permissions {
			if _, bad := p["license_gated"]; bad {
				t.Errorf("permission %v carries license_gated; entitlement is gated on the route (x-required-feature), not the permission", p["id"])
			}
			if _, ok := p["dangerous"]; !ok {
				t.Errorf("permission %v is missing the dangerous marker", p["id"])
			}
			if p["id"] == "audit:export" {
				found = true
			}
		}
		if !found {
			t.Error("audit:export not surfaced via registry endpoint")
		}
	})
}

// @ac AC-15
// AC-15: GET /admin/roles returns the 5 built-in roles. Caller must hold
// role:read; viewer role does, so we use it.
func TestAPI_RBAC_GetRoles(t *testing.T) {
	t.Run("system-rbac/AC-15", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		req, _ := http.NewRequest("GET", url+"/api/v1/roles", nil)
		req.AddCookie(roleCookies[auth.RoleViewer])
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, b)
		}
		var got struct {
			Roles []struct {
				ID          string   `json:"id"`
				IsBuiltIn   bool     `json:"is_built_in"`
				Permissions []string `json:"permissions"`
			} `json:"roles"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&got)
		if len(got.Roles) != 5 {
			t.Errorf("roles = %d, want 5", len(got.Roles))
		}
		seen := map[string]bool{}
		for _, r := range got.Roles {
			seen[r.ID] = true
			if !r.IsBuiltIn {
				t.Errorf("role %q is_built_in = false, want true", r.ID)
			}
		}
		for _, expected := range []string{"viewer", "auditor", "ops_lead", "security_admin", "admin"} {
			if !seen[expected] {
				t.Errorf("missing built-in role %q", expected)
			}
		}
	})
}

// AC-09 + AC-15: GET /admin/roles without role:read → 403.
func TestAPI_RBAC_AdminRolesDeniesAnonymous(t *testing.T) {
	t.Run("system-rbac/AC-15/anon", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		resp := doGet(t, url+"/api/v1/roles")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401 (no role / anonymous)", resp.StatusCode)
		}
	})
}

// @ac AC-23
// AC-23: RBAC runs before the feature check inside the handler, not just in
// the contract. For a route carrying both gates, a caller who lacks the
// permission is denied whatever the license state, and the status code
// therefore carries no information about what the deployment bought.
//
// Both license states are exercised. Checking only the licensed instance would
// pass even if the handler ran the checks in the wrong order, because an
// enabled feature makes the feature check a no-op.
func TestAPI_RBAC_RBACBeforeFeatureInBothLicenseStates(t *testing.T) {
	t.Run("system-rbac/AC-23", func(t *testing.T) {
		url, _ := freshAPIServer(t)

		anonymousCall := func(key string) (int, string) {
			req, _ := http.NewRequest("POST", url+"/api/v1/diagnostics:premium-echo",
				strings.NewReader(`{"message":"rbac-before-feature"}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Idempotency-Key", key)
			resp := doReq(t, req)
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			return resp.StatusCode, string(b)
		}

		// Unlicensed. This is the leg that catches a wrong order: with the
		// feature check first, the deployment's lack of a license would answer
		// before the caller's lack of a session, and the caller would get 402.
		unlicensedCode, unlicensedBody := anonymousCall("rbac-first-unlicensed")
		if unlicensedCode != http.StatusUnauthorized {
			t.Errorf("unlicensed anonymous status = %d, want 401; body=%s",
				unlicensedCode, unlicensedBody)
		}
		if unlicensedCode == http.StatusPaymentRequired {
			t.Error("402 on an unlicensed instance makes the status an entitlement oracle")
		}
		if !strings.Contains(unlicensedBody, "auth.required") {
			t.Errorf("unlicensed anonymous body lacks auth.required: %s", unlicensedBody)
		}

		// Licensed for premium_diagnostics.
		installEnterpriseLicense(t, "premium_diagnostics")
		licensedCode, licensedBody := anonymousCall("rbac-first-licensed")
		if licensedCode != http.StatusUnauthorized {
			t.Errorf("licensed anonymous status = %d, want 401; body=%s",
				licensedCode, licensedBody)
		}
		if licensedCode != unlicensedCode {
			t.Errorf("status differs with license state: %d unlicensed vs %d licensed. "+
				"The denial must not tell an unauthenticated caller what the deployment bought.",
				unlicensedCode, licensedCode)
		}
	})
}

// Touch the license import so it's not unused when the AC-10 test happens
// to skip due to missing DSN.
var _ = license.PremiumDiagnostics
