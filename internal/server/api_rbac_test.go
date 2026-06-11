// @spec system-rbac
//
// API integration tests for the RBAC demo endpoints. Verifies the
// full middleware chain: correlation → identity binder → idempotency →
// handler-level EnforcePermission → license gate. Skipped without
// OPENWATCH_TEST_DSN since the audit writer needs Postgres.

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
// AC-08: caller with the permission and (when gated) a valid license
// reaches the handler.
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
// AC-09: anonymous caller gets 403 authz.permission_denied (RBAC check
// fires before license).
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
		if resp.StatusCode != http.StatusForbidden {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d, want 403; body=%s", resp.StatusCode, b)
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "authz.permission_denied") {
			t.Errorf("body lacks authz.permission_denied: %s", b)
		}
	})
}

// @ac AC-10
// AC-10: RBAC passes (security_admin has remediation:execute), but no
// license is installed → 402 license.feature_unavailable. Confirms RBAC
// fails first ordering — anonymous would have gotten 403 instead.
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
// 402. RBAC fails first.
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
			Permissions []struct {
				ID           string  `json:"id"`
				Category     string  `json:"category"`
				Dangerous    bool    `json:"dangerous"`
				LicenseGated *string `json:"license_gated"`
			} `json:"permissions"`
			Roles []struct {
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
		// Spot-check: remediation:execute is license-gated.
		found := false
		for _, p := range got.Permissions {
			if p.ID == "remediation:execute" {
				found = true
				if p.LicenseGated == nil || *p.LicenseGated != "remediation_execution" {
					t.Errorf("remediation:execute license_gated = %v, want remediation_execution", p.LicenseGated)
				}
			}
		}
		if !found {
			t.Error("remediation:execute not surfaced via registry endpoint")
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
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403 (no role)", resp.StatusCode)
		}
	})
}

// Touch the license import so it's not unused when the AC-10 test happens
// to skip due to missing DSN.
var _ = license.PremiumDiagnostics
