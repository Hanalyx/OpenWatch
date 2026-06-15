// @spec api-auth-policy
//
// Read + replace the workspace authentication policy under
// /api/v1/auth-policy: per-verb RBAC, bounds rejection, audit on update.

package server

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/server/api"
)

// @ac AC-01
func TestAuthPolicy_GetRBAC(t *testing.T) {
	t.Run("api-auth-policy/AC-01", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		// Anonymous denied.
		if r := doReq(t, asRole(t, "GET", url+"/api/v1/auth-policy", "", nil)); r.StatusCode != http.StatusUnauthorized && r.StatusCode != http.StatusForbidden {
			t.Errorf("anon get = %d, want 401/403", r.StatusCode)
		}
		// Viewer lacks system:auth_policy_read → 403.
		if r := doReq(t, asRole(t, "GET", url+"/api/v1/auth-policy", auth.RoleViewer, nil)); r.StatusCode != http.StatusForbidden {
			t.Errorf("viewer get = %d, want 403", r.StatusCode)
		}
		// Admin → 200 with the seeded defaults.
		r := doReq(t, asRole(t, "GET", url+"/api/v1/auth-policy", auth.RoleAdmin, nil))
		if r.StatusCode != http.StatusOK {
			t.Fatalf("admin get = %d, want 200", r.StatusCode)
		}
		var p api.AuthPolicy
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if p.RequireMfa {
			t.Errorf("default require_mfa = true, want false")
		}
		if p.SessionIdleTimeoutSeconds != 900 || p.SessionAbsoluteTimeoutSeconds != 43200 {
			t.Errorf("default windows = (%d,%d), want (900,43200)",
				p.SessionIdleTimeoutSeconds, p.SessionAbsoluteTimeoutSeconds)
		}
	})
}

// @ac AC-02
func TestAuthPolicy_PutRBACAndRoundTrip(t *testing.T) {
	t.Run("api-auth-policy/AC-02", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := map[string]any{
			"require_mfa":                      true,
			"session_idle_timeout_seconds":     1800,
			"session_absolute_timeout_seconds": 86400,
		}
		// Viewer lacks system:auth_policy_write → 403.
		if r := doReq(t, asRole(t, "PUT", url+"/api/v1/auth-policy", auth.RoleViewer, body)); r.StatusCode != http.StatusForbidden {
			t.Errorf("viewer put = %d, want 403", r.StatusCode)
		}
		// Admin → 200 with the updated values.
		r := doReq(t, asRole(t, "PUT", url+"/api/v1/auth-policy", auth.RoleAdmin, body))
		if r.StatusCode != http.StatusOK {
			t.Fatalf("admin put = %d, want 200", r.StatusCode)
		}
		var p api.AuthPolicy
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !p.RequireMfa || p.SessionIdleTimeoutSeconds != 1800 || p.SessionAbsoluteTimeoutSeconds != 86400 {
			t.Errorf("put echo = %+v, want require_mfa true / 1800 / 86400", p)
		}
		// A subsequent GET returns the new values.
		gr := doReq(t, asRole(t, "GET", url+"/api/v1/auth-policy", auth.RoleAdmin, nil))
		var p2 api.AuthPolicy
		if err := json.NewDecoder(gr.Body).Decode(&p2); err != nil {
			t.Fatalf("decode get: %v", err)
		}
		if !p2.RequireMfa || p2.SessionIdleTimeoutSeconds != 1800 {
			t.Errorf("get after put = %+v, want persisted values", p2)
		}
	})
}

// @ac AC-03
func TestAuthPolicy_PutRejectsOutOfBounds(t *testing.T) {
	t.Run("api-auth-policy/AC-03", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		// Idle below the 300 s floor.
		tooShort := map[string]any{
			"require_mfa":                      false,
			"session_idle_timeout_seconds":     60,
			"session_absolute_timeout_seconds": 43200,
		}
		r := doReq(t, asRole(t, "PUT", url+"/api/v1/auth-policy", auth.RoleAdmin, tooShort))
		if r.StatusCode != http.StatusBadRequest {
			t.Fatalf("idle-too-short put = %d, want 400", r.StatusCode)
		}
		if b := readBody(t, r); !strings.Contains(b, "auth_policy.invalid") {
			t.Errorf("error code missing auth_policy.invalid: %s", b)
		}
		// Absolute shorter than idle.
		absLtIdle := map[string]any{
			"require_mfa":                      false,
			"session_idle_timeout_seconds":     7200,
			"session_absolute_timeout_seconds": 3600,
		}
		if r := doReq(t, asRole(t, "PUT", url+"/api/v1/auth-policy", auth.RoleAdmin, absLtIdle)); r.StatusCode != http.StatusBadRequest {
			t.Errorf("absolute<idle put = %d, want 400", r.StatusCode)
		}
		// The stored policy is unchanged (still the seeded defaults).
		gr := doReq(t, asRole(t, "GET", url+"/api/v1/auth-policy", auth.RoleAdmin, nil))
		var p api.AuthPolicy
		_ = json.NewDecoder(gr.Body).Decode(&p)
		if p.SessionIdleTimeoutSeconds != 900 {
			t.Errorf("rejected put leaked into store: idle = %d, want 900", p.SessionIdleTimeoutSeconds)
		}
	})
}

// @ac AC-04
func TestAuthPolicy_PutEmitsAudit(t *testing.T) {
	t.Run("api-auth-policy/AC-04", func(t *testing.T) {
		// Source inspection — PutAuthPolicy emits audit.AuthPolicyUpdated on
		// the success path with the require_mfa + timeout values.
		raw, err := os.ReadFile("authpolicy_handlers.go")
		if err != nil {
			t.Fatalf("read source: %v", err)
		}
		if !strings.Contains(string(raw), "audit.AuthPolicyUpdated") {
			t.Error("PutAuthPolicy does not emit audit.AuthPolicyUpdated")
		}
	})
}
