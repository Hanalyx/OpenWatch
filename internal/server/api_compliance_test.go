// @spec system-compliance-lens
//
// The default-lens config endpoints + the corpus-derived frameworks list.

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/server/api"
)

// @ac AC-04
// AC-04: GET /compliance/frameworks (host:read) lists corpus families; the
// compliance config GET is system:read and PUT is system:config:write
// (viewer 403), round-trips the value, and rejects an invalid family (400).
func TestCompliance_FrameworksAndDefaultLens(t *testing.T) {
	t.Run("system-compliance-lens/AC-04", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		host := seedHostForIntel(t, pool)
		seedRuleStateForHostWithFrameworks(t, pool, host, "r.a", "pass",
			map[string]string{"stig_rhel9": "V-1"})

		// Frameworks list → contains the "stig" family.
		fr := doReq(t, asRole(t, "GET", url+"/api/v1/compliance/frameworks", auth.RoleViewer, nil))
		if fr.StatusCode != http.StatusOK {
			t.Fatalf("frameworks = %d, want 200", fr.StatusCode)
		}
		raw := readBody(t, fr)
		if !strings.Contains(raw, `"id":"stig"`) && !strings.Contains(raw, `"id": "stig"`) {
			t.Errorf("frameworks missing stig family: %s", raw)
		}

		// Config GET → default empty (All rules).
		gr := doReq(t, asRole(t, "GET", url+"/api/v1/system/compliance/config", auth.RoleViewer, nil))
		var cfg api.ComplianceConfig
		_ = json.NewDecoder(gr.Body).Decode(&cfg)
		gr.Body.Close()
		if gr.StatusCode != http.StatusOK || cfg.DefaultFramework != "" {
			t.Errorf("get config = %d default=%q, want 200 empty", gr.StatusCode, cfg.DefaultFramework)
		}

		// PUT as viewer → 403.
		if vr := doReq(t, asRole(t, "PUT", url+"/api/v1/system/compliance/config", auth.RoleViewer,
			map[string]any{"default_framework": "stig"})); vr.StatusCode != http.StatusForbidden {
			t.Errorf("viewer put = %d, want 403", vr.StatusCode)
		}

		// PUT as admin → 200, and the value round-trips.
		if pr := doReq(t, asRole(t, "PUT", url+"/api/v1/system/compliance/config", auth.RoleAdmin,
			map[string]any{"default_framework": "stig"})); pr.StatusCode != http.StatusOK {
			t.Fatalf("admin put = %d, want 200", pr.StatusCode)
		}
		gr2 := doReq(t, asRole(t, "GET", url+"/api/v1/system/compliance/config", auth.RoleViewer, nil))
		var cfg2 api.ComplianceConfig
		_ = json.NewDecoder(gr2.Body).Decode(&cfg2)
		gr2.Body.Close()
		if cfg2.DefaultFramework != "stig" {
			t.Errorf("after put, default = %q, want stig", cfg2.DefaultFramework)
		}

		// Invalid family → 400.
		if br := doReq(t, asRole(t, "PUT", url+"/api/v1/system/compliance/config", auth.RoleAdmin,
			map[string]any{"default_framework": "BAD SPACE"})); br.StatusCode != http.StatusBadRequest {
			t.Errorf("invalid put = %d, want 400", br.StatusCode)
		}
	})
}

// @ac AC-06
// AC-06: GET /compliance/frameworks narrows to the enabled-frameworks
// allowlist by default; all=true returns the full corpus list.
func TestCompliance_FrameworksAllowlistFilter(t *testing.T) {
	t.Run("system-compliance-lens/AC-06", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		host := seedHostForIntel(t, pool)
		seedRuleStateForHostWithFrameworks(t, pool, host, "r.stig", "pass",
			map[string]string{"stig_rhel9": "V-1"})
		seedRuleStateForHostWithFrameworks(t, pool, host, "r.cis", "pass",
			map[string]string{"cis_rhel9": "1.1"})

		hasFam := func(raw, id string) bool {
			return strings.Contains(raw, `"id":"`+id+`"`) || strings.Contains(raw, `"id": "`+id+`"`)
		}

		// No allowlist → both families present.
		raw := readBody(t, doReq(t, asRole(t, "GET", url+"/api/v1/compliance/frameworks", auth.RoleViewer, nil)))
		if !hasFam(raw, "stig") || !hasFam(raw, "cis") {
			t.Fatalf("unfiltered frameworks missing a family: %s", raw)
		}

		// Restrict the allowlist to stig.
		if pr := doReq(t, asRole(t, "PUT", url+"/api/v1/system/compliance/config", auth.RoleAdmin,
			map[string]any{"default_framework": "", "enabled_frameworks": []string{"stig"}})); pr.StatusCode != http.StatusOK {
			t.Fatalf("put allowlist = %d, want 200", pr.StatusCode)
		}

		// Default list → stig only (cis filtered out).
		raw = readBody(t, doReq(t, asRole(t, "GET", url+"/api/v1/compliance/frameworks", auth.RoleViewer, nil)))
		if !hasFam(raw, "stig") || hasFam(raw, "cis") {
			t.Errorf("filtered frameworks = %s, want stig only", raw)
		}

		// all=true → full corpus list again.
		raw = readBody(t, doReq(t, asRole(t, "GET", url+"/api/v1/compliance/frameworks?all=true", auth.RoleViewer, nil)))
		if !hasFam(raw, "stig") || !hasFam(raw, "cis") {
			t.Errorf("all=true frameworks = %s, want both", raw)
		}
	})
}
