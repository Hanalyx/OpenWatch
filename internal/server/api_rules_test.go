// @spec api-rules
//
// AC traceability (this file; AC-01/AC-02 live in internal/kensa/library_test.go):
//   AC-03  TestRules_RBAC_AnonymousRejected_ViewerAllowed
//   AC-04  TestRules_ListShape

package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Hanalyx/openwatch/internal/auth"
)

// @ac AC-03
func TestRules_RBAC_AnonymousRejected_ViewerAllowed(t *testing.T) {
	t.Run("api-rules/AC-03", func(t *testing.T) {
		url, _ := freshAPIServer(t)

		// Anonymous: no session cookie.
		resp := doGet(t, url+"/api/v1/rules")
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
			t.Errorf("anonymous status = %d, want 401/403", resp.StatusCode)
		}

		// Viewer holds scan:read.
		req := asRole(t, "GET", url+"/api/v1/rules", auth.RoleViewer, nil)
		resp2 := doReq(t, req)
		resp2.Body.Close()
		if resp2.StatusCode != http.StatusOK {
			t.Errorf("viewer status = %d, want 200 (scan:read suffices)", resp2.StatusCode)
		}
	})
}

// @ac AC-04
func TestRules_ListShape(t *testing.T) {
	t.Run("api-rules/AC-04", func(t *testing.T) {
		url, _ := freshAPIServer(t)

		var body struct {
			Total int `json:"total"`
			Rules []struct {
				Id            string              `json:"id"`
				Title         string              `json:"title"`
				Description   string              `json:"description"`
				Severity      string              `json:"severity"`
				Category      string              `json:"category"`
				Tags          []string            `json:"tags"`
				FrameworkRefs map[string][]string `json:"framework_refs"`
				Remediation   struct {
					Mechanism string `json:"mechanism"`
					Manual    bool   `json:"manual"`
				} `json:"remediation"`
			} `json:"rules"`
		}
		req := asRole(t, "GET", url+"/api/v1/rules", auth.RoleViewer, nil)
		resp := doReq(t, req)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		resp.Body.Close()

		// The fixture library (freshAPIServer) wires two rules.
		if body.Total != 2 || len(body.Rules) != 2 {
			t.Fatalf("total=%d rules=%d, want 2/2 (fixture)", body.Total, len(body.Rules))
		}
		var sawAutomated, sawManual bool
		for _, r := range body.Rules {
			if r.Id == "" || r.Title == "" || r.Severity == "" || r.Category == "" {
				t.Errorf("rule %q missing required fields: %+v", r.Id, r)
			}
			if len(r.FrameworkRefs) == 0 {
				t.Errorf("rule %q has no framework_refs", r.Id)
			}
			if r.Remediation.Manual {
				sawManual = true
				if r.Remediation.Mechanism != "manual" {
					t.Errorf("rule %q manual but mechanism=%q", r.Id, r.Remediation.Mechanism)
				}
			} else {
				sawAutomated = true
				if r.Remediation.Mechanism == "" || r.Remediation.Mechanism == "manual" {
					t.Errorf("rule %q automated but mechanism=%q", r.Id, r.Remediation.Mechanism)
				}
			}
		}
		if !sawAutomated || !sawManual {
			t.Errorf("expected both an automated and a manual remediation in the fixture")
		}
	})
}
