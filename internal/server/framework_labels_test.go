// @spec system-compliance-lens
//
// AC traceability (DSN-gated):
//
//	AC-14  TestFrameworkLabels_EverySurfaceNamesFrameworksFromKensa

package server

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/scanresult"
)

// @ac AC-14
// AC-14 (D-2 S-7): every API surface that lists framework ids carries Kensa's
// label for each, so the UI renders labels instead of deriving them, and
// NIST 800-53, NIST SP 800-171 and CMMC Level 2 stay distinguishable.
func TestFrameworkLabels_EverySurfaceNamesFrameworksFromKensa(t *testing.T) {
	t.Run("system-compliance-lens/AC-14", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		host := seedHostForIntel(t, pool)
		now := time.Now().UTC().Truncate(time.Second)
		refs := `{"nist_800_53": ["AC-2"], "nist_800_171": ["3.1.1[a]"], "cmmc_l2": ["AC.L2-3.1.1"]}`
		seedRuleState(t, pool, host, "fw-labels", "fail", "high", now, 1, refs)

		want := map[string]string{
			"nist_800_53":  "NIST 800-53",
			"nist_800_171": "NIST SP 800-171 Rev 2",
			"cmmc_l2":      "CMMC Level 2",
		}
		get := func(path string, into any) {
			t.Helper()
			resp := doReq(t, asRole(t, "GET", url+path, auth.RoleViewer, nil))
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET %s = %d, want 200", path, resp.StatusCode)
			}
			if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
				t.Fatalf("decode %s: %v", path, err)
			}
		}
		distinct := func(where string, labels map[string]string) {
			t.Helper()
			seen := map[string]string{}
			for id, l := range labels {
				if prev, dup := seen[l]; dup {
					t.Errorf("%s: %s and %s share the label %q", where, prev, id, l)
				}
				seen[l] = id
			}
		}

		t.Run("host lens chips", func(t *testing.T) {
			var body struct {
				Frameworks []struct {
					FrameworkID string `json:"framework_id"`
					Label       string `json:"label"`
				} `json:"frameworks"`
				Overall struct {
					Label string `json:"label"`
				} `json:"overall"`
			}
			get("/api/v1/hosts/"+host.String()+"/compliance/frameworks", &body)
			got := map[string]string{}
			for _, f := range body.Frameworks {
				got[f.FrameworkID] = f.Label
			}
			for id, l := range want {
				if got[id] != l {
					t.Errorf("label for %s = %q, want %q", id, got[id], l)
				}
			}
			distinct("host frameworks", got)
			if body.Overall.Label != "All rules" {
				t.Errorf("overall label = %q, want All rules", body.Overall.Label)
			}
		})

		t.Run("report lens picker", func(t *testing.T) {
			var body struct {
				Frameworks []struct {
					Framework string `json:"framework"`
					Label     string `json:"label"`
				} `json:"frameworks"`
			}
			get("/api/v1/reports/frameworks", &body)
			got := map[string]string{}
			for _, f := range body.Frameworks {
				got[f.Framework] = f.Label
			}
			for id, l := range want {
				if got[id] != l {
					t.Errorf("label for %s = %q, want %q", id, got[id], l)
				}
			}
			distinct("report frameworks", got)
		})

		t.Run("rule library", func(t *testing.T) {
			var body struct {
				Rules []struct {
					FrameworkRefs map[string][]string `json:"framework_refs"`
				} `json:"rules"`
				FrameworkLabels map[string]string `json:"framework_labels"`
			}
			get("/api/v1/rules", &body)
			for _, r := range body.Rules {
				for id := range r.FrameworkRefs {
					if body.FrameworkLabels[id] == "" {
						t.Errorf("rule library references %s but framework_labels has no label for it", id)
					}
				}
			}
			if body.FrameworkLabels["cis_rhel9"] != "CIS (RHEL 9)" || body.FrameworkLabels["nist_800_53"] != "NIST 800-53" {
				t.Errorf("framework_labels = %v", body.FrameworkLabels)
			}
		})

		t.Run("scan detail", func(t *testing.T) {
			scanID := seedScan(t, pool, host, now, []scanresult.Result{{
				RuleID: "fw-labels-scan", Status: "fail", Severity: "high",
				FrameworkRefs: map[string][]string{
					"nist_800_53": {"AC-2"}, "nist_800_171": {"3.1.1[a]"}, "cmmc_l2": {"AC.L2-3.1.1"},
				},
			}})
			var body struct {
				FrameworkLabels map[string]string `json:"framework_labels"`
			}
			get("/api/v1/scans/"+scanID.String(), &body)
			for id, l := range want {
				if body.FrameworkLabels[id] != l {
					t.Errorf("label for %s = %q, want %q", id, body.FrameworkLabels[id], l)
				}
			}
			distinct("scan detail", body.FrameworkLabels)
		})
	})
}
