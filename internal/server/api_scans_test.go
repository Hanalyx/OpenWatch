// @spec api-scans
//
// AC traceability (DSN-gated like every api_*_test in this package, except
// AC-07 which is source-inspection):
//
//	AC-01  TestScans_RBAC_AnonymousRejected_ViewerAllowed
//	AC-02  TestScans_ListByHost_OrderingPaginationAnd404
//	AC-03  TestScanById_ShapeAnd404
//	AC-04  TestScanDetail_NoRawCheckOutput
//	AC-05  TestScanRuleEvidence_ShapeAnd404
//	AC-06  TestScanOSCAL_PerRuleAndWholeScanParseAnd404
//	AC-07  TestScansSurface_OwnsEvidence_HostTabDoesNot

package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/scanresult"
)

// seedScan inserts a completed scan_runs row for hostID and persists the
// given per-rule results into the durable store. Returns the scan id.
func seedScan(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, finishedAt time.Time, results []scanresult.Result) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	scanID := uuid.Must(uuid.NewV7())
	var p, f, s, e int
	for _, r := range results {
		switch r.Status {
		case scanresult.StatusPass:
			p++
		case scanresult.StatusFail:
			f++
		case scanresult.StatusSkipped:
			s++
		case scanresult.StatusError:
			e++
		}
	}
	_, err := pool.Exec(ctx, `
		INSERT INTO scan_runs
			(id, host_id, trigger_source, status, queued_at, started_at,
			 finished_at, policy_version, rules_pass, rules_fail, rules_skipped, rules_error)
		VALUES ($1, $2, 'on_demand', 'completed', $3, $3, $3, 'policy-v1', $4, $5, $6, $7)`,
		scanID, hostID, finishedAt, p, f, s, e)
	if err != nil {
		t.Fatalf("seed scan_run: %v", err)
	}
	if err := scanresult.NewWriter(pool).Persist(ctx, scanresult.PersistBatch{
		ScanID: scanID, HostID: hostID, Results: results,
	}); err != nil {
		t.Fatalf("persist scan results: %v", err)
	}
	return scanID
}

// evidenceWithChecks builds an evidenceDoc JSON blob with one command's
// structured check evidence (the proof the /scans surface exposes).
func evidenceWithChecks(detail, command, stdout string) []byte {
	return []byte(`{"detail":"` + detail + `","checks":[{"method":"config_value","command":"` +
		command + `","stdout":"` + stdout + `","exit_code":0,"expected":"1","actual":"1"}]}`)
}

func passWithEvidence(ruleID, severity string, ev []byte) scanresult.Result {
	return scanresult.Result{
		RuleID: ruleID, Status: scanresult.StatusPass, Severity: severity,
		Evidence: ev, FrameworkRefs: map[string][]string{"cis_rhel9_v2": {"1.1.1"}},
	}
}

// @ac AC-01
func TestScans_RBAC_AnonymousRejected_ViewerAllowed(t *testing.T) {
	t.Run("api-scans/AC-01", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)

		// Anonymous: no session cookie.
		resp := doGet(t, url+"/api/v1/scans?host_id="+hostID.String())
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
			t.Errorf("anonymous status = %d, want 401/403", resp.StatusCode)
		}

		// Viewer holds scan:read.
		req := asRole(t, "GET", url+"/api/v1/scans?host_id="+hostID.String(), auth.RoleViewer, nil)
		resp2 := doReq(t, req)
		resp2.Body.Close()
		if resp2.StatusCode != http.StatusOK {
			t.Errorf("viewer status = %d, want 200 (scan:read suffices)", resp2.StatusCode)
		}
	})
}

// @ac AC-02
func TestScans_ListByHost_OrderingPaginationAnd404(t *testing.T) {
	t.Run("api-scans/AC-02", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)

		base := time.Now().UTC().Add(-3 * time.Hour)
		// Three scans, oldest -> newest.
		s1 := seedScan(t, pool, hostID, base, []scanresult.Result{passWithEvidence("r1", "low", nil)})
		s2 := seedScan(t, pool, hostID, base.Add(time.Hour), []scanresult.Result{passWithEvidence("r1", "low", nil)})
		s3 := seedScan(t, pool, hostID, base.Add(2*time.Hour), []scanresult.Result{passWithEvidence("r1", "low", nil)})
		_ = s1

		// Unknown host -> 404.
		ghost := uuid.Must(uuid.NewV7())
		req := asRole(t, "GET", url+"/api/v1/scans?host_id="+ghost.String(), auth.RoleViewer, nil)
		r404 := doReq(t, req)
		r404.Body.Close()
		if r404.StatusCode != http.StatusNotFound {
			t.Errorf("unknown host status = %d, want 404", r404.StatusCode)
		}

		// Page 1 (limit 2): newest first -> s3, s2; next_cursor present.
		var page struct {
			Scans []struct {
				ScanID string `json:"scan_id"`
			} `json:"scans"`
			NextCursor *time.Time `json:"next_cursor"`
		}
		req = asRole(t, "GET", url+"/api/v1/scans?host_id="+hostID.String()+"&limit=2", auth.RoleViewer, nil)
		resp := doReq(t, req)
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
			t.Fatalf("decode page1: %v", err)
		}
		resp.Body.Close()
		if len(page.Scans) != 2 || page.Scans[0].ScanID != s3.String() || page.Scans[1].ScanID != s2.String() {
			t.Fatalf("page1 = %+v, want [s3 s2] newest-first", page.Scans)
		}
		if page.NextCursor == nil {
			t.Fatal("page1 next_cursor = nil, want a cursor (more rows exist)")
		}

		// Page 2 via cursor -> s1.
		cursor := page.NextCursor.Format(time.RFC3339Nano)
		req = asRole(t, "GET", url+"/api/v1/scans?host_id="+hostID.String()+"&limit=2&cursor="+cursor, auth.RoleViewer, nil)
		resp = doReq(t, req)
		var page2 struct {
			Scans []struct {
				ScanID string `json:"scan_id"`
			} `json:"scans"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&page2); err != nil {
			t.Fatalf("decode page2: %v", err)
		}
		resp.Body.Close()
		if len(page2.Scans) != 1 || page2.Scans[0].ScanID != s1.String() {
			t.Errorf("page2 = %+v, want [s1]", page2.Scans)
		}
	})
}

// @ac AC-03
func TestScanById_ShapeAnd404(t *testing.T) {
	t.Run("api-scans/AC-03", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)
		scanID := seedScan(t, pool, hostID, time.Now().UTC(), []scanresult.Result{
			passWithEvidence("r-pass", "low", evidenceWithChecks("ok", "grep x /etc/y", "x=1")),
			{RuleID: "r-fail", Status: scanresult.StatusFail, Severity: "high", Evidence: evidenceWithChecks("bad", "grep z /etc/y", "z=0")},
			{RuleID: "r-skip", Status: scanresult.StatusSkipped, Severity: ""},
		})

		var detail struct {
			Scan    map[string]any `json:"scan"`
			Results []struct {
				RuleID      string  `json:"rule_id"`
				Title       string  `json:"title"`
				Category    string  `json:"category"`
				Status      string  `json:"status"`
				Description *string `json:"description"`
				HasEvidence bool    `json:"has_evidence"`
			} `json:"results"`
		}
		req := asRole(t, "GET", url+"/api/v1/scans/"+scanID.String(), auth.RoleViewer, nil)
		resp := doReq(t, req)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
			t.Fatalf("decode: %v", err)
		}
		resp.Body.Close()
		if len(detail.Results) != 3 {
			t.Errorf("results = %d, want 3 (one per persisted rule)", len(detail.Results))
		}
		if detail.Scan["scan_id"] != scanID.String() {
			t.Errorf("scan.scan_id = %v, want %s", detail.Scan["scan_id"], scanID)
		}
		// Title/category/description are catalog-resolved; the test server
		// wires no catalog, so title falls back to rule_id, category to
		// "uncategorized" (both never empty), and description is omitted.
		for _, rr := range detail.Results {
			if rr.Title == "" || rr.Category == "" {
				t.Errorf("rule %s: title=%q category=%q, both must be non-empty (fallbacks)", rr.RuleID, rr.Title, rr.Category)
			}
			if rr.RuleID == "r-pass" {
				if rr.Title != "r-pass" || rr.Category != "uncategorized" {
					t.Errorf("no-catalog fallback wrong: title=%q category=%q", rr.Title, rr.Category)
				}
				if rr.Description != nil && *rr.Description != "" {
					t.Errorf("r-pass description = %v, want empty without a catalog", *rr.Description)
				}
			}
		}

		// Unknown scan -> 404.
		ghost := uuid.Must(uuid.NewV7())
		req = asRole(t, "GET", url+"/api/v1/scans/"+ghost.String(), auth.RoleViewer, nil)
		r404 := doReq(t, req)
		r404.Body.Close()
		if r404.StatusCode != http.StatusNotFound {
			t.Errorf("unknown scan status = %d, want 404", r404.StatusCode)
		}
	})
}

// @ac AC-04
func TestScanDetail_NoRawCheckOutput(t *testing.T) {
	t.Run("api-scans/AC-04", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)
		scanID := seedScan(t, pool, hostID, time.Now().UTC(), []scanresult.Result{
			passWithEvidence("r-pass", "low", evidenceWithChecks("ok", "cat /etc/secret-config", "PASSWORD=hunter2")),
		})

		req := asRole(t, "GET", url+"/api/v1/scans/"+scanID.String(), auth.RoleViewer, nil)
		resp := doReq(t, req)
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		body := string(bodyBytes)

		// The list payload must carry has_evidence but NOT raw output.
		if !strings.Contains(body, `"has_evidence"`) {
			t.Error("scan-detail payload missing has_evidence")
		}
		for _, leak := range []string{`"command"`, `"stdout"`, `"stderr"`, "PASSWORD=hunter2", "cat /etc/secret-config"} {
			if strings.Contains(body, leak) {
				t.Errorf("scan-detail payload leaked raw check output: %q must not appear in the list view", leak)
			}
		}
	})
}

// @ac AC-05
func TestScanRuleEvidence_ShapeAnd404(t *testing.T) {
	t.Run("api-scans/AC-05", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)
		scanID := seedScan(t, pool, hostID, time.Now().UTC(), []scanresult.Result{
			passWithEvidence("r-pass", "low", evidenceWithChecks("looks good", "sysctl kernel.randomize_va_space", "= 2")),
		})

		var ev struct {
			RuleID string `json:"rule_id"`
			Status string `json:"status"`
			Detail string `json:"detail"`
			Checks []struct {
				Command  string `json:"command"`
				Stdout   string `json:"stdout"`
				ExitCode int    `json:"exit_code"`
			} `json:"checks"`
		}
		req := asRole(t, "GET", url+"/api/v1/scans/"+scanID.String()+"/rules/r-pass/evidence", auth.RoleViewer, nil)
		resp := doReq(t, req)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		if err := json.NewDecoder(resp.Body).Decode(&ev); err != nil {
			t.Fatalf("decode: %v", err)
		}
		resp.Body.Close()
		if ev.Detail != "looks good" || len(ev.Checks) != 1 {
			t.Fatalf("evidence = %+v, want detail+1 check", ev)
		}
		if ev.Checks[0].Command != "sysctl kernel.randomize_va_space" || ev.Checks[0].Stdout != "= 2" {
			t.Errorf("check = %+v, want the stored command/stdout", ev.Checks[0])
		}

		// Unknown rule -> 404.
		req = asRole(t, "GET", url+"/api/v1/scans/"+scanID.String()+"/rules/no-such-rule/evidence", auth.RoleViewer, nil)
		r404 := doReq(t, req)
		r404.Body.Close()
		if r404.StatusCode != http.StatusNotFound {
			t.Errorf("unknown rule status = %d, want 404", r404.StatusCode)
		}
	})
}

// @ac AC-06
func TestScanOSCAL_PerRuleAndWholeScanParseAnd404(t *testing.T) {
	t.Run("api-scans/AC-06", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)
		scanID := seedScan(t, pool, hostID, time.Now().UTC(), []scanresult.Result{
			passWithEvidence("r-pass", "low", evidenceWithChecks("ok", "true", "")),
			{RuleID: "r-fail", Status: scanresult.StatusFail, Severity: "high", Evidence: evidenceWithChecks("nope", "false", "")},
		})

		assertOSCAL := func(path string) {
			req := asRole(t, "GET", url+path, auth.RoleViewer, nil)
			resp := doReq(t, req)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s status = %d, want 200", path, resp.StatusCode)
			}
			if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
				t.Errorf("%s Content-Disposition = %q, want attachment", path, cd)
			}
			var doc map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
				t.Fatalf("%s decode OSCAL: %v", path, err)
			}
			if _, ok := doc["assessment-results"]; !ok {
				t.Errorf("%s OSCAL doc missing assessment-results root (got keys %v)", path, keysOf(doc))
			}
		}
		assertOSCAL("/api/v1/scans/" + scanID.String() + "/rules/r-pass/oscal")
		assertOSCAL("/api/v1/scans/" + scanID.String() + "/oscal")

		// Unknown scan -> 404 on both OSCAL routes.
		ghost := uuid.Must(uuid.NewV7())
		for _, p := range []string{
			"/api/v1/scans/" + ghost.String() + "/oscal",
			"/api/v1/scans/" + ghost.String() + "/rules/r-pass/oscal",
		} {
			req := asRole(t, "GET", url+p, auth.RoleViewer, nil)
			r := doReq(t, req)
			r.Body.Close()
			if r.StatusCode != http.StatusNotFound {
				t.Errorf("%s status = %d, want 404", p, r.StatusCode)
			}
		}
	})
}

// @ac AC-07
// Source-inspection: evidence lives only at /scans. scans_handlers.go is
// the sanctioned home for the token "evidence"; the api-host-compliance
// pinned files stay evidence-free so the host tab cannot leak check output.
func TestScansSurface_OwnsEvidence_HostTabDoesNot(t *testing.T) {
	t.Run("api-scans/AC-07", func(t *testing.T) {
		_, file, _, _ := runtime.Caller(0)
		dir := filepath.Dir(file)

		scansSrc, err := os.ReadFile(filepath.Join(dir, "scans_handlers.go"))
		if err != nil {
			t.Fatalf("read scans_handlers.go: %v", err)
		}
		if !strings.Contains(strings.ToLower(string(scansSrc)), "evidence") {
			t.Error("scans_handlers.go does not reference evidence — the /scans surface must expose it")
		}

		forbidden := regexp.MustCompile(`(?i)\bevidence\b`)
		for _, f := range []string{"host_compliance_handler.go", "host_compliance_lens_handler.go"} {
			b, err := os.ReadFile(filepath.Join(dir, f))
			if err != nil {
				t.Fatalf("read %s: %v", f, err)
			}
			if forbidden.MatchString(string(b)) {
				t.Errorf("%s references evidence — the host Compliance tab must stay evidence-free (api-host-compliance C-02)", f)
			}
		}
	})
}

// keysOf returns the top-level keys of a decoded JSON object (for error msgs).
func keysOf(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
