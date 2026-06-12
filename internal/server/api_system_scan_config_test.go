// @spec api-system-scan-config
//
// AC traceability (this file; DSN-gated like every api_*_test here):
//
//	AC-01  TestAPI_SystemScanConfig_GET_ReturnsDefaultsWhenEmpty
//	AC-02  TestAPI_SystemScanConfig_RBAC
//	AC-03  TestAPI_SystemScanConfig_PUT_RoundTrip
//	AC-04  TestAPI_SystemScanConfig_PUT_ClampsOutOfBounds_MalformedRejected
//	AC-05  TestAPI_SystemScanConfig_PUT_EmitsAudit
//	AC-06  TestAPI_FleetComplianceStates_LadderOrderAndCounts
//	AC-07  TestAPI_ScanSchedulePreview_ProjectionFigures
//	AC-08  TestAPI_ScanVariables_GET_ListsCatalogWithFlags
//	AC-09  TestAPI_ScanVariables_PUT_OverridesValidationAndAudit
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/auth"
)

// validScanBody returns an in-bounds full config body.
func validScanBody() map[string]any {
	return map[string]any{
		"enabled":               true,
		"unknown_mins":          360,
		"critical_mins":         240,
		"non_compliant_mins":    480,
		"partial_mins":          720,
		"mostly_compliant_mins": 1440,
		"compliant_mins":        2880,
		"rate_limit":            25,
		"maintenance_global":    false,
	}
}

// seedScheduleRow inserts a host_compliance_schedule row directly.
func seedScheduleRow(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID,
	state string, next time.Time, maintenance bool) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO host_compliance_schedule
			(host_id, compliance_state, next_scheduled_scan, maintenance_mode)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (host_id) DO UPDATE
		   SET compliance_state = EXCLUDED.compliance_state,
		       next_scheduled_scan = EXCLUDED.next_scheduled_scan,
		       maintenance_mode = EXCLUDED.maintenance_mode`,
		hostID, state, next, maintenance)
	if err != nil {
		t.Fatalf("seed schedule row %s: %v", hostID, err)
	}
}

// @ac AC-01
// AC-01: with no persisted row, GET returns the baked-in defaults as
// BOTH config and defaults in the {config, defaults} envelope.
func TestAPI_SystemScanConfig_GET_ReturnsDefaultsWhenEmpty(t *testing.T) {
	t.Run("api-system-scan-config/AC-01", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		req := asRole(t, "GET", url+"/api/v1/system/scan/config", auth.RoleViewer, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		var body struct {
			Config   map[string]any `json:"config"`
			Defaults map[string]any `json:"defaults"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		want := map[string]float64{
			"unknown_mins": 360, "critical_mins": 240, "non_compliant_mins": 480,
			"partial_mins": 720, "mostly_compliant_mins": 1440, "compliant_mins": 2880,
			"rate_limit": 25,
		}
		for _, section := range []map[string]any{body.Config, body.Defaults} {
			for k, v := range want {
				if got := section[k].(float64); got != v {
					t.Errorf("%s = %v, want %v", k, got, v)
				}
			}
			if got := section["enabled"].(bool); !got {
				t.Errorf("enabled = %v, want true", got)
			}
			if got := section["maintenance_global"].(bool); got {
				t.Errorf("maintenance_global = %v, want false", got)
			}
		}
	})
}

// @ac AC-02
// AC-02: RBAC across all four endpoints — anonymous rejected
// everywhere; viewer PUT rejected and leaves the config untouched.
func TestAPI_SystemScanConfig_RBAC(t *testing.T) {
	t.Run("api-system-scan-config/AC-02", func(t *testing.T) {
		url, _ := freshAPIServer(t)

		for _, p := range []string{
			"/api/v1/system/scan/config",
			"/api/v1/system/scan/schedule-preview",
			"/api/v1/fleet/compliance/states",
		} {
			req, _ := http.NewRequest("GET", url+p, nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("%s anon GET: %v", p, err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
				t.Errorf("%s anonymous status = %d, want 401/403", p, resp.StatusCode)
			}
		}

		// Viewer PUT: 403 and nothing persisted.
		body := validScanBody()
		body["critical_mins"] = 30
		req := asRole(t, "PUT", url+"/api/v1/system/scan/config", auth.RoleViewer, body)
		resp := doReq(t, req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("viewer PUT status = %d, want 403", resp.StatusCode)
		}
		getReq := asRole(t, "GET", url+"/api/v1/system/scan/config", auth.RoleViewer, nil)
		getResp := doReq(t, getReq)
		defer getResp.Body.Close()
		var after struct {
			Config map[string]any `json:"config"`
		}
		_ = json.NewDecoder(getResp.Body).Decode(&after)
		if got := after.Config["critical_mins"].(float64); got != 240 {
			t.Errorf("config changed by forbidden PUT: critical_mins = %v, want 240", got)
		}
	})
}

// @ac AC-03
// AC-03: in-bounds PUT round-trips; defaults stay baked-in.
func TestAPI_SystemScanConfig_PUT_RoundTrip(t *testing.T) {
	t.Run("api-system-scan-config/AC-03", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := validScanBody()
		body["critical_mins"] = 60
		body["enabled"] = false
		req := asRole(t, "PUT", url+"/api/v1/system/scan/config", auth.RoleAdmin, body)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("PUT status = %d, want 200", resp.StatusCode)
		}
		var echoed map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&echoed)
		if got := echoed["critical_mins"].(float64); got != 60 {
			t.Errorf("echo critical_mins = %v, want 60", got)
		}

		getReq := asRole(t, "GET", url+"/api/v1/system/scan/config", auth.RoleViewer, nil)
		getResp := doReq(t, getReq)
		defer getResp.Body.Close()
		var after struct {
			Config   map[string]any `json:"config"`
			Defaults map[string]any `json:"defaults"`
		}
		_ = json.NewDecoder(getResp.Body).Decode(&after)
		if got := after.Config["critical_mins"].(float64); got != 60 {
			t.Errorf("persisted critical_mins = %v, want 60", got)
		}
		if got := after.Config["enabled"].(bool); got {
			t.Errorf("persisted enabled = %v, want false", got)
		}
		if got := after.Defaults["critical_mins"].(float64); got != 240 {
			t.Errorf("defaults drifted: critical_mins = %v, want 240", got)
		}
	})
}

// @ac AC-04
// AC-04: out-of-bounds values are CLAMPED (200, echoed, persisted),
// never rejected; malformed JSON still 400s.
func TestAPI_SystemScanConfig_PUT_ClampsOutOfBounds_MalformedRejected(t *testing.T) {
	t.Run("api-system-scan-config/AC-04", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := validScanBody()
		body["critical_mins"] = 1      // below 5m floor
		body["compliant_mins"] = 99999 // above 48h ceiling
		body["rate_limit"] = 0         // below 1 floor
		req := asRole(t, "PUT", url+"/api/v1/system/scan/config", auth.RoleAdmin, body)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("clamping PUT status = %d, want 200 (clamp, not reject)", resp.StatusCode)
		}
		var echoed map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&echoed)
		if got := echoed["critical_mins"].(float64); got != 5 {
			t.Errorf("clamped critical_mins = %v, want 5", got)
		}
		if got := echoed["compliant_mins"].(float64); got != 2880 {
			t.Errorf("clamped compliant_mins = %v, want 2880", got)
		}
		if got := echoed["rate_limit"].(float64); got != 1 {
			t.Errorf("clamped rate_limit = %v, want 1", got)
		}

		// Clamped values are what persisted.
		getReq := asRole(t, "GET", url+"/api/v1/system/scan/config", auth.RoleViewer, nil)
		getResp := doReq(t, getReq)
		defer getResp.Body.Close()
		var after struct {
			Config map[string]any `json:"config"`
		}
		_ = json.NewDecoder(getResp.Body).Decode(&after)
		if got := after.Config["critical_mins"].(float64); got != 5 {
			t.Errorf("persisted clamped critical_mins = %v, want 5", got)
		}

		// Malformed body: 400.
		malformed := asRole(t, "PUT", url+"/api/v1/system/scan/config", auth.RoleAdmin, nil)
		malformed.Body = http.NoBody
		mResp := doReq(t, malformed)
		mResp.Body.Close()
		if mResp.StatusCode != http.StatusBadRequest {
			t.Errorf("malformed PUT status = %d, want 400", mResp.StatusCode)
		}
	})
}

// @ac AC-05
// AC-05: a successful PUT emits SystemConfigChanged with config_key
// "scan" and old/new snapshots.
func TestAPI_SystemScanConfig_PUT_EmitsAudit(t *testing.T) {
	t.Run("api-system-scan-config/AC-05", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		body := validScanBody()
		body["rate_limit"] = 50
		req := asRole(t, "PUT", url+"/api/v1/system/scan/config", auth.RoleAdmin, body)
		resp := doReq(t, req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("PUT status = %d, want 200", resp.StatusCode)
		}

		// Audit emission is async; poll briefly for the scan-keyed row.
		deadline := time.Now().Add(3 * time.Second)
		for {
			var raw []byte
			err := pool.QueryRow(context.Background(), `
				SELECT detail FROM audit_events
				 WHERE action = $1 AND detail->>'config_key' = 'scan'
				 ORDER BY recorded_at DESC LIMIT 1`,
				string(audit.SystemConfigChanged)).Scan(&raw)
			if err == nil {
				var d struct {
					OldValue map[string]any `json:"old_value"`
					NewValue map[string]any `json:"new_value"`
				}
				if err := json.Unmarshal(raw, &d); err != nil {
					t.Fatalf("unmarshal detail: %v", err)
				}
				if d.NewValue["rate_limit"].(float64) != 50 {
					t.Errorf("audit new_value.rate_limit = %v, want 50", d.NewValue["rate_limit"])
				}
				if d.OldValue["rate_limit"].(float64) != 25 {
					t.Errorf("audit old_value.rate_limit = %v, want 25 (default)", d.OldValue["rate_limit"])
				}
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("no system.config.changed audit row for config_key=scan")
			}
			time.Sleep(50 * time.Millisecond)
		}
	})
}

// @ac AC-06
// AC-06: fleet states — six entries in ladder order, zero counts
// included, unseeded hosts count as unknown, deleted hosts excluded.
func TestAPI_FleetComplianceStates_LadderOrderAndCounts(t *testing.T) {
	t.Run("api-system-scan-config/AC-06", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		now := time.Now().UTC()

		critical := seedHostForIntel(t, pool)
		seedScheduleRow(t, pool, critical, "critical", now.Add(time.Hour), false)
		mostly := seedHostForIntel(t, pool)
		seedScheduleRow(t, pool, mostly, "mostly_compliant", now.Add(time.Hour), false)
		_ = seedHostForIntel(t, pool) // unseeded — counts as unknown

		// Soft-deleted host with a schedule row: counts nowhere.
		ghost := seedHostForIntel(t, pool)
		seedScheduleRow(t, pool, ghost, "compliant", now.Add(time.Hour), false)
		if _, err := pool.Exec(context.Background(),
			`UPDATE hosts SET deleted_at = now() WHERE id = $1`, ghost); err != nil {
			t.Fatalf("soft-delete: %v", err)
		}

		req := asRole(t, "GET", url+"/api/v1/fleet/compliance/states", auth.RoleViewer, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		var body struct {
			States []struct {
				State     string `json:"state"`
				HostCount int    `json:"host_count"`
			} `json:"states"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}

		wantOrder := []string{"critical", "non_compliant", "partial",
			"mostly_compliant", "compliant", "unknown"}
		if len(body.States) != 6 {
			t.Fatalf("states len = %d, want 6", len(body.States))
		}
		counts := map[string]int{}
		for i, s := range body.States {
			if s.State != wantOrder[i] {
				t.Errorf("states[%d] = %s, want %s (ladder order)", i, s.State, wantOrder[i])
			}
			counts[s.State] = s.HostCount
		}
		if counts["critical"] != 1 || counts["mostly_compliant"] != 1 {
			t.Errorf("counts = %v, want critical:1 mostly_compliant:1", counts)
		}
		if counts["unknown"] != 1 {
			t.Errorf("unknown = %d, want 1 (unseeded live host)", counts["unknown"])
		}
		if counts["compliant"] != 0 {
			t.Errorf("compliant = %d, want 0 (soft-deleted host excluded)", counts["compliant"])
		}
		if counts["non_compliant"] != 0 || counts["partial"] != 0 {
			t.Errorf("zero-count states missing or non-zero: %v", counts)
		}
	})
}

// @ac AC-07
// AC-07: schedule preview — next_scan_at = soonest FUTURE scan,
// due_now counts overdue rows, 24 buckets place rows by hour,
// maintenance rows excluded, queue depth from scan_runs.
func TestAPI_ScanSchedulePreview_ProjectionFigures(t *testing.T) {
	t.Run("api-system-scan-config/AC-07", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		now := time.Now().UTC()

		overdue := seedHostForIntel(t, pool)
		seedScheduleRow(t, pool, overdue, "critical", now.Add(-time.Hour), false)
		soon := seedHostForIntel(t, pool)
		seedScheduleRow(t, pool, soon, "partial", now.Add(30*time.Minute), false)
		later := seedHostForIntel(t, pool)
		seedScheduleRow(t, pool, later, "compliant", now.Add(5*time.Hour+30*time.Minute), false)
		maint := seedHostForIntel(t, pool)
		seedScheduleRow(t, pool, maint, "critical", now.Add(10*time.Minute), true) // excluded

		// Queue depth: one queued scan_runs row.
		jobID := uuid.Must(uuid.NewV7())
		if _, err := pool.Exec(context.Background(), `
			INSERT INTO scan_runs (id, host_id, trigger_source, status)
			VALUES ($1, $2, 'on_demand', 'queued')`, jobID, overdue); err != nil {
			t.Fatalf("seed scan_run: %v", err)
		}

		req := asRole(t, "GET", url+"/api/v1/system/scan/schedule-preview", auth.RoleViewer, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		var body struct {
			NextScanAt  *time.Time `json:"next_scan_at"`
			DueNow      int        `json:"due_now"`
			QueuedJobs  int        `json:"queued_jobs"`
			RunningJobs int        `json:"running_jobs"`
			Buckets     []struct {
				HourOffset int `json:"hour_offset"`
				DueCount   int `json:"due_count"`
			} `json:"buckets"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}

		if body.DueNow != 1 {
			t.Errorf("due_now = %d, want 1 (overdue host; maintenance row excluded)", body.DueNow)
		}
		if body.NextScanAt == nil || body.NextScanAt.Sub(now) > 31*time.Minute ||
			body.NextScanAt.Sub(now) < 29*time.Minute {
			t.Errorf("next_scan_at = %v, want ~now+30m (maintenance row must not win)", body.NextScanAt)
		}
		if body.QueuedJobs != 1 || body.RunningJobs != 0 {
			t.Errorf("queue depth = %d/%d, want 1/0", body.QueuedJobs, body.RunningJobs)
		}
		if len(body.Buckets) != 24 {
			t.Fatalf("buckets len = %d, want 24", len(body.Buckets))
		}
		for _, b := range body.Buckets {
			want := 0
			switch b.HourOffset {
			case 0:
				want = 1 // +30m
			case 5:
				want = 1 // +5h30m
			}
			if b.DueCount != want {
				t.Errorf("bucket[%d] = %d, want %d", b.HourOffset, b.DueCount, want)
			}
		}
	})
}

// @ac AC-08
// AC-08 (v1.1.0): GET /system/scan/variables lists the fixture
// catalog's corpus-used variables sorted by name with defaults,
// effective values, rule attribution, and the configure_me flag;
// anonymous callers are rejected.
func TestAPI_ScanVariables_GET_ListsCatalogWithFlags(t *testing.T) {
	t.Run("api-system-scan-config/AC-08", func(t *testing.T) {
		url, _ := freshAPIServer(t)

		// Anonymous: rejected.
		anon, _ := http.NewRequest("GET", url+"/api/v1/system/scan/variables", nil)
		anonResp, err := http.DefaultClient.Do(anon)
		if err != nil {
			t.Fatalf("anon GET: %v", err)
		}
		anonResp.Body.Close()
		if anonResp.StatusCode != http.StatusUnauthorized && anonResp.StatusCode != http.StatusForbidden {
			t.Errorf("anonymous status = %d, want 401/403", anonResp.StatusCode)
		}

		req := asRole(t, "GET", url+"/api/v1/system/scan/variables", auth.RoleViewer, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		var body struct {
			Variables []struct {
				Name         string   `json:"name"`
				Default      string   `json:"default"`
				Value        string   `json:"value"`
				Overridden   bool     `json:"overridden"`
				AffectsRules int      `json:"affects_rules"`
				RuleIds      []string `json:"rule_ids"`
				ConfigureMe  bool     `json:"configure_me"`
			} `json:"variables"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(body.Variables) != 2 {
			t.Fatalf("variables len = %d, want 2 (fixture catalog)", len(body.Variables))
		}
		// Sorted by name: banner_text < ssh_max_auth_tries.
		banner, ssh := body.Variables[0], body.Variables[1]
		if banner.Name != "banner_text" || !banner.ConfigureMe ||
			banner.Default != "Authorized use only" || banner.Value != banner.Default ||
			banner.Overridden || banner.AffectsRules != 1 {
			t.Errorf("banner_text entry = %+v, want placeholder defaults", banner)
		}
		if ssh.Name != "ssh_max_auth_tries" || ssh.ConfigureMe ||
			ssh.AffectsRules != 2 || len(ssh.RuleIds) != 2 {
			t.Errorf("ssh_max_auth_tries entry = %+v", ssh)
		}
	})
}

// @ac AC-09
// AC-09 (v1.1.0): PUT round-trips an override; default-equal values
// are dropped; unknown names 400 with the key named; viewer PUT 403;
// audit carries config_key scan_variables.
func TestAPI_ScanVariables_PUT_OverridesValidationAndAudit(t *testing.T) {
	t.Run("api-system-scan-config/AC-09", func(t *testing.T) {
		url, pool := freshAPIServer(t)

		fetchVars := func() map[string]struct {
			Value      string
			Overridden bool
		} {
			t.Helper()
			req := asRole(t, "GET", url+"/api/v1/system/scan/variables", auth.RoleViewer, nil)
			resp := doReq(t, req)
			defer resp.Body.Close()
			var body struct {
				Variables []struct {
					Name       string `json:"name"`
					Value      string `json:"value"`
					Overridden bool   `json:"overridden"`
				} `json:"variables"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatalf("decode vars: %v", err)
			}
			out := map[string]struct {
				Value      string
				Overridden bool
			}{}
			for _, v := range body.Variables {
				out[v.Name] = struct {
					Value      string
					Overridden bool
				}{v.Value, v.Overridden}
			}
			return out
		}

		// Valid override + a default-equal value (dropped at write).
		put := asRole(t, "PUT", url+"/api/v1/system/scan/variables", auth.RoleAdmin,
			map[string]any{"overrides": map[string]string{
				"banner_text":        "Property of ACME Corp",
				"ssh_max_auth_tries": "4", // equals the default -> dropped
			}})
		resp := doReq(t, put)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("PUT status = %d, want 200", resp.StatusCode)
		}
		var echoed struct {
			Overrides map[string]string `json:"overrides"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&echoed)
		if len(echoed.Overrides) != 1 || echoed.Overrides["banner_text"] != "Property of ACME Corp" {
			t.Errorf("echoed overrides = %v, want only the banner override", echoed.Overrides)
		}

		vars := fetchVars()
		if v := vars["banner_text"]; !v.Overridden || v.Value != "Property of ACME Corp" {
			t.Errorf("banner_text after PUT = %+v, want overridden", v)
		}
		if v := vars["ssh_max_auth_tries"]; v.Overridden {
			t.Errorf("default-equal override was not dropped: %+v", v)
		}

		// Unknown name: 400 naming the key; nothing persisted.
		bad := asRole(t, "PUT", url+"/api/v1/system/scan/variables", auth.RoleAdmin,
			map[string]any{"overrides": map[string]string{"no_such_var": "x"}})
		badResp := doReq(t, bad)
		defer badResp.Body.Close()
		if badResp.StatusCode != http.StatusBadRequest {
			t.Fatalf("unknown-name PUT status = %d, want 400", badResp.StatusCode)
		}
		var env struct {
			Error struct {
				Code   string         `json:"code"`
				Detail map[string]any `json:"detail"`
			} `json:"error"`
		}
		_ = json.NewDecoder(badResp.Body).Decode(&env)
		if env.Error.Code != "validation.field_invalid" || env.Error.Detail["field"] != "no_such_var" {
			t.Errorf("unknown-name envelope = %+v, want validation.field_invalid naming no_such_var", env.Error)
		}
		if v := fetchVars()["banner_text"]; !v.Overridden {
			t.Errorf("failed PUT clobbered the prior override")
		}

		// Viewer: 403.
		viewer := asRole(t, "PUT", url+"/api/v1/system/scan/variables", auth.RoleViewer,
			map[string]any{"overrides": map[string]string{}})
		vResp := doReq(t, viewer)
		vResp.Body.Close()
		if vResp.StatusCode != http.StatusForbidden {
			t.Errorf("viewer PUT status = %d, want 403", vResp.StatusCode)
		}

		// Audit: SystemConfigChanged with config_key scan_variables.
		deadline := time.Now().Add(3 * time.Second)
		for {
			var n int
			_ = pool.QueryRow(context.Background(), `
				SELECT COUNT(*) FROM audit_events
				 WHERE action = $1 AND detail->>'config_key' = 'scan_variables'`,
				string(audit.SystemConfigChanged)).Scan(&n)
			if n > 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("no SystemConfigChanged audit row for scan_variables")
			}
			time.Sleep(50 * time.Millisecond)
		}
	})
}
