// @spec api-system-intelligence-config
//
// AC traceability (this file):
//
//   AC-01  TestAPI_SystemIntelligenceConfig_GET_ReturnsDefaultsWhenEmpty
//   AC-02  TestAPI_SystemIntelligenceConfig_GET_AsAnonymous_Forbidden
//   AC-03  TestAPI_SystemIntelligenceConfig_PUT_RoundTrip
//   AC-04  TestAPI_SystemIntelligenceConfig_PUT_AsViewer_Forbidden
//   AC-05  TestAPI_SystemIntelligenceConfig_PUT_RejectsOutOfRangeIntervalSec
//   AC-06  TestAPI_SystemIntelligenceConfig_PUT_RejectsOutOfRangeRateLimit
//   AC-07  TestAPI_SystemIntelligenceConfig_PUT_MalformedBody_Returns400
//   AC-08  TestAPI_SystemIntelligenceConfig_PUT_EmitsAuditWithOldAndNewSnapshots

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/auth"
)

// validIntelligenceBody returns a body that passes every range check.
// Callers override one field to exercise one rule per test.
func validIntelligenceBody() map[string]any {
	return map[string]any{
		"interval_sec":       3600,
		"rate_limit":         10,
		"maintenance_global": false,
	}
}

// AC-01: GET on a fresh DB returns the baked-in defaults + a defaults
// sub-object equal to the same values.
// @ac AC-01
func TestAPI_SystemIntelligenceConfig_GET_ReturnsDefaultsWhenEmpty(t *testing.T) {
	t.Run("api-system-intelligence-config/AC-01", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		req := asRole(t, "GET", url+"/api/v1/system/intelligence/config", auth.RoleViewer, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		var body struct {
			Config   map[string]any `json:"config"`
			Defaults map[string]any `json:"defaults"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got := body.Config["interval_sec"].(float64); got != 3600 {
			t.Errorf("config.interval_sec: want 3600, got %v", got)
		}
		if got := body.Config["rate_limit"].(float64); got != 10 {
			t.Errorf("config.rate_limit: want 10, got %v", got)
		}
		if got := body.Config["maintenance_global"].(bool); got != false {
			t.Errorf("config.maintenance_global: want false, got %v", got)
		}
		if got := body.Defaults["interval_sec"].(float64); got != 3600 {
			t.Errorf("defaults.interval_sec: want 3600, got %v", got)
		}
		if got := body.Defaults["rate_limit"].(float64); got != 10 {
			t.Errorf("defaults.rate_limit: want 10, got %v", got)
		}
	})
}

// AC-02: GET as anonymous (no system:read) returns 403.
// @ac AC-02
func TestAPI_SystemIntelligenceConfig_GET_AsAnonymous_Forbidden(t *testing.T) {
	t.Run("api-system-intelligence-config/AC-02", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		req, _ := http.NewRequest("GET", url+"/api/v1/system/intelligence/config", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 anon, got %d", resp.StatusCode)
		}
	})
}

// AC-03: PUT with valid body persists; subsequent GET returns the same.
// @ac AC-03
func TestAPI_SystemIntelligenceConfig_PUT_RoundTrip(t *testing.T) {
	t.Run("api-system-intelligence-config/AC-03", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := validIntelligenceBody()
		body["interval_sec"] = 1800
		body["rate_limit"] = 20
		body["maintenance_global"] = true
		req := asRole(t, "PUT", url+"/api/v1/system/intelligence/config", auth.RoleAdmin, body)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("PUT: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 PUT, got %d", resp.StatusCode)
		}

		req2 := asRole(t, "GET", url+"/api/v1/system/intelligence/config", auth.RoleViewer, nil)
		resp2, err := http.DefaultClient.Do(req2)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp2.Body.Close()
		var roundTrip struct {
			Config map[string]any `json:"config"`
		}
		if err := json.NewDecoder(resp2.Body).Decode(&roundTrip); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got := roundTrip.Config["interval_sec"].(float64); got != 1800 {
			t.Errorf("interval_sec round-trip: want 1800, got %v", got)
		}
		if got := roundTrip.Config["rate_limit"].(float64); got != 20 {
			t.Errorf("rate_limit round-trip: want 20, got %v", got)
		}
		if got := roundTrip.Config["maintenance_global"].(bool); got != true {
			t.Errorf("maintenance_global round-trip: want true, got %v", got)
		}
	})
}

// AC-04: PUT as viewer (no system:config_write) returns 403; persisted
// state MUST NOT change.
// @ac AC-04
func TestAPI_SystemIntelligenceConfig_PUT_AsViewer_Forbidden(t *testing.T) {
	t.Run("api-system-intelligence-config/AC-04", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := validIntelligenceBody()
		body["interval_sec"] = 600
		req := asRole(t, "PUT", url+"/api/v1/system/intelligence/config", auth.RoleViewer, body)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("PUT: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", resp.StatusCode)
		}

		// State unchanged — GET still shows defaults.
		req2 := asRole(t, "GET", url+"/api/v1/system/intelligence/config", auth.RoleViewer, nil)
		resp2, err := http.DefaultClient.Do(req2)
		if err != nil {
			t.Fatalf("GET (verify): %v", err)
		}
		defer resp2.Body.Close()
		var rt struct {
			Config map[string]any `json:"config"`
		}
		_ = json.NewDecoder(resp2.Body).Decode(&rt)
		if got := rt.Config["interval_sec"].(float64); got != 3600 {
			t.Errorf("forbidden PUT mutated state: interval_sec=%v", got)
		}
	})
}

// AC-05: PUT with interval_sec out of range returns 400 with
// detail.field="interval_sec".
// @ac AC-05
func TestAPI_SystemIntelligenceConfig_PUT_RejectsOutOfRangeIntervalSec(t *testing.T) {
	t.Run("api-system-intelligence-config/AC-05", func(t *testing.T) {
		url, _ := freshAPIServer(t)

		// Below floor (300).
		bodyLow := validIntelligenceBody()
		bodyLow["interval_sec"] = 60
		reqLow := asRole(t, "PUT", url+"/api/v1/system/intelligence/config", auth.RoleAdmin, bodyLow)
		respLow, err := http.DefaultClient.Do(reqLow)
		if err != nil {
			t.Fatalf("PUT (below): %v", err)
		}
		defer respLow.Body.Close()
		if respLow.StatusCode != http.StatusBadRequest {
			t.Fatalf("below floor: expected 400, got %d", respLow.StatusCode)
		}
		field := decodeFieldFromError(t, respLow)
		if field != "interval_sec" {
			t.Errorf("below floor: want field=interval_sec, got %q", field)
		}

		// Above ceiling (86400).
		bodyHigh := validIntelligenceBody()
		bodyHigh["interval_sec"] = 100000
		reqHigh := asRole(t, "PUT", url+"/api/v1/system/intelligence/config", auth.RoleAdmin, bodyHigh)
		respHigh, err := http.DefaultClient.Do(reqHigh)
		if err != nil {
			t.Fatalf("PUT (above): %v", err)
		}
		defer respHigh.Body.Close()
		if respHigh.StatusCode != http.StatusBadRequest {
			t.Fatalf("above ceiling: expected 400, got %d", respHigh.StatusCode)
		}
	})
}

// AC-06: PUT with rate_limit out of range returns 400 with
// detail.field="rate_limit".
// @ac AC-06
func TestAPI_SystemIntelligenceConfig_PUT_RejectsOutOfRangeRateLimit(t *testing.T) {
	t.Run("api-system-intelligence-config/AC-06", func(t *testing.T) {
		url, _ := freshAPIServer(t)

		// Below floor (1).
		bodyLow := validIntelligenceBody()
		bodyLow["rate_limit"] = 0
		reqLow := asRole(t, "PUT", url+"/api/v1/system/intelligence/config", auth.RoleAdmin, bodyLow)
		respLow, err := http.DefaultClient.Do(reqLow)
		if err != nil {
			t.Fatalf("PUT (below): %v", err)
		}
		defer respLow.Body.Close()
		if respLow.StatusCode != http.StatusBadRequest {
			t.Fatalf("below floor: expected 400, got %d", respLow.StatusCode)
		}
		field := decodeFieldFromError(t, respLow)
		if field != "rate_limit" {
			t.Errorf("below floor: want field=rate_limit, got %q", field)
		}

		// Above ceiling (200).
		bodyHigh := validIntelligenceBody()
		bodyHigh["rate_limit"] = 300
		reqHigh := asRole(t, "PUT", url+"/api/v1/system/intelligence/config", auth.RoleAdmin, bodyHigh)
		respHigh, err := http.DefaultClient.Do(reqHigh)
		if err != nil {
			t.Fatalf("PUT (above): %v", err)
		}
		defer respHigh.Body.Close()
		if respHigh.StatusCode != http.StatusBadRequest {
			t.Fatalf("above ceiling: expected 400, got %d", respHigh.StatusCode)
		}
	})
}

// AC-07: PUT with a malformed body returns 400.
// @ac AC-07
func TestAPI_SystemIntelligenceConfig_PUT_MalformedBody_Returns400(t *testing.T) {
	t.Run("api-system-intelligence-config/AC-07", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		// asRole with nil body produces an auth-cookied request with no
		// body; we then attach the malformed bytes directly so the
		// 403 gate is satisfied and we exercise the decode error.
		req := asRole(t, "PUT", url+"/api/v1/system/intelligence/config", auth.RoleAdmin, nil)
		req.Header.Set("Content-Type", "application/json")
		req.Body = http.NoBody
		req.GetBody = nil
		req.Body = io.NopCloser(bytes.NewReader([]byte("not-json")))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("PUT: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", resp.StatusCode)
		}
	})
}

// AC-08: A successful PUT emits exactly one audit.SystemConfigChanged
// event whose detail.old_value reflects the prior snapshot and
// detail.new_value reflects the just-saved snapshot.
// @ac AC-08
func TestAPI_SystemIntelligenceConfig_PUT_EmitsAuditWithOldAndNewSnapshots(t *testing.T) {
	t.Run("api-system-intelligence-config/AC-08", func(t *testing.T) {
		url, pool := freshAPIServer(t)

		// Read the audit row count before — we want the delta.
		startCount := auditCount(t, pool, audit.SystemConfigChanged)

		body := validIntelligenceBody()
		body["interval_sec"] = 7200
		body["rate_limit"] = 50
		req := asRole(t, "PUT", url+"/api/v1/system/intelligence/config", auth.RoleAdmin, body)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("PUT: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		endCount := auditCount(t, pool, audit.SystemConfigChanged)
		if endCount-startCount != 1 {
			t.Fatalf("audit delta: want 1 SystemConfigChanged, got %d", endCount-startCount)
		}

		// Inspect the most recent event detail. old_value should reflect
		// defaults (no prior write); new_value should reflect the just-
		// saved values.
		detail := mostRecentAuditDetail(t, pool, audit.SystemConfigChanged)
		old, ok := detail["old_value"].(map[string]any)
		if !ok {
			t.Fatalf("old_value not a map: %T", detail["old_value"])
		}
		if got := old["interval_sec"]; jsonNumberToInt(t, got) != 3600 {
			t.Errorf("old.interval_sec: want 3600 (default), got %v", got)
		}
		newV, ok := detail["new_value"].(map[string]any)
		if !ok {
			t.Fatalf("new_value not a map: %T", detail["new_value"])
		}
		if got := newV["interval_sec"]; jsonNumberToInt(t, got) != 7200 {
			t.Errorf("new.interval_sec: want 7200, got %v", got)
		}
		if got := newV["rate_limit"]; jsonNumberToInt(t, got) != 50 {
			t.Errorf("new.rate_limit: want 50, got %v", got)
		}
	})
}

// ---------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------

func decodeFieldFromError(t *testing.T, resp *http.Response) string {
	t.Helper()
	var env struct {
		Error struct {
			Detail map[string]any `json:"detail"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("decode err: %v", err)
		return ""
	}
	if env.Error.Detail == nil {
		return ""
	}
	f, _ := env.Error.Detail["field"].(string)
	return f
}

func auditCount(t *testing.T, pool *pgxpool.Pool, code audit.Code) int {
	t.Helper()
	var n int
	row := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE action = $1`, string(code))
	if err := row.Scan(&n); err != nil {
		t.Fatalf("audit count: %v", err)
	}
	return n
}

func mostRecentAuditDetail(t *testing.T, pool *pgxpool.Pool, code audit.Code) map[string]any {
	t.Helper()
	var raw []byte
	row := pool.QueryRow(context.Background(),
		`SELECT detail FROM audit_events WHERE action = $1 ORDER BY recorded_at DESC LIMIT 1`,
		string(code))
	if err := row.Scan(&raw); err != nil {
		t.Fatalf("audit detail scan: %v", err)
	}
	var detail map[string]any
	if err := json.Unmarshal(raw, &detail); err != nil {
		t.Fatalf("audit detail unmarshal: %v", err)
	}
	return detail
}

func jsonNumberToInt(t *testing.T, v any) int {
	t.Helper()
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	default:
		t.Fatalf("not a number: %T", v)
		return 0
	}
}
