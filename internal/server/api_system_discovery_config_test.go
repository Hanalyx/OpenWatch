// @spec api-system-discovery-config
//
// AC traceability (this file):
//
//   AC-01  TestAPI_SystemDiscoveryConfig_GET_ReturnsDefaultsWhenEmpty
//   AC-02  TestAPI_SystemDiscoveryConfig_GET_AsAnonymous_Forbidden
//   AC-03  TestAPI_SystemDiscoveryConfig_PUT_RoundTrip
//   AC-04  TestAPI_SystemDiscoveryConfig_PUT_AsViewer_Forbidden
//   AC-05  TestAPI_SystemDiscoveryConfig_PUT_RejectsOutOfRangeIntervalSec
//   AC-06  TestAPI_SystemDiscoveryConfig_PUT_RejectsOutOfRangeRateLimit
//   AC-07  TestAPI_SystemDiscoveryConfig_PUT_EmitsAuditWithOldAndNewSnapshots
//   AC-08  TestAPI_SystemDiscoverySweep_EnqueuesUndiscoveredHosts
//   AC-09  TestAPI_SystemDiscoverySweep_AsViewer_Forbidden
//   AC-10  TestAPI_SystemDiscoverySweep_ZeroDueHostsReturns200
//   AC-11  TestAPI_SystemDiscoveryConfig_PUT_MalformedBody_Returns400

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// validDiscoveryBody returns a body that passes every range check.
func validDiscoveryBody() map[string]any {
	return map[string]any{
		"interval_sec":            86400,
		"rate_limit":              25,
		"detect_on_first_contact": true,
		"maintenance_global":      false,
	}
}

// @ac AC-01
func TestAPI_SystemDiscoveryConfig_GET_ReturnsDefaultsWhenEmpty(t *testing.T) {
	t.Run("api-system-discovery-config/AC-01", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		req := asRole(t, "GET", url+"/api/v1/system/discovery/config", auth.RoleViewer, nil)
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
		if got := body.Config["interval_sec"].(float64); got != 86400 {
			t.Errorf("config.interval_sec: want 86400, got %v", got)
		}
		if got := body.Config["rate_limit"].(float64); got != 25 {
			t.Errorf("config.rate_limit: want 25, got %v", got)
		}
		if got := body.Config["detect_on_first_contact"].(bool); !got {
			t.Errorf("config.detect_on_first_contact: want true, got %v", got)
		}
		if got := body.Config["maintenance_global"].(bool); got != false {
			t.Errorf("config.maintenance_global: want false, got %v", got)
		}
		if got := body.Defaults["interval_sec"].(float64); got != 86400 {
			t.Errorf("defaults.interval_sec: want 86400, got %v", got)
		}
	})
}

// @ac AC-02
func TestAPI_SystemDiscoveryConfig_GET_AsAnonymous_Forbidden(t *testing.T) {
	t.Run("api-system-discovery-config/AC-02", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		req, _ := http.NewRequest("GET", url+"/api/v1/system/discovery/config", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 anon, got %d", resp.StatusCode)
		}
	})
}

// @ac AC-03
func TestAPI_SystemDiscoveryConfig_PUT_RoundTrip(t *testing.T) {
	t.Run("api-system-discovery-config/AC-03", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := validDiscoveryBody()
		body["interval_sec"] = 43200
		body["rate_limit"] = 50
		body["detect_on_first_contact"] = false
		req := asRole(t, "PUT", url+"/api/v1/system/discovery/config", auth.RoleAdmin, body)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("PUT: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 PUT, got %d", resp.StatusCode)
		}

		req2 := asRole(t, "GET", url+"/api/v1/system/discovery/config", auth.RoleViewer, nil)
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
		if got := roundTrip.Config["interval_sec"].(float64); got != 43200 {
			t.Errorf("interval_sec round-trip: want 43200, got %v", got)
		}
		if got := roundTrip.Config["rate_limit"].(float64); got != 50 {
			t.Errorf("rate_limit round-trip: want 50, got %v", got)
		}
		if got := roundTrip.Config["detect_on_first_contact"].(bool); got != false {
			t.Errorf("detect_on_first_contact round-trip: want false, got %v", got)
		}
	})
}

// @ac AC-04
func TestAPI_SystemDiscoveryConfig_PUT_AsViewer_Forbidden(t *testing.T) {
	t.Run("api-system-discovery-config/AC-04", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := validDiscoveryBody()
		body["interval_sec"] = 7200
		req := asRole(t, "PUT", url+"/api/v1/system/discovery/config", auth.RoleViewer, body)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("PUT: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", resp.StatusCode)
		}

		// State unchanged — GET still shows defaults.
		req2 := asRole(t, "GET", url+"/api/v1/system/discovery/config", auth.RoleViewer, nil)
		resp2, err := http.DefaultClient.Do(req2)
		if err != nil {
			t.Fatalf("GET (verify): %v", err)
		}
		defer resp2.Body.Close()
		var rt struct {
			Config map[string]any `json:"config"`
		}
		_ = json.NewDecoder(resp2.Body).Decode(&rt)
		if got := rt.Config["interval_sec"].(float64); got != 86400 {
			t.Errorf("forbidden PUT mutated state: interval_sec=%v", got)
		}
	})
}

// @ac AC-05
func TestAPI_SystemDiscoveryConfig_PUT_RejectsOutOfRangeIntervalSec(t *testing.T) {
	t.Run("api-system-discovery-config/AC-05", func(t *testing.T) {
		url, _ := freshAPIServer(t)

		bodyLow := validDiscoveryBody()
		bodyLow["interval_sec"] = 600
		reqLow := asRole(t, "PUT", url+"/api/v1/system/discovery/config", auth.RoleAdmin, bodyLow)
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

		bodyHigh := validDiscoveryBody()
		bodyHigh["interval_sec"] = 700000
		reqHigh := asRole(t, "PUT", url+"/api/v1/system/discovery/config", auth.RoleAdmin, bodyHigh)
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

// @ac AC-06
func TestAPI_SystemDiscoveryConfig_PUT_RejectsOutOfRangeRateLimit(t *testing.T) {
	t.Run("api-system-discovery-config/AC-06", func(t *testing.T) {
		url, _ := freshAPIServer(t)

		bodyLow := validDiscoveryBody()
		bodyLow["rate_limit"] = 0
		reqLow := asRole(t, "PUT", url+"/api/v1/system/discovery/config", auth.RoleAdmin, bodyLow)
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

		bodyHigh := validDiscoveryBody()
		bodyHigh["rate_limit"] = 600
		reqHigh := asRole(t, "PUT", url+"/api/v1/system/discovery/config", auth.RoleAdmin, bodyHigh)
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

// @ac AC-07
func TestAPI_SystemDiscoveryConfig_PUT_EmitsAuditWithOldAndNewSnapshots(t *testing.T) {
	t.Run("api-system-discovery-config/AC-07", func(t *testing.T) {
		url, pool := freshAPIServer(t)

		startCount := auditCount(t, pool, audit.SystemConfigChanged)

		body := validDiscoveryBody()
		body["interval_sec"] = 172800
		body["rate_limit"] = 100
		req := asRole(t, "PUT", url+"/api/v1/system/discovery/config", auth.RoleAdmin, body)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("PUT: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		endCount := startCount
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			endCount = auditCount(t, pool, audit.SystemConfigChanged)
			if endCount-startCount >= 1 {
				break
			}
			time.Sleep(25 * time.Millisecond)
		}
		if endCount-startCount != 1 {
			t.Fatalf("audit delta: want 1 SystemConfigChanged, got %d", endCount-startCount)
		}

		detail := mostRecentAuditDetail(t, pool, audit.SystemConfigChanged)
		old, ok := detail["old_value"].(map[string]any)
		if !ok {
			t.Fatalf("old_value not a map: %T", detail["old_value"])
		}
		if got := old["interval_sec"]; jsonNumberToInt(t, got) != 86400 {
			t.Errorf("old.interval_sec: want 86400 (default), got %v", got)
		}
		newV, ok := detail["new_value"].(map[string]any)
		if !ok {
			t.Fatalf("new_value not a map: %T", detail["new_value"])
		}
		if got := newV["interval_sec"]; jsonNumberToInt(t, got) != 172800 {
			t.Errorf("new.interval_sec: want 172800, got %v", got)
		}
		if got := newV["rate_limit"]; jsonNumberToInt(t, got) != 100 {
			t.Errorf("new.rate_limit: want 100, got %v", got)
		}
	})
}

// @ac AC-08
func TestAPI_SystemDiscoverySweep_EnqueuesUndiscoveredHosts(t *testing.T) {
	t.Run("api-system-discovery-config/AC-08", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()

		// Seed: user FK first, then 4 hosts in different states.
		_, _ = pool.Exec(ctx, "TRUNCATE TABLE job_queue")
		var userID uuid.UUID
		_ = pool.QueryRow(ctx,
			`INSERT INTO users (id, username, email, password_hash) VALUES (gen_random_uuid(), $1, $2, 'stub') RETURNING id`,
			"sweep-u", "sweep-u@example.com").Scan(&userID)

		now := time.Now().UTC()
		deletedAt := now.Add(-time.Minute)

		h1 := seedSweepHost(t, pool, userID, "h1-null", nil, false, nil)
		_ = seedSweepHost(t, pool, userID, "h2-done", &now, false, nil)
		_ = seedSweepHost(t, pool, userID, "h3-maint", nil, true, nil)
		_ = seedSweepHost(t, pool, userID, "h4-deleted", nil, false, &deletedAt)

		req := asRole(t, "POST", url+"/api/v1/system/discovery/sweep", auth.RoleAdmin, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST sweep: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		var body struct {
			Enqueued int `json:"enqueued"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.Enqueued != 1 {
			t.Errorf("enqueued: want 1, got %d", body.Enqueued)
		}

		// DB check — exactly one host.discovery row for h1 in job_queue.
		var queuedHostID uuid.UUID
		err = pool.QueryRow(ctx,
			`SELECT (payload->>'host_id')::uuid FROM job_queue WHERE job_type = 'host.discovery'`,
		).Scan(&queuedHostID)
		if err != nil {
			t.Fatalf("query job_queue: %v", err)
		}
		if queuedHostID != h1 {
			t.Errorf("queued host_id = %s, want h1 = %s", queuedHostID, h1)
		}
	})
}

// @ac AC-09
func TestAPI_SystemDiscoverySweep_AsViewer_Forbidden(t *testing.T) {
	t.Run("api-system-discovery-config/AC-09", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		_, _ = pool.Exec(context.Background(), "TRUNCATE TABLE job_queue")
		req := asRole(t, "POST", url+"/api/v1/system/discovery/sweep", auth.RoleViewer, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST sweep: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", resp.StatusCode)
		}
		var n int
		_ = pool.QueryRow(context.Background(),
			`SELECT count(*) FROM job_queue WHERE job_type = 'host.discovery'`).Scan(&n)
		if n != 0 {
			t.Errorf("forbidden sweep enqueued %d jobs", n)
		}
	})
}

// @ac AC-10
func TestAPI_SystemDiscoverySweep_ZeroDueHostsReturns200(t *testing.T) {
	t.Run("api-system-discovery-config/AC-10", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		req := asRole(t, "POST", url+"/api/v1/system/discovery/sweep", auth.RoleAdmin, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST sweep: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 (zero hosts is steady state), got %d", resp.StatusCode)
		}
		var body struct {
			Enqueued int `json:"enqueued"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.Enqueued != 0 {
			t.Errorf("enqueued: want 0, got %d", body.Enqueued)
		}
	})
}

// @ac AC-11
// AC-11: PUT with a malformed JSON body returns 400.
func TestAPI_SystemDiscoveryConfig_PUT_MalformedBody_Returns400(t *testing.T) {
	t.Run("api-system-discovery-config/AC-11", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		// asRole with nil body produces an auth-cookied request with no
		// body; we attach malformed bytes directly so the 403 gate is
		// satisfied and the handler exercises the decode error.
		req := asRole(t, "PUT", url+"/api/v1/system/discovery/config", auth.RoleAdmin, nil)
		req.Header.Set("Content-Type", "application/json")
		req.Body = io.NopCloser(bytes.NewReader([]byte("not-json")))
		req.GetBody = nil
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

// seedSweepHost is a thin host-row insert helper local to this file.
func seedSweepHost(t *testing.T, pool *pgxpool.Pool, userID uuid.UUID, name string,
	osDiscoveredAt *time.Time, maintenance bool, deletedAt *time.Time,
) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO hosts (id, hostname, ip_address, port, environment, created_by,
		                   os_discovered_at, maintenance_mode, deleted_at)
		VALUES ($1, $2, $3, 22, 'prod', $4, $5, $6, $7)`,
		id, name, "192.0.2.1", userID, osDiscoveredAt, maintenance, deletedAt)
	if err != nil {
		t.Fatalf("seed host %s: %v", name, err)
	}
	return id
}
