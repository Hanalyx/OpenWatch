// @spec api-system-connectivity, api-fleet-connectivity-breakdown, api-host-connectivity-check
//
// AC traceability (this file):
//
//   api-system-connectivity/AC-01  TestAPI_SystemConnectivity_Config_GET_ReturnsDefaultsWhenEmpty
//   api-system-connectivity/AC-02  TestAPI_SystemConnectivity_Config_PUT_RoundTrip
//   api-system-connectivity/AC-03  TestAPI_SystemConnectivity_Config_PUT_RejectsBelowMinimum
//   api-system-connectivity/AC-04  TestAPI_SystemConnectivity_Config_PUT_RejectsAboveMaximum
//   api-system-connectivity/AC-06  TestAPI_SystemConnectivity_Config_PUT_AsViewer_Forbidden
//   api-system-connectivity/AC-07  TestAPI_SystemConnectivity_Config_PUT_Anonymous_Forbidden
//   api-system-connectivity/AC-08  TestAPI_SystemConnectivity_Status_ReturnsTypedSnapshot
//   api-system-connectivity/AC-09  TestAPI_SystemConnectivity_Status_Anonymous_Forbidden
//   api-fleet-connectivity-breakdown/AC-01..03  TestAPI_FleetConnectivity_Breakdown_ClassifiesByHysteresisBand
//   api-fleet-connectivity-breakdown/AC-05  TestAPI_FleetConnectivity_Breakdown_HighConsecDominates
//   api-fleet-connectivity-breakdown/AC-06  TestAPI_FleetConnectivity_Breakdown_EmptyFleet_ZeroNotError
//   api-fleet-connectivity-breakdown/AC-07  TestAPI_FleetConnectivity_Breakdown_Anonymous_Forbidden
//   api-host-connectivity-check/AC-03  TestAPI_HostConnectivity_Check_NotFound_Returns404
//   api-host-connectivity-check/AC-05  TestAPI_HostConnectivity_Check_MissingIdempotencyKey_Returns400

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/auth"
)

// ---------------------------------------------------------------------
// System connectivity config (GET / PUT)
// ---------------------------------------------------------------------

// AC-01: GET on a fresh DB returns the baked-in defaults + defaults
// sub-object equal to the same values.
// @ac AC-01
func TestAPI_SystemConnectivity_Config_GET_ReturnsDefaultsWhenEmpty(t *testing.T) {
	t.Run("api-system-connectivity/AC-01", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		req := asRole(t, "GET", url+"/api/v1/system/connectivity/config", auth.RoleViewer, nil)
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
		if got := body.Config["interval_sec"].(float64); got != 300 {
			t.Errorf("config.interval_sec: want 300, got %v", got)
		}
		if got := body.Defaults["unreachable_threshold"].(float64); got != 2 {
			t.Errorf("defaults.unreachable_threshold: want 2, got %v", got)
		}
	})
}

// AC-02: PUT with valid body persists; subsequent GET returns the same.
// @ac AC-02
func TestAPI_SystemConnectivity_Config_PUT_RoundTrip(t *testing.T) {
	t.Run("api-system-connectivity/AC-02", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := map[string]any{
			"interval_sec":          600,
			"timeout_sec":           10,
			"unreachable_threshold": 3,
			"rate_limit":            25,
			"maintenance_global":    false,
		}
		req := asRole(t, "PUT", url+"/api/v1/system/connectivity/config", auth.RoleAdmin, body)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("PUT: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 PUT, got %d", resp.StatusCode)
		}

		req2 := asRole(t, "GET", url+"/api/v1/system/connectivity/config", auth.RoleViewer, nil)
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
		if got := roundTrip.Config["interval_sec"].(float64); got != 600 {
			t.Errorf("interval_sec round-trip: want 600, got %v", got)
		}
	})
}

// AC-03: PUT below minimum rejects with 400 + field name.
// @ac AC-03
func TestAPI_SystemConnectivity_Config_PUT_RejectsBelowMinimum(t *testing.T) {
	t.Run("api-system-connectivity/AC-03", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := map[string]any{
			"interval_sec":          10, // below 60
			"timeout_sec":           5,
			"unreachable_threshold": 2,
			"rate_limit":            50,
			"maintenance_global":    false,
		}
		req := asRole(t, "PUT", url+"/api/v1/system/connectivity/config", auth.RoleAdmin, body)
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

// AC-04: PUT above maximum rejects with 400.
// @ac AC-04
func TestAPI_SystemConnectivity_Config_PUT_RejectsAboveMaximum(t *testing.T) {
	t.Run("api-system-connectivity/AC-04", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := map[string]any{
			"interval_sec":          99999, // above 86400
			"timeout_sec":           5,
			"unreachable_threshold": 2,
			"rate_limit":            50,
			"maintenance_global":    false,
		}
		req := asRole(t, "PUT", url+"/api/v1/system/connectivity/config", auth.RoleAdmin, body)
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

// AC-06: PUT as viewer (no system:config_write) returns 403.
// @ac AC-06
func TestAPI_SystemConnectivity_Config_PUT_AsViewer_Forbidden(t *testing.T) {
	t.Run("api-system-connectivity/AC-06", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := map[string]any{
			"interval_sec":          600,
			"timeout_sec":           5,
			"unreachable_threshold": 2,
			"rate_limit":            50,
			"maintenance_global":    false,
		}
		req := asRole(t, "PUT", url+"/api/v1/system/connectivity/config", auth.RoleViewer, body)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("PUT: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", resp.StatusCode)
		}
	})
}

// AC-07: PUT anonymous returns 403.
// @ac AC-07
func TestAPI_SystemConnectivity_Config_PUT_Anonymous_Forbidden(t *testing.T) {
	t.Run("api-system-connectivity/AC-07", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		req, _ := http.NewRequest("PUT", url+"/api/v1/system/connectivity/config", bytes.NewReader([]byte("{}")))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("PUT: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 anon, got %d", resp.StatusCode)
		}
	})
}

// AC-08: GET status returns the typed snapshot.
// @ac AC-08
func TestAPI_SystemConnectivity_Status_ReturnsTypedSnapshot(t *testing.T) {
	t.Run("api-system-connectivity/AC-08", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		req := asRole(t, "GET", url+"/api/v1/system/connectivity/status", auth.RoleViewer, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		var body struct {
			MaintenanceActive    bool `json:"maintenance_active"`
			ProbeCount           int  `json:"probe_count"`
			ProbeSuccessCount    int  `json:"probe_success_count"`
			ProbeFailureCount    int  `json:"probe_failure_count"`
			StateTransitionCount int  `json:"state_transition_count"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.MaintenanceActive {
			t.Errorf("expected maintenance_active=false, got true")
		}
	})
}

// AC-09: GET status anonymous returns 403.
// @ac AC-09
func TestAPI_SystemConnectivity_Status_Anonymous_Forbidden(t *testing.T) {
	t.Run("api-system-connectivity/AC-09", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		req, _ := http.NewRequest("GET", url+"/api/v1/system/connectivity/status", nil)
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

// ---------------------------------------------------------------------
// Fleet connectivity breakdown
// ---------------------------------------------------------------------

// AC-01..AC-03: classifies online vs degraded vs critical vs down vs
// never_probed based on consecutive_failures + reachability_status.
// @ac AC-02
func TestAPI_FleetConnectivity_Breakdown_ClassifiesByHysteresisBand(t *testing.T) {
	t.Run("api-fleet-connectivity-breakdown/AC-02", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		uid := firstSeededUserID(t, pool)

		// 5 hosts: 1 online, 1 degraded, 1 critical, 1 down, 1 never_probed.
		mkHost := func(label string) uuid.UUID {
			id, _ := uuid.NewV7()
			_, err := pool.Exec(context.Background(),
				`INSERT INTO hosts (id, hostname, ip_address, created_by)
				 VALUES ($1, $2, $3::inet, $4)`,
				id, "h-"+label+"-"+id.String(), "192.0.2.10", uid)
			if err != nil {
				t.Fatalf("seed host: %v", err)
			}
			return id
		}
		setLiveness := func(id uuid.UUID, status string, consec int) {
			_, err := pool.Exec(context.Background(),
				`INSERT INTO host_liveness (host_id, reachability_status, consecutive_failures, last_probe_at)
				 VALUES ($1, $2, $3, now())`,
				id, status, consec)
			if err != nil {
				t.Fatalf("seed liveness: %v", err)
			}
		}
		online := mkHost("online")
		degraded := mkHost("degraded")
		critical := mkHost("critical")
		down := mkHost("down")
		_ = mkHost("never") // never_probed: no host_liveness row
		setLiveness(online, "reachable", 0)
		setLiveness(degraded, "reachable", 1)
		setLiveness(critical, "unreachable", 2)
		setLiveness(down, "unreachable", 4)

		req := asRole(t, "GET", url+"/api/v1/fleet/connectivity/breakdown", auth.RoleViewer, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		var got struct {
			Online      int64 `json:"online"`
			Degraded    int64 `json:"degraded"`
			Critical    int64 `json:"critical"`
			Down        int64 `json:"down"`
			NeverProbed int64 `json:"never_probed"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.Online != 1 || got.Degraded != 1 || got.Critical != 1 || got.Down != 1 || got.NeverProbed != 1 {
			t.Errorf("breakdown mismatch: %+v", got)
		}
	})
}

// AC-05: a host with consecutive_failures>=3 lands in "down" regardless
// of reachability_status value.
// @ac AC-05
func TestAPI_FleetConnectivity_Breakdown_HighConsecDominates(t *testing.T) {
	t.Run("api-fleet-connectivity-breakdown/AC-05", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		uid := firstSeededUserID(t, pool)
		id, _ := uuid.NewV7()
		_, _ = pool.Exec(context.Background(),
			`INSERT INTO hosts (id, hostname, ip_address, created_by)
			 VALUES ($1, $2, $3::inet, $4)`,
			id, "h-"+id.String(), "192.0.2.10", uid)
		// reachable + consec=5 → still down, because consec>=3.
		_, _ = pool.Exec(context.Background(),
			`INSERT INTO host_liveness (host_id, reachability_status, consecutive_failures, last_probe_at)
			 VALUES ($1, 'reachable', 5, now())`, id)

		req := asRole(t, "GET", url+"/api/v1/fleet/connectivity/breakdown", auth.RoleViewer, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		var got struct {
			Online int64 `json:"online"`
			Down   int64 `json:"down"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&got)
		if got.Down != 1 || got.Online != 0 {
			t.Errorf("expected down=1 online=0, got %+v", got)
		}
	})
}

// AC-06: empty fleet returns all zeros, never an error.
// @ac AC-06
func TestAPI_FleetConnectivity_Breakdown_EmptyFleet_ZeroNotError(t *testing.T) {
	t.Run("api-fleet-connectivity-breakdown/AC-06", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		req := asRole(t, "GET", url+"/api/v1/fleet/connectivity/breakdown", auth.RoleViewer, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		var got struct {
			Online      int64 `json:"online"`
			Degraded    int64 `json:"degraded"`
			Critical    int64 `json:"critical"`
			Down        int64 `json:"down"`
			NeverProbed int64 `json:"never_probed"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&got)
		if got.Online != 0 || got.Degraded != 0 || got.Critical != 0 || got.Down != 0 || got.NeverProbed != 0 {
			t.Errorf("empty fleet should be all zeros, got %+v", got)
		}
	})
}

// AC-07: anonymous request returns 403.
// @ac AC-07
func TestAPI_FleetConnectivity_Breakdown_Anonymous_Forbidden(t *testing.T) {
	t.Run("api-fleet-connectivity-breakdown/AC-07", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		req, _ := http.NewRequest("GET", url+"/api/v1/fleet/connectivity/breakdown", nil)
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

// ---------------------------------------------------------------------
// Host on-demand connectivity check
// ---------------------------------------------------------------------

// AC-03: POST against {id} that doesn't exist returns 404.
// @ac AC-03
func TestAPI_HostConnectivity_Check_NotFound_Returns404(t *testing.T) {
	t.Run("api-host-connectivity-check/AC-03", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		missing, _ := uuid.NewV7()
		req := asRole(t, "POST", url+"/api/v1/hosts/"+missing.String()+"/connectivity:check", auth.RoleViewer, nil)
		req.Header.Set("Idempotency-Key", "test-key-"+missing.String())
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", resp.StatusCode)
		}
	})
}

// AC-05: POST without an Idempotency-Key header returns 400.
// @ac AC-05
func TestAPI_HostConnectivity_Check_MissingIdempotencyKey_Returns400(t *testing.T) {
	t.Run("api-host-connectivity-check/AC-05", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		uid := firstSeededUserID(t, pool)
		id, _ := uuid.NewV7()
		_, _ = pool.Exec(context.Background(),
			`INSERT INTO hosts (id, hostname, ip_address, created_by)
			 VALUES ($1, $2, $3::inet, $4)`,
			id, "h-"+id.String(), "192.0.2.10", uid)

		req := asRole(t, "POST", url+"/api/v1/hosts/"+id.String()+"/connectivity:check", auth.RoleViewer, nil)
		// Intentionally no Idempotency-Key.
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 for missing Idempotency-Key, got %d", resp.StatusCode)
		}
	})
}
