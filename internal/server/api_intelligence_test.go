// @spec api-os-intelligence
//
// AC traceability (this file):
//
//	AC-01  TestAPI_Intelligence_Events_ViewerCanList
//	AC-02  TestAPI_Intelligence_Events_Anonymous_Forbidden
//	AC-03  TestAPI_Intelligence_Events_LimitTooHigh_Returns400
//	AC-04  TestAPI_Intelligence_Events_FilterByHostAndCode
//	AC-05  TestAPI_Intelligence_Events_CursorPagination
//	AC-06  TestAPI_Intelligence_State_UnknownHost_Returns404
//	AC-07  TestAPI_Intelligence_State_NoSnapshotYet_Returns404
//	AC-08  TestAPI_Intelligence_State_WithSnapshot_Returns200
//	AC-09  TestAPI_Intelligence_Events_UnknownSeverity_Returns400
//	AC-10  TestAPI_Intelligence_Events_TimeRangeFilter

package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/server/api"
)

// seedIntelEvent inserts one host_intelligence_events row.
func seedIntelEvent(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, code, severity string, detectedAt time.Time) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO host_intelligence_events
		   (id, host_id, event_code, severity, detail, occurred_at, detected_at, correlation_id)
		 VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, 'seed-corr')`,
		id, hostID, code, severity, []byte(`{"sample":"detail"}`), detectedAt, detectedAt)
	if err != nil {
		t.Fatalf("seed intel event: %v", err)
	}
	return id
}

func seedIntelState(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, snapshot map[string]any, collectedAt time.Time) {
	t.Helper()
	raw, _ := json.Marshal(snapshot)
	_, err := pool.Exec(context.Background(),
		`INSERT INTO host_intelligence_state (host_id, snapshot, collected_at, created_at, updated_at)
		 VALUES ($1, $2::jsonb, $3, now(), now())
		 ON CONFLICT (host_id) DO UPDATE SET snapshot = EXCLUDED.snapshot, collected_at = EXCLUDED.collected_at`,
		hostID, raw, collectedAt)
	if err != nil {
		t.Fatalf("seed intel state: %v", err)
	}
}

func seedHostForIntel(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	creator := firstSeededUserID(t, pool)
	id, _ := uuid.NewV7()
	// Use the full id in the hostname — UUIDv7's leading bytes are a
	// millisecond timestamp, so id.String()[:8] would collide when two
	// hosts are seeded in the same ms (idx_hosts_hostname_environment_active
	// UNIQUE breaks).
	_, err := pool.Exec(context.Background(),
		`INSERT INTO hosts (id, hostname, ip_address, created_by)
		 VALUES ($1, $2, $3::inet, $4)`,
		id, "intel-"+id.String(), "192.0.2.30", creator)
	if err != nil {
		t.Fatalf("seed host: %v", err)
	}
	return id
}

// @ac AC-01
func TestAPI_Intelligence_Events_ViewerCanList(t *testing.T) {
	t.Run("api-os-intelligence/AC-01", func(t *testing.T) {
		srv, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)
		seedIntelEvent(t, pool, hostID, "system.package.updated", "info",
			time.Now().UTC().Add(-1*time.Minute))

		req := asRole(t, "GET", srv+"/api/v1/intelligence/events", auth.RoleViewer, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
		}
		var page api.IntelligenceEventsPage
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(page.Items) == 0 {
			t.Errorf("expected at least one item")
		}
	})
}

// @ac AC-02
func TestAPI_Intelligence_Events_Anonymous_Forbidden(t *testing.T) {
	t.Run("api-os-intelligence/AC-02", func(t *testing.T) {
		srv, _ := freshAPIServer(t)
		req, _ := http.NewRequest("GET", srv+"/api/v1/intelligence/events", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401 anon, got %d", resp.StatusCode)
		}
	})
}

// @ac AC-03
func TestAPI_Intelligence_Events_LimitTooHigh_Returns400(t *testing.T) {
	t.Run("api-os-intelligence/AC-03", func(t *testing.T) {
		srv, _ := freshAPIServer(t)
		req := asRole(t, "GET", srv+"/api/v1/intelligence/events?limit=300", auth.RoleViewer, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", resp.StatusCode)
		}
	})
}

// @ac AC-04
func TestAPI_Intelligence_Events_FilterByHostAndCode(t *testing.T) {
	t.Run("api-os-intelligence/AC-04", func(t *testing.T) {
		srv, pool := freshAPIServer(t)
		hostA := seedHostForIntel(t, pool)
		hostB := seedHostForIntel(t, pool)
		base := time.Now().UTC().Add(-5 * time.Minute)
		seedIntelEvent(t, pool, hostA, "system.package.updated", "info", base)
		seedIntelEvent(t, pool, hostA, "security.port.opened", "high", base.Add(time.Second))
		seedIntelEvent(t, pool, hostB, "system.package.updated", "info", base.Add(2*time.Second))

		q := url.Values{}
		q.Set("host_id", hostA.String())
		q.Set("event_code", "system.package.updated")
		req := asRole(t, "GET", srv+"/api/v1/intelligence/events?"+q.Encode(),
			auth.RoleViewer, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, b)
		}
		var page api.IntelligenceEventsPage
		_ = json.NewDecoder(resp.Body).Decode(&page)
		if len(page.Items) != 1 {
			t.Errorf("expected 1 filtered item, got %d", len(page.Items))
		}
		if len(page.Items) > 0 && page.Items[0].EventCode != "system.package.updated" {
			t.Errorf("filter leak: event_code=%q", page.Items[0].EventCode)
		}
	})
}

// @ac AC-05
func TestAPI_Intelligence_Events_CursorPagination(t *testing.T) {
	t.Run("api-os-intelligence/AC-05", func(t *testing.T) {
		srv, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)
		base := time.Now().UTC().Add(-1 * time.Hour)
		for i := 0; i < 5; i++ {
			seedIntelEvent(t, pool, hostID, "system.package.updated", "info",
				base.Add(time.Duration(i)*time.Minute))
		}

		req := asRole(t, "GET", srv+"/api/v1/intelligence/events?limit=2", auth.RoleViewer, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET page1: %v", err)
		}
		defer resp.Body.Close()
		var page1 api.IntelligenceEventsPage
		_ = json.NewDecoder(resp.Body).Decode(&page1)
		if len(page1.Items) != 2 {
			t.Fatalf("page1 items=%d, want 2", len(page1.Items))
		}
		if page1.NextCursor == nil || *page1.NextCursor == "" {
			t.Fatalf("page1 next_cursor missing")
		}

		q := url.Values{}
		q.Set("limit", "2")
		q.Set("cursor", *page1.NextCursor)
		req2 := asRole(t, "GET", srv+"/api/v1/intelligence/events?"+q.Encode(),
			auth.RoleViewer, nil)
		resp2, err := http.DefaultClient.Do(req2)
		if err != nil {
			t.Fatalf("GET page2: %v", err)
		}
		defer resp2.Body.Close()
		var page2 api.IntelligenceEventsPage
		_ = json.NewDecoder(resp2.Body).Decode(&page2)
		if len(page2.Items) != 2 {
			t.Errorf("page2 items=%d, want 2", len(page2.Items))
		}
	})
}

// @ac AC-06
func TestAPI_Intelligence_State_UnknownHost_Returns404(t *testing.T) {
	t.Run("api-os-intelligence/AC-06", func(t *testing.T) {
		srv, _ := freshAPIServer(t)
		missing, _ := uuid.NewV7()
		req := asRole(t, "GET", srv+"/api/v1/intelligence/state/"+missing.String(),
			auth.RoleAdmin, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected 404, got %d", resp.StatusCode)
		}
	})
}

// @ac AC-07
func TestAPI_Intelligence_State_NoSnapshotYet_Returns404(t *testing.T) {
	t.Run("api-os-intelligence/AC-07", func(t *testing.T) {
		srv, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)
		req := asRole(t, "GET", srv+"/api/v1/intelligence/state/"+hostID.String(),
			auth.RoleAdmin, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected 404 (no snapshot yet), got %d", resp.StatusCode)
		}
		var env api.ErrorEnvelope
		_ = json.NewDecoder(resp.Body).Decode(&env)
		if env.Error.Code != "hosts.not_found" {
			t.Errorf("error.code=%q, want hosts.not_found", env.Error.Code)
		}
	})
}

// @ac AC-08
func TestAPI_Intelligence_State_WithSnapshot_Returns200(t *testing.T) {
	t.Run("api-os-intelligence/AC-08", func(t *testing.T) {
		srv, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)
		collected := time.Now().UTC().Add(-1 * time.Minute).Truncate(time.Microsecond)
		seedIntelState(t, pool, hostID, map[string]any{
			"kernel_release": "5.14.0-test",
			"packages":       map[string]any{"openssh": "9.0"},
		}, collected)

		req := asRole(t, "GET", srv+"/api/v1/intelligence/state/"+hostID.String(),
			auth.RoleAdmin, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, b)
		}
		var state api.IntelligenceState
		if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if state.Snapshot == nil {
			t.Errorf("snapshot is nil")
		} else if state.Snapshot["kernel_release"] != "5.14.0-test" {
			t.Errorf("snapshot.kernel_release=%v", state.Snapshot["kernel_release"])
		}
	})
}

// @ac AC-09
func TestAPI_Intelligence_Events_UnknownSeverity_Returns400(t *testing.T) {
	t.Run("api-os-intelligence/AC-09", func(t *testing.T) {
		srv, _ := freshAPIServer(t)
		req := asRole(t, "GET",
			srv+"/api/v1/intelligence/events?severity=panic", auth.RoleViewer, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		// oapi-codegen's request-validator rejects out-of-enum BEFORE
		// the handler runs; either path returns 400.
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", resp.StatusCode)
		}
	})
}

// @ac AC-10
func TestAPI_Intelligence_Events_TimeRangeFilter(t *testing.T) {
	t.Run("api-os-intelligence/AC-10", func(t *testing.T) {
		srv, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)
		base := time.Now().UTC().Add(-1 * time.Hour).Truncate(time.Second)
		seedIntelEvent(t, pool, hostID, "system.package.updated", "info", base)
		seedIntelEvent(t, pool, hostID, "system.package.updated", "info", base.Add(30*time.Minute))
		seedIntelEvent(t, pool, hostID, "system.package.updated", "info", base.Add(50*time.Minute))

		q := url.Values{}
		q.Set("since", base.Add(20*time.Minute).Format(time.RFC3339Nano))
		q.Set("until", base.Add(40*time.Minute).Format(time.RFC3339Nano))
		req := asRole(t, "GET",
			srv+"/api/v1/intelligence/events?"+q.Encode(), auth.RoleViewer, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		var page api.IntelligenceEventsPage
		_ = json.NewDecoder(resp.Body).Decode(&page)
		if len(page.Items) != 1 {
			t.Errorf("time-range filter returned %d items, want 1", len(page.Items))
		}
	})
}
