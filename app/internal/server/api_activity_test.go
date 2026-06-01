// @spec api-activity
//
// AC traceability (this file):
//
//	AC-01  TestAPI_Activity_ViewerCanList
//	AC-02  TestAPI_Activity_Anonymous_Forbidden
//	AC-03  TestAPI_Activity_LimitTooHigh_400
//	AC-04  TestAPI_Activity_SourceFilter
//	AC-05  TestAPI_Activity_UnknownSeverity_400
//	AC-06  TestAPI_Activity_UnknownSource_400
//	AC-07  TestAPI_Activity_CursorPagination
//	AC-08  TestAPI_Activity_AdminSeesAll
//	AC-09  TestAPI_Activity_Viewer_PartialFleet
//	AC-10  TestAPI_Activity_TimeRangeFilter

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

	"github.com/Hanalyx/openwatch/internal/alertrouter"
	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/server/api"
)

// seedAllForActivity inserts one row per source for the activity tests.
func seedAllForActivity(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, base time.Time) {
	t.Helper()
	store := alertrouter.NewPgxStore(pool)
	_, err := store.Insert(context.Background(), alertrouter.Alert{
		Type: alertrouter.AlertTypeHostUnreachable, Severity: alertrouter.SeverityHigh,
		HostID: hostID, OccurredAt: base.Add(-3 * time.Minute),
		Title: "alert seed", Tags: map[string]string{"severity": "high"},
	})
	if err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	txnID, _ := uuid.NewV7()
	scanID, _ := uuid.NewV7()
	_, err = pool.Exec(context.Background(),
		`INSERT INTO transactions (id, host_id, rule_id, scan_id, status, severity,
		                           change_kind, evidence, framework_refs, occurred_at)
		 VALUES ($1, $2, $3, $4, 'fail', 'medium', 'state_changed', '{}'::jsonb, '{}'::jsonb, $5)`,
		txnID, hostID, "rule-xyz", scanID, base.Add(-2*time.Minute))
	if err != nil {
		t.Fatalf("seed txn: %v", err)
	}
	intelID, _ := uuid.NewV7()
	_, err = pool.Exec(context.Background(),
		`INSERT INTO host_intelligence_events
		   (id, host_id, event_code, severity, detail, occurred_at, detected_at, correlation_id)
		 VALUES ($1, $2, 'system.package.updated', 'medium', '{}'::jsonb, $3, $3, 'seed-corr')`,
		intelID, hostID, base.Add(-1*time.Minute))
	if err != nil {
		t.Fatalf("seed intel: %v", err)
	}
	auditID, _ := uuid.NewV7()
	_, err = pool.Exec(context.Background(),
		`INSERT INTO audit_events (id, correlation_id, actor_type, action, severity, occurred_at, detail)
		 VALUES ($1, 'seed-corr', 'user', 'auth.login.success', 'info', $2, '{}'::jsonb)`,
		auditID, base.Add(-30*time.Second))
	if err != nil {
		t.Fatalf("seed audit: %v", err)
	}
}

// @ac AC-01
func TestAPI_Activity_ViewerCanList(t *testing.T) {
	t.Run("api-activity/AC-01", func(t *testing.T) {
		srv, pool := freshAPIServer(t)
		host := seedHostForIntel(t, pool)
		seedAllForActivity(t, pool, host, time.Now().UTC())
		req := asRole(t, "GET", srv+"/api/v1/activity", auth.RoleViewer, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status=%d body=%s", resp.StatusCode, b)
		}
		var page api.ActivityPage
		_ = json.NewDecoder(resp.Body).Decode(&page)
		// Viewer has host:read but lacks alert:read + audit:read in
		// the default RBAC matrix — so it sees transactions + intel
		// (2 items) and hidden_count = 2 (alert + audit).
		if len(page.Items) < 1 {
			t.Errorf("expected at least one item, got %d", len(page.Items))
		}
	})
}

// @ac AC-02
func TestAPI_Activity_Anonymous_Forbidden(t *testing.T) {
	t.Run("api-activity/AC-02", func(t *testing.T) {
		srv, _ := freshAPIServer(t)
		req, _ := http.NewRequest("GET", srv+"/api/v1/activity", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status=%d, want 403", resp.StatusCode)
		}
	})
}

// @ac AC-03
func TestAPI_Activity_LimitTooHigh_400(t *testing.T) {
	t.Run("api-activity/AC-03", func(t *testing.T) {
		srv, _ := freshAPIServer(t)
		req := asRole(t, "GET", srv+"/api/v1/activity?limit=300", auth.RoleViewer, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status=%d, want 400", resp.StatusCode)
		}
	})
}

// @ac AC-04
func TestAPI_Activity_SourceFilter(t *testing.T) {
	t.Run("api-activity/AC-04", func(t *testing.T) {
		srv, pool := freshAPIServer(t)
		host := seedHostForIntel(t, pool)
		seedAllForActivity(t, pool, host, time.Now().UTC())

		req := asRole(t, "GET", srv+"/api/v1/activity?source=alert", auth.RoleAdmin, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		var page api.ActivityPage
		_ = json.NewDecoder(resp.Body).Decode(&page)
		for _, it := range page.Items {
			if it.Source != "alert" {
				t.Errorf("item.source=%q, want alert", it.Source)
			}
		}
	})
}

// @ac AC-05
func TestAPI_Activity_UnknownSeverity_400(t *testing.T) {
	t.Run("api-activity/AC-05", func(t *testing.T) {
		srv, _ := freshAPIServer(t)
		req := asRole(t, "GET", srv+"/api/v1/activity?severity=panic", auth.RoleViewer, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status=%d, want 400", resp.StatusCode)
		}
	})
}

// @ac AC-06
func TestAPI_Activity_UnknownSource_400(t *testing.T) {
	t.Run("api-activity/AC-06", func(t *testing.T) {
		srv, _ := freshAPIServer(t)
		req := asRole(t, "GET", srv+"/api/v1/activity?source=zombie", auth.RoleViewer, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status=%d, want 400", resp.StatusCode)
		}
	})
}

// @ac AC-07
func TestAPI_Activity_CursorPagination(t *testing.T) {
	t.Run("api-activity/AC-07", func(t *testing.T) {
		srv, pool := freshAPIServer(t)
		host := seedHostForIntel(t, pool)
		base := time.Now().UTC()
		// 4 alerts as the candidate set.
		store := alertrouter.NewPgxStore(pool)
		for i := 0; i < 4; i++ {
			_, err := store.Insert(context.Background(), alertrouter.Alert{
				Type: alertrouter.AlertTypeDriftMinor, Severity: alertrouter.SeverityLow,
				HostID: host, OccurredAt: base.Add(-time.Duration(i) * time.Minute),
				Title: "drift",
			})
			if err != nil {
				t.Fatalf("seed alert %d: %v", i, err)
			}
		}

		req := asRole(t, "GET", srv+"/api/v1/activity?limit=2", auth.RoleAdmin, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		var p1 api.ActivityPage
		_ = json.NewDecoder(resp.Body).Decode(&p1)
		if len(p1.Items) != 2 || p1.NextCursor == nil {
			t.Fatalf("page1 items=%d cursor=%v", len(p1.Items), p1.NextCursor)
		}

		q := url.Values{}
		q.Set("limit", "2")
		q.Set("cursor", *p1.NextCursor)
		req2 := asRole(t, "GET", srv+"/api/v1/activity?"+q.Encode(), auth.RoleAdmin, nil)
		resp2, err := http.DefaultClient.Do(req2)
		if err != nil {
			t.Fatalf("GET2: %v", err)
		}
		defer resp2.Body.Close()
		var p2 api.ActivityPage
		_ = json.NewDecoder(resp2.Body).Decode(&p2)
		if len(p2.Items) != 2 {
			t.Errorf("page2 items=%d, want 2", len(p2.Items))
		}
		if p2.NextCursor != nil {
			t.Errorf("page2 cursor=%v, want nil (terminal)", *p2.NextCursor)
		}
	})
}

// @ac AC-08
func TestAPI_Activity_AdminSeesAll(t *testing.T) {
	t.Run("api-activity/AC-08", func(t *testing.T) {
		srv, pool := freshAPIServer(t)
		host := seedHostForIntel(t, pool)
		seedAllForActivity(t, pool, host, time.Now().UTC())

		req := asRole(t, "GET", srv+"/api/v1/activity", auth.RoleAdmin, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		var page api.ActivityPage
		_ = json.NewDecoder(resp.Body).Decode(&page)
		// Admin has alert:read + host:read + audit:read — all 4 visible,
		// hidden_count = 0.
		if len(page.Items) < 4 {
			t.Errorf("admin items=%d, want >= 4", len(page.Items))
		}
		if page.HiddenCount != 0 {
			t.Errorf("admin hidden_count=%d, want 0", page.HiddenCount)
		}
	})
}

// @ac AC-09
func TestAPI_Activity_Viewer_PartialFleet(t *testing.T) {
	t.Run("api-activity/AC-09", func(t *testing.T) {
		srv, pool := freshAPIServer(t)
		host := seedHostForIntel(t, pool)
		seedAllForActivity(t, pool, host, time.Now().UTC())

		req := asRole(t, "GET", srv+"/api/v1/activity", auth.RoleViewer, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		var page api.ActivityPage
		_ = json.NewDecoder(resp.Body).Decode(&page)
		// Viewer has host:read only — sees transactions + intelligence,
		// hidden_count covers alerts + audit (count depends on what
		// auth seeded; just assert non-zero).
		if page.HiddenCount == 0 {
			t.Errorf("viewer hidden_count=0, want > 0 (alerts + audit suppressed)")
		}
	})
}

// @ac AC-10
func TestAPI_Activity_TimeRangeFilter(t *testing.T) {
	t.Run("api-activity/AC-10", func(t *testing.T) {
		srv, pool := freshAPIServer(t)
		host := seedHostForIntel(t, pool)
		base := time.Now().UTC()
		seedAllForActivity(t, pool, host, base)

		since := base.Add(-2*time.Minute - 30*time.Second).Format(time.RFC3339Nano)
		until := base.Add(-45 * time.Second).Format(time.RFC3339Nano)
		q := url.Values{}
		q.Set("since", since)
		q.Set("until", until)
		req := asRole(t, "GET", srv+"/api/v1/activity?"+q.Encode(), auth.RoleAdmin, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		var page api.ActivityPage
		_ = json.NewDecoder(resp.Body).Decode(&page)
		// In window: txn (-2m), intel (-1m). Outside: alert, audit.
		if len(page.Items) != 2 {
			t.Errorf("items=%d, want 2 (txn + intel in window)", len(page.Items))
		}
	})
}
