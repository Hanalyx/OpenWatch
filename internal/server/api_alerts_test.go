// @spec api-alerts
//
// AC traceability (this file):
//
//	AC-01  TestAPI_Alerts_List_ViewerCanRead
//	AC-02  TestAPI_Alerts_List_Anonymous_Forbidden
//	AC-03  TestAPI_Alerts_List_LimitTooHigh_400
//	AC-04  TestAPI_Alerts_List_FilterByStateHostSeverity
//	AC-05  TestAPI_Alerts_List_CursorPagination
//	AC-06  TestAPI_Alerts_Acknowledge_Success
//	AC-07  TestAPI_Alerts_Acknowledge_Viewer_403
//	AC-08  TestAPI_Alerts_Acknowledge_Unknown_404
//	AC-09  TestAPI_Alerts_Acknowledge_OnResolved_409
//	AC-10  TestAPI_Alerts_Silence_PastUntil_400
//	AC-11  TestAPI_Alerts_Silence_NoBody_Indefinite_200
//	AC-12  TestAPI_Alerts_Resolve_Then_Conflict
//	AC-13  TestAPI_Alerts_Dismiss_Then_Conflict
//	AC-14  TestAPI_Alerts_List_UnknownSeverity_400
//	AC-15  TestAPI_Alerts_List_UnknownState_400

package server

import (
	"context"
	"encoding/json"
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

func seedAlertRow(t *testing.T, pool *pgxpool.Pool, atype alertrouter.AlertType, sev alertrouter.Severity, hostID uuid.UUID, occurredAt time.Time) uuid.UUID {
	t.Helper()
	store := alertrouter.NewPgxStore(pool)
	a := alertrouter.Alert{
		Type:       atype,
		Severity:   sev,
		HostID:     hostID,
		OccurredAt: occurredAt,
		Title:      string(atype) + " seed",
		Body:       "test body",
		Tags:       map[string]string{"severity": string(sev)},
	}
	id, err := store.Insert(context.Background(), a)
	if err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	return id
}

// @ac AC-01
func TestAPI_Alerts_List_ViewerCanRead(t *testing.T) {
	t.Run("api-alerts/AC-01", func(t *testing.T) {
		srv, pool := freshAPIServer(t)
		seedAlertRow(t, pool, alertrouter.AlertTypeHostUnreachable,
			alertrouter.SeverityHigh, uuid.Nil, time.Now().UTC().Add(-1*time.Minute))

		req := asRole(t, "GET", srv+"/api/v1/alerts", auth.RoleViewer, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status=%d, want 200", resp.StatusCode)
		}
		var page api.AlertsPage
		_ = json.NewDecoder(resp.Body).Decode(&page)
		if len(page.Items) == 0 {
			t.Errorf("expected at least one alert")
		}
	})
}

// @ac AC-02
func TestAPI_Alerts_List_Anonymous_Forbidden(t *testing.T) {
	t.Run("api-alerts/AC-02", func(t *testing.T) {
		srv, _ := freshAPIServer(t)
		req, _ := http.NewRequest("GET", srv+"/api/v1/alerts", nil)
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
func TestAPI_Alerts_List_LimitTooHigh_400(t *testing.T) {
	t.Run("api-alerts/AC-03", func(t *testing.T) {
		srv, _ := freshAPIServer(t)
		req := asRole(t, "GET", srv+"/api/v1/alerts?limit=300", auth.RoleViewer, nil)
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
func TestAPI_Alerts_List_FilterByStateHostSeverity(t *testing.T) {
	t.Run("api-alerts/AC-04", func(t *testing.T) {
		srv, pool := freshAPIServer(t)
		h1 := seedHostForIntel(t, pool)
		h2 := seedHostForIntel(t, pool)
		now := time.Now().UTC()
		seedAlertRow(t, pool, alertrouter.AlertTypeHostUnreachable, alertrouter.SeverityHigh, h1, now.Add(-3*time.Minute))
		seedAlertRow(t, pool, alertrouter.AlertTypeHostUnreachable, alertrouter.SeverityMedium, h1, now.Add(-2*time.Minute))
		seedAlertRow(t, pool, alertrouter.AlertTypeHostUnreachable, alertrouter.SeverityHigh, h2, now.Add(-1*time.Minute))

		q := url.Values{}
		q.Set("state", "active")
		q.Set("host_id", h1.String())
		q.Set("severity", "high")
		req := asRole(t, "GET", srv+"/api/v1/alerts?"+q.Encode(), auth.RoleViewer, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer resp.Body.Close()
		var page api.AlertsPage
		_ = json.NewDecoder(resp.Body).Decode(&page)
		if len(page.Items) != 1 {
			t.Errorf("expected 1 filtered item, got %d", len(page.Items))
		}
	})
}

// @ac AC-05
func TestAPI_Alerts_List_CursorPagination(t *testing.T) {
	t.Run("api-alerts/AC-05", func(t *testing.T) {
		srv, pool := freshAPIServer(t)
		base := time.Now().UTC().Add(-1 * time.Hour)
		for i := 0; i < 5; i++ {
			seedAlertRow(t, pool, alertrouter.AlertTypeDriftMinor,
				alertrouter.SeverityLow, uuid.Nil, base.Add(time.Duration(i)*time.Minute))
		}
		req := asRole(t, "GET", srv+"/api/v1/alerts?limit=2", auth.RoleViewer, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer resp.Body.Close()
		var p1 api.AlertsPage
		_ = json.NewDecoder(resp.Body).Decode(&p1)
		if len(p1.Items) != 2 || p1.NextCursor == nil {
			t.Fatalf("page1 items=%d cursor=%v", len(p1.Items), p1.NextCursor)
		}

		q := url.Values{}
		q.Set("limit", "2")
		q.Set("cursor", *p1.NextCursor)
		req2 := asRole(t, "GET", srv+"/api/v1/alerts?"+q.Encode(), auth.RoleViewer, nil)
		resp2, err := http.DefaultClient.Do(req2)
		if err != nil {
			t.Fatalf("Do2: %v", err)
		}
		defer resp2.Body.Close()
		var p2 api.AlertsPage
		_ = json.NewDecoder(resp2.Body).Decode(&p2)
		if len(p2.Items) != 2 {
			t.Errorf("page2 items=%d, want 2", len(p2.Items))
		}
	})
}

// @ac AC-06
func TestAPI_Alerts_Acknowledge_Success(t *testing.T) {
	t.Run("api-alerts/AC-06", func(t *testing.T) {
		srv, pool := freshAPIServer(t)
		id := seedAlertRow(t, pool, alertrouter.AlertTypeHostUnreachable,
			alertrouter.SeverityHigh, uuid.Nil, time.Now().UTC())
		req := asRole(t, "POST", srv+"/api/v1/alerts/"+id.String()+":acknowledge",
			auth.RoleAdmin, map[string]any{"reason": "saw it"})
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status=%d, want 200", resp.StatusCode)
		}
		var a api.Alert
		_ = json.NewDecoder(resp.Body).Decode(&a)
		if a.State != "acknowledged" {
			t.Errorf("state=%q, want acknowledged", a.State)
		}
	})
}

// @ac AC-07
func TestAPI_Alerts_Acknowledge_Viewer_403(t *testing.T) {
	t.Run("api-alerts/AC-07", func(t *testing.T) {
		srv, pool := freshAPIServer(t)
		id := seedAlertRow(t, pool, alertrouter.AlertTypeHostUnreachable,
			alertrouter.SeverityHigh, uuid.Nil, time.Now().UTC())
		req := asRole(t, "POST", srv+"/api/v1/alerts/"+id.String()+":acknowledge",
			auth.RoleViewer, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status=%d, want 403", resp.StatusCode)
		}
	})
}

// @ac AC-08
func TestAPI_Alerts_Acknowledge_Unknown_404(t *testing.T) {
	t.Run("api-alerts/AC-08", func(t *testing.T) {
		srv, _ := freshAPIServer(t)
		missing, _ := uuid.NewV7()
		req := asRole(t, "POST", srv+"/api/v1/alerts/"+missing.String()+":acknowledge",
			auth.RoleAdmin, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("status=%d, want 404", resp.StatusCode)
		}
	})
}

// @ac AC-09
func TestAPI_Alerts_Acknowledge_OnResolved_409(t *testing.T) {
	t.Run("api-alerts/AC-09", func(t *testing.T) {
		srv, pool := freshAPIServer(t)
		id := seedAlertRow(t, pool, alertrouter.AlertTypeHostUnreachable,
			alertrouter.SeverityHigh, uuid.Nil, time.Now().UTC())
		req := asRole(t, "POST", srv+"/api/v1/alerts/"+id.String()+":resolve",
			auth.RoleAdmin, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		_ = resp.Body.Close()

		req2 := asRole(t, "POST", srv+"/api/v1/alerts/"+id.String()+":acknowledge",
			auth.RoleAdmin, nil)
		resp2, err := http.DefaultClient.Do(req2)
		if err != nil {
			t.Fatalf("Do2: %v", err)
		}
		defer resp2.Body.Close()
		if resp2.StatusCode != http.StatusConflict {
			t.Errorf("status=%d, want 409", resp2.StatusCode)
		}
	})
}

// @ac AC-10
func TestAPI_Alerts_Silence_PastUntil_400(t *testing.T) {
	t.Run("api-alerts/AC-10", func(t *testing.T) {
		srv, pool := freshAPIServer(t)
		id := seedAlertRow(t, pool, alertrouter.AlertTypeDriftMinor,
			alertrouter.SeverityMedium, uuid.Nil, time.Now().UTC())
		past := time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339Nano)
		req := asRole(t, "POST", srv+"/api/v1/alerts/"+id.String()+":silence",
			auth.RoleAdmin, map[string]any{"until": past})
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status=%d, want 400", resp.StatusCode)
		}
	})
}

// @ac AC-11
func TestAPI_Alerts_Silence_NoBody_Indefinite_200(t *testing.T) {
	t.Run("api-alerts/AC-11", func(t *testing.T) {
		srv, pool := freshAPIServer(t)
		id := seedAlertRow(t, pool, alertrouter.AlertTypeDriftMinor,
			alertrouter.SeverityLow, uuid.Nil, time.Now().UTC())
		req := asRole(t, "POST", srv+"/api/v1/alerts/"+id.String()+":silence",
			auth.RoleAdmin, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status=%d, want 200", resp.StatusCode)
		}
		var a api.Alert
		_ = json.NewDecoder(resp.Body).Decode(&a)
		if a.State != "silenced" {
			t.Errorf("state=%q, want silenced", a.State)
		}
		if a.SilencedUntil != nil {
			t.Errorf("silenced_until=%v, want null (indefinite)", a.SilencedUntil)
		}
	})
}

// @ac AC-12
func TestAPI_Alerts_Resolve_Then_Conflict(t *testing.T) {
	t.Run("api-alerts/AC-12", func(t *testing.T) {
		srv, pool := freshAPIServer(t)
		id := seedAlertRow(t, pool, alertrouter.AlertTypeHostUnreachable,
			alertrouter.SeverityHigh, uuid.Nil, time.Now().UTC())
		req := asRole(t, "POST", srv+"/api/v1/alerts/"+id.String()+":resolve",
			auth.RoleAdmin, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("first resolve status=%d, want 200", resp.StatusCode)
		}
		req2 := asRole(t, "POST", srv+"/api/v1/alerts/"+id.String()+":resolve",
			auth.RoleAdmin, nil)
		resp2, err := http.DefaultClient.Do(req2)
		if err != nil {
			t.Fatalf("Do2: %v", err)
		}
		defer resp2.Body.Close()
		if resp2.StatusCode != http.StatusConflict {
			t.Errorf("repeat resolve status=%d, want 409", resp2.StatusCode)
		}
	})
}

// @ac AC-13
func TestAPI_Alerts_Dismiss_Then_Conflict(t *testing.T) {
	t.Run("api-alerts/AC-13", func(t *testing.T) {
		srv, pool := freshAPIServer(t)
		id := seedAlertRow(t, pool, alertrouter.AlertTypeDriftMinor,
			alertrouter.SeverityLow, uuid.Nil, time.Now().UTC())
		req := asRole(t, "POST", srv+"/api/v1/alerts/"+id.String()+":dismiss",
			auth.RoleAdmin, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("first dismiss status=%d, want 200", resp.StatusCode)
		}
		req2 := asRole(t, "POST", srv+"/api/v1/alerts/"+id.String()+":dismiss",
			auth.RoleAdmin, nil)
		resp2, err := http.DefaultClient.Do(req2)
		if err != nil {
			t.Fatalf("Do2: %v", err)
		}
		defer resp2.Body.Close()
		if resp2.StatusCode != http.StatusConflict {
			t.Errorf("repeat dismiss status=%d, want 409", resp2.StatusCode)
		}
	})
}

// @ac AC-14
func TestAPI_Alerts_List_UnknownSeverity_400(t *testing.T) {
	t.Run("api-alerts/AC-14", func(t *testing.T) {
		srv, _ := freshAPIServer(t)
		req := asRole(t, "GET", srv+"/api/v1/alerts?severity=panic", auth.RoleViewer, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status=%d, want 400", resp.StatusCode)
		}
	})
}

// @ac AC-15
func TestAPI_Alerts_List_UnknownState_400(t *testing.T) {
	t.Run("api-alerts/AC-15", func(t *testing.T) {
		srv, _ := freshAPIServer(t)
		req := asRole(t, "GET", srv+"/api/v1/alerts?state=zombie", auth.RoleViewer, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status=%d, want 400", resp.StatusCode)
		}
	})
}
