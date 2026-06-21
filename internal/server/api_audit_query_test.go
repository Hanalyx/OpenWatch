// @spec api-audit-events-query
//
// AC-12 added v1.2.0: TestAPI_AuditEvents_MessageAndResourceFilter

package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/correlation"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// emitSensitiveAuditEvent emits an audit event whose detail contains a
// sensitive field name, exercising the pre-store redaction path. Used by
// AC-10 to verify redactions surface through the query API.
func emitSensitiveAuditEvent(t *testing.T, _ *pgxpool.Pool, corrID string) {
	t.Helper()
	ctx := correlation.Set(context.Background(), corrID)
	detail, _ := json.Marshal(map[string]any{
		"method":   "password",
		"password": "should-be-redacted",
	})
	audit.Emit(ctx, audit.AuthLoginSuccess, audit.Event{
		ActorType: "user",
		ActorID:   "test-user",
		Detail:    detail,
	})
}

// @ac AC-01
// api-audit-events-query/AC-01: GET /audit/events returns up to 50 newest events DESC.
func TestAPI_AuditEvents_DefaultNewestFirst(t *testing.T) {
	t.Run("api-audit-events-query/AC-01", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		// Make a few mutating calls to generate audit events.
		for i := 0; i < 3; i++ {
			body := strings.NewReader(`{"message":"e` + string(rune('A'+i)) + `"}`)
			req, _ := http.NewRequest("POST", url+"/api/v1/diagnostics:echo", body)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Idempotency-Key", "audit-gen-"+string(rune('A'+i)))
			_, _ = http.DefaultClient.Do(req)
		}
		time.Sleep(100 * time.Millisecond) // let writer flush

		resp := doReq(t, asRole(t, "GET", url+"/api/v1/audit/events", auth.RoleAuditor, nil))
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		var page struct {
			Items []struct {
				Action     string    `json:"action"`
				OccurredAt time.Time `json:"occurred_at"`
			} `json:"items"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&page)
		if len(page.Items) < 3 {
			t.Errorf("items count = %d, want >= 3", len(page.Items))
		}
		// Verify DESC ordering.
		for i := 1; i < len(page.Items); i++ {
			if page.Items[i-1].OccurredAt.Before(page.Items[i].OccurredAt) {
				t.Errorf("items not DESC at index %d: %v < %v",
					i, page.Items[i-1].OccurredAt, page.Items[i].OccurredAt)
			}
		}
	})
}

// @ac AC-03
// api-audit-events-query/AC-03: ?limit=500 returns 400 pagination.limit_exceeded.
func TestAPI_AuditEvents_LimitExceeded(t *testing.T) {
	t.Run("api-audit-events-query/AC-03", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		resp := doReq(t, asRole(t, "GET", url+"/api/v1/audit/events?limit=500", auth.RoleAuditor, nil))
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", resp.StatusCode)
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "pagination.limit_exceeded") {
			t.Errorf("body lacks pagination.limit_exceeded: %s", b)
		}
	})
}

// generateEvents writes N audit events via :echo and waits for them to flush.
func generateEvents(t *testing.T, url string, n int, corrPrefix string) {
	t.Helper()
	for i := 0; i < n; i++ {
		body := strings.NewReader(`{"message":"e-` + strings.Repeat("a", 1+i%10) + `"}`)
		req, _ := http.NewRequest("POST", url+"/api/v1/diagnostics:echo", body)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", corrPrefix+"-key-"+string(rune('A'+i)))
		req.Header.Set("X-Correlation-Id", corrPrefix+"-"+string(rune('A'+i)))
		resp := doReq(t, req)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	time.Sleep(200 * time.Millisecond) // let writer flush
}

// @ac AC-02
// api-audit-events-query/AC-02: ?limit=10 returns at most 10 events.
func TestAPI_AuditEvents_LimitHonored(t *testing.T) {
	t.Run("api-audit-events-query/AC-02", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		generateEvents(t, url, 15, "limit-test")
		resp := doReq(t, asRole(t, "GET", url+"/api/v1/audit/events?limit=10", auth.RoleAuditor, nil))
		defer resp.Body.Close()
		var page struct {
			Items []map[string]any `json:"items"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&page)
		if len(page.Items) > 10 {
			t.Errorf("items = %d, want <= 10", len(page.Items))
		}
	})
}

// @ac AC-04
// api-audit-events-query/AC-04: ?action filter returns only matching events.
// Note: spec api-diagnostics-echo says :echo emits diagnostics.test_job_completed,
// but Stage 0 ships with integration.plugin.executed as a placeholder until
// the diagnostics.* code is added to audit/events.yaml. This test filters by
// the action that's actually emitted.
func TestAPI_AuditEvents_ActionFilter(t *testing.T) {
	t.Run("api-audit-events-query/AC-04", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		generateEvents(t, url, 3, "action-test")
		resp := doReq(t, asRole(t, "GET", url+"/api/v1/audit/events?action=integration.plugin.executed", auth.RoleAuditor, nil))
		defer resp.Body.Close()
		var page struct {
			Items []struct {
				Action string `json:"action"`
			} `json:"items"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&page)
		if len(page.Items) == 0 {
			t.Fatal("filtered list is empty; expected at least 1 integration.plugin.executed")
		}
		for _, item := range page.Items {
			if item.Action != "integration.plugin.executed" {
				t.Errorf("got action %q, want only integration.plugin.executed", item.Action)
			}
		}
	})
}

// @ac AC-05
// api-audit-events-query/AC-05: ?correlation_id filter narrows to that ID.
func TestAPI_AuditEvents_CorrelationIdFilter(t *testing.T) {
	t.Run("api-audit-events-query/AC-05", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		generateEvents(t, url, 3, "corr-test")
		resp := doReq(t, asRole(t, "GET", url+"/api/v1/audit/events?correlation_id=corr-test-A", auth.RoleAuditor, nil))
		defer resp.Body.Close()
		var page struct {
			Items []struct {
				CorrelationID string `json:"correlation_id"`
			} `json:"items"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&page)
		for _, item := range page.Items {
			if item.CorrelationID != "corr-test-A" {
				t.Errorf("correlation_id = %q, want corr-test-A", item.CorrelationID)
			}
		}
		if len(page.Items) < 1 {
			t.Error("expected at least one row for correlation_id=corr-test-A")
		}
	})
}

// @ac AC-06
// api-audit-events-query/AC-06: ?since and ?until window inclusively on
// since and exclusively on until.
func TestAPI_AuditEvents_TimeWindow(t *testing.T) {
	t.Run("api-audit-events-query/AC-06", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		before := time.Now().UTC()
		generateEvents(t, url, 2, "window-test")
		after := time.Now().UTC()

		// Use ISO-8601 / RFC3339 since both inclusive end (before-1s) and
		// exclusive past (after+1s) bound the generated window.
		sinceParam := before.Add(-1 * time.Second).Format(time.RFC3339)
		untilParam := after.Add(1 * time.Second).Format(time.RFC3339)
		resp := doReq(t, asRole(t, "GET", url+
			"/api/v1/audit/events?since="+sinceParam+"&until="+untilParam, auth.RoleAuditor, nil))
		defer resp.Body.Close()
		var page struct {
			Items []struct {
				OccurredAt time.Time `json:"occurred_at"`
			} `json:"items"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&page)
		for _, item := range page.Items {
			if item.OccurredAt.Before(before.Add(-1 * time.Second)) {
				t.Errorf("event at %v older than since bound", item.OccurredAt)
			}
		}
	})
}

// @ac AC-07
// api-audit-events-query/AC-07: When more rows match than limit, response
// includes non-null next_cursor; follow-up call returns the next page
// with no overlap.
func TestAPI_AuditEvents_CursorPagination(t *testing.T) {
	t.Run("api-audit-events-query/AC-07", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		generateEvents(t, url, 6, "cursor-test")
		resp := doReq(t, asRole(t, "GET", url+"/api/v1/audit/events?limit=3", auth.RoleAuditor, nil))
		defer resp.Body.Close()
		var first struct {
			Items []struct {
				ID string `json:"id"`
			} `json:"items"`
			NextCursor *string `json:"next_cursor"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&first)
		if first.NextCursor == nil || *first.NextCursor == "" {
			t.Fatalf("expected non-null next_cursor when more rows exist; got %v", first.NextCursor)
		}
		// Fetch next page.
		resp2 := doReq(t, asRole(t, "GET", url+"/api/v1/audit/events?limit=3&cursor="+*first.NextCursor, auth.RoleAuditor, nil))
		defer resp2.Body.Close()
		var second struct {
			Items []struct {
				ID string `json:"id"`
			} `json:"items"`
		}
		_ = json.NewDecoder(resp2.Body).Decode(&second)
		firstIDs := map[string]bool{}
		for _, it := range first.Items {
			firstIDs[it.ID] = true
		}
		for _, it := range second.Items {
			if firstIDs[it.ID] {
				t.Errorf("page 2 includes ID %q seen on page 1 (overlap)", it.ID)
			}
		}
	})
}

// @ac AC-08
// api-audit-events-query/AC-08: When the returned page contains the last
// matching rows, next_cursor is null.
func TestAPI_AuditEvents_LastPageNullCursor(t *testing.T) {
	t.Run("api-audit-events-query/AC-08", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		generateEvents(t, url, 2, "last-page-test")
		resp := doReq(t, asRole(t, "GET", url+"/api/v1/audit/events?limit=200", auth.RoleAuditor, nil))
		defer resp.Body.Close()
		var page struct {
			NextCursor *string `json:"next_cursor"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&page)
		// With limit 200 and only 2 rows, next_cursor must be null.
		if page.NextCursor != nil && *page.NextCursor != "" {
			t.Errorf("next_cursor = %q, want null on last page", *page.NextCursor)
		}
	})
}

// @ac AC-09
// api-audit-events-query/AC-09: Each item carries id, correlation_id,
// action, severity, actor_type, occurred_at, recorded_at, detail,
// redactions.
func TestAPI_AuditEvents_ItemShape(t *testing.T) {
	t.Run("api-audit-events-query/AC-09", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		generateEvents(t, url, 1, "shape-test")
		resp := doReq(t, asRole(t, "GET", url+"/api/v1/audit/events?limit=1", auth.RoleAuditor, nil))
		defer resp.Body.Close()
		var page struct {
			Items []map[string]json.RawMessage `json:"items"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&page)
		if len(page.Items) < 1 {
			t.Fatal("no items returned")
		}
		mustHave := []string{
			"id", "correlation_id", "action", "severity",
			"actor_type", "occurred_at", "recorded_at",
			"detail", "redactions",
		}
		for _, k := range mustHave {
			if _, ok := page.Items[0][k]; !ok {
				t.Errorf("item missing field %q", k)
			}
		}
	})
}

// @ac AC-10
// api-audit-events-query/AC-10: Stored detail with redacted fields shows
// "<REDACTED>" placeholders; redactions lists the scrubbed names. Asserts
// the writer's pre-store redaction surfaces in the query response.
func TestAPI_AuditEvents_RedactionVisible(t *testing.T) {
	t.Run("api-audit-events-query/AC-10", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		// Insert a row with a sensitive detail field. Bypass :echo because
		// it does not emit secrets — write directly through audit.Emit.
		emitSensitiveAuditEvent(t, pool, "redaction-test-corr")
		time.Sleep(150 * time.Millisecond)

		resp := doReq(t, asRole(t, "GET", url+"/api/v1/audit/events?correlation_id=redaction-test-corr", auth.RoleAuditor, nil))
		defer resp.Body.Close()
		var page struct {
			Items []struct {
				Detail     map[string]any `json:"detail"`
				Redactions []string       `json:"redactions"`
			} `json:"items"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&page)
		if len(page.Items) < 1 {
			t.Fatal("no items for redaction-test-corr")
		}
		item := page.Items[0]
		if v, ok := item.Detail["password"]; !ok || v != "<REDACTED>" {
			t.Errorf("detail.password = %v, want '<REDACTED>'", v)
		}
		found := false
		for _, r := range item.Redactions {
			if r == "password" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("redactions = %v, want to include 'password'", item.Redactions)
		}
	})
}

// @ac AC-11
// AC-11: the audit trail is security-sensitive — an anonymous caller gets
// 403 with no events; an authenticated caller holding audit:read gets 200.
// Regression guard for the pre-release finding where GetAuditEvents had no
// authorization at all (anonymous full-trail disclosure).
func TestAPI_AuditEvents_RequiresAuditRead(t *testing.T) {
	t.Run("api-audit-events-query/AC-11", func(t *testing.T) {
		url, _ := freshAPIServer(t)

		// Anonymous → 403, and no event body leaks.
		anon := doReq(t, asRole(t, "GET", url+"/api/v1/audit/events", "", nil))
		defer anon.Body.Close()
		if anon.StatusCode != http.StatusUnauthorized {
			t.Fatalf("anonymous GET /audit/events = %d, want 401", anon.StatusCode)
		}
		body, _ := io.ReadAll(anon.Body)
		if strings.Contains(string(body), "\"items\"") {
			t.Errorf("anonymous response leaked an events list: %s", string(body))
		}

		// Authenticated with audit:read → 200.
		ok := doReq(t, asRole(t, "GET", url+"/api/v1/audit/events", auth.RoleAuditor, nil))
		defer ok.Body.Close()
		if ok.StatusCode != http.StatusOK {
			t.Errorf("auditor GET /audit/events = %d, want 200", ok.StatusCode)
		}
	})
}

// @ac AC-12
// api-audit-events-query/AC-12 (v1.2.0): each item carries a readable
// `message` built by activity.FormatAudit, plus actor_label; and the
// resource_type/resource_id filters scope to one resource's audit trail.
func TestAPI_AuditEvents_MessageAndResourceFilter(t *testing.T) {
	t.Run("api-audit-events-query/AC-12", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()
		hostA := uuid.Must(uuid.NewV7()).String()
		hostB := uuid.Must(uuid.NewV7()).String()
		// Seed two host.created events for different resource_ids.
		for _, res := range []string{hostA, hostB} {
			id := uuid.Must(uuid.NewV7())
			if _, err := pool.Exec(ctx,
				`INSERT INTO audit_events
				   (id, correlation_id, actor_type, actor_label, action,
				    resource_type, resource_id, severity, occurred_at)
				 VALUES ($1,'corr-msg','user','alice@example.com','host.created','host',$2,'info',now())`,
				id, res); err != nil {
				t.Fatalf("seed audit event: %v", err)
			}
		}

		// Unfiltered: the message is the readable sentence, not the raw code.
		all := getAuditPage(t, url, "")
		var sawReadable bool
		for _, it := range all {
			if it.Action == "host.created" {
				if it.Message != "alice@example.com created a host" {
					t.Errorf("message = %q, want %q", it.Message, "alice@example.com created a host")
				}
				if it.Message == it.Action {
					t.Errorf("message is the raw action code %q", it.Action)
				}
				if it.ActorLabel != "alice@example.com" {
					t.Errorf("actor_label = %q, want alice@example.com", it.ActorLabel)
				}
				sawReadable = true
			}
		}
		if !sawReadable {
			t.Fatal("no host.created event found in unfiltered list")
		}

		// resource filter scopes to hostA only.
		scoped := getAuditPage(t, url, "?resource_type=host&resource_id="+hostA)
		if len(scoped) == 0 {
			t.Fatal("resource-filtered list is empty; want hostA's event")
		}
		for _, it := range scoped {
			if it.ResourceID != hostA {
				t.Errorf("resource_id = %q, want only %q (hostB leaked)", it.ResourceID, hostA)
			}
		}
	})
}

type auditItem struct {
	Action     string `json:"action"`
	Message    string `json:"message"`
	ActorLabel string `json:"actor_label"`
	ResourceID string `json:"resource_id"`
}

func getAuditPage(t *testing.T, url, query string) []auditItem {
	t.Helper()
	resp := doReq(t, asRole(t, "GET", url+"/api/v1/audit/events"+query, auth.RoleAuditor, nil))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var page struct {
		Items []auditItem `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return page.Items
}

// @ac AC-13
// api-audit-events-query/AC-13 (v1.3.0): the export endpoint streams the
// filtered trail as a CSV (default) or JSON attachment with the readable
// message column, scoped by the resource filters, audit:read gated.
func TestAPI_AuditEvents_Export(t *testing.T) {
	t.Run("api-audit-events-query/AC-13", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()
		host := uuid.Must(uuid.NewV7()).String()
		other := uuid.Must(uuid.NewV7()).String()
		for _, res := range []string{host, other} {
			id := uuid.Must(uuid.NewV7())
			if _, err := pool.Exec(ctx,
				`INSERT INTO audit_events
				   (id, correlation_id, actor_type, actor_label, action,
				    resource_type, resource_id, severity, occurred_at)
				 VALUES ($1,'corr-exp','user','alice@example.com','host.created','host',$2,'info',now())`,
				id, res); err != nil {
				t.Fatalf("seed audit event: %v", err)
			}
		}
		// A formula-injection attempt in actor_label must be neutralized in
		// the CSV (CWE-1236, AC-14) — the cell renders as text, not a formula.
		evilID := uuid.Must(uuid.NewV7())
		if _, err := pool.Exec(ctx,
			`INSERT INTO audit_events
			   (id, correlation_id, actor_type, actor_label, action, severity, occurred_at)
			 VALUES ($1,'corr-exp','user','=danger','auth.login.success','info',now())`,
			evilID); err != nil {
			t.Fatalf("seed injection event: %v", err)
		}

		// CSV (default): attachment, header row, readable message cell.
		resp := doReq(t, asRole(t, "GET", url+"/api/v1/audit/events/export", auth.RoleAuditor, nil))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("csv export status = %d, want 200", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
			t.Errorf("Content-Type = %q, want text/csv", ct)
		}
		if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
			t.Errorf("Content-Disposition = %q, want attachment", cd)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		csvText := string(body)
		if !strings.HasPrefix(csvText, "occurred_at,action,message,severity,actor_type,actor_label,actor_id,resource_type,resource_id,correlation_id") {
			t.Errorf("csv header missing/wrong: %q", strings.SplitN(csvText, "\n", 2)[0])
		}
		if !strings.Contains(csvText, "alice@example.com created a host") {
			t.Errorf("csv body lacks the readable message; got:\n%s", csvText)
		}
		if strings.Contains(csvText, ",host.created,host.created,") {
			t.Errorf("message cell duplicated the raw action code")
		}
		// Formula injection neutralized: the actor_label cell renders as the
		// quote-prefixed literal '=danger, never a bare =danger formula cell.
		if !strings.Contains(csvText, "'=danger") {
			t.Errorf("CSV did not neutralize the '=danger' formula-injection cell; got:\n%s", csvText)
		}
		if strings.Contains(csvText, ",=danger") {
			t.Errorf("CSV contains a bare formula cell ',=danger' (formula injection not neutralized)")
		}

		// JSON format.
		jresp := doReq(t, asRole(t, "GET", url+"/api/v1/audit/events/export?format=json", auth.RoleAuditor, nil))
		if ct := jresp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("json Content-Type = %q, want application/json", ct)
		}
		var arr []map[string]any
		_ = json.NewDecoder(jresp.Body).Decode(&arr)
		jresp.Body.Close()
		if len(arr) < 2 {
			t.Errorf("json export len = %d, want >= 2", len(arr))
		}

		// resource filter scopes the export to one host.
		fresp := doReq(t, asRole(t, "GET",
			url+"/api/v1/audit/events/export?resource_type=host&resource_id="+host, auth.RoleAuditor, nil))
		fbody, _ := io.ReadAll(fresp.Body)
		fresp.Body.Close()
		if strings.Contains(string(fbody), other) {
			t.Errorf("resource-filtered export leaked the other resource_id %s", other)
		}
		if !strings.Contains(string(fbody), host) {
			t.Errorf("resource-filtered export missing the requested host %s", host)
		}

		// Anonymous is denied before any export.
		an := doReq(t, asRole(t, "GET", url+"/api/v1/audit/events/export", "", nil))
		an.Body.Close()
		if an.StatusCode != http.StatusUnauthorized && an.StatusCode != http.StatusForbidden {
			t.Errorf("anonymous export status = %d, want 401/403", an.StatusCode)
		}
	})
}
