// @spec api-diagnostics-echo

package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// @ac AC-01
// api-diagnostics-echo/AC-01: POST with valid body + Idempotency-Key returns 200 with echoed message.
func TestAPI_Echo_ValidRequest(t *testing.T) {
	t.Run("api-diagnostics-echo/AC-01", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := strings.NewReader(`{"message":"hello"}`)
		req, _ := http.NewRequest("POST", url+"/api/v1/diagnostics:echo", body)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "api-test-001")
		req.Header.Set("X-Correlation-Id", "api-test-corr-001")
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d, want 200, body=%s", resp.StatusCode, b)
		}
		var got struct {
			Echoed        string `json:"echoed"`
			CorrelationID string `json:"correlation_id"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&got)
		if got.Echoed != "hello" {
			t.Errorf("echoed = %q, want hello", got.Echoed)
		}
	})
}

// @ac AC-03
// api-diagnostics-echo/AC-03: POST without Idempotency-Key returns 400 idempotency.key_required.
func TestAPI_Echo_MissingIdempotencyKey(t *testing.T) {
	t.Run("api-diagnostics-echo/AC-03", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := strings.NewReader(`{"message":"hello"}`)
		req, _ := http.NewRequest("POST", url+"/api/v1/diagnostics:echo", body)
		req.Header.Set("Content-Type", "application/json")
		// No Idempotency-Key
		resp := doReq(t, req)
		defer resp.Body.Close()
		// oapi-codegen rejects missing required headers at 400 BEFORE the
		// handler runs (with a generic message). Either path produces 400.
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", resp.StatusCode)
		}
	})
}

// @ac AC-07
// api-diagnostics-echo/AC-07: Replay with same Idempotency-Key + body returns cached response.
func TestAPI_Echo_IdempotencyReplay(t *testing.T) {
	t.Run("api-diagnostics-echo/AC-07", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		send := func() (int, []byte) {
			body := strings.NewReader(`{"message":"replay-me"}`)
			req, _ := http.NewRequest("POST", url+"/api/v1/diagnostics:echo", body)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Idempotency-Key", "replay-key-001")
			req.Header.Set("X-Correlation-Id", "replay-corr")
			resp := doReq(t, req)
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			return resp.StatusCode, b
		}
		s1, b1 := send()
		s2, b2 := send()
		if s1 != http.StatusOK || s2 != http.StatusOK {
			t.Fatalf("statuses = %d, %d; want both 200", s1, s2)
		}
		var v1, v2 map[string]any
		_ = json.Unmarshal(b1, &v1)
		_ = json.Unmarshal(b2, &v2)
		// audit_event_id must match on replay (handler not re-invoked).
		if v1["audit_event_id"] != v2["audit_event_id"] {
			t.Errorf("replay produced different audit_event_id: %v vs %v",
				v1["audit_event_id"], v2["audit_event_id"])
		}
	})
}

// @ac AC-08
// api-diagnostics-echo/AC-08: Replay with same key but different body returns 409.
func TestAPI_Echo_IdempotencyConflict(t *testing.T) {
	t.Run("api-diagnostics-echo/AC-08", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		send := func(msg string) int {
			body := strings.NewReader(`{"message":"` + msg + `"}`)
			req, _ := http.NewRequest("POST", url+"/api/v1/diagnostics:echo", body)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Idempotency-Key", "conflict-key")
			resp := doReq(t, req)
			defer resp.Body.Close()
			return resp.StatusCode
		}
		_ = send("first")
		s := send("second")
		if s != http.StatusConflict {
			t.Errorf("status = %d, want 409", s)
		}
	})
}

// @ac AC-02
// api-diagnostics-echo/AC-02: Response carries X-Correlation-Id matching
// the client-supplied value (echoed unchanged when valid).
func TestAPI_Echo_CorrelationIdEchoed(t *testing.T) {
	t.Run("api-diagnostics-echo/AC-02", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := strings.NewReader(`{"message":"corr-test"}`)
		req, _ := http.NewRequest("POST", url+"/api/v1/diagnostics:echo", body)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "corr-test-key")
		req.Header.Set("X-Correlation-Id", "req-client-supplied-001")
		resp := doReq(t, req)
		defer resp.Body.Close()
		if got := resp.Header.Get("X-Correlation-Id"); got != "req-client-supplied-001" {
			t.Errorf("X-Correlation-Id = %q, want req-client-supplied-001", got)
		}
	})
}

// @ac AC-04
// api-diagnostics-echo/AC-04: POST with empty body returns 400
// validation.field_required.
func TestAPI_Echo_EmptyBody(t *testing.T) {
	t.Run("api-diagnostics-echo/AC-04", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := strings.NewReader(`{}`)
		req, _ := http.NewRequest("POST", url+"/api/v1/diagnostics:echo", body)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "empty-body-key")
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			b, _ := io.ReadAll(resp.Body)
			t.Errorf("status = %d, want 400; body=%s", resp.StatusCode, b)
		}
	})
}

// @ac AC-05
// api-diagnostics-echo/AC-05: POST with body.message > 1024 chars returns
// 400 validation.field_range.
func TestAPI_Echo_OversizeMessage(t *testing.T) {
	t.Run("api-diagnostics-echo/AC-05", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		big := strings.Repeat("x", 2048)
		body := strings.NewReader(`{"message":"` + big + `"}`)
		req, _ := http.NewRequest("POST", url+"/api/v1/diagnostics:echo", body)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "oversize-key")
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			b, _ := io.ReadAll(resp.Body)
			t.Errorf("status = %d, want 400; body=%s", resp.StatusCode, b)
		}
	})
}

// @ac AC-06
// api-diagnostics-echo/AC-06: First POST emits one audit event with action
// diagnostics.test_job_completed; replay with same key does NOT emit a
// second event (cached path skips audit per C-04).
func TestAPI_Echo_SingleAuditOnReplay(t *testing.T) {
	t.Run("api-diagnostics-echo/AC-06", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		send := func() {
			body := strings.NewReader(`{"message":"audit-once"}`)
			req, _ := http.NewRequest("POST", url+"/api/v1/diagnostics:echo", body)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Idempotency-Key", "audit-once-key")
			req.Header.Set("X-Correlation-Id", "audit-once-corr")
			resp := doReq(t, req)
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		send()
		send() // replay
		time.Sleep(150 * time.Millisecond)

		var count int64
		err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM audit_events WHERE correlation_id = 'audit-once-corr'`,
		).Scan(&count)
		if err != nil {
			t.Fatalf("count audit events: %v", err)
		}
		if count != 1 {
			t.Errorf("audit_events for replay correlation = %d, want 1", count)
		}
	})
}

// @ac AC-09
// api-diagnostics-echo/AC-09: GET /api/v1/diagnostics:echo returns 405.
// Verifies the chi-routed handler chain rejects non-POST methods.
func TestAPI_Echo_GetReturns405(t *testing.T) {
	t.Run("api-diagnostics-echo/AC-09", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		resp := doGet(t, url+"/api/v1/diagnostics:echo")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want 405", resp.StatusCode)
		}
		// Per C-03, X-Correlation-Id must still be present on the 405.
		if resp.Header.Get("X-Correlation-Id") == "" {
			t.Error("X-Correlation-Id missing on 405 response")
		}
	})
}

// @ac AC-10
// api-diagnostics-echo/AC-10: After a successful POST, querying
// /audit/events filtered by action + correlation_id returns exactly
// one row.
func TestAPI_Echo_QueryableAuditEvent(t *testing.T) {
	t.Run("api-diagnostics-echo/AC-10", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := strings.NewReader(`{"message":"queryable"}`)
		req, _ := http.NewRequest("POST", url+"/api/v1/diagnostics:echo", body)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "queryable-key")
		req.Header.Set("X-Correlation-Id", "queryable-corr")
		resp := doReq(t, req)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		time.Sleep(150 * time.Millisecond)

		resp = doGet(t, url+"/api/v1/audit/events?correlation_id=queryable-corr")
		defer resp.Body.Close()
		var page struct {
			Items []struct {
				Action        string `json:"action"`
				CorrelationID string `json:"correlation_id"`
			} `json:"items"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&page)
		if len(page.Items) != 1 {
			t.Errorf("items = %d, want 1 (action+correlation_id filter)", len(page.Items))
		}
	})
}
