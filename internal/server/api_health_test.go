// @spec api-health

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
// api-health/AC-01: GET /api/v1/health returns 200 with Content-Type application/json.
func TestAPI_Health_Returns200JSON(t *testing.T) {
	t.Run("api-health/AC-01", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		resp := doGet(t, url+"/api/v1/health")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
	})
}

// @ac AC-02
// api-health/AC-02: Response body has status="healthy", db_connected=true, version.
func TestAPI_Health_BodyShape(t *testing.T) {
	t.Run("api-health/AC-02", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		resp := doGet(t, url+"/api/v1/health")
		defer resp.Body.Close()
		var got struct {
			Status      string `json:"status"`
			DbConnected bool   `json:"db_connected"`
			Version     string `json:"version"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.Status != "healthy" {
			t.Errorf("status = %q, want healthy", got.Status)
		}
		if !got.DbConnected {
			t.Error("db_connected = false")
		}
		if got.Version == "" {
			t.Error("version is empty")
		}
	})
}

// @ac AC-03
// api-health/AC-03: Response has X-Correlation-Id header.
func TestAPI_Health_CorrelationIdHeader(t *testing.T) {
	t.Run("api-health/AC-03", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		resp := doGet(t, url+"/api/v1/health")
		defer resp.Body.Close()
		if cid := resp.Header.Get("X-Correlation-Id"); cid == "" {
			t.Error("X-Correlation-Id header missing")
		} else if !strings.HasPrefix(cid, "req-") {
			t.Errorf("X-Correlation-Id = %q, want req- prefix", cid)
		}
	})
}

// @ac AC-04
// api-health/AC-04: When the database is unreachable, the endpoint returns
// 503 with error.code = "server.unavailable". Simulated by closing the
// pool out from under the running server so the next Ping fails.
func TestAPI_Health_DBUnreachableReturns503(t *testing.T) {
	t.Run("api-health/AC-04", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		// Close the pool — subsequent /health DB ping will fail.
		pool.Close()
		resp := doGet(t, url+"/api/v1/health")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			b, _ := io.ReadAll(resp.Body)
			t.Errorf("status = %d, want 503; body=%s", resp.StatusCode, b)
			return
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "server.unavailable") {
			t.Errorf("body lacks server.unavailable code: %s", b)
		}
	})
}

// @ac AC-05
// api-health/AC-05: Healthy-path p99 < 100ms over 100 calls.
func TestAPI_Health_LatencyP99(t *testing.T) {
	t.Run("api-health/AC-05", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		const n = 100
		durs := make([]time.Duration, n)
		for i := 0; i < n; i++ {
			start := time.Now()
			resp := doGet(t, url+"/api/v1/health")
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			durs[i] = time.Since(start)
		}
		// Sort + p99.
		for i := 1; i < n; i++ {
			v := durs[i]
			j := i - 1
			for j >= 0 && durs[j] > v {
				durs[j+1] = durs[j]
				j--
			}
			durs[j+1] = v
		}
		p99 := durs[int(float64(n)*0.99)]
		if p99 > 100*time.Millisecond {
			t.Errorf("/health p99 = %v, want < 100ms", p99)
		}
		t.Logf("/health p99 = %v over %d calls", p99, n)
	})
}

// @ac AC-06
// api-health/AC-06: The endpoint MUST NOT emit an audit event per request.
// Probe traffic at health-check rates would drown the audit signal.
func TestAPI_Health_NoAuditEmission(t *testing.T) {
	t.Run("api-health/AC-06", func(t *testing.T) {
		url, pool := freshAPIServer(t)

		// Establish baseline count.
		var before int64
		_ = pool.QueryRow(context.Background(),
			`SELECT count(*) FROM audit_events`).Scan(&before)

		for i := 0; i < 10; i++ {
			resp := doGet(t, url+"/api/v1/health")
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		// Give the writer time to flush if anything had been queued.
		time.Sleep(150 * time.Millisecond)

		var after int64
		_ = pool.QueryRow(context.Background(),
			`SELECT count(*) FROM audit_events`).Scan(&after)
		if after != before {
			t.Errorf("audit_events grew by %d after 10 /health calls; want 0", after-before)
		}
	})
}
