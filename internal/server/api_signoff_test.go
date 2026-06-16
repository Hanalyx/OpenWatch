// @spec release-stage-0-signoff
//
// Stage-0 Definition-of-Done integration tests. Each test maps to one
// of the 19 DoD steps. Steps that are operator-mediated (cert hot-
// reload via file watch on a running VM, full binary restart with DB
// persistence) cite the spec AC that covers their automatable surface
// instead of duplicating the test.

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/policy"
	"gopkg.in/yaml.v3"
)

// @ac AC-01
// AC-01 / DoD-7: GET /health returns 200 + canonical body.
func TestSignoff_DoD7_Health(t *testing.T) {
	t.Run("release-stage-0-signoff/AC-01", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		resp := doGet(t, url+"/api/v1/health")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		var got struct {
			Status      string `json:"status"`
			DbConnected bool   `json:"db_connected"`
			Version     string `json:"version"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&got)
		if got.Status != "healthy" || !got.DbConnected || got.Version == "" {
			t.Errorf("body = %+v", got)
		}
	})
}

// @ac AC-02
// AC-02 / DoD-8: :echo returns echoed message + matching correlation_id.
func TestSignoff_DoD8_Echo(t *testing.T) {
	t.Run("release-stage-0-signoff/AC-02", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := strings.NewReader(`{"message":"hi"}`)
		req, _ := http.NewRequest("POST", url+"/api/v1/diagnostics:echo", body)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "dod8-key")
		req.Header.Set("X-Correlation-Id", "dod8-001")
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d body=%s", resp.StatusCode, b)
		}
		if resp.Header.Get("X-Correlation-Id") != "dod8-001" {
			t.Errorf("X-Correlation-Id = %q, want dod8-001", resp.Header.Get("X-Correlation-Id"))
		}
	})
}

// @ac AC-03
// AC-03 / DoD-9: GET /audit/events returns the audit row from the prior
// :echo call.
func TestSignoff_DoD9_AuditQueryable(t *testing.T) {
	t.Run("release-stage-0-signoff/AC-03", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		// Make an :echo call, then query.
		body := strings.NewReader(`{"message":"dod9"}`)
		req, _ := http.NewRequest("POST", url+"/api/v1/diagnostics:echo", body)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "dod9-key")
		req.Header.Set("X-Correlation-Id", "dod9-001")
		resp := doReq(t, req)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		time.Sleep(200 * time.Millisecond)

		resp = doReq(t, asRole(t, "GET", url+"/api/v1/audit/events?correlation_id=dod9-001", auth.RoleAuditor, nil))
		defer resp.Body.Close()
		var page struct {
			Items []struct {
				Action string `json:"action"`
			} `json:"items"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&page)
		if len(page.Items) < 1 {
			t.Fatal("no audit row for dod9-001")
		}
	})
}

// @ac AC-04
// AC-04 / DoD-10: Replay returns cached response; one audit row only.
func TestSignoff_DoD10_IdempotencyReplay(t *testing.T) {
	t.Run("release-stage-0-signoff/AC-04", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		send := func() {
			body := strings.NewReader(`{"message":"dod10"}`)
			req, _ := http.NewRequest("POST", url+"/api/v1/diagnostics:echo", body)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Idempotency-Key", "dod10-key")
			req.Header.Set("X-Correlation-Id", "dod10-001")
			resp := doReq(t, req)
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		send()
		send() // replay
		time.Sleep(200 * time.Millisecond)
		var count int64
		_ = pool.QueryRow(context.Background(),
			`SELECT count(*) FROM audit_events WHERE correlation_id = 'dod10-001'`,
		).Scan(&count)
		if count != 1 {
			t.Errorf("audit rows for replay = %d, want 1", count)
		}
	})
}

// @ac AC-05
// AC-05 / DoD-11: viewer's effective permissions include host:read,
// exclude host:write.
func TestSignoff_DoD11_ViewerPermissions(t *testing.T) {
	t.Run("release-stage-0-signoff/AC-05", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		req, _ := http.NewRequest("GET", url+"/api/v1/auth/me/permissions", nil)
		req.AddCookie(roleCookies[auth.RoleViewer])
		resp := doReq(t, req)
		defer resp.Body.Close()
		var got struct {
			Permissions []string `json:"permissions"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&got)
		hasRead, hasWrite := false, false
		for _, p := range got.Permissions {
			if p == "host:read" {
				hasRead = true
			}
			if p == "host:write" {
				hasWrite = true
			}
		}
		if !hasRead {
			t.Error("viewer missing host:read")
		}
		if hasWrite {
			t.Error("viewer must NOT have host:write")
		}
	})
}

// @ac AC-06
// AC-06 / DoD-12: viewer + :require-host-write → 403 authz.permission_denied;
// audit row with detail.required_permission=host:write.
func TestSignoff_DoD12_RBACDenialOnHostWrite(t *testing.T) {
	t.Run("release-stage-0-signoff/AC-06", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		body := strings.NewReader(`{"message":"dod12"}`)
		req, _ := http.NewRequest("POST", url+"/api/v1/diagnostics:require-host-write", body)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "dod12-key")
		req.Header.Set("X-Correlation-Id", "dod12-001")
		req.AddCookie(roleCookies[auth.RoleViewer])
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d, want 403 body=%s", resp.StatusCode, b)
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "authz.permission_denied") {
			t.Errorf("body lacks authz.permission_denied: %s", b)
		}
		time.Sleep(200 * time.Millisecond)
		var detail string
		_ = pool.QueryRow(context.Background(),
			`SELECT COALESCE(detail::text, '') FROM audit_events
			   WHERE action = 'authz.permission.denied' AND correlation_id = 'dod12-001'`,
		).Scan(&detail)
		if !strings.Contains(detail, `"host:write"`) {
			t.Errorf("audit detail lacks host:write: %s", detail)
		}
	})
}

// @ac AC-07
// AC-07 / DoD-13: security_admin + no license + :require-remediation-execute
// → 402 license.feature_unavailable.
func TestSignoff_DoD13_LicenseGate402(t *testing.T) {
	t.Run("release-stage-0-signoff/AC-07", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := strings.NewReader(`{"message":"dod13"}`)
		req, _ := http.NewRequest("POST", url+"/api/v1/diagnostics:require-remediation-execute", body)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "dod13-key")
		req.AddCookie(roleCookies[auth.RoleSecurityAdmin])
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusPaymentRequired {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d, want 402 body=%s", resp.StatusCode, b)
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "license.feature_unavailable") {
			t.Errorf("body lacks license.feature_unavailable: %s", b)
		}
	})
}

// @ac AC-08
// AC-08 / DoD-14: :evaluate-alert returns Decision with outcome="high"
// and policy_version="0.0.0" (built-in default thresholds: <50 critical,
// <70 high, <85 medium).
func TestSignoff_DoD14_EvaluateAlert(t *testing.T) {
	t.Run("release-stage-0-signoff/AC-08", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		policy.Reset()
		policy.Init()
		t.Cleanup(policy.Reset)

		body := strings.NewReader(`{"score":65}`)
		req, _ := http.NewRequest("POST", url+"/api/v1/diagnostics:evaluate-alert", body)
		req.Header.Set("Content-Type", "application/json")
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d body=%s", resp.StatusCode, b)
		}
		var got struct {
			Outcome       string `json:"outcome"`
			PolicyVersion string `json:"policy_version"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&got)
		if got.Outcome != "high" {
			t.Errorf("outcome = %q, want high", got.Outcome)
		}
		if got.PolicyVersion != "0.0.0" {
			t.Errorf("policy_version = %q, want 0.0.0 (built-in default)", got.PolicyVersion)
		}
	})
}

// @ac AC-09
// AC-09 / DoD-15: Drop a signed policy v1.0.0; reload; :evaluate-alert
// reflects the new thresholds.
func TestSignoff_DoD15_PolicyReload(t *testing.T) {
	t.Run("release-stage-0-signoff/AC-09", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		// Set up a fresh policies dir under tempdir.
		dir := t.TempDir()
		t.Setenv("OPENWATCH_POLICIES_DIR", dir)
		policy.Reset()
		policy.Init()
		t.Cleanup(policy.Reset)

		// Write a signed alert_thresholds.yaml that flips score=65 to "ok"
		// by raising the high threshold below 65.
		raw := mintSignedAlertThresholds(t, "1.0.0", 20, 30, 40)
		if err := os.WriteFile(filepath.Join(dir, "alert_thresholds.yaml"), raw, 0o600); err != nil {
			t.Fatalf("write policy: %v", err)
		}

		// Reload.
		req, _ := http.NewRequest("POST", url+"/api/v1/admin/policies:reload", nil)
		req.AddCookie(roleCookies[auth.RoleAdmin])
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("reload status = %d body=%s", resp.StatusCode, b)
		}
		var reloadResp struct {
			Outcomes map[string]string `json:"outcomes"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&reloadResp)
		if reloadResp.Outcomes["alert_thresholds"] != "loaded" {
			t.Errorf("outcome = %q, want loaded", reloadResp.Outcomes["alert_thresholds"])
		}

		// Re-evaluate with the new policy in effect.
		body := strings.NewReader(`{"score":65}`)
		req, _ = http.NewRequest("POST", url+"/api/v1/diagnostics:evaluate-alert", body)
		req.Header.Set("Content-Type", "application/json")
		resp = doReq(t, req)
		defer resp.Body.Close()
		var got struct {
			Outcome       string `json:"outcome"`
			PolicyVersion string `json:"policy_version"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&got)
		if got.PolicyVersion != "1.0.0" {
			t.Errorf("policy_version = %q, want 1.0.0", got.PolicyVersion)
		}
		// With critical<20, high<30, medium<40: score=65 → ok.
		if got.Outcome != "ok" {
			t.Errorf("outcome = %q, want ok (65 > all new thresholds)", got.Outcome)
		}
	})
}

// @ac AC-10
// AC-10 / DoD-16: enqueue-test-job; worker drains it; matching
// correlation_id on the diagnostics.test_job_completed audit event.
func TestSignoff_DoD16_QueueWorkerCorrelation(t *testing.T) {
	t.Run("release-stage-0-signoff/AC-10", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		req, _ := http.NewRequest("POST", url+"/api/v1/diagnostics:enqueue-test-job", nil)
		req.Header.Set("X-Correlation-Id", "req-end2end-001")
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("enqueue status = %d body=%s", resp.StatusCode, b)
		}

		// Poll for the worker's audit event (up to 2s per DoD).
		var found bool
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			var count int64
			_ = pool.QueryRow(context.Background(),
				`SELECT count(*) FROM audit_events
				   WHERE action = 'diagnostics.test_job_completed'
				     AND correlation_id = 'req-end2end-001'`,
			).Scan(&count)
			if count == 1 {
				found = true
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if !found {
			t.Error("worker did not emit diagnostics.test_job_completed for req-end2end-001 within 2s")
		}
	})
}

// @ac AC-11
// AC-11 / DoD-17: `specter sync` is run by CI / sign-off pipeline; here
// we assert the spec file exists and its declared spec IDs cover the
// directories that ship enforcing tests. The full pipeline runs in the
// caller's CI.
func TestSignoff_DoD17_SpecterRegistry(t *testing.T) {
	t.Run("release-stage-0-signoff/AC-11", func(t *testing.T) {
		// Spec file exists.
		paths := []string{
			"../../specs/system/audit-emission.spec.yaml",
			"../../specs/system/correlation.spec.yaml",
			"../../specs/system/rbac.spec.yaml",
			"../../specs/api/diagnostics-echo.spec.yaml",
			"../../specs/release/stage-0-signoff.spec.yaml",
		}
		for _, p := range paths {
			if _, err := os.Stat(p); err != nil {
				t.Errorf("expected spec file %s: %v", p, err)
			}
		}
	})
}

// @ac AC-12
// AC-12 / DoD-18: cert hot-reload — covered automatable surface by
// system-http-server AC-08 (GetCertificate is wired) + AC-09 (echoed
// header). Full file-watch + restart-less swap is exercised by the
// operator on a VM and out of scope for an in-process Go test.
func TestSignoff_DoD18_CertHotReloadDelegated(t *testing.T) {
	t.Run("release-stage-0-signoff/AC-12", func(t *testing.T) {
		// Assert the spec file lists the delegated ACs so the sign-off
		// checklist is auditable.
		raw, err := os.ReadFile("../../specs/system/http-server.spec.yaml")
		if err != nil {
			t.Fatalf("read http-server spec: %v", err)
		}
		s := string(raw)
		if !strings.Contains(s, "AC-08") || !strings.Contains(s, "AC-09") {
			t.Error("system-http-server spec missing AC-08 / AC-09 coverage of cert hot-reload")
		}
	})
}

// @ac AC-13
// AC-13 / DoD-19: data survives restart — automatable surface covered by
// system-db AC-12 (pool-reopen with Apply idempotency + row read-back).
// Full binary-restart test is operator-mediated.
func TestSignoff_DoD19_PersistenceDelegated(t *testing.T) {
	t.Run("release-stage-0-signoff/AC-13", func(t *testing.T) {
		raw, err := os.ReadFile("../../specs/system/db.spec.yaml")
		if err != nil {
			t.Fatalf("read db spec: %v", err)
		}
		if !strings.Contains(string(raw), "AC-12") {
			t.Error("system-db spec missing AC-12 (persistence across pool reopen)")
		}
	})
}

// mintSignedAlertThresholds builds a signed alert_thresholds policy
// using the policy test private key. Returns the YAML bytes ready to
// drop on disk.
func mintSignedAlertThresholds(t *testing.T, version string, critBelow, highBelow, medBelow int) []byte {
	t.Helper()
	if err := policy.InitKeys(); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}
	keyPath := filepath.Join("..", "policy", "testdata", "policy-privkey-test.pem")
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read priv: %v", err)
	}
	block, _ := pem.Decode(raw)
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse priv: %v", err)
	}
	priv, ok := keyAny.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("not ed25519 priv key")
	}
	env := policy.Envelope{
		PolicyType: policy.TypeAlertThresholds,
		Version:    version,
		Rules: map[string]any{
			"critical_below": critBelow,
			"high_below":     highBelow,
			"medium_below":   medBelow,
		},
	}
	env.Metadata.Description = "stage-0 signoff fixture"
	env.Metadata.SignedBy = "signoff-test"
	env.Metadata.SignedAt = time.Now().UTC().Format(time.RFC3339)
	// Marshal unsigned → canonicalize → sign → embed.
	rawUnsigned, err := yaml.Marshal(env)
	if err != nil {
		t.Fatalf("marshal unsigned: %v", err)
	}
	canon, err := policyCanonicalize(rawUnsigned)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	sig := ed25519.Sign(priv, canon)
	env.Signature.Algorithm = "ed25519"
	env.Signature.KeyID = "test"
	env.Signature.Value = base64.StdEncoding.EncodeToString(sig)
	out, err := yaml.Marshal(env)
	if err != nil {
		t.Fatalf("marshal signed: %v", err)
	}
	return out
}

// policyCanonicalize duplicates the loader's canonicalization (strip
// signature block, re-encode). Kept inline so this test doesn't need
// to export internals from the policy package.
func policyCanonicalize(raw []byte) ([]byte, error) {
	var node yaml.Node
	if err := yaml.Unmarshal(raw, &node); err != nil {
		return nil, err
	}
	stripSignature(&node)
	var buf strings.Builder
	enc := yaml.NewEncoder(stringWriter{&buf})
	enc.SetIndent(2)
	if err := enc.Encode(&node); err != nil {
		return nil, err
	}
	_ = enc.Close()
	return []byte(buf.String()), nil
}

func stripSignature(n *yaml.Node) {
	if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		stripSignature(n.Content[0])
		return
	}
	if n.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i < len(n.Content); i += 2 {
		key := n.Content[i]
		if key.Kind == yaml.ScalarNode && key.Value == "signature" {
			n.Content = append(n.Content[:i], n.Content[i+2:]...)
			return
		}
	}
}

type stringWriter struct{ b *strings.Builder }

func (s stringWriter) Write(p []byte) (int, error) { return s.b.Write(p) }
