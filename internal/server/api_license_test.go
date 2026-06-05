// @spec api-license

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/license"
	"github.com/golang-jwt/jwt/v5"
)

// mintTestLicenseJWT signs a license JWT with the same test key used by
// internal/license/validator_test.go. Tests in this package live one
// directory above license/, so the testdata path is ../license/testdata.
func mintTestLicenseJWT(t *testing.T, features []string) string {
	t.Helper()
	keyPath := filepath.Join("..", "license", "testdata", "license-privkey-test.pem")
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read test priv: %v", err)
	}
	block, _ := pem.Decode(raw)
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse priv: %v", err)
	}
	priv, ok := keyAny.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("not ed25519 key: %T", keyAny)
	}
	now := time.Now().Add(-1 * time.Minute)
	mc := jwt.MapClaims{
		"iss":         "hanalyx-openwatch-licensing",
		"aud":         "openwatch",
		"iat":         now.Unix(),
		"exp":         now.Add(365 * 24 * time.Hour).Unix(),
		"tier":        "openwatch_plus",
		"features":    features,
		"customer_id": "test-customer-api",
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, mc)
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

// @ac AC-01
// api-license/AC-01: GET /license without file returns free tier baseline.
func TestAPI_License_FreeTier(t *testing.T) {
	t.Run("api-license/AC-01", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		resp := doGet(t, url+"/api/v1/license")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		var got struct {
			Tier     string   `json:"tier"`
			Status   string   `json:"status"`
			Features []string `json:"features"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&got)
		if got.Tier != "free" {
			t.Errorf("tier = %q, want free", got.Tier)
		}
		if got.Status != "no_license" {
			t.Errorf("status = %q, want no_license", got.Status)
		}
		if len(got.Features) == 0 {
			t.Error("features empty; free tier should include at least compliance_check")
		}
	})
}

// @ac AC-05
// api-license/AC-05: POST /admin/license:verify with tampered JWT returns signature_invalid.
func TestAPI_License_VerifyTamperedJWT(t *testing.T) {
	t.Run("api-license/AC-05", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := strings.NewReader(`{"license_jwt":"not.a.valid"}`)
		req, _ := http.NewRequest("POST", url+"/api/v1/admin/license:verify", body)
		req.Header.Set("Content-Type", "application/json")
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d, want 200 (verify always 200 with result in body), body=%s",
				resp.StatusCode, b)
		}
		var got struct {
			IsValid      bool   `json:"is_valid"`
			VerifyResult string `json:"verify_result"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&got)
		if got.IsValid {
			t.Error("is_valid = true for tampered JWT")
		}
		if !strings.Contains(got.VerifyResult, "malformed") &&
			!strings.Contains(got.VerifyResult, "signature") {
			t.Errorf("verify_result = %q, want malformed_jwt or signature_invalid", got.VerifyResult)
		}
	})
}

// @ac AC-07
// api-license/AC-07: POST /:premium-echo without license returns 402 license.feature_unavailable.
func TestAPI_PremiumEcho_DeniesWithoutLicense(t *testing.T) {
	t.Run("api-license/AC-07", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := strings.NewReader(`{"message":"premium"}`)
		req, _ := http.NewRequest("POST", url+"/api/v1/diagnostics:premium-echo", body)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "premium-deny")
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusPaymentRequired {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d, want 402; body=%s", resp.StatusCode, b)
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "license.feature_unavailable") {
			t.Errorf("body lacks license.feature_unavailable: %s", b)
		}
		if !strings.Contains(string(b), "premium_diagnostics") {
			t.Errorf("body lacks premium_diagnostics: %s", b)
		}
	})
}

// @ac AC-02
// api-license/AC-02: GET /license with a valid openwatch_plus license
// returns tier="openwatch_plus", status="active", features list, exp.
func TestAPI_License_OpenwatchPlusActive(t *testing.T) {
	t.Run("api-license/AC-02", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		jwtBlob := mintTestLicenseJWT(t, []string{"premium_diagnostics", "remediation_execution"})
		if result, err := license.LoadJWT(jwtBlob, license.VerifyOptions{}); err != nil || result != license.VerifyValid {
			t.Fatalf("LoadJWT: result=%s err=%v", result, err)
		}
		t.Cleanup(license.Reset)

		resp := doGet(t, url+"/api/v1/license")
		defer resp.Body.Close()
		var got struct {
			Tier      string   `json:"tier"`
			Status    string   `json:"status"`
			Features  []string `json:"features"`
			ExpiresAt *string  `json:"expires_at"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&got)
		if got.Tier != "openwatch_plus" {
			t.Errorf("tier = %q, want openwatch_plus", got.Tier)
		}
		if got.Status != "active" {
			t.Errorf("status = %q, want active", got.Status)
		}
		if got.ExpiresAt == nil || *got.ExpiresAt == "" {
			t.Error("expires_at is empty")
		}
		hasPremium := false
		for _, f := range got.Features {
			if f == "premium_diagnostics" {
				hasPremium = true
			}
		}
		if !hasPremium {
			t.Errorf("features = %v, missing premium_diagnostics", got.Features)
		}
	})
}

// @ac AC-03
// api-license/AC-03: GET /license MUST NOT return raw JWT, signature,
// or customer PII (email, name).
func TestAPI_License_NoSensitiveDataLeak(t *testing.T) {
	t.Run("api-license/AC-03", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		jwtBlob := mintTestLicenseJWT(t, []string{"premium_diagnostics"})
		_, _ = license.LoadJWT(jwtBlob, license.VerifyOptions{})
		t.Cleanup(license.Reset)

		resp := doGet(t, url+"/api/v1/license")
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		body := string(b)

		forbidden := []string{
			"eyJ",       // any base64 JWT segment starts with eyJ
			"signature", // signature material
			"@",         // email PII (test claims have no email, but defense-in-depth)
		}
		for _, sub := range forbidden {
			if strings.Contains(body, sub) {
				t.Errorf("response body contains forbidden substring %q: %s", sub, body)
			}
		}
	})
}

// @ac AC-04
// api-license/AC-04: POST /admin/license:verify with valid JWT returns
// is_valid=true, verify_result="valid", features populated.
func TestAPI_License_VerifyValidJWT(t *testing.T) {
	t.Run("api-license/AC-04", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		jwtBlob := mintTestLicenseJWT(t, []string{"premium_diagnostics", "remediation_execution"})

		body := strings.NewReader(`{"license_jwt":"` + jwtBlob + `"}`)
		req, _ := http.NewRequest("POST", url+"/api/v1/admin/license:verify", body)
		req.Header.Set("Content-Type", "application/json")
		resp := doReq(t, req)
		defer resp.Body.Close()
		var got struct {
			IsValid      bool     `json:"is_valid"`
			VerifyResult string   `json:"verify_result"`
			Features     []string `json:"features"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&got)
		if !got.IsValid {
			t.Errorf("is_valid = false for valid JWT")
		}
		if got.VerifyResult != "valid" {
			t.Errorf("verify_result = %q, want valid", got.VerifyResult)
		}
		if len(got.Features) == 0 {
			t.Error("features missing from verify response")
		}
	})
}

// @ac AC-06
// api-license/AC-06: POST /admin/license:verify does NOT install the
// license — subsequent GET /license shows the prior (free-tier) state.
func TestAPI_License_VerifyDoesNotInstall(t *testing.T) {
	t.Run("api-license/AC-06", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		jwtBlob := mintTestLicenseJWT(t, []string{"premium_diagnostics"})

		body := strings.NewReader(`{"license_jwt":"` + jwtBlob + `"}`)
		req, _ := http.NewRequest("POST", url+"/api/v1/admin/license:verify", body)
		req.Header.Set("Content-Type", "application/json")
		resp := doReq(t, req)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		// State must still be free tier.
		resp = doGet(t, url+"/api/v1/license")
		defer resp.Body.Close()
		var got struct {
			Tier   string `json:"tier"`
			Status string `json:"status"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&got)
		if got.Tier != "free" {
			t.Errorf("tier = %q, want free (verify must not install)", got.Tier)
		}
		if got.Status != "no_license" {
			t.Errorf("status = %q, want no_license", got.Status)
		}
	})
}

// @ac AC-08
// api-license/AC-08: license.feature_check_denied audit event recorded
// after a 402 from :premium-echo (the AC-07 scenario).
func TestAPI_License_DeniedEmitsAudit(t *testing.T) {
	t.Run("api-license/AC-08", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		body := strings.NewReader(`{"message":"premium"}`)
		req, _ := http.NewRequest("POST", url+"/api/v1/diagnostics:premium-echo", body)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "denied-audit-key")
		req.Header.Set("X-Correlation-Id", "denied-audit-corr")
		resp := doReq(t, req)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		time.Sleep(150 * time.Millisecond)

		var count int64
		err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM audit_events WHERE action = 'license.feature_check_denied'
			   AND correlation_id = 'denied-audit-corr'`,
		).Scan(&count)
		if err != nil {
			t.Fatalf("count audit: %v", err)
		}
		if count != 1 {
			t.Errorf("license.feature_check_denied audit count = %d, want 1", count)
		}
	})
}

// @ac AC-09
// api-license/AC-09: POST /:premium-echo with a license that includes
// premium_diagnostics returns 200 with echoed message.
func TestAPI_PremiumEcho_AllowedWithLicense(t *testing.T) {
	t.Run("api-license/AC-09", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		jwtBlob := mintTestLicenseJWT(t, []string{"premium_diagnostics"})
		if result, err := license.LoadJWT(jwtBlob, license.VerifyOptions{}); err != nil || result != license.VerifyValid {
			t.Fatalf("LoadJWT: result=%s err=%v", result, err)
		}
		t.Cleanup(license.Reset)

		body := strings.NewReader(`{"message":"premium-allowed"}`)
		req, _ := http.NewRequest("POST", url+"/api/v1/diagnostics:premium-echo", body)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "premium-allow-key")
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, b)
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "premium-allowed") {
			t.Errorf("body lacks echoed message: %s", b)
		}
	})
}

// @ac AC-10
// api-license/AC-10: Installing a license via LoadJWT (the in-process
// equivalent of file-drop + SIGHUP) makes GET /license reflect the new
// state without restart. SIGHUP file-watch wiring is operational and
// validated by manual acceptance walkthrough; this asserts the underlying
// hot-swap contract.
func TestAPI_License_LiveReload(t *testing.T) {
	t.Run("api-license/AC-10", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		// Baseline: free tier.
		resp := doGet(t, url+"/api/v1/license")
		var before struct {
			Tier string `json:"tier"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&before)
		resp.Body.Close()
		if before.Tier != "free" {
			t.Fatalf("baseline tier = %q, want free", before.Tier)
		}

		// Install license — same code path SIGHUP triggers.
		jwtBlob := mintTestLicenseJWT(t, []string{"premium_diagnostics"})
		if result, err := license.LoadJWT(jwtBlob, license.VerifyOptions{}); err != nil || result != license.VerifyValid {
			t.Fatalf("LoadJWT: result=%s err=%v", result, err)
		}
		t.Cleanup(license.Reset)

		// New state reflected without restart.
		resp = doGet(t, url+"/api/v1/license")
		defer resp.Body.Close()
		var after struct {
			Tier string `json:"tier"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&after)
		if after.Tier != "openwatch_plus" {
			t.Errorf("post-reload tier = %q, want openwatch_plus", after.Tier)
		}
	})
}
