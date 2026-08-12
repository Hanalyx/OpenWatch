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
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/license"
	"github.com/Hanalyx/openwatch/internal/server/api"
	"github.com/golang-jwt/jwt/v5"
)

// licenseAnonymousFields is the key set an anonymous GET /license may carry.
// A pre-login screen needs these three to lock or unlock a control, and none
// of them is a customer or infrastructure fact. Spec api-license C-06.
var licenseAnonymousFields = []string{"features", "status", "tier"}

// licenseGatedFields is every property that requires system:read. They name
// the buyer, the contract, how we sign, and what this host's clock did.
// in_grace_period is here for a different reason: status already carries the
// same fact, so a pre-login screen does not need it. Spec api-license C-06,
// C-09.
var licenseGatedFields = []string{
	"clock_rollback_detected",
	"customer_id",
	"expires_at",
	"in_grace_period",
	"using_prev_key",
}

// mintTestLicenseJWT signs a license JWT with the same test key used by
// internal/license/validator_test.go, expiring one year out.
func mintTestLicenseJWT(t *testing.T, features []string) string {
	t.Helper()
	return mintLicenseJWT(t, features, time.Now().Add(365*24*time.Hour))
}

// mintLicenseJWT signs a license JWT that expires at exp. Tests in this
// package live one directory above license/, so the testdata path is
// ../license/testdata. Pass an exp in the past to mint a license inside the
// 30-day grace window.
func mintLicenseJWT(t *testing.T, features []string, exp time.Time) string {
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
	// The server verifies against the real embedded key, but this JWT is signed
	// with the testdata key. Install it as the active verifier (restored on
	// cleanup). The embedded key is asserted real by license AC-14's guard test.
	t.Cleanup(license.SetVerificationKeyForTesting(priv.Public().(ed25519.PublicKey)))
	now := time.Now().Add(-1 * time.Minute)
	mc := jwt.MapClaims{
		"iss":         "licensing@hanalyx.com",
		"aud":         "openwatch",
		"iat":         now.Unix(),
		"exp":         exp.Unix(),
		"tier":        "enterprise",
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

// installLicense loads jwtBlob into the process license state and restores the
// free-tier baseline on cleanup.
//
// watermark is the LastKnownGood the loader verifies against. Set it ahead of
// the wall clock to make the load report a clock rollback; leave it zero for a
// clean load. The watermark ratchets forward inside the loaded state, so a test
// that installs a rollback license and then wants a clean one must call
// license.Reset in between.
func installLicense(t *testing.T, jwtBlob string, watermark time.Time) {
	t.Helper()
	result, err := license.LoadJWT(jwtBlob, license.VerifyOptions{LastKnownGood: watermark})
	if err != nil || result != license.VerifyValid {
		t.Fatalf("LoadJWT: result=%s err=%v", result, err)
	}
	t.Cleanup(license.Reset)
}

// installEnterpriseLicense installs a one-year enterprise license granting
// features, against a clean watermark. This is the ordinary fixture: active,
// not in grace, no rollback.
func installEnterpriseLicense(t *testing.T, features ...string) {
	t.Helper()
	installLicense(t, mintTestLicenseJWT(t, features), time.Time{})
}

// getLicenseBody performs GET /api/v1/license as the given role and returns the
// decoded body as a generic map. Pass auth.RoleID("") for an anonymous call.
//
// Decoding into a map rather than a struct is what makes the field-set
// assertions real. A struct silently drops any property nobody listed, so a
// field added to LicenseStateResponse later would slip past unnoticed. Spec
// api-license AC-11.
func getLicenseBody(t *testing.T, url string, role auth.RoleID) map[string]json.RawMessage {
	t.Helper()
	req := asRole(t, "GET", url+"/api/v1/license", role, nil)
	resp := doReq(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET /license as %q: status = %d, want 200; body=%s", role, resp.StatusCode, b)
	}
	var body map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode /license body as %q: %v", role, err)
	}
	return body
}

// licenseKeys returns the sorted top-level key set of a decoded body.
func licenseKeys(body map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(body))
	for k := range body {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// sameKeySet reports whether two sorted key sets are equal. Compared as joined
// strings so a failure message shows both sets in full.
func sameKeySet(a, b []string) bool {
	return strings.Join(a, ",") == strings.Join(b, ",")
}

// licenseBool decodes a JSON boolean property, failing the test when it is
// missing or not a boolean.
func licenseBool(t *testing.T, body map[string]json.RawMessage, name string) bool {
	t.Helper()
	raw, ok := body[name]
	if !ok {
		t.Fatalf("%s missing from body with keys %v", name, licenseKeys(body))
	}
	var v bool
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("%s = %s, want a boolean: %v", name, raw, err)
	}
	return v
}

// licenseString decodes a JSON string property, failing the test when it is
// missing or not a string.
func licenseString(t *testing.T, body map[string]json.RawMessage, name string) string {
	t.Helper()
	raw, ok := body[name]
	if !ok {
		t.Fatalf("%s missing from body with keys %v", name, licenseKeys(body))
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("%s = %s, want a string: %v", name, raw, err)
	}
	return v
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
		// :verify is admin-gated: anonymously it is a signature and
		// entitlement oracle on an /admin/ path.
		req := asRole(t, "POST", url+"/api/v1/admin/license:verify", auth.RoleAdmin,
			map[string]string{"license_jwt": "not.a.valid"})
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
// api-license/AC-07: POST /:premium-echo by a caller holding system:read,
// with no license installed, returns 402 license.feature_unavailable. The
// caller must be authenticated, because RBAC runs before the feature check.
func TestAPI_PremiumEcho_DeniesWithoutLicense(t *testing.T) {
	t.Run("api-license/AC-07", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		req := asRole(t, "POST", url+"/api/v1/diagnostics:premium-echo", auth.RoleViewer,
			map[string]string{"message": "premium"})
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
// api-license/AC-02: GET /license with a valid enterprise license returns
// tier="enterprise", status="active" and the feature list to any caller.
// expires_at is populated only for a caller holding system:read; the anonymous
// body carries the three public fields and nothing else, which AC-11 pins.
func TestAPI_License_OpenwatchPlusActive(t *testing.T) {
	t.Run("api-license/AC-02", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		installEnterpriseLicense(t, "premium_diagnostics", "remediation_execution")

		for _, role := range []auth.RoleID{"", auth.RoleViewer} {
			body := getLicenseBody(t, url, role)
			if tier := licenseString(t, body, "tier"); tier != "enterprise" {
				t.Errorf("role %q: tier = %q, want enterprise", role, tier)
			}
			if status := licenseString(t, body, "status"); status != "active" {
				t.Errorf("role %q: status = %q, want active", role, status)
			}
			var features []string
			if err := json.Unmarshal(body["features"], &features); err != nil {
				t.Fatalf("role %q: decode features: %v", role, err)
			}
			hasPremium := false
			for _, f := range features {
				if f == "premium_diagnostics" {
					hasPremium = true
				}
			}
			if !hasPremium {
				t.Errorf("role %q: features = %v, missing premium_diagnostics", role, features)
			}
		}

		// expires_at is gated, so it appears for system:read and nowhere else.
		if exp := licenseString(t, getLicenseBody(t, url, auth.RoleViewer), "expires_at"); exp == "" {
			t.Error("expires_at is empty for a system:read caller")
		}
	})
}

// @ac AC-03
// api-license/AC-03: GET /license MUST NOT return raw JWT, signature, or
// customer PII (email, name) to any caller, including one holding system:read.
// Checking only the anonymous body would prove little now that the allowlist
// drops most of the response before it is written.
func TestAPI_License_NoSensitiveDataLeak(t *testing.T) {
	t.Run("api-license/AC-03", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		installEnterpriseLicense(t, "premium_diagnostics")

		forbidden := []string{
			"eyJ",       // any base64 JWT segment starts with eyJ
			"signature", // signature material
			"@",         // email PII (test claims have no email, but defense-in-depth)
		}
		for _, role := range []auth.RoleID{"", auth.RoleViewer} {
			req := asRole(t, "GET", url+"/api/v1/license", role, nil)
			resp := doReq(t, req)
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			body := string(b)
			for _, sub := range forbidden {
				if strings.Contains(body, sub) {
					t.Errorf("role %q: response body contains forbidden substring %q: %s",
						role, sub, body)
				}
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

		req := asRole(t, "POST", url+"/api/v1/admin/license:verify", auth.RoleAdmin,
			map[string]string{"license_jwt": jwtBlob})
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
// license. A subsequent GET /license shows the prior (free-tier) state.
func TestAPI_License_VerifyDoesNotInstall(t *testing.T) {
	t.Run("api-license/AC-06", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		jwtBlob := mintTestLicenseJWT(t, []string{"premium_diagnostics"})

		req := asRole(t, "POST", url+"/api/v1/admin/license:verify", auth.RoleAdmin,
			map[string]string{"license_jwt": jwtBlob})
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
// after a 402 from :premium-echo (the AC-07 scenario). The caller holds
// system:read, because an anonymous caller is now denied by RBAC and never
// reaches the feature check.
func TestAPI_License_DeniedEmitsAudit(t *testing.T) {
	t.Run("api-license/AC-08", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		req := asRole(t, "POST", url+"/api/v1/diagnostics:premium-echo", auth.RoleViewer,
			map[string]string{"message": "premium"})
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
// api-license/AC-09: POST /:premium-echo by a caller holding system:read,
// with a license that includes premium_diagnostics, returns 200 with the
// echoed message.
func TestAPI_PremiumEcho_AllowedWithLicense(t *testing.T) {
	t.Run("api-license/AC-09", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		installEnterpriseLicense(t, "premium_diagnostics")

		req := asRole(t, "POST", url+"/api/v1/diagnostics:premium-echo", auth.RoleViewer,
			map[string]string{"message": "premium-allowed"})
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

		// Install license, the same code path SIGHUP triggers.
		installEnterpriseLicense(t, "premium_diagnostics")

		// New state reflected without restart.
		resp = doGet(t, url+"/api/v1/license")
		defer resp.Body.Close()
		var after struct {
			Tier string `json:"tier"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&after)
		if after.Tier != "enterprise" {
			t.Errorf("post-reload tier = %q, want enterprise", after.Tier)
		}
	})
}

// @ac AC-11
// api-license/AC-11: the anonymous GET /license body is exactly three fields.
//
// The assertion is on the WHOLE decoded key set, not on five named fields
// being absent. That is the point: a property added to LicenseStateResponse
// later fails this test until someone sorts it into a class on purpose, and
// the question it forces is the one C-06 wants the next author to answer.
func TestAPI_License_AnonymousBodyIsAllowlisted(t *testing.T) {
	t.Run("api-license/AC-11", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		installEnterpriseLicense(t, "premium_diagnostics", "remediation_execution")

		got := licenseKeys(getLicenseBody(t, url, ""))
		if !sameKeySet(got, licenseAnonymousFields) {
			t.Errorf("anonymous key set = %v, want exactly %v.\n"+
				"A field is anonymous only if a pre-login screen needs it AND it is "+
				"not a customer or infrastructure fact (C-06). An unsorted field is "+
				"gated by default, so add it to the handler allowlist only on purpose.",
				got, licenseAnonymousFields)
		}
	})
}

// @ac AC-12
// api-license/AC-12: a caller holding system:read sees the whole response.
//
// expires_at sits inside the same permission check that already protected
// customer_id. It was set outside it, which is how a contract end date stayed
// anonymous while the customer's identity did not. A contract end date lets
// anyone who can reach the port time renewal pressure and predict the day
// enterprise features stop.
func TestAPI_License_SystemReadSeesFullResponse(t *testing.T) {
	t.Run("api-license/AC-12", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		installEnterpriseLicense(t, "premium_diagnostics")

		body := getLicenseBody(t, url, auth.RoleViewer)
		for _, field := range append(append([]string{}, licenseAnonymousFields...), licenseGatedFields...) {
			if _, ok := body[field]; !ok {
				t.Errorf("system:read body is missing %q; keys = %v", field, licenseKeys(body))
			}
		}
		if cid := licenseString(t, body, "customer_id"); cid == "" {
			t.Error("customer_id is empty for a system:read caller")
		}
		if exp := licenseString(t, body, "expires_at"); exp == "" {
			t.Error("expires_at is empty for a system:read caller")
		}
	})
}

// @ac AC-13
// api-license/AC-13: presence never encodes value.
//
// GET /license runs twice against two loaded licenses, one where the gated
// flags are true and one where they are false. The anonymous key set is
// identical across both runs and the system:read key set is identical across
// both runs; only the values differ. Without this, an anonymous caller could
// read a gated flag from whether the field appeared at all.
//
// expires_at is covered by the same rule and is the one gated field that is
// not a boolean: whenever a license is loaded it is present for system:read
// and absent anonymously, whatever date it holds.
//
// using_prev_key is deliberately tested in its false state only, and this leg
// is partial on purpose rather than forgotten. No build can reach the true
// state: internal/license/keys/ ships only license-pubkey-current.pem, so
// ring.prev is nil, and internal/license/validator.go sets usingPrev only when
// the signature verifies against ring.prev. The true case becomes reachable
// when a key rotation ships a second PEM, and this test should grow the flip
// then. Until it does, the presence rule still applies to a permanently-false
// field: using_prev_key is absent anonymously and present with value false for
// system:read, in both runs.
func TestAPI_License_PresenceNeverEncodesValue(t *testing.T) {
	t.Run("api-license/AC-13", func(t *testing.T) {
		url, _ := freshAPIServer(t)

		// Run one: gated flags true. The license expired yesterday, inside the
		// 30-day grace window, and loads against a watermark two hours ahead of
		// the clock, so in_grace_period and clock_rollback_detected are both set.
		installLicense(t,
			mintLicenseJWT(t, []string{"premium_diagnostics"}, time.Now().Add(-24*time.Hour)),
			time.Now().Add(2*time.Hour))
		trueAnon := getLicenseBody(t, url, "")
		trueRead := getLicenseBody(t, url, auth.RoleViewer)
		if !licenseBool(t, trueRead, "in_grace_period") {
			t.Error("run one: in_grace_period = false, want true (license is inside the grace window)")
		}
		if !licenseBool(t, trueRead, "clock_rollback_detected") {
			t.Error("run one: clock_rollback_detected = false, want true (loaded behind the watermark)")
		}

		// The watermark ratchets forward inside the loaded state, so clear it
		// before installing the clean license or run two inherits the rollback.
		license.Reset()

		// Run two: the same fields, all false.
		installEnterpriseLicense(t, "premium_diagnostics")
		falseAnon := getLicenseBody(t, url, "")
		falseRead := getLicenseBody(t, url, auth.RoleViewer)
		if licenseBool(t, falseRead, "in_grace_period") {
			t.Error("run two: in_grace_period = true, want false (license is active)")
		}
		if licenseBool(t, falseRead, "clock_rollback_detected") {
			t.Error("run two: clock_rollback_detected = true, want false (clean watermark)")
		}

		// using_prev_key is false in both runs, for the reason above. Assert the
		// value, not just the key, so the field is pinned to the state a shipped
		// build can actually produce.
		if licenseBool(t, trueRead, "using_prev_key") {
			t.Error("run one: using_prev_key = true; no build embeds a prev key")
		}
		if licenseBool(t, falseRead, "using_prev_key") {
			t.Error("run two: using_prev_key = true; no build embeds a prev key")
		}

		if !sameKeySet(licenseKeys(trueAnon), licenseKeys(falseAnon)) {
			t.Errorf("anonymous key set differs with the flag values: %v vs %v. "+
				"Absence itself would be the disclosure.",
				licenseKeys(trueAnon), licenseKeys(falseAnon))
		}
		if !sameKeySet(licenseKeys(trueRead), licenseKeys(falseRead)) {
			t.Errorf("system:read key set differs with the flag values: %v vs %v",
				licenseKeys(trueRead), licenseKeys(falseRead))
		}

		// Each gated field is present for system:read and absent anonymously in
		// BOTH runs, expires_at included whatever date it holds.
		for _, run := range []struct {
			name string
			anon map[string]json.RawMessage
			read map[string]json.RawMessage
		}{
			{"flags true", trueAnon, trueRead},
			{"flags false", falseAnon, falseRead},
		} {
			for _, field := range licenseGatedFields {
				if _, ok := run.anon[field]; ok {
					t.Errorf("%s: %q present anonymously; keys = %v", run.name, field, licenseKeys(run.anon))
				}
				if _, ok := run.read[field]; !ok {
					t.Errorf("%s: %q missing for system:read; keys = %v", run.name, field, licenseKeys(run.read))
				}
			}
		}
	})
}

// @ac AC-14
// api-license/AC-14: clock_rollback_detected renders
// License.ClockRollbackDetected, and only for system:read.
//
// This is the flag's first and only consumer. Before it the rollback warning
// reached the audit log and no further, so an operator running the SPA could
// not see the warning at all. Gating it does not hide the detection from an
// adversary with root, who can read the audit log and the watermark row
// directly. What it denies is the cheap unauthenticated version: with the
// field exposed, a curl loop can binary-search the tolerance boundary to find
// the largest rollback that goes unflagged, at no cost and with no session.
func TestAPI_License_ClockRollbackDetectedIsGated(t *testing.T) {
	t.Run("api-license/AC-14", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		jwtBlob := mintTestLicenseJWT(t, []string{"premium_diagnostics"})

		// Clock wound back behind the stored watermark.
		installLicense(t, jwtBlob, time.Now().Add(2*time.Hour))
		if !licenseBool(t, getLicenseBody(t, url, auth.RoleViewer), "clock_rollback_detected") {
			t.Error("clock_rollback_detected = false after a rollback load, want true")
		}
		if _, ok := getLicenseBody(t, url, "")["clock_rollback_detected"]; ok {
			t.Error("clock_rollback_detected is readable anonymously")
		}

		license.Reset()

		// The same license against a clean watermark.
		installLicense(t, jwtBlob, time.Time{})
		if licenseBool(t, getLicenseBody(t, url, auth.RoleViewer), "clock_rollback_detected") {
			t.Error("clock_rollback_detected = true against a clean watermark, want false")
		}
		if _, ok := getLicenseBody(t, url, "")["clock_rollback_detected"]; ok {
			t.Error("clock_rollback_detected is readable anonymously")
		}
	})
}

// @ac AC-15
// api-license/AC-15: an anonymous POST /:premium-echo is stopped by RBAC, not
// by the license.
//
// Both halves matter. Testing only the licensed instance would pass even if
// the handler ran the checks in the wrong order, and testing only the
// unlicensed one would pass on a 402 that happens to look like a denial.
// License state is process-global rather than per-caller, so the feature check
// alone told the server what the DEPLOYMENT bought and never who was asking.
func TestAPI_PremiumEcho_AnonymousStoppedByRBAC(t *testing.T) {
	t.Run("api-license/AC-15", func(t *testing.T) {
		url, _ := freshAPIServer(t)

		// No license installed: still 401, never 402.
		req, _ := http.NewRequest("POST", url+"/api/v1/diagnostics:premium-echo",
			strings.NewReader(`{"message":"anon-unlicensed"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "anon-unlicensed-key")
		resp := doReq(t, req)
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("unlicensed anonymous status = %d, want 401 (RBAC runs first); body=%s",
				resp.StatusCode, b)
		}
		if !strings.Contains(string(b), "auth.required") {
			t.Errorf("unlicensed anonymous body lacks auth.required: %s", b)
		}

		// premium_diagnostics enabled: still 401, never 200.
		installEnterpriseLicense(t, "premium_diagnostics")
		req, _ = http.NewRequest("POST", url+"/api/v1/diagnostics:premium-echo",
			strings.NewReader(`{"message":"anon-licensed"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "anon-licensed-key")
		resp = doReq(t, req)
		b, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("licensed anonymous status = %d, want 401 (a licensed instance must not "+
				"open the route to everyone); body=%s", resp.StatusCode, b)
		}
		if strings.Contains(string(b), "anon-licensed") {
			t.Errorf("licensed anonymous call reached the handler and echoed: %s", b)
		}
	})
}

// @ac AC-16
// api-license/AC-16: an authenticated caller whose role does not grant
// system:read gets 403 authz.permission_denied, with the same result whether
// or not the license grants premium_diagnostics.
//
// All five built-in roles hold system:read, so the fixture sessions cannot
// produce this case. The identity is built directly instead: IsAnonymous
// false with a RoleID auth.BuiltInRoles does not resolve is authenticated and
// grants nothing, which is exactly the 403 case. The handler is called
// directly because that identity cannot be minted through the session binder.
func TestAPI_PremiumEcho_AuthenticatedWithoutPermission(t *testing.T) {
	t.Run("api-license/AC-16", func(t *testing.T) {
		_, pool := freshAPIServer(t)
		h := &handlers{pool: pool}

		unknownRole := auth.RoleID("role-that-grants-nothing")
		if _, resolves := auth.BuiltInRoles[unknownRole]; resolves {
			t.Fatalf("fixture role %q resolves in BuiltInRoles; pick one that does not", unknownRole)
		}

		call := func(key string) (int, string) {
			req := httptest.NewRequest("POST", "/api/v1/diagnostics:premium-echo",
				strings.NewReader(`{"message":"no-permission"}`))
			req.Header.Set("Content-Type", "application/json")
			req = req.WithContext(auth.SetIdentity(req.Context(), auth.Identity{
				ID:          "authenticated-but-unprivileged",
				RoleID:      unknownRole,
				IsAnonymous: false,
			}))
			rec := httptest.NewRecorder()
			h.PostDiagnosticsPremiumEcho(rec, req, api.PostDiagnosticsPremiumEchoParams{
				IdempotencyKey: key,
			})
			return rec.Code, rec.Body.String()
		}

		// Unlicensed: 403, not 402. The status must not tell the caller what
		// the deployment bought.
		code, body := call("no-perm-unlicensed")
		if code != http.StatusForbidden {
			t.Errorf("unlicensed status = %d, want 403; body=%s", code, body)
		}
		if !strings.Contains(body, "authz.permission_denied") {
			t.Errorf("unlicensed body lacks authz.permission_denied: %s", body)
		}

		// Licensed for premium_diagnostics: the same 403.
		installEnterpriseLicense(t, "premium_diagnostics")
		code, body = call("no-perm-licensed")
		if code != http.StatusForbidden {
			t.Errorf("licensed status = %d, want 403; body=%s", code, body)
		}
		if !strings.Contains(body, "authz.permission_denied") {
			t.Errorf("licensed body lacks authz.permission_denied: %s", body)
		}
	})
}

// @ac AC-17
// api-license/AC-17: the contract declares the permission the handler
// enforces. The declaration is what puts the route in scope for the per-route
// enforcement gate in system-rbac AC-18, which then holds the handler to the
// matching typed constant at build time. Verified by source inspection of
// api/openapi.yaml.
func TestAPI_PremiumEcho_ContractDeclaresPermission(t *testing.T) {
	t.Run("api-license/AC-17", func(t *testing.T) {
		gates := operationGates(t)
		got, ok := gates["postDiagnosticsPremiumEcho"]
		if !ok {
			t.Fatal("postDiagnosticsPremiumEcho is not in api/openapi.yaml; the contract or the parser is stale")
		}
		if got.Permission != "system:read" {
			t.Errorf("x-required-permission = %q, want system:read", got.Permission)
		}
		if got.Feature != "premium_diagnostics" {
			t.Errorf("x-required-feature = %q, want premium_diagnostics", got.Feature)
		}
	})
}

// @ac AC-18
// api-license/AC-18: grace state stays public through status, and gating
// in_grace_period closes nothing.
//
// All three surfaces are asserted together rather than any one alone. Both
// fields come from a single inGrace boolean in internal/license/validator.go,
// so they are one fact written twice, not two facts that happen to agree.
// in_grace_period is gated as surface minimization, and this test keeps the
// record honest: an anonymous caller still reads grace state from status on
// two routes, so nobody may later cite the gate as having made grace state
// private.
func TestAPI_License_GraceStaysPublicThroughStatus(t *testing.T) {
	t.Run("api-license/AC-18", func(t *testing.T) {
		url, _ := freshAPIServer(t)

		capabilitiesStatus := func() string {
			resp := doGet(t, url+"/api/v1/capabilities")
			defer resp.Body.Close()
			var got struct {
				Status string `json:"status"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
				t.Fatalf("decode /capabilities: %v", err)
			}
			return got.Status
		}

		// Inside the grace window.
		installLicense(t,
			mintLicenseJWT(t, []string{"premium_diagnostics"}, time.Now().Add(-24*time.Hour)),
			time.Time{})
		if s := licenseString(t, getLicenseBody(t, url, ""), "status"); s != "grace" {
			t.Errorf("anonymous /license status = %q, want grace", s)
		}
		if s := capabilitiesStatus(); s != "grace" {
			t.Errorf("anonymous /capabilities status = %q, want grace", s)
		}
		if !licenseBool(t, getLicenseBody(t, url, auth.RoleViewer), "in_grace_period") {
			t.Error("system:read in_grace_period = false inside the grace window, want true")
		}

		license.Reset()

		// Outside the grace window, all three report the non-grace state.
		installEnterpriseLicense(t, "premium_diagnostics")
		if s := licenseString(t, getLicenseBody(t, url, ""), "status"); s != "active" {
			t.Errorf("anonymous /license status = %q, want active", s)
		}
		if s := capabilitiesStatus(); s != "active" {
			t.Errorf("anonymous /capabilities status = %q, want active", s)
		}
		if licenseBool(t, getLicenseBody(t, url, auth.RoleViewer), "in_grace_period") {
			t.Error("system:read in_grace_period = true outside the grace window, want false")
		}
	})
}

// @ac AC-19
// api-license/AC-19: POST /:premium-echo with a message longer than 1024
// characters returns 400 validation.field_range, the same as :echo does for
// the same input, and the rejected request writes nothing.
//
// The oversized message is sent by a caller holding system:read against a
// licensed instance, which is what proves the cap is independent of the RBAC
// gate. RBAC does not close this: an authenticated caller with system:read can
// still write unbounded text into the audit log, and a compliance reviewer
// later reads that content as evidence. Testing the cap only against an
// anonymous caller would pass on the 401 and prove nothing.
//
// The no-replay half holds because internal/idempotency/middleware.go stores a
// row only after the handler returns and only for a 2xx, so a 400 must not
// become a cached success.
func TestAPI_PremiumEcho_MessageLengthCapped(t *testing.T) {
	t.Run("api-license/AC-19", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		installEnterpriseLicense(t, "premium_diagnostics")

		const idemKey = "premium-oversize-key"
		const corrID = "premium-oversize-corr"
		oversized := strings.Repeat("A", 1025)

		req := asRole(t, "POST", url+"/api/v1/diagnostics:premium-echo", auth.RoleViewer,
			map[string]string{"message": oversized})
		req.Header.Set("Idempotency-Key", idemKey)
		req.Header.Set("X-Correlation-Id", corrID)
		resp := doReq(t, req)
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 for a %d-character message; body=%s",
				resp.StatusCode, len(oversized), b)
		}
		if !strings.Contains(string(b), "validation.field_range") {
			t.Errorf("body lacks validation.field_range: %s", b)
		}
		time.Sleep(150 * time.Millisecond) // let the audit writer flush

		// Nothing attacker-controlled reached the audit log.
		var audits int64
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM audit_events WHERE correlation_id = $1`, corrID,
		).Scan(&audits); err != nil {
			t.Fatalf("count audit: %v", err)
		}
		if audits != 0 {
			t.Errorf("audit rows for the rejected request = %d, want 0; the cap exists to keep "+
				"unbounded attacker-controlled text out of the audit log", audits)
		}

		// And the 400 was not cached for replay.
		var cached int64
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM idempotency_keys WHERE key = $1`, idemKey,
		).Scan(&cached); err != nil {
			t.Fatalf("count idempotency rows: %v", err)
		}
		if cached != 0 {
			t.Errorf("idempotency rows for the rejected request = %d, want 0", cached)
		}
	})
}
