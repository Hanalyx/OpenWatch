// @spec system-license-validation
//
// AC traceability:
// @ac AC-01  (TestVerify_ValidJWT)
// @ac AC-02  (TestVerify_TamperedSignature)
// @ac AC-03  (TestVerify_PrevKey)
// @ac AC-04  (TestVerify_WrongIssuer)
// @ac AC-05  (TestVerify_WrongAudience)
// @ac AC-06  (TestVerify_HardExpired)
// @ac AC-07  (TestVerify_GracePeriod)
// @ac AC-08  (TestVerify_IatInFuture (NotYetValid via iat tampering))
// @ac AC-09  (TestVerify_ClockRollback)
// @ac AC-10  (TestVerify_FingerprintMismatch)
// @ac AC-11  (TestVerify_UnknownFeature)
// @ac AC-12  (TestVerify_MalformedJWT)
// @ac AC-13  (TestVerify_P99Latency)
// @ac AC-15  (TestVerify_ClockRollbackTolerance)
// @ac AC-16  (TestVerify_ZeroWatermark)
// @ac AC-17  (TestVerify_OlderLicenseIsNotRollback)

package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/perftest"
	"github.com/golang-jwt/jwt/v5"
)

// signJWT mints a test license JWT signed with the package's test
// private key. Tests load the private key from internal/license/testdata
// (alongside the embedded public key).
func signJWT(t *testing.T, c claims, useKeyPath string) string {
	t.Helper()
	if useKeyPath == "" {
		useKeyPath = filepath.Join("testdata", "license-privkey-test.pem")
	}
	raw, err := os.ReadFile(useKeyPath)
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
		t.Fatalf("not ed25519: %T", keyAny)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, &c)
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func validClaims() claims {
	now := time.Now().Add(-1 * time.Minute)
	return claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    expectedIssuer,
			Audience:  jwt.ClaimStrings{expectedAudience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(365 * 24 * time.Hour)),
		},
		Tier:       TierEnterprise,
		Features:   []string{"premium_diagnostics", "remediation_execution"},
		CustomerID: "test-customer",
	}
}

// claimsAt mints claims whose iat and exp bracket base, so a test that hands
// Verify an injected clock is not tripped by the iat skew check on its way to
// the assertion it actually cares about.
func claimsAt(base time.Time) claims {
	c := validClaims()
	c.IssuedAt = jwt.NewNumericDate(base.Add(-24 * time.Hour))
	c.ExpiresAt = jwt.NewNumericDate(base.Add(365 * 24 * time.Hour))
	return c
}

// fixedNow returns a clock stuck at t, for VerifyOptions.Now. Time travel in
// these tests is injected, never slept for.
func fixedNow(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

// restoreStateAfter snapshots the package-global license state and puts it back
// when the test ends. The state is process-wide, so a test that installs a
// license must not leak it into whichever test runs next.
func restoreStateAfter(t *testing.T) {
	t.Helper()
	prev := current.Load()
	t.Cleanup(func() { current.Store(prev) })
}

// mustRing builds a key ring from the testdata signing key (the same key
// signJWT signs with), so the verification-logic tests are independent of
// whichever real production key is embedded in keys/license-pubkey-current.pem.
// That the embedded key is NOT this test key is covered separately by
// TestEmbeddedKey_NotTestKey (AC-14).
func mustRing(t *testing.T) *publicKeyRing {
	t.Helper()
	return &publicKeyRing{current: testKeyPublic(t, "license-privkey-test.pem")}
}

// @ac AC-01  (Valid JWT validates and returns a populated License.)
func TestVerify_ValidJWT(t *testing.T) {
	t.Run("system-license-validation/AC-01", func(t *testing.T) {

		jwtBlob := signJWT(t, validClaims(), "")
		lic, result, err := Verify(jwtBlob, mustRing(t), VerifyOptions{})
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if result != VerifyValid {
			t.Errorf("result = %s, want valid", result)
		}
		if lic == nil {
			t.Fatal("license is nil on valid JWT")
		}
		if lic.Tier != TierEnterprise {
			t.Errorf("tier = %s, want enterprise", lic.Tier)
		}
		if len(lic.Features) != 2 {
			t.Errorf("features = %v, want 2 entries", lic.Features)
		}
	})
}

// @ac AC-02  (Tampered signature returns SignatureInvalid.)
func TestVerify_TamperedSignature(t *testing.T) {
	t.Run("system-license-validation/AC-02", func(t *testing.T) {

		jwtBlob := signJWT(t, validClaims(), "")
		// Flip a character in the signature segment.
		parts := strings.Split(jwtBlob, ".")
		tampered := parts[0] + "." + parts[1] + "." + flipFirst(parts[2])
		_, result, _ := Verify(tampered, mustRing(t), VerifyOptions{})
		if result != VerifySignatureInvalid {
			t.Errorf("result = %s, want signature_invalid", result)
		}
	})
}

// @ac AC-04  (Wrong issuer returns IssuerInvalid.)
func TestVerify_WrongIssuer(t *testing.T) {
	t.Run("system-license-validation/AC-04", func(t *testing.T) {

		c := validClaims()
		c.Issuer = "evil-co"
		jwtBlob := signJWT(t, c, "")
		_, result, _ := Verify(jwtBlob, mustRing(t), VerifyOptions{})
		if result != VerifyIssuerInvalid {
			t.Errorf("result = %s, want issuer_invalid", result)
		}
	})
}

// @ac AC-05  (Wrong audience returns AudienceInvalid.)
func TestVerify_WrongAudience(t *testing.T) {
	t.Run("system-license-validation/AC-05", func(t *testing.T) {

		c := validClaims()
		c.Audience = jwt.ClaimStrings{"some-other-product"}
		jwtBlob := signJWT(t, c, "")
		_, result, _ := Verify(jwtBlob, mustRing(t), VerifyOptions{})
		if result != VerifyAudienceInvalid {
			t.Errorf("result = %s, want audience_invalid", result)
		}
	})
}

// @ac AC-06  (Expired beyond grace returns Expired.)
func TestVerify_HardExpired(t *testing.T) {
	t.Run("system-license-validation/AC-06", func(t *testing.T) {

		c := validClaims()
		c.IssuedAt = jwt.NewNumericDate(time.Now().Add(-400 * 24 * time.Hour))
		c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-90 * 24 * time.Hour))
		jwtBlob := signJWT(t, c, "")
		_, result, _ := Verify(jwtBlob, mustRing(t), VerifyOptions{})
		if result != VerifyExpired {
			t.Errorf("result = %s, want expired", result)
		}
	})
}

// @ac AC-07  (Expired but within grace validates with InGracePeriod=true.)
func TestVerify_GracePeriod(t *testing.T) {
	t.Run("system-license-validation/AC-07", func(t *testing.T) {

		c := validClaims()
		c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-7 * 24 * time.Hour)) // 7 days ago, within 30-day grace
		jwtBlob := signJWT(t, c, "")
		lic, result, _ := Verify(jwtBlob, mustRing(t), VerifyOptions{})
		if result != VerifyValid {
			t.Errorf("result = %s, want valid (grace)", result)
		}
		if lic == nil || !lic.InGracePeriod {
			t.Error("expected InGracePeriod = true")
		}
		if lic != nil && lic.Status != StatusGrace {
			t.Errorf("status = %s, want grace", lic.Status)
		}
	})
}

// @ac AC-08  (iat in the future (beyond clock-skew budget) returns NotYetValid.)
func TestVerify_IatInFuture(t *testing.T) {
	t.Run("system-license-validation/AC-08", func(t *testing.T) {

		c := validClaims()
		c.IssuedAt = jwt.NewNumericDate(time.Now().Add(2 * time.Hour))
		c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(48 * time.Hour))
		jwtBlob := signJWT(t, c, "")
		_, result, _ := Verify(jwtBlob, mustRing(t), VerifyOptions{})
		if result != VerifyNotYetValid {
			t.Errorf("result = %s, want not_yet_valid", result)
		}
	})
}

// @ac AC-09  (now more than an hour behind LastKnownGood returns ClockRollback.)
func TestVerify_ClockRollback(t *testing.T) {
	t.Run("system-license-validation/AC-09", func(t *testing.T) {
		// The clock has been wound back two hours, well past the one-hour
		// tolerance. The comparison is now against the watermark, not the
		// license iat (decision record 03), so the license itself is ordinary.
		lkg := time.Now()
		now := lkg.Add(-2 * time.Hour)

		jwtBlob := signJWT(t, claimsAt(now), "")
		_, result, err := Verify(jwtBlob, mustRing(t), VerifyOptions{
			Now:           fixedNow(now),
			LastKnownGood: lkg,
		})
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if result != VerifyClockRollback {
			t.Errorf("result = %s, want clock_rollback", result)
		}
	})
}

// @ac AC-11  (An unknown feature id stays Valid, is carried, and enables nothing.)
func TestVerify_UnknownFeature(t *testing.T) {
	t.Run("system-license-validation/AC-11", func(t *testing.T) {
		restoreStateAfter(t)

		c := validClaims()
		c.Features = []string{"premium_diagnostics", "not_a_real_feature"}
		jwtBlob := signJWT(t, c, "")

		lic, result, err := Verify(jwtBlob, mustRing(t), VerifyOptions{})
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if result != VerifyValid {
			t.Fatalf("result = %s, want valid; an unknown id must not invalidate a license", result)
		}
		if len(lic.Features) != 1 || lic.Features[0] != PremiumDiagnostics {
			t.Errorf("Features = %v, want only premium_diagnostics", lic.Features)
		}
		if len(lic.UnknownFeatures) != 1 || lic.UnknownFeatures[0] != "not_a_real_feature" {
			t.Errorf("UnknownFeatures = %v, want [not_a_real_feature]", lic.UnknownFeatures)
		}

		// An unknown id must not switch anything on. Install through setState so
		// the lookup map is the one the hot path reads. A hand-built State has a
		// nil map, and every IsEnabled call against it would answer false for the
		// wrong reason. The known feature is the control.
		setState(&State{License: lic, LoadedAt: time.Now()})
		if !IsEnabled(PremiumDiagnostics) {
			t.Error("premium_diagnostics not enabled; the known half of the claim was dropped")
		}
		if IsEnabled(Feature("not_a_real_feature")) {
			t.Error("an unregistered feature id enabled itself")
		}
	})
}

// @ac AC-12  (Malformed JWT returns MalformedJWT without panicking.)
func TestVerify_MalformedJWT(t *testing.T) {
	t.Run("system-license-validation/AC-12", func(t *testing.T) {

		// Truly malformed input: not 3 dot-separated base64 segments.
		_, result, _ := Verify("garbage-not-a-jwt-at-all", mustRing(t), VerifyOptions{})
		if result != VerifyMalformedJWT {
			t.Errorf("result = %s, want malformed_jwt exactly (not signature_invalid)", result)
		}
	})
}

// @ac AC-03  (A JWT signed with the prev key validates and sets UsingPrevKey.)
func TestVerify_PrevKey(t *testing.T) {
	t.Run("system-license-validation/AC-03", func(t *testing.T) {
		// The current slot holds a key nothing here signs with, so verification
		// against current must fail and the prev slot must catch it. Generating
		// that key here keeps the test independent of whichever real key the
		// binary embeds.
		unrelatedPub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate an unrelated current key: %v", err)
		}
		ring := &publicKeyRing{
			current: unrelatedPub,
			prev:    testKeyPublic(t, "license-privkey-test.pem"),
		}

		jwtBlob := signJWT(t, validClaims(), "")
		lic, result, err := Verify(jwtBlob, ring, VerifyOptions{})
		if err != nil {
			t.Fatalf("Verify (prev key path): %v", err)
		}
		if result != VerifyValid {
			t.Fatalf("result = %s, want valid; the prev slot holds the signing key, "+
				"so key rotation would fail in the field", result)
		}
		if !lic.UsingPrevKey {
			t.Error("UsingPrevKey = false, want true; the warning surface stays dark on a rotated key")
		}
	})
}

// @ac AC-15  (Inside the one-hour tolerance stays Valid; outside it is a rollback.)
func TestVerify_ClockRollbackTolerance(t *testing.T) {
	t.Run("system-license-validation/AC-15", func(t *testing.T) {
		lkg := time.Now()
		cases := []struct {
			name   string
			behind time.Duration
			want   VerifyResult
		}{
			// NTP pulling a drifted clock backwards is normal and must not
			// raise a tamper-grade event.
			{"inside the tolerance", 59 * time.Minute, VerifyValid},
			{"outside the tolerance", 61 * time.Minute, VerifyClockRollback},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				now := lkg.Add(-tc.behind)
				jwtBlob := signJWT(t, claimsAt(now), "")
				_, result, err := Verify(jwtBlob, mustRing(t), VerifyOptions{
					Now:           fixedNow(now),
					LastKnownGood: lkg,
				})
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				if result != tc.want {
					t.Errorf("now %v behind the watermark: result = %s, want %s", tc.behind, result, tc.want)
				}
			})
		}
	})
}

// @ac AC-16  (A zero LastKnownGood never reports a rollback.)
func TestVerify_ZeroWatermark(t *testing.T) {
	t.Run("system-license-validation/AC-16", func(t *testing.T) {
		// The injected clock sits five years before the real one, which is what
		// a wound-back clock looks like. The claims are minted around that
		// injected time on purpose. Dated from the real present, the iat skew
		// check fires first and the result says nothing about the watermark.
		now := time.Now().Add(-5 * 365 * 24 * time.Hour)
		jwtBlob := signJWT(t, claimsAt(now), "")

		lic, result, err := Verify(jwtBlob, mustRing(t), VerifyOptions{Now: fixedNow(now)})
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		// Exactly Valid. Accepting anything other than clock_rollback would let
		// a not_yet_valid from the skew check pass for the wrong reason.
		if result != VerifyValid {
			t.Fatalf("result = %s, want valid; a first boot has no watermark to sit behind", result)
		}
		if lic.Status != StatusActive {
			t.Errorf("status = %s, want active", lic.Status)
		}
	})
}

// @ac AC-17  (A license issued before the watermark is not a rollback.)
func TestVerify_OlderLicenseIsNotRollback(t *testing.T) {
	t.Run("system-license-validation/AC-17", func(t *testing.T) {
		// iat sits 200 days behind the watermark while now sits on it. The old
		// code compared iat against the watermark and called this a rollback,
		// which found downgrades instead of wound-back clocks. Installing an
		// older license carries an earlier expiry, so it gains an attacker
		// nothing (decision record 03).
		now := time.Now()
		c := validClaims()
		c.IssuedAt = jwt.NewNumericDate(now.Add(-200 * 24 * time.Hour))
		c.ExpiresAt = jwt.NewNumericDate(now.Add(100 * 24 * time.Hour))
		jwtBlob := signJWT(t, c, "")

		_, result, err := Verify(jwtBlob, mustRing(t), VerifyOptions{
			Now:           fixedNow(now),
			LastKnownGood: now,
		})
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if result != VerifyValid {
			t.Errorf("result = %s, want valid; installing an older license is not a rollback", result)
		}
	})
}

// @ac AC-10  (Mismatched fingerprint returns FingerprintMismatch.)
func TestVerify_FingerprintMismatch(t *testing.T) {
	t.Run("system-license-validation/AC-10", func(t *testing.T) {
		c := validClaims()
		c.Fingerprint = "deployment-a"
		jwtBlob := signJWT(t, c, "")
		_, result, err := Verify(jwtBlob, mustRing(t), VerifyOptions{
			Fingerprint: "deployment-b",
		})
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if result != VerifyFingerprintMismatch {
			t.Errorf("result = %s, want fingerprint_mismatch", result)
		}
	})
}

// @ac AC-13  (Validator latency p99 < 1ms for a single JWT signature verify.)
func TestVerify_P99Latency(t *testing.T) {
	t.Run("system-license-validation/AC-13", func(t *testing.T) {

		jwtBlob := signJWT(t, validClaims(), "")
		ring := mustRing(t)

		const n = 1000
		durs := make([]time.Duration, n)
		for i := 0; i < n; i++ {
			start := time.Now()
			_, _, _ = Verify(jwtBlob, ring, VerifyOptions{})
			durs[i] = time.Since(start)
		}
		// Simple sort + p99 pick.
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
		if p99 > 1*time.Millisecond {
			perftest.Budgetf(t, "Verify p99 = %v, want < 1ms", p99)
		}
		t.Logf("Verify p99 = %v over %d calls", p99, n)
	})
}

func flipFirst(s string) string {
	if s == "" {
		return s
	}
	first := s[0]
	if first == 'A' {
		first = 'B'
	} else {
		first = 'A'
	}
	return string(first) + s[1:]
}
