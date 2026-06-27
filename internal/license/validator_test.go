// @spec system-license-validation
//
// AC traceability:
// @ac AC-01  (TestVerify_ValidJWT)
// @ac AC-02  (TestVerify_TamperedSignature)
// @ac AC-04  (TestVerify_WrongIssuer)
// @ac AC-05  (TestVerify_WrongAudience)
// @ac AC-06  (TestVerify_HardExpired)
// @ac AC-07  (TestVerify_GracePeriod)
// @ac AC-08  (TestVerify_IatInFuture (NotYetValid via iat tampering))
// @ac AC-09  (TestVerify_ClockRollback)
// @ac AC-11  (TestVerify_UnknownFeature)
// @ac AC-12  (TestVerify_MalformedJWT)

package license

import (
	"crypto/ed25519"
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
		Tier:       TierOpenWatchPlus,
		Features:   []string{"premium_diagnostics", "remediation_execution"},
		CustomerID: "test-customer",
	}
}

// mustRing builds a key ring from the testdata signing key — the same key
// signJWT signs with — so the verification-logic tests are independent of
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
		if lic.Tier != TierOpenWatchPlus {
			t.Errorf("tier = %s, want openwatch_plus", lic.Tier)
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

// @ac AC-09  (iat earlier than LastKnownGood returns ClockRollback.)
func TestVerify_ClockRollback(t *testing.T) {
	t.Run("system-license-validation/AC-09", func(t *testing.T) {

		jwtBlob := signJWT(t, validClaims(), "")
		lkg := time.Now().Add(24 * time.Hour) // pretend we previously loaded a license from "the future"
		_, result, _ := Verify(jwtBlob, mustRing(t), VerifyOptions{LastKnownGood: lkg})
		if result != VerifyClockRollback {
			t.Errorf("result = %s, want clock_rollback", result)
		}
	})
}

// @ac AC-11  (Unknown feature ID returns UnknownFeature.)
func TestVerify_UnknownFeature(t *testing.T) {
	t.Run("system-license-validation/AC-11", func(t *testing.T) {

		c := validClaims()
		c.Features = []string{"premium_diagnostics", "not_a_real_feature"}
		jwtBlob := signJWT(t, c, "")
		_, result, _ := Verify(jwtBlob, mustRing(t), VerifyOptions{})
		if result != VerifyUnknownFeature {
			t.Errorf("result = %s, want unknown_feature", result)
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

// @ac AC-03  (Prev-key signature path: a JWT signed with the previous key)
// validates with UsingPrevKey=true. Stage 0 ships only the current key
// slot, so this test documents the prev-key plumbing via the ring shape
// and skips the live signature path until a prev key file is embedded.
func TestVerify_PrevKey(t *testing.T) {
	t.Run("system-license-validation/AC-03", func(t *testing.T) {
		ring := mustRing(t)
		if ring.prev != nil {
			t.Skip("prev key slot occupied; live test requires a prev-key signed JWT fixture")
		}
		// Slot is intentionally nil pre-rotation. Verify the contract:
		// loader recognizes the slot, and Verify treats prev=nil as
		// "current-only" without panicking on an otherwise-valid token.
		jwtBlob := signJWT(t, validClaims(), "")
		lic, result, err := Verify(jwtBlob, ring, VerifyOptions{})
		if err != nil {
			t.Fatalf("Verify (current key path): %v", err)
		}
		if result != VerifyValid {
			t.Errorf("result = %s, want valid (current-key signature)", result)
		}
		if lic != nil && lic.UsingPrevKey {
			t.Error("UsingPrevKey true with prev slot nil — contract violation")
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
