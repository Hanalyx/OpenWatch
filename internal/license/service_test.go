// @spec system-license-validation
//
// AC traceability:
// @ac AC-18  (TestLoadJWT_WatermarkIsARatchet)

package license

import (
	"testing"
	"time"
)

// installTestKeyring points the package-global keyring at the testdata signing
// key for the duration of the test, so the load path verifies the JWTs these
// tests mint instead of the real key the binary embeds. It also restores the
// license state, which LoadJWT swaps process-wide.
func installTestKeyring(t *testing.T) {
	t.Helper()
	restoreStateAfter(t)
	t.Cleanup(SetVerificationKeyForTesting(testKeyPublic(t, "license-privkey-test.pem")))
	Reset()
}

// @ac AC-18
// AC-18: the last_known_good watermark only ever moves forward. Verify tolerates
// an hour of backwards drift, so a load at 59 minutes behind the watermark
// succeeds. Writing that accepted reading back would drop the watermark by 59
// minutes, and repeating it would walk the watermark down after the clock with
// no check ever failing.
func TestLoadJWT_WatermarkIsARatchet(t *testing.T) {
	t.Run("system-license-validation/AC-18", func(t *testing.T) {
		installTestKeyring(t)

		anchor := time.Now()
		jwtBlob := signJWT(t, claimsAt(anchor.Add(-2*time.Hour)), "")

		result, err := LoadJWT(jwtBlob, VerifyOptions{Now: fixedNow(anchor)})
		if err != nil {
			t.Fatalf("first load: %v", err)
		}
		if result != VerifyValid {
			t.Fatalf("first load: result = %s, want valid", result)
		}
		if got := CurrentState().LastKnownGood; !got.Equal(anchor) {
			t.Fatalf("watermark after first load = %v, want %v", got, anchor)
		}

		// Same blob, clock walked back 59 minutes. Inside the tolerance, so the
		// load succeeds, which is exactly the case that could lower the mark.
		earlier := anchor.Add(-59 * time.Minute)
		result, err = LoadJWT(jwtBlob, VerifyOptions{Now: fixedNow(earlier)})
		if err != nil {
			t.Fatalf("second load: %v", err)
		}
		if result != VerifyValid {
			t.Fatalf("second load: result = %s, want valid; 59 minutes is inside the tolerance", result)
		}
		if got := CurrentState().LastKnownGood; !got.Equal(anchor) {
			t.Errorf("watermark = %v, want %v; an accepted load moved it backwards", got, anchor)
		}
	})
}

// TestLoadJWT_ReloadIsNotRollback pins the false positive that decision record
// 03 closed. Loading an unchanged license file twice reported clock_rollback,
// because the check compared the license iat against the watermark the first
// load had just written. The comparison is now against now, so a reload is
// ordinary.
func TestLoadJWT_ReloadIsNotRollback(t *testing.T) {
	installTestKeyring(t)

	anchor := time.Now()
	jwtBlob := signJWT(t, claimsAt(anchor.Add(-2*time.Hour)), "")

	for i, at := range []time.Time{anchor, anchor.Add(time.Second)} {
		result, err := LoadJWT(jwtBlob, VerifyOptions{Now: fixedNow(at)})
		if err != nil {
			t.Fatalf("load %d: %v", i+1, err)
		}
		if result != VerifyValid {
			t.Fatalf("load %d: result = %s, want valid; reloading an unchanged license is not a rollback", i+1, result)
		}
	}
}
