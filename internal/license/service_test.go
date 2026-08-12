// @spec system-license-validation
//
// AC traceability:
// @ac AC-18  (TestLoadJWT_WatermarkIsARatchet)
// @ac AC-22  (TestLoadJWT_ClockRollbackWarnsAndLoads,
//             TestLoadJWT_ClockRollbackIsNotABypass)
// @ac AC-23  (TestLoadJWT_ReloadDoesNotClearTheWarning)

package license

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/golang-jwt/jwt/v5"
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

// auditRecorder captures what the audit writer was asked to persist, so a test
// can assert an emission without a database behind it. EmitSync writes straight
// through to storage, which is what the license.* events use.
type auditRecorder struct {
	mu      sync.Mutex
	events  []audit.Code
	details []json.RawMessage // parallel to events
}

func (r *auditRecorder) InsertEvent(_ audit.Ctx, ev *audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev.Action)
	r.details = append(r.details, ev.Detail)
	return nil
}

// detailFor returns the decoded detail map of the first event with this code,
// and whether such an event was recorded. Assertions read the emitted detail
// rather than the License struct, so they measure what an auditor can see.
func (r *auditRecorder) detailFor(t *testing.T, code audit.Code) (map[string]any, bool) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, c := range r.events {
		if c != code {
			continue
		}
		var m map[string]any
		if len(r.details[i]) == 0 {
			return nil, true
		}
		if err := json.Unmarshal(r.details[i], &m); err != nil {
			t.Fatalf("decode %s detail %q: %v", code, r.details[i], err)
		}
		return m, true
	}
	return nil, false
}

func (r *auditRecorder) saw(code audit.Code) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.events {
		if c == code {
			return true
		}
	}
	return false
}

// installAuditRecorder points the package-level audit writer at a recorder for
// the duration of the test. Without it every emission logs "called before Init"
// and is dropped, so an assertion on an event would pass or fail for reasons
// that have nothing to do with the license code.
func installAuditRecorder(t *testing.T) *auditRecorder {
	t.Helper()
	rec := &auditRecorder{}
	audit.Init(rec, audit.DefaultWriterOptions())
	t.Cleanup(func() { audit.Shutdown(time.Second) })
	return rec
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

// @ac AC-22
// AC-22: a detected rollback warns and still loads (C-14). The watermark row
// sits in the customer's own database and the adversary has root there, so
// denying would be evadable by deleting the row, while a false positive would
// silently drop a paying deployment to free tier. The license installs, carries
// the mark, and the audit event fires.
func TestLoadJWT_ClockRollbackWarnsAndLoads(t *testing.T) {
	t.Run("system-license-validation/AC-22", func(t *testing.T) {
		installTestKeyring(t)
		rec := installAuditRecorder(t)

		watermark := time.Now()
		wound := watermark.Add(-6 * time.Hour) // far outside the one-hour tolerance
		jwtBlob := signJWT(t, claimsAt(wound), "")

		result, err := LoadJWT(jwtBlob, VerifyOptions{
			Now:           fixedNow(wound),
			LastKnownGood: watermark,
		})
		if err != nil {
			t.Fatalf("LoadJWT: %v", err)
		}
		if result != VerifyValid {
			t.Fatalf("result = %s, want valid; a rollback warns, it does not deny", result)
		}

		st := CurrentState()
		if st == nil || st.License == nil {
			t.Fatal("no license installed; the warning path still has to install")
		}
		if !st.License.ClockRollbackDetected {
			t.Error("ClockRollbackDetected = false, want true; the load is unmarked and the warning is invisible")
		}
		if !IsEnabled(PremiumDiagnostics) {
			t.Error("premium_diagnostics not enabled; the license did not take effect")
		}

		// EmitLoadResult is what the boot and SIGHUP paths call. Under a
		// fail-open policy the result it switches on is Valid, so the rollback
		// event has to be emitted off the flag or it stops firing exactly when
		// it becomes the only signal an operator has.
		EmitLoadResult(context.Background(), "test", result, st.License, nil)
		if !rec.saw(audit.LicenseClockRollbackDetected) {
			t.Error("license.clock_rollback_detected was not emitted")
		}
		if !rec.saw(audit.LicenseInstalled) {
			t.Error("license.installed was not emitted; the install itself went unrecorded")
		}
	})
}

// @ac AC-22
// AC-22: the re-verify is not a bypass. On a rollback the loader verifies a
// second time with the watermark cleared, so every other check has to hold on
// that second pass. Expiry, fingerprint binding and nbf are all checked AFTER
// the rollback branch in Verify, which means the second pass is the only thing
// standing between a wound-back clock and an otherwise invalid license.
//
// Each case runs twice, once with the clock wound back and once with it at the
// watermark. Identical verdicts are the point: the rollback path must not
// change the answer.
func TestLoadJWT_ClockRollbackIsNotABypass(t *testing.T) {
	t.Run("system-license-validation/AC-22", func(t *testing.T) {
		installTestKeyring(t)

		watermark := time.Now()
		wound := watermark.Add(-6 * time.Hour)

		cases := []struct {
			name        string
			blob        func(t *testing.T) string
			fingerprint string
			want        VerifyResult
		}{
			{
				name: "expired beyond grace",
				blob: func(t *testing.T) string {
					c := claimsAt(wound)
					c.IssuedAt = jwt.NewNumericDate(wound.Add(-400 * 24 * time.Hour))
					c.ExpiresAt = jwt.NewNumericDate(wound.Add(-90 * 24 * time.Hour))
					return signJWT(t, c, "")
				},
				want: VerifyExpired,
			},
			{
				name: "bound to another deployment",
				blob: func(t *testing.T) string {
					c := claimsAt(wound)
					c.Fingerprint = "deployment-a"
					return signJWT(t, c, "")
				},
				fingerprint: "deployment-b",
				want:        VerifyFingerprintMismatch,
			},
			{
				name: "nbf still in the future",
				blob: func(t *testing.T) string {
					c := claimsAt(wound)
					c.NotBefore = jwt.NewNumericDate(watermark.Add(24 * time.Hour))
					return signJWT(t, c, "")
				},
				want: VerifyNotYetValid,
			},
			{
				name: "wrong issuer",
				blob: func(t *testing.T) string {
					c := claimsAt(wound)
					c.Issuer = "evil-co"
					return signJWT(t, c, "")
				},
				want: VerifyIssuerInvalid,
			},
			{
				name: "tampered signature",
				blob: func(t *testing.T) string {
					signed := signJWT(t, claimsAt(wound), "")
					parts := strings.Split(signed, ".")
					return parts[0] + "." + parts[1] + "." + flipFirst(parts[2])
				},
				want: VerifySignatureInvalid,
			},
		}

		clocks := []struct {
			name string
			now  time.Time
		}{
			{"clock wound back", wound},
			{"clock at the watermark", watermark},
		}

		for _, tc := range cases {
			for _, clock := range clocks {
				t.Run(tc.name+", "+clock.name, func(t *testing.T) {
					Reset()
					result, _ := LoadJWT(tc.blob(t), VerifyOptions{
						Now:           fixedNow(clock.now),
						LastKnownGood: watermark,
						Fingerprint:   tc.fingerprint,
					})
					if result != tc.want {
						t.Errorf("result = %s, want %s; the rollback re-verify became a bypass", result, tc.want)
					}
					if st := CurrentState(); st != nil && st.License != nil {
						t.Errorf("a refused license was installed: tier %s", st.License.Tier)
					}
					if IsEnabled(PremiumDiagnostics) {
						t.Error("a refused license enabled a paid feature")
					}
				})
			}
		}
	})
}

// @ac AC-23
// AC-23: reloading a license does not clear a rollback warning. The load has to
// ratchet against the watermark it was GIVEN, not only the one already in
// process. On a fresh boot the in-process value is zero while the given value is
// the persisted watermark, so measuring only the in-process one lets a rollback
// load store a time behind T. The next reload then sees the lowered value, finds
// no rollback, and the alert goes away with nothing fixed.
func TestLoadJWT_ReloadDoesNotClearTheWarning(t *testing.T) {
	t.Run("system-license-validation/AC-23", func(t *testing.T) {
		installTestKeyring(t)

		watermark := time.Now() // T, as read from the database at boot
		wound := watermark.Add(-6 * time.Hour)
		jwtBlob := signJWT(t, claimsAt(wound), "")

		// Boot: the clock is behind T, so this warns and loads.
		result, err := LoadJWT(jwtBlob, VerifyOptions{
			Now:           fixedNow(wound),
			LastKnownGood: watermark,
		})
		if err != nil {
			t.Fatalf("boot load: %v", err)
		}
		if result != VerifyValid {
			t.Fatalf("boot load: result = %s, want valid", result)
		}
		st := CurrentState()
		if st.License == nil || !st.License.ClockRollbackDetected {
			t.Fatal("boot load did not mark the rollback")
		}
		if got := st.LastKnownGood; !got.Equal(watermark) {
			t.Fatalf("watermark after the boot load = %v, want %v; the load stored a time behind the one it was given", got, watermark)
		}

		// Reload with empty options, which is what the SIGHUP handler in
		// cmd/openwatch/main.go passes. It does not re-read the database, so
		// the in-process value is the only thing left to catch the rollback.
		result, err = LoadJWT(jwtBlob, VerifyOptions{Now: fixedNow(wound)})
		if err != nil {
			t.Fatalf("reload: %v", err)
		}
		if result != VerifyValid {
			t.Fatalf("reload: result = %s, want valid", result)
		}
		st = CurrentState()
		if st.License == nil {
			t.Fatal("reload dropped the license")
		}
		if !st.License.ClockRollbackDetected {
			t.Error("the reload cleared the rollback warning; reloading would make the alert go away with nothing fixed")
		}
		if got := st.LastKnownGood; !got.Equal(watermark) {
			t.Errorf("watermark after the reload = %v, want %v", got, watermark)
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
