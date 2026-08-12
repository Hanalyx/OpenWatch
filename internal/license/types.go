// Package license owns license file loading, JWT validation, atomic state
// for hot-path IsEnabled checks, the RequireFeature HTTP middleware, and
// the license.* audit emissions.
//
// One State per process, swapped atomically on Load and Reload. Hot path:
//
//	if !license.IsEnabled(license.RemediationExecution) { ... }
//
// is one atomic pointer load + one map read (~20ns).
//
// Spec:
//   - specs/system/license-validation.spec.yaml
//   - specs/system/license-features.spec.yaml
package license

import "time"

// Status is the license lifecycle stage at runtime.
type Status string

const (
	StatusActive    Status = "active"     // valid signature, not expired
	StatusGrace     Status = "grace"      // expired but within 30-day grace window
	StatusExpired   Status = "expired"    // past grace; only free features available
	StatusNoLicense Status = "no_license" // boot-time fallback when no file present
	StatusInvalid   Status = "invalid"    // signature/claims invalid; rejected
)

// VerifyResult is the typed outcome of a single license validation pass.
// /admin/license:verify returns this verbatim.
type VerifyResult string

const (
	VerifyValid               VerifyResult = "valid"
	VerifySignatureInvalid    VerifyResult = "signature_invalid"
	VerifyIssuerInvalid       VerifyResult = "issuer_invalid"
	VerifyAudienceInvalid     VerifyResult = "audience_invalid"
	VerifyExpired             VerifyResult = "expired"
	VerifyNotYetValid         VerifyResult = "not_yet_valid"
	VerifyFingerprintMismatch VerifyResult = "fingerprint_mismatch"
	VerifyClockRollback       VerifyResult = "clock_rollback"
	VerifyMalformedJWT        VerifyResult = "malformed_jwt"
)

// Two results were removed because nothing produced them. "unknown_feature"
// went when an unknown id stopped invalidating a license (decision record 04).
// "clock_skew" never had a producer at all: an iat beyond the skew budget
// returns not_yet_valid. The contract types verify_result as a plain string,
// not an enum, so neither removal changes the wire.

// License is the parsed and validated license claims. Sensitive material
// (raw JWT, signature) is NOT persisted here — only the operational shape.
type License struct {
	Tier            Tier
	Status          Status
	Features        []Feature
	Issuer          string
	Audience        string
	CustomerID      string // opaque tenant identifier
	IssuedAt        time.Time
	ExpiresAt       time.Time
	Fingerprint     string // bound deployment fingerprint; empty = portable
	UsingPrevKey    bool   // signed with the previous key (warning surface)
	InGracePeriod   bool   // expired but within 30-day grace
	UnknownFeatures []string
	// ClockRollbackDetected reports that this deployment's clock sits behind
	// the recorded watermark by more than the tolerance. It is a WARNING, not
	// a denial: the license still loads. See decision record 06.
	ClockRollbackDetected bool
}

// State is the runtime snapshot kept under an atomic.Pointer. Lock-free
// readers see either an old or new State, never a partial state.
type State struct {
	License       *License // nil when no license loaded (free tier)
	LoadedAt      time.Time
	LastKnownGood time.Time
	enabled       map[Feature]bool // precomputed for IsEnabled hot path
}

// IsEnabled is the hot-path check the RequireFeature middleware calls.
// Free-tier features are always enabled; non-free features require a
// license that explicitly grants them.
//
// p99 < 50ns per specs/system/license-features.spec.yaml AC-8.
func (s *State) IsEnabled(f Feature) bool {
	if s == nil {
		// No state loaded yet — treat as no_license. Free features are
		// still allowed via the registry fallback below.
		if meta, ok := FeatureRegistry[f]; ok && meta.Tier == TierFree {
			return true
		}
		return false
	}
	return s.enabled[f]
}
