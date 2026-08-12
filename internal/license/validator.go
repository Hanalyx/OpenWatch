package license

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	expectedIssuer   = "licensing@hanalyx.com"
	expectedAudience = "openwatch"
	gracePeriod      = 30 * 24 * time.Hour
	clockSkewBudget  = 10 * time.Second
)

// claims is the JSON shape of the JWT payload. Claims beyond standard
// JWT registered claims (iss, aud, exp, iat, nbf) carry license details.
type claims struct {
	jwt.RegisteredClaims
	Tier        Tier     `json:"tier,omitempty"`
	Features    []string `json:"features,omitempty"`
	CustomerID  string   `json:"customer_id,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
}

// VerifyOptions configures how strict Verify is. Production uses the
// defaults; tests inject Now() to simulate time travel and Fingerprint
// to test binding.
type VerifyOptions struct {
	Now         func() time.Time
	Fingerprint string // deployment fingerprint; "" skips the check
	// LastKnownGood is the latest wall-clock time this deployment has been
	// observed at, persisted across restarts. Verify refuses when `now` is
	// meaningfully behind it. Zero skips the check, which is correct on a
	// first boot: there is nothing yet to be behind.
	//
	// This is compared against `now`, NOT against the license's iat. A
	// rolled-back clock does not move iat, so an iat comparison detects
	// installing an older license instead, which is a different thing and
	// not a threat here. See decision record 03.
	LastKnownGood      time.Time
	AllowDeprecatedKey bool // true only in OPENWATCH_DEV_MODE
}

// clockRollbackTolerance is how far behind the watermark `now` may sit before
// Verify calls it a rollback. NTP correcting a drifted clock backwards is
// normal and must not trip a tamper-grade audit event; winding back far enough
// to matter against a 30-day grace period is not.
const clockRollbackTolerance = time.Hour

// Verify parses a JWT license, checks the signature against the keyring,
// validates claims, and returns either a populated License (when Valid)
// or a typed VerifyResult on failure.
//
// Spec: specs/system/license-validation.spec.yaml.
func Verify(jwtBlob string, ring *publicKeyRing, opts VerifyOptions) (*License, VerifyResult, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}

	usingPrev := false
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		// We accept only EdDSA. JWT v5 maps Ed25519 to EdDSA.
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return ring.current, nil
	}

	// WithoutClaimsValidation: we do exp/iat/nbf checks manually below so we
	// can implement the 30-day grace period (jwt v5's default validator
	// rejects expired tokens before our custom logic runs).
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithoutClaimsValidation(),
	)
	parsed, err := parser.ParseWithClaims(jwtBlob, &claims{}, keyFunc)
	if err != nil {
		// Try the prev key if the signature failed against current.
		//
		// Match on ErrTokenSignatureInvalid, which is what jwt v5 wraps every
		// verification failure in. Do NOT match ErrSignatureInvalid: that
		// sentinel is defined and returned only by the HMAC path (hmac.go), so
		// an Ed25519 mismatch (ErrEd25519Verification, ed25519.go) never
		// carries it. Matching it made this branch unreachable, which meant key
		// rotation would have failed in the field the first release a prev key
		// shipped, and only then.
		if ring.prev != nil && errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			parsed, err = parser.ParseWithClaims(jwtBlob, &claims{}, func(*jwt.Token) (interface{}, error) {
				return ring.prev, nil
			})
			if err == nil {
				usingPrev = true
			}
		}
		// Try the deprecated key in dev mode.
		if err != nil && opts.AllowDeprecatedKey && ring.deprecated != nil {
			parsed, err = parser.ParseWithClaims(jwtBlob, &claims{}, func(*jwt.Token) (interface{}, error) {
				return ring.deprecated, nil
			})
		}
		if err != nil {
			return nil, classifyParseError(err), err
		}
	}

	c, ok := parsed.Claims.(*claims)
	if !ok {
		return nil, VerifyMalformedJWT, fmt.Errorf("claims type mismatch")
	}

	// Issuer/audience.
	if c.Issuer != expectedIssuer {
		return nil, VerifyIssuerInvalid, nil
	}
	if !audienceMatch(c.Audience, expectedAudience) {
		return nil, VerifyAudienceInvalid, nil
	}

	now := opts.Now()

	// iat: must exist; must not be > now + clockSkewBudget.
	if c.IssuedAt == nil {
		return nil, VerifyMalformedJWT, fmt.Errorf("iat missing")
	}
	iat := c.IssuedAt.Time
	if iat.After(now.Add(clockSkewBudget)) {
		return nil, VerifyNotYetValid, nil
	}

	// Clock rollback: now must not sit behind the watermark by more than the
	// tolerance. Expiry is the only control a license has once it is issued,
	// because verification is offline and nothing phones home, so winding the
	// clock back is the one way left to keep running past exp.
	if !opts.LastKnownGood.IsZero() && now.Before(opts.LastKnownGood.Add(-clockRollbackTolerance)) {
		return nil, VerifyClockRollback, nil
	}

	// nbf if present.
	if c.NotBefore != nil && c.NotBefore.Time.After(now) {
		return nil, VerifyNotYetValid, nil
	}

	// exp + grace period.
	if c.ExpiresAt == nil {
		return nil, VerifyMalformedJWT, fmt.Errorf("exp missing")
	}
	exp := c.ExpiresAt.Time
	inGrace := false
	switch {
	case now.Before(exp):
		// not yet expired
	case now.Before(exp.Add(gracePeriod)):
		inGrace = true
	default:
		return nil, VerifyExpired, nil
	}

	// Fingerprint binding (optional).
	if opts.Fingerprint != "" && c.Fingerprint != "" && c.Fingerprint != opts.Fingerprint {
		return nil, VerifyFingerprintMismatch, nil
	}

	// Feature claims. An id this binary does not know is carried, not fatal.
	//
	// Licenses are minted from a registry that moves faster than customer
	// upgrades, so rejecting the whole token would turn shipping a new flag
	// into a total outage for an install that is otherwise entitled. The
	// install degrades to the features it understands. See decision record 04.
	features, unknown := translateFeatures(c.Features)

	tier := c.Tier
	if tier == "" {
		tier = TierFree
	}

	status := StatusActive
	if inGrace {
		status = StatusGrace
	}

	return &License{
		Tier:          tier,
		Status:        status,
		Features:      features,
		Issuer:        c.Issuer,
		Audience:      audienceString(c.Audience),
		CustomerID:    c.CustomerID,
		IssuedAt:      iat,
		ExpiresAt:     exp,
		Fingerprint:   c.Fingerprint,
		UsingPrevKey:  usingPrev,
		InGracePeriod: inGrace,
		// The caller audits these; the verifier only reports them.
		UnknownFeatures: unknown,
	}, VerifyValid, nil
}

// classifyParseError maps jwt parser errors to typed VerifyResults so
// callers don't have to errors.Is against the entire jwt v5 error surface.
func classifyParseError(err error) VerifyResult {
	switch {
	case errors.Is(err, jwt.ErrTokenSignatureInvalid), errors.Is(err, jwt.ErrSignatureInvalid):
		return VerifySignatureInvalid
	case errors.Is(err, jwt.ErrTokenExpired):
		return VerifyExpired
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return VerifyNotYetValid
	case errors.Is(err, jwt.ErrTokenMalformed):
		return VerifyMalformedJWT
	default:
		// JWT v5 wraps signature errors as ErrTokenSignatureInvalid most of
		// the time. Anything else: treat as malformed.
		if strings.Contains(err.Error(), "signature") {
			return VerifySignatureInvalid
		}
		return VerifyMalformedJWT
	}
}

// audienceMatch handles JWT v5's jwt.ClaimStrings type (audience can be
// a single string or an array).
func audienceMatch(aud jwt.ClaimStrings, want string) bool {
	for _, a := range aud {
		if a == want {
			return true
		}
	}
	return false
}

func audienceString(aud jwt.ClaimStrings) string {
	if len(aud) == 0 {
		return ""
	}
	return aud[0]
}

// translateFeatures maps the JWT's string feature claims to typed Feature
// constants. Unknown ids are returned separately so the caller can record and
// audit them; they do not invalidate the license.
func translateFeatures(claims []string) (known []Feature, unknown []string) {
	for _, s := range claims {
		f := Feature(s)
		if _, ok := FeatureRegistry[f]; ok {
			known = append(known, f)
		} else {
			unknown = append(unknown, s)
		}
	}
	return known, unknown
}
