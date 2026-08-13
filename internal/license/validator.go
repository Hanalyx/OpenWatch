package license

import (
	"crypto/ed25519"
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
	LastKnownGood time.Time
	// AllowDeprecatedKey admits the reserved deprecated slot. Nothing sets it
	// outside tests, dev mode included, so the slot never enters the candidate
	// list in production. It is the only policy gate in slot selection, which
	// is what AC-24 tests: a kid naming that slot must not open it.
	AllowDeprecatedKey bool
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

	// WithoutClaimsValidation: we do exp/iat/nbf checks manually below so we
	// can implement the 30-day grace period (jwt v5's default validator
	// rejects expired tokens before our custom logic runs).
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithoutClaimsValidation(),
	)

	// Which ring slots this call may verify against, in the order they are
	// tried. Slot policy is applied here and nowhere else, so the `kid` header
	// below cannot route around it.
	candidates := trialKeys(ring, opts)

	// `kid` reorders that list so the named slot is tried first. It never adds
	// to the list.
	//
	// The header is matched against the allowed slots built above, not against
	// the whole ring, so a header naming the deprecated key matches nothing
	// unless AllowDeprecatedKey put that slot in the list, which nothing in
	// production does. That is what separates this from a thumbprint-to-key
	// map. A map hands back any ring member whose thumbprint matches, which
	// would open the deprecated slot to anyone able to read a public key and
	// stamp a header.
	kid := keyIDFromJWT(jwtBlob)
	if kid != "" {
		candidates = preferKeyID(candidates, kid)
	}

	var (
		parsed   *jwt.Token
		err      error
		verified keyCandidate
	)
	for _, cand := range candidates {
		key := cand.key
		parsed, err = parser.ParseWithClaims(jwtBlob, &claims{}, func(token *jwt.Token) (interface{}, error) {
			// We accept only EdDSA. JWT v5 maps Ed25519 to EdDSA.
			if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return key, nil
		})
		if err == nil {
			// Keep the slot that verified, not the code path that ran. A kid
			// header can put any allowed slot first, so anything inferred from
			// the sequence of attempts would be wrong.
			verified = cand
			break
		}
		// Only a signature mismatch justifies reaching for another key.
		//
		// Match on ErrTokenSignatureInvalid, which is what jwt v5 wraps every
		// verification failure in. Do NOT match ErrSignatureInvalid: that
		// sentinel is defined and returned only by the HMAC path (hmac.go), so
		// an Ed25519 mismatch (ErrEd25519Verification, ed25519.go) never
		// carries it. Matching it made this branch unreachable, which meant key
		// rotation would have failed in the field the first release a prev key
		// shipped, and only then.
		//
		// Every other parse error is decided before the signature is checked,
		// so it does not depend on which key is in hand. Stopping early on one
		// costs nothing: another slot would return the same class of error.
		if !errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			break
		}
	}
	if err != nil {
		return nil, classifyParseError(err), err
	}

	// UsingPrevKey is read off the slot that verified. It is the one place the
	// flag is set, so a candidate that loses its slot identity on the way here
	// would leave using_prev_key reporting the opposite of the truth.
	usingPrev := verified.isPrev

	// Did the kid name the key that actually verified? Compare thumbprints
	// rather than asking whether preferKeyID reordered anything. A kid like the
	// literal string "current" names no slot, so it reorders nothing and the
	// current key still verifies. That kid did not select the key either, and a
	// reorder check would call it a match.
	mismatchedKeyID := ""
	if kid != "" && KeyID(verified.key) != kid {
		mismatchedKeyID = kid
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
		// A kid that did not name the verifying key. Empty is the normal case.
		MismatchedKeyID: mismatchedKeyID,
		// The caller audits these; the verifier only reports them.
		UnknownFeatures: unknown,
	}, VerifyValid, nil
}

// keyCandidate is one ring slot the verifier is allowed to try, paired with
// what the caller has to be told about it.
type keyCandidate struct {
	key ed25519.PublicKey
	// isPrev drives License.UsingPrevKey, which the API surfaces as
	// using_prev_key. The deprecated slot deliberately leaves it false.
	isPrev bool
}

// trialKeys returns the ring slots this call may verify against, in the order
// they are tried.
//
// The deprecated slot is admitted only when the caller allows it, so the
// dev-mode gate lives in this one place. The current slot is always listed,
// even when it holds nothing, so the returned list is never empty and a ring
// with no usable key still fails through the normal signature path.
func trialKeys(ring *publicKeyRing, opts VerifyOptions) []keyCandidate {
	cands := []keyCandidate{{key: ring.current}}
	if ring.prev != nil {
		cands = append(cands, keyCandidate{key: ring.prev, isPrev: true})
	}
	if opts.AllowDeprecatedKey && ring.deprecated != nil {
		cands = append(cands, keyCandidate{key: ring.deprecated})
	}
	return cands
}

// preferKeyID moves the candidate whose key ID equals kid to the front, keeping
// the rest in trial order. A kid that matches nothing leaves the order alone.
//
// The result is always a permutation of what came in. Nothing is dropped, so a
// mislabeled token still reaches the key that signed it, and nothing is added,
// so the slot policy the caller applied still holds.
//
// Dropping the other slots would be the tempting read of "select the key", and
// it is wrong. The issuer stamps kid before any verifier reads it, so a stale
// or mistyped kid is an issuer mislabel, not an attack: the signature still has
// to verify against a key this build already trusts. Refusing to look further
// would brick a paying install over a header no attacker can turn into a forged
// license.
func preferKeyID(cands []keyCandidate, kid string) []keyCandidate {
	for i, c := range cands {
		if KeyID(c.key) != kid {
			continue
		}
		reordered := make([]keyCandidate, 0, len(cands))
		reordered = append(reordered, c)
		reordered = append(reordered, cands[:i]...)
		reordered = append(reordered, cands[i+1:]...)
		return reordered
	}
	return cands
}

// keyIDFromJWT reads the `kid` header out of an unverified token. It returns ""
// when the header is absent, is not a string, or cannot be decoded at all.
//
// Nothing here is trusted. The value only picks which already-trusted key to
// try, and a token that lies about its kid still has to pass the signature
// check against that key. A "" result takes the plain trial order, which is the
// path every license took before kid was read.
func keyIDFromJWT(jwtBlob string) string {
	// Errors are ignored on purpose. A token too broken to yield a header is
	// also too broken to verify, and the parse below reports that properly.
	token, _, _ := jwt.NewParser().ParseUnverified(jwtBlob, jwt.MapClaims{})
	if token == nil {
		return ""
	}
	kid, _ := token.Header["kid"].(string)
	return kid
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
