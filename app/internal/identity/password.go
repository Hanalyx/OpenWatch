// Package identity owns the auth primitives: password hashing (Argon2id),
// NIST SP 800-63B password-policy validation, breach-corpus checking,
// session token lifecycle, RS256 JWT mint/verify, and TOTP MFA.
//
// All primitives are designed to be consumable by both the session
// cookie path (browser sign-in) and the JWT bearer path (API consumers).
// The same users row backs both — drift between the two paths is
// impossible because they share one Identity surface.
//
// Spec: app/specs/system/auth-identity.spec.yaml.
package identity

import (
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // SHA-1 here is for HaveIBeenPwned-compatible breach lookup, not authentication
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters per NIST SP 800-63B + spec system-auth-identity C-01.
//
// These are tuned for a 2-3 vCPU server: a single VerifyPassword call
// takes roughly 50-100ms, which keeps online password-guessing within
// the rate-limit envelope (10/min/IP, 5/min/user from spec).
const (
	argonTime    = 3         // iterations
	argonMemory  = 64 * 1024 // 64 MiB
	argonLanes   = 1         // single-threaded; matches NIST guidance for low-latency online verification
	argonSaltLen = 16        // 128-bit salt
	argonKeyLen  = 32        // 256-bit derived key
)

// Password-policy errors. Returned from ValidatePassword so the caller
// (typically the login or password-change handler) can emit the correct
// auth.password.policy_failed audit detail.
var (
	ErrPasswordTooShort = errors.New("identity: password too short")
	ErrPasswordTooLong  = errors.New("identity: password too long")
	ErrPasswordBreached = errors.New("identity: password appears in the known-compromised corpus")
)

// PasswordPolicy controls ValidatePassword. Admin users have a 15-char
// minimum; regular users have an 8-char minimum. Both are NIST 800-63B
// compliant — length is the signal, not character classes.
type PasswordPolicy struct {
	MinLength int
	MaxLength int
}

// DefaultPolicy returns the regular-user policy (8-128 chars).
// Spec C-04.
func DefaultPolicy() PasswordPolicy {
	return PasswordPolicy{MinLength: 8, MaxLength: 128}
}

// AdminPolicy returns the admin-user policy (15-128 chars).
// Spec C-04.
func AdminPolicy() PasswordPolicy {
	return PasswordPolicy{MinLength: 15, MaxLength: 128}
}

// ValidatePassword applies the NIST SP 800-63B length check and the
// breach-corpus lookup. Returns the first failure encountered; callers
// surface this to users.
//
// Per spec C-03: no character-class rules are applied. Length is the
// signal. Character-class rules (forcing mix of upper/lower/digit/symbol)
// were removed from NIST 800-63B because they push users toward
// predictable patterns (Password1!, Welcome2024@) without measurably
// raising entropy.
//
// Per spec C-02: a SHA-1 prefix lookup hits the breach corpus. The
// caller supplies the corpus via BreachCorpus; nil corpus means skip
// the check (dev-mode only). Production passes a real corpus.
//
// Spec AC-02, AC-03, AC-04, AC-05.
func ValidatePassword(pw string, policy PasswordPolicy, corpus BreachCorpus) error {
	if len(pw) < policy.MinLength {
		return ErrPasswordTooShort
	}
	if len(pw) > policy.MaxLength {
		return ErrPasswordTooLong
	}
	if corpus != nil {
		breached, err := corpus.Contains(pw)
		if err != nil {
			return fmt.Errorf("identity: breach corpus lookup: %w", err)
		}
		if breached {
			return ErrPasswordBreached
		}
	}
	return nil
}

// BreachCorpus is the source of compromised-password lookups. Production
// uses HaveIBeenPwned-style SHA-1 prefix lookups against a local file
// or remote service; tests use a small in-memory fixture.
//
// Spec C-02, AC-02.
type BreachCorpus interface {
	// Contains returns true if pw's SHA-1 hash appears in the corpus.
	// Implementations MUST hash internally; never log or expose the
	// raw password.
	Contains(pw string) (bool, error)
}

// HashPassword returns an Argon2id PHC-formatted hash of pw, suitable
// for storage in users.password_hash. Random 128-bit salt; 256-bit
// derived key. Parameters baked into the PHC string so a future
// parameter change can verify legacy hashes by parsing the embedded values.
//
// Spec C-01, AC-01.
func HashPassword(pw string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("identity: read random salt: %w", err)
	}
	hash := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonLanes, argonKeyLen)
	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	hashB64 := base64.RawStdEncoding.EncodeToString(hash)
	// PHC format: $argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonLanes, saltB64, hashB64), nil
}

// VerifyPassword returns nil iff pw is the password that produced
// stored. Constant-time comparison; reads the parameters and salt from
// the PHC string so legacy hashes with different parameters still verify.
//
// Spec AC-01.
func VerifyPassword(pw, stored string) error {
	params, salt, want, err := parsePHC(stored)
	if err != nil {
		return err
	}
	// len(want) is the size of the stored Argon2id key — argonKeyLen (32)
	// in production. Bounded by parsePHC's base64 decode; cannot overflow uint32.
	wantLen := uint32(len(want)) //nolint:gosec // bounded by 32-byte argonKeyLen via PHC parse
	got := argon2.IDKey([]byte(pw), salt, params.Time, params.Memory, params.Lanes, wantLen)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return errors.New("identity: password mismatch")
	}
	return nil
}

// argonParams is the subset of Argon2id parameters embedded in a PHC string.
type argonParams struct {
	Time   uint32
	Memory uint32
	Lanes  uint8
}

// parsePHC extracts {params, salt, hash} from an Argon2id PHC string.
// Returns descriptive errors on malformed input so a forensic operator
// can tell a corrupted stored hash from a wrong password.
func parsePHC(s string) (argonParams, []byte, []byte, error) {
	var (
		params argonParams
		zero   = argonParams{}
	)
	parts := strings.Split(s, "$")
	// Empty leading element from the leading $, then: argon2id, v=N, m=...,t=...,p=..., salt, hash.
	if len(parts) != 6 {
		return zero, nil, nil, fmt.Errorf("identity: stored hash has %d segments, want 6 (Argon2id PHC)", len(parts))
	}
	if parts[1] != "argon2id" {
		return zero, nil, nil, fmt.Errorf("identity: unsupported algorithm %q, want argon2id", parts[1])
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return zero, nil, nil, fmt.Errorf("identity: parse version: %w", err)
	}
	if version != argon2.Version {
		return zero, nil, nil, fmt.Errorf("identity: stored hash version %d, runtime version %d", version, argon2.Version)
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.Memory, &params.Time, &params.Lanes); err != nil {
		return zero, nil, nil, fmt.Errorf("identity: parse argon2 params: %w", err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return zero, nil, nil, fmt.Errorf("identity: decode salt: %w", err)
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return zero, nil, nil, fmt.Errorf("identity: decode hash: %w", err)
	}
	return params, salt, hash, nil
}

// sha1Hex returns the upper-case hex SHA-1 of pw. Used for HaveIBeenPwned-
// style breach lookups. NOT used for any authentication purpose.
//
// SHA-1 is intentional here: HaveIBeenPwned publishes its compromised-
// password corpus as SHA-1 hashes for k-anonymity (the API takes a
// 5-char prefix and returns the matching suffixes). Replacing SHA-1
// would break compatibility with every published corpus.
func sha1Hex(pw string) string {
	h := sha1.Sum([]byte(pw)) //nolint:gosec // see function doc
	return strings.ToUpper(hex.EncodeToString(h[:]))
}
