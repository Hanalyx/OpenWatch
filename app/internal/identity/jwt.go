package identity

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// JWT lifecycle errors. Identity binder middleware translates these
// to specific auth.login.failure audit reasons (spec C-11).
var (
	ErrJWTInvalid = errors.New("identity: jwt invalid")
	ErrJWTExpired = errors.New("identity: jwt expired")
)

// AccessTokenWindow is the JWT access-token lifetime. 30 min per spec C-08.
const AccessTokenWindow = 30 * time.Minute

// Claims is the OpenWatch JWT payload. Stored under standard registered
// claims for sub/iat/exp/jti plus role for fast authorization without
// a DB lookup on every request.
//
// The role here is a snapshot at token-issue time. RBAC + license
// middleware re-evaluates against the registry on every request, so a
// token issued with an outdated role still respects revocation when
// the user's role changes (combined check finds the role gone).
type Claims struct {
	jwt.RegisteredClaims
	Role string `json:"role"`
}

// jwtKey is the active RS256 signing key. Loaded from file at boot or
// generated ephemerally for tests. Loading is goroutine-safe — readers
// hold a snapshot via atomic-ish pattern (sync.RWMutex).
//
// Rotation is operator-driven: drop a new key file, signal SIGHUP, the
// binder swaps in. Implementing the SIGHUP swap is Slice-A follow-up.
var (
	jwtKeyMu sync.RWMutex
	jwtKey   *rsa.PrivateKey
)

// LoadJWTKey reads an RSA private key (PEM, PKCS#1 or PKCS#8) from
// path and installs it as the active signing key. Returns error if
// the file is missing, unparseable, or the key is < 2048 bits (we
// refuse weak keys; NIST SP 800-57 sets 2048 as the floor through 2030).
//
// Spec C-08.
func LoadJWTKey(path string) error {
	raw, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return fmt.Errorf("identity: read jwt key %q: %w", path, err)
	}
	key, err := parsePrivateKey(raw)
	if err != nil {
		return fmt.Errorf("identity: parse jwt key %q: %w", path, err)
	}
	if key.N.BitLen() < 2048 {
		return fmt.Errorf("identity: jwt key is %d bits, minimum 2048", key.N.BitLen())
	}
	jwtKeyMu.Lock()
	jwtKey = key
	jwtKeyMu.Unlock()
	return nil
}

// SetEphemeralJWTKey generates a fresh 2048-bit RSA key and installs
// it. Intended for tests and dev mode. Production deployments call
// LoadJWTKey instead.
func SetEphemeralJWTKey() error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("identity: generate ephemeral jwt key: %w", err)
	}
	jwtKeyMu.Lock()
	jwtKey = key
	jwtKeyMu.Unlock()
	return nil
}

// activeKey returns the currently-installed key. Returns nil if no key
// has been loaded — callers must check before signing.
func activeKey() *rsa.PrivateKey {
	jwtKeyMu.RLock()
	defer jwtKeyMu.RUnlock()
	return jwtKey
}

func parsePrivateKey(raw []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	// Try PKCS#1 first (BEGIN RSA PRIVATE KEY), fall back to PKCS#8 (BEGIN PRIVATE KEY).
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	anyKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("not PKCS#1 or PKCS#8: %w", err)
	}
	rsaKey, ok := anyKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA key: %T", anyKey)
	}
	return rsaKey, nil
}

// IssueJWT mints an RS256 access token for the given user + role. The
// token expires AccessTokenWindow (30 min) from now. jti is a random
// UUIDv7 for replay detection / forensic correlation.
//
// Spec AC-11, C-08.
func IssueJWT(userID uuid.UUID, role string) (string, Claims, error) {
	key := activeKey()
	if key == nil {
		return "", Claims{}, errors.New("identity: no JWT signing key installed")
	}
	now := time.Now().UTC()
	jti, err := uuid.NewV7()
	if err != nil {
		return "", Claims{}, fmt.Errorf("identity: jti: %w", err)
	}
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(AccessTokenWindow)),
			ID:        jti.String(),
		},
		Role: role,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := tok.SignedString(key)
	if err != nil {
		return "", Claims{}, fmt.Errorf("identity: sign jwt: %w", err)
	}
	return signed, claims, nil
}

// VerifyJWT parses and validates a signed JWT against the active
// signing key's public component. Returns the claims on success or
// one of the JWT lifecycle errors.
//
// Spec AC-11, C-08.
func VerifyJWT(signed string) (Claims, error) {
	key := activeKey()
	if key == nil {
		return Claims{}, errors.New("identity: no JWT signing key installed")
	}
	var claims Claims
	tok, err := jwt.ParseWithClaims(signed, &claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return &key.PublicKey, nil
	})
	if err != nil {
		// jwt.ErrTokenExpired sits behind a wrapping; check via errors.Is.
		if errors.Is(err, jwt.ErrTokenExpired) {
			return Claims{}, ErrJWTExpired
		}
		return Claims{}, fmt.Errorf("%w: %v", ErrJWTInvalid, err)
	}
	if !tok.Valid {
		return Claims{}, ErrJWTInvalid
	}
	return claims, nil
}
