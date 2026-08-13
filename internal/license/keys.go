package license

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// Embedded license-signing public keys. Only the current slot is required.
//
//go:embed keys/*.pem
var embeddedKeys embed.FS

// publicKeyRing holds the parsed keys at package init. A token matching no slot
// fails validation. A token matching the prev slot verifies and sets the
// UsingPrevKey warning flag.
//
// Rotation is two-stage: current, then prev, then retired. Hold prev for at
// least the license term plus the grace period, about 13 months at the issuer's
// typical 365-day term, and no license signed with that key can still be valid
// when it is retired.
//
// The deprecated slot is reserved and is NOT a third rotation stage. Nothing
// enables it: no production VerifyOptions sets AllowDeprecatedKey, dev mode
// included. It is retained because it is the only policy gate in slot
// selection, which is what the kid contract tests against
// (system-license-validation AC-24: a kid naming this slot must not open it).
type publicKeyRing struct {
	current    ed25519.PublicKey
	prev       ed25519.PublicKey // nil unless a rotation has shipped one
	deprecated ed25519.PublicKey // nil; reserved, see above
}

// loadEmbeddedKeys parses the PEM files baked into the binary. Called
// once at package init via the package-level state in service.go.
func loadEmbeddedKeys() (*publicKeyRing, error) {
	ring := &publicKeyRing{}

	cur, err := parsePEMPublicKey("keys/license-pubkey-current.pem")
	if err != nil {
		return nil, fmt.Errorf("license: load current key: %w", err)
	}
	ring.current = cur

	// Both are optional. To rotate, drop license-pubkey-prev.pem into
	// internal/license/keys/ and it is picked up automatically. The deprecated
	// slot is reserved rather than part of rotation; see publicKeyRing.
	if prev, err := parsePEMPublicKey("keys/license-pubkey-prev.pem"); err == nil {
		ring.prev = prev
	}
	if dep, err := parsePEMPublicKey("keys/license-pubkey-deprecated.pem"); err == nil {
		ring.deprecated = dep
	}

	return ring, nil
}

// parsePEMPublicKey reads an embedded PEM file and extracts the Ed25519
// public key.
func parsePEMPublicKey(path string) (ed25519.PublicKey, error) {
	raw, err := embeddedKeys.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	ed, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an Ed25519 public key", path)
	}
	return ed, nil
}

// KeyID returns the JWT `kid` value for a license-signing public key. It is the
// SHA-256 of the key's SPKI DER encoding, in base64url with no padding.
//
// The value is a pure function of the key bytes. The issuer and the verifier
// each derive it on their own, so no name-to-key registry has to be kept in
// sync between them.
//
// A slot name such as "current" could not do that job. A license signed while a
// key sat in the current slot would still carry the label "current" after
// rotation moved that key to the prev slot. The label would then name the wrong
// key, and the license would never be minted again to correct it.
//
// An input that is not a valid Ed25519 public key returns "". An empty key ID
// matches no `kid` header, so it selects nothing.
func KeyID(pub ed25519.PublicKey) string {
	if len(pub) != ed25519.PublicKeySize {
		return ""
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// SetVerificationKeyForTesting installs pub as the sole active license
// verification key and returns a function that restores the prior keyring.
//
// It exists so tests (including in dependent packages such as internal/server)
// can verify JWTs signed with the testdata key while the shipped binary embeds
// the real, offline-generated key. internal/-scoped; never used on a production
// code path. That the embedded trust anchor is NOT the testdata key is asserted
// by TestEmbeddedKey_NotTestKey (system-license-validation AC-14).
func SetVerificationKeyForTesting(pub ed25519.PublicKey) (restore func()) {
	_ = Init()
	prev := activeKeyring()
	setKeyring(&publicKeyRing{current: pub})
	return func() { setKeyring(prev) }
}
