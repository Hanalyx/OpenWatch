package license

import (
	"crypto/ed25519"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"fmt"
)

// Embedded license-signing public keys. The current slot is required;
// prev and deprecated slots are added when key rotation lands (post Stage 0).
//
//go:embed keys/*.pem
var embeddedKeys embed.FS

// publicKeys holds the parsed keys at package init. Mismatches against
// every slot fail validation; matches against prev or deprecated emit
// warnings (UsingPrevKey flag).
type publicKeyRing struct {
	current    ed25519.PublicKey
	prev       ed25519.PublicKey // may be nil in Stage 0
	deprecated ed25519.PublicKey // may be nil in Stage 0
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

	// Prev/deprecated are optional in Stage 0. When the rotation pattern
	// arrives, drop license-pubkey-prev.pem / license-pubkey-deprecated.pem
	// into internal/license/keys/ and they're picked up automatically.
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
