package policy

import (
	"crypto/ed25519"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"fmt"
	"sync/atomic"
)

// Embedded admin signing keys. Stage 0 ships one key; rotation lands
// later. The keyring is loaded at package boot via InitKeys.
//
//go:embed keys/*.pem
var embeddedKeys embed.FS

type keyring struct {
	current ed25519.PublicKey
}

var activeKeys atomic.Pointer[keyring]

// InitKeys loads the embedded admin public keys. Called once at boot.
// Safe to call multiple times; subsequent calls re-read the keys.
//
// Spec system-policy C-01.
func InitKeys() error {
	ring := &keyring{}
	cur, err := parseEmbeddedKey("keys/policy-pubkey-current.pem")
	if err != nil {
		return fmt.Errorf("policy: load admin signing key: %w", err)
	}
	ring.current = cur
	activeKeys.Store(ring)
	return nil
}

func parseEmbeddedKey(path string) (ed25519.PublicKey, error) {
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

func activeKeyring() *keyring {
	return activeKeys.Load()
}

// SetVerificationKeyForTesting installs pub as the sole active admin
// verification key and returns a function that restores the prior keyring.
//
// It exists so tests (including in dependent packages such as internal/server)
// can verify policy envelopes signed with the testdata key while the shipped
// binary embeds the real, offline-generated key. internal/-scoped; never used
// on a production code path. That the embedded trust anchor is NOT the testdata
// key is asserted by TestEmbeddedPolicyKey_NotTestKey (system-policy AC-13).
func SetVerificationKeyForTesting(pub ed25519.PublicKey) (restore func()) {
	prev := activeKeys.Load()
	activeKeys.Store(&keyring{current: pub})
	return func() { activeKeys.Store(prev) }
}
