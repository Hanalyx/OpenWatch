// @spec system-policy
//
// AC traceability:
// @ac AC-13  (TestEmbeddedPolicyKey_NotTestKey)

package policy

import (
	"crypto/ed25519"
	"testing"
)

// @ac AC-13
// AC-13: the embedded current admin-policy public key MUST NOT be the testdata
// signing key. This guards against the SEC-H1 regression where the shipped
// trust anchor is the committed test key, which would let anyone with repo
// access sign forged admin-policy envelopes.
func TestEmbeddedPolicyKey_NotTestKey(t *testing.T) {
	t.Run("system-policy/AC-13", func(t *testing.T) {
		embedded, err := parseEmbeddedKey("keys/policy-pubkey-current.pem")
		if err != nil {
			t.Fatalf("parse embedded current key: %v", err)
		}
		testPub := loadTestPrivKey(t).Public().(ed25519.PublicKey)
		if embedded.Equal(testPub) {
			t.Fatal("SEC-H1 regression: embedded keys/policy-pubkey-current.pem is the testdata " +
				"key. Ship the real offline-generated public key (private key stays in the vault).")
		}
	})
}
