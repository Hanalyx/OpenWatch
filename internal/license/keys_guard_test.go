// @spec system-license-validation
//
// AC traceability:
// @ac AC-14  (TestEmbeddedKey_NotTestKey)

package license

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// @ac AC-14
// AC-14: the embedded current license public key MUST NOT be the testdata
// signing key. This guards against the SEC-H1 regression where the shipped
// trust anchor is the committed test key, which would let anyone with repo
// access forge license JWTs of any tier/feature.
func TestEmbeddedKey_NotTestKey(t *testing.T) {
	t.Run("system-license-validation/AC-14", func(t *testing.T) {
		embedded, err := parsePEMPublicKey("keys/license-pubkey-current.pem")
		if err != nil {
			t.Fatalf("parse embedded current key: %v", err)
		}
		if embedded.Equal(testKeyPublic(t, "license-privkey-test.pem")) {
			t.Fatal("SEC-H1 regression: embedded keys/license-pubkey-current.pem is the testdata " +
				"key. Ship the real offline-generated public key (private key stays in the vault).")
		}
	})
}

// testKeyPublic derives the Ed25519 public half of a PKCS#8 test private key
// under testdata/.
func testKeyPublic(t *testing.T, name string) ed25519.PublicKey {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read testdata/%s: %v", name, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("no PEM block in testdata/%s", name)
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse testdata/%s: %v", name, err)
	}
	priv, ok := keyAny.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("testdata/%s is not an Ed25519 private key", name)
	}
	return priv.Public().(ed25519.PublicKey)
}
