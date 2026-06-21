// @spec api-reports
//
//	AC-14  TestSigner_SignVerify   (Ed25519 sign/verify, key id, ephemeral, seed loading)
//	AC-15  TestGenerate_Signed      (Generate signs the snapshot; signature verifies; unsigned stays null)

package report

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

// @ac AC-14
// The signer produces an Ed25519 signature over a content address that
// verifies with its public key; a tampered content address or the wrong
// key fails. An empty key path is ephemeral; a 32-byte seed file loads a
// stable (non-ephemeral) key; a wrong-size seed errors.
func TestSigner_SignVerify(t *testing.T) {
	t.Run("api-reports/AC-14", func(t *testing.T) {
		s, err := NewSigner("")
		if err != nil {
			t.Fatalf("NewSigner ephemeral: %v", err)
		}
		if !s.Ephemeral() {
			t.Errorf("empty key path should be ephemeral")
		}
		sha := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		sig, keyID := s.Sign(sha)
		if keyID != s.KeyID() {
			t.Errorf("Sign keyID %q != KeyID() %q", keyID, s.KeyID())
		}
		if !VerifySignature(s.PublicKey(), sha, sig) {
			t.Errorf("valid signature did not verify")
		}
		// Tampered content address must not verify.
		if VerifySignature(s.PublicKey(), sha[:62]+"ff", sig) {
			t.Errorf("tampered content verified (should not)")
		}
		// A different key must not verify.
		s2, _ := NewSigner("")
		if VerifySignature(s2.PublicKey(), sha, sig) {
			t.Errorf("signature verified under the wrong key (should not)")
		}

		// A 32-byte seed file loads a stable, non-ephemeral key.
		seed := make([]byte, ed25519.SeedSize)
		for i := range seed {
			seed[i] = byte(i + 1)
		}
		f := filepath.Join(t.TempDir(), "report-signing.key")
		if err := os.WriteFile(f, seed, 0o600); err != nil {
			t.Fatal(err)
		}
		a, err := NewSigner(f)
		if err != nil {
			t.Fatalf("NewSigner from seed: %v", err)
		}
		b, _ := NewSigner(f)
		if a.Ephemeral() {
			t.Errorf("file-loaded signer should not be ephemeral")
		}
		if a.KeyID() != b.KeyID() {
			t.Errorf("same seed gave different key ids: %s vs %s", a.KeyID(), b.KeyID())
		}
		// Wrong-size seed errors.
		if err := os.WriteFile(f, []byte("too short"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewSigner(f); err == nil {
			t.Errorf("a wrong-size seed should error")
		}
	})
}

// @ac AC-15
// Generate with a wired signer stores an Ed25519 signature + key id that
// verifies over the snapshot's content address (and survives a Get
// round-trip); a service with no signer leaves the signature null.
func TestGenerate_Signed(t *testing.T) {
	t.Run("api-reports/AC-15", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		signer, _ := NewSigner("")
		svc := NewService(pool).WithSigner(signer)
		owner := seedUser(t, pool)
		h := seedHost(t, pool, owner, false)
		seedRuleState(t, pool, h, "r1", "fail", "high")

		rep, err := svc.Generate(ctx, "alice@example.com", GenerateRequest{})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if len(rep.Signature) == 0 {
			t.Fatalf("signed service produced no signature")
		}
		if rep.SigningKeyID != signer.KeyID() {
			t.Errorf("signing_key_id = %q, want %q", rep.SigningKeyID, signer.KeyID())
		}
		if !VerifySignature(signer.PublicKey(), rep.ContentSHA256, rep.Signature) {
			t.Errorf("stored signature does not verify over content_sha256")
		}

		// Get round-trips the signature.
		got, err := svc.Get(ctx, rep.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if !VerifySignature(signer.PublicKey(), got.ContentSHA256, got.Signature) {
			t.Errorf("fetched signature does not verify")
		}

		// A service without a signer leaves the signature null.
		svc2 := NewService(pool)
		rep2, err := svc2.Generate(ctx, "bob@example.com", GenerateRequest{})
		if err != nil {
			t.Fatalf("Generate unsigned: %v", err)
		}
		if len(rep2.Signature) != 0 || rep2.SigningKeyID != "" {
			t.Errorf("unsigned service set signature/key: %x / %q", rep2.Signature, rep2.SigningKeyID)
		}
	})
}
