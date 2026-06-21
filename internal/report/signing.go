package report

// Ed25519 signing for report snapshots. A snapshot is signed over its
// content address (content_sha256) with a domain-separated payload, so a
// signature attests "OpenWatch's report key vouches for this exact
// content at generation time" - the tamper-evidence the design calls for.
// Verification is offline: a holder of the public key (served by the
// signing-key endpoint) checks the signature over the same payload, and
// re-hashing the canonical JSON face confirms the content matches the
// signed hash.
//
// Key custody: the private key is a 32-byte raw Ed25519 seed loaded from
// a config path (mode 0600), never stored in the DB - the same custody
// model as the credential key. When no key is configured the signer runs
// EPHEMERAL (a fresh key per boot) for development; production MUST
// provide a durable key so signatures verify across restarts.
//
// Spec: api-reports v1.5.0.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
)

// signingDomain domain-separates the signature so a report signature can
// never be replayed as a signature over some other protocol's bytes.
const signingDomain = "openwatch/report-snapshot/v1\n"

// Signer signs report snapshots with an Ed25519 key.
type Signer struct {
	priv      ed25519.PrivateKey
	pub       ed25519.PublicKey
	keyID     string
	ephemeral bool
}

// NewSigner builds a Signer. When keyFile is non-empty it loads a 32-byte
// raw Ed25519 seed from that path (mode 0600 expected); when empty it
// generates an ephemeral key for development (Ephemeral() reports true so
// the caller can warn). The key id is a stable fingerprint of the public
// key.
func NewSigner(keyFile string) (*Signer, error) {
	if keyFile == "" {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("report: generate ephemeral signing key: %w", err)
		}
		return newSignerFromKeypair(pub, priv, true), nil
	}
	seed, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("report: read signing key %s: %w", keyFile, err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("report: signing key must be %d raw bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return newSignerFromKeypair(pub, priv, false), nil
}

func newSignerFromKeypair(pub ed25519.PublicKey, priv ed25519.PrivateKey, ephemeral bool) *Signer {
	return &Signer{priv: priv, pub: pub, keyID: keyIDFor(pub), ephemeral: ephemeral}
}

// keyIDFor derives a stable, public key id from the public key: the
// hex-encoded first 8 bytes of its SHA-256, prefixed for the algorithm.
func keyIDFor(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "ed25519-" + hex.EncodeToString(sum[:8])
}

// signingPayload is the domain-separated message actually signed: the
// domain tag followed by the content address. A verifier reconstructs it
// from the published content_sha256.
func signingPayload(contentSHA256 string) []byte {
	return append([]byte(signingDomain), []byte(contentSHA256)...)
}

// Sign returns the Ed25519 signature over the snapshot's content address
// and the key id that produced it.
func (s *Signer) Sign(contentSHA256 string) (sig []byte, keyID string) {
	return ed25519.Sign(s.priv, signingPayload(contentSHA256)), s.keyID
}

// PublicKey returns the verifying key.
func (s *Signer) PublicKey() ed25519.PublicKey { return s.pub }

// KeyID returns the signer's key id.
func (s *Signer) KeyID() string { return s.keyID }

// Ephemeral reports whether the signer is a per-boot development key (no
// durable key was configured).
func (s *Signer) Ephemeral() bool { return s.ephemeral }

// VerifySignature checks an Ed25519 signature over a content address with
// the given public key. Offline-verifiable: callers reconstruct the
// payload from the published content_sha256.
func VerifySignature(pub ed25519.PublicKey, contentSHA256 string, sig []byte) bool {
	return ed25519.Verify(pub, signingPayload(contentSHA256), sig)
}
