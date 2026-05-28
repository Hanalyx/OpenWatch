// Package ssh is the OpenWatch SSH dial layer. The connectivity-check
// endpoint, the future scan executor, and any other operation that
// needs to reach a host via SSH go through this package's Dial.
// Plaintext credentials are decrypted by internal/credential and
// passed in for the duration of one dial; they never leave this layer
// in any log, error, or audit row.
//
// Spec: app/specs/system/ssh-connectivity.spec.yaml.
package ssh

import (
	"crypto/dsa" //nolint:staticcheck // we explicitly reject DSA keys; need the type to detect them
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// Key-validation errors.
var (
	ErrWeakKey    = errors.New("ssh: key below NIST SP 800-57 minimum strength")
	ErrInvalidKey = errors.New("ssh: private key is unparseable or malformed")
)

// RSAMinBits is the lower bound for RSA keys per NIST SP 800-57 (good
// through 2030). Keys below this size are rejected.
const RSAMinBits = 2048

// ECDSAMinBits is the lower bound for ECDSA curves. P-256 = 256 bits.
const ECDSAMinBits = 256

// ValidateAuthKey parses an OpenSSH-format private key (PEM) and
// applies the NIST SP 800-57 strength check. Returns:
//   - ErrInvalidKey if the PEM is unparseable
//   - ErrWeakKey if the key is below the minimum strength for its algorithm
//   - nil if the key is acceptable for use with a Dial
//
// Spec AC-05, AC-10, C-02.
func ValidateAuthKey(pem []byte, passphrase string) error {
	signer, err := parseSigner(pem, passphrase)
	if err != nil {
		return err
	}
	pub := signer.PublicKey()
	cryptoPub, ok := pub.(ssh.CryptoPublicKey)
	if !ok {
		// Some key types don't expose the underlying crypto key (e.g.,
		// SSH certificates). Conservatively accept — the underlying
		// type-check happened at parse.
		return nil
	}
	switch k := cryptoPub.CryptoPublicKey().(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < RSAMinBits {
			return fmt.Errorf("%w: RSA %d bits, minimum %d", ErrWeakKey, k.N.BitLen(), RSAMinBits)
		}
	case ed25519.PublicKey:
		// Ed25519 is unconditionally accepted (FIPS 186-5; constant 256-bit
		// security level; no parameter knobs to get wrong).
	case *ecdsa.PublicKey:
		if k.Params().BitSize < ECDSAMinBits {
			return fmt.Errorf("%w: ECDSA %d bits, minimum %d", ErrWeakKey, k.Params().BitSize, ECDSAMinBits)
		}
	case *dsa.PublicKey:
		return fmt.Errorf("%w: DSA keys are not allowed", ErrWeakKey)
	default:
		// Unknown key type — refuse rather than guess.
		return fmt.Errorf("%w: unrecognized public-key type %T", ErrWeakKey, k)
	}
	return nil
}

// parseSigner returns an ssh.Signer for the given PEM bytes. Used by
// both ValidateAuthKey and the Dial path so a key that passes
// validation will also load at dial time.
func parseSigner(pem []byte, passphrase string) (ssh.Signer, error) {
	if len(pem) == 0 {
		return nil, fmt.Errorf("%w: empty key", ErrInvalidKey)
	}
	var signer ssh.Signer
	var err error
	if passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(pem, []byte(passphrase))
	} else {
		signer, err = ssh.ParsePrivateKey(pem)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	return signer, nil
}
