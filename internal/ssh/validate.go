// Package ssh is the OpenWatch SSH dial layer. The connectivity-check
// endpoint, the future scan executor, and any other operation that
// needs to reach a host via SSH go through this package's Dial.
// Plaintext credentials are decrypted by internal/credential and
// passed in for the duration of one dial; they never leave this layer
// in any log, error, or audit row.
//
// Spec: specs/system/ssh-connectivity.spec.yaml.
package ssh

import (
	"github.com/Hanalyx/openwatch/internal/sshkey"
	"golang.org/x/crypto/ssh"
)

// Key-validation errors. The parser and strength check live in
// internal/sshkey, shared with the credential store; these are the same
// values, so errors.Is works with either name.
var (
	ErrWeakKey    = sshkey.ErrWeakKey
	ErrInvalidKey = sshkey.ErrInvalidKey
)

// RSAMinBits is the lower bound for RSA keys per NIST SP 800-57 (good
// through 2030). Keys below this size are rejected.
const RSAMinBits = sshkey.RSAMinBits

// ECDSAMinBits is the lower bound for ECDSA curves. P-256 = 256 bits.
const ECDSAMinBits = sshkey.ECDSAMinBits

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
	return sshkey.CheckStrength(signer.PublicKey())
}

// parseSigner returns an ssh.Signer for the given PEM bytes. Used by
// both ValidateAuthKey and the Dial path so a key that passes
// validation will also load at dial time.
func parseSigner(pem []byte, passphrase string) (ssh.Signer, error) {
	return sshkey.ParseSigner(pem, passphrase)
}
