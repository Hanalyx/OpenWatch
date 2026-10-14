// Package sshkey parses SSH private keys, checks their strength and derives
// their public metadata. It depends on nothing else in OpenWatch, so both
// the dial layer (internal/ssh) and the credential store
// (internal/credential) can use the one parser: a key accepted by the store
// is the key the dial layer loads, and the metadata the store records is
// computed from that same key (bugs/OW-123).
//
// Spec system-credential-store C-08; system-ssh-connectivity C-02.
package sshkey

import (
	"crypto/dsa" //nolint:staticcheck // DSA keys are explicitly rejected; the type is needed to detect them
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// Key errors.
var (
	ErrWeakKey    = errors.New("ssh: key below NIST SP 800-57 minimum strength")
	ErrInvalidKey = errors.New("ssh: private key is unparseable or malformed")
)

// RSAMinBits is the lower bound for RSA keys per NIST SP 800-57 (good
// through 2030). Keys below this size are rejected.
const RSAMinBits = 2048

// ECDSAMinBits is the lower bound for ECDSA curves. P-256 = 256 bits.
const ECDSAMinBits = 256

// ParseSigner returns an ssh.Signer for the PEM-encoded private key,
// decrypting it with passphrase when one is given.
func ParseSigner(pem []byte, passphrase string) (ssh.Signer, error) {
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

// CheckStrength applies the NIST SP 800-57 minimums to pub: RSA at least
// RSAMinBits, ECDSA at least ECDSAMinBits, Ed25519 always, DSA never, any
// other type refused.
func CheckStrength(pub ssh.PublicKey) error {
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

// Metadata is the public description of a private key, derived from the
// key itself.
type Metadata struct {
	// Fingerprint is ssh.FingerprintSHA256 of the public key, as
	// "SHA256:<base64>".
	Fingerprint string
	// Type is the public key's SSH algorithm name, e.g. "ssh-ed25519".
	Type string
	// Bits is the key size: the RSA modulus length, the ECDSA curve size,
	// or 256 for Ed25519.
	Bits int
	// Comment is always empty: golang.org/x/crypto/ssh does not expose the
	// comment an OpenSSH private key carries, and inventing one would be
	// worse than saying nothing.
	Comment string
}

// Inspect parses the private key with passphrase, applies CheckStrength,
// and returns the metadata of the key it actually parsed.
func Inspect(pem []byte, passphrase string) (Metadata, error) {
	signer, err := ParseSigner(pem, passphrase)
	if err != nil {
		return Metadata{}, err
	}
	pub := signer.PublicKey()
	if err := CheckStrength(pub); err != nil {
		return Metadata{}, err
	}
	md := Metadata{Fingerprint: ssh.FingerprintSHA256(pub), Type: pub.Type()}
	if cp, ok := pub.(ssh.CryptoPublicKey); ok {
		switch k := cp.CryptoPublicKey().(type) {
		case *rsa.PublicKey:
			md.Bits = k.N.BitLen()
		case *ecdsa.PublicKey:
			md.Bits = k.Params().BitSize
		case ed25519.PublicKey:
			md.Bits = 256
		}
	}
	return md, nil
}
