// Package secretkey owns the AES-256-GCM data encryption key (DEK)
// used to encrypt at-rest secrets. One DEK serves multiple consumers
// (MFA secrets in internal/identity, SSH credentials in
// internal/credential) so operators rotate one file, not several.
//
// Production path: /etc/openwatch/secrets/credential-key — 32 random
// bytes, mode 0600, owner openwatch. Configurable via the
// OPENWATCH_CREDENTIAL_KEY_FILE env var.
//
// Spec: app/specs/system/credential-store.spec.yaml C-01;
//
//	app/specs/system/auth-identity.spec.yaml C-09.
package secretkey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

// KeySize is the AES-256 key length in bytes.
const KeySize = 32

// Errors returned by the package.
var (
	ErrKeyNotLoaded = errors.New("secretkey: no key loaded")
	ErrCipherShort  = errors.New("secretkey: ciphertext too short")
)

// Key wraps the AES-256-GCM key + a constructed AEAD. The AEAD is
// allocated once at load time and reused.
type Key struct {
	aead cipher.AEAD
	// raw holds the original 32-byte key material. Required for HKDF
	// sub-key derivation (e.g., scheduler.DeriveQueueKey). The AES
	// round keys derived from this value are already in memory via
	// the cipher.Block held inside aead, so retaining the raw bytes
	// does not meaningfully expand the in-process attack surface.
	// Callers MUST NOT log this value.
	raw []byte
}

// Material returns the raw 32-byte key material for HKDF sub-key
// derivation only. The returned slice MUST be treated as read-only —
// mutating it would corrupt every subsequent Encrypt/Decrypt call.
// Callers MUST NOT log, transmit, or persist this value.
func (k *Key) Material() []byte {
	return k.raw
}

// Encrypt seals plaintext with a fresh nonce, returning nonce||ciphertext.
func (k *Key) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("secretkey: read nonce: %w", err)
	}
	return k.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt reverses Encrypt. Returns ErrCipherShort if the input is
// shorter than the nonce.
func (k *Key) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < k.aead.NonceSize() {
		return nil, ErrCipherShort
	}
	nonce := ciphertext[:k.aead.NonceSize()]
	body := ciphertext[k.aead.NonceSize():]
	pt, err := k.aead.Open(nil, nonce, body, nil)
	if err != nil {
		return nil, fmt.Errorf("secretkey: open: %w", err)
	}
	return pt, nil
}

// keyFromBytes constructs a Key from a 32-byte raw key. Rejects any
// other length.
func keyFromBytes(b []byte) (*Key, error) {
	if len(b) != KeySize {
		return nil, fmt.Errorf("secretkey: key size = %d, want %d", len(b), KeySize)
	}
	block, err := aes.NewCipher(b)
	if err != nil {
		return nil, fmt.Errorf("secretkey: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secretkey: new gcm: %w", err)
	}
	// Copy the bytes so a caller mutating the input slice does not
	// affect us. The copy lives for the process lifetime alongside
	// the AEAD's internal round keys.
	raw := make([]byte, len(b))
	copy(raw, b)
	return &Key{aead: aead, raw: raw}, nil
}

// Package-level active key. Loaders set it; consumers read it via Active.
var (
	mu     sync.RWMutex
	active *Key
)

// Active returns the loaded key or ErrKeyNotLoaded. Callers MUST check
// the error — encrypting with a nil key would silently produce nothing.
func Active() (*Key, error) {
	mu.RLock()
	defer mu.RUnlock()
	if active == nil {
		return nil, ErrKeyNotLoaded
	}
	return active, nil
}

// LoadFromFile reads a 32-byte raw-binary DEK from path and installs
// it as the active key. Refuses files that aren't mode 0600 — a
// world-readable key file is a configuration error.
func LoadFromFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("secretkey: stat %q: %w", path, err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return fmt.Errorf("secretkey: %q has permissions %o, must be 0600", path, mode)
	}
	raw, err := os.ReadFile(path) //nolint:gosec // operator-supplied path; perms pre-checked
	if err != nil {
		return fmt.Errorf("secretkey: read %q: %w", path, err)
	}
	k, err := keyFromBytes(raw)
	if err != nil {
		return err
	}
	mu.Lock()
	active = k
	mu.Unlock()
	return nil
}

// SetEphemeral installs a random 32-byte key. Tests and dev mode only.
func SetEphemeral() error {
	raw := make([]byte, KeySize)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Errorf("secretkey: ephemeral key: %w", err)
	}
	k, err := keyFromBytes(raw)
	if err != nil {
		return err
	}
	mu.Lock()
	active = k
	mu.Unlock()
	return nil
}

// Reset clears the active key. Tests call this for isolation.
func Reset() {
	mu.Lock()
	active = nil
	mu.Unlock()
}
