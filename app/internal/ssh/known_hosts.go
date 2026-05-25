package ssh

import (
	"errors"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
)

// Mode controls how the dial layer treats a server's host key.
type Mode int

const (
	// ModeStrict requires the server's host key to be in the known-hosts
	// store before the connection succeeds. Reject unknown.
	ModeStrict Mode = iota

	// ModeTOFU (trust-on-first-use) records the first key it sees for a
	// hostname; subsequent connections behave like Strict against that
	// stored key. A different key from the same hostname returns
	// ErrHostKeyMismatch.
	ModeTOFU
)

// Host-key verification errors.
var (
	ErrHostKeyUnknown  = errors.New("ssh: host key not in known-hosts store")
	ErrHostKeyMismatch = errors.New("ssh: host key changed since first connection")
)

// KnownHostsStore persists (hostname → public-key fingerprint). The
// in-memory implementation is the default; production deploys can
// drop in a PG-backed store later by satisfying the same interface.
type KnownHostsStore interface {
	// Get returns the stored marshalled public key for hostname, or
	// (nil, false) if no entry exists.
	Get(hostname string) ([]byte, bool)
	// Put stores the marshalled public key for hostname. Idempotent for
	// the same key; should reject (or signal upward via error) if the
	// caller tries to overwrite a different key — the caller decides
	// whether that's allowed, not the store.
	Put(hostname string, marshalled []byte) error
}

// MemoryStore is an in-memory KnownHostsStore. Goroutine-safe.
type MemoryStore struct {
	mu   sync.RWMutex
	keys map[string][]byte
}

// NewMemoryStore constructs an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{keys: map[string][]byte{}}
}

// Get implements KnownHostsStore.
func (m *MemoryStore) Get(hostname string) ([]byte, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	k, ok := m.keys[hostname]
	if !ok {
		return nil, false
	}
	// Return a copy so callers can't mutate the stored bytes.
	out := make([]byte, len(k))
	copy(out, k)
	return out, true
}

// Put implements KnownHostsStore. Overwrites any prior value for the
// hostname — the policy (whether a different key is acceptable) is the
// caller's decision, not the store's.
func (m *MemoryStore) Put(hostname string, marshalled []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	stored := make([]byte, len(marshalled))
	copy(stored, marshalled)
	m.keys[hostname] = stored
	return nil
}

// hostKeyCallback returns the ssh.HostKeyCallback that enforces the
// caller's Mode against the supplied store. Builds the closure so the
// dial config can plug it in directly.
//
// Spec C-04, C-05, AC-06, AC-07.
func hostKeyCallback(mode Mode, store KnownHostsStore, hostname string) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, presented ssh.PublicKey) error {
		marshalled := presented.Marshal()
		stored, ok := store.Get(hostname)
		switch mode {
		case ModeStrict:
			if !ok {
				return ErrHostKeyUnknown
			}
			if !bytesEqual(stored, marshalled) {
				return ErrHostKeyMismatch
			}
			return nil
		case ModeTOFU:
			if !ok {
				return store.Put(hostname, marshalled)
			}
			if !bytesEqual(stored, marshalled) {
				return ErrHostKeyMismatch
			}
			return nil
		}
		return ErrHostKeyUnknown
	}
}

// bytesEqual is a constant-time byte slice comparison helper.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
