package ssh

import (
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/Hanalyx/openwatch/internal/credential"
)

// Auth-method preference tokens. Plain strings (not a typed enum) so the
// ssh package stays decoupled from connprofile — callers translate.
const (
	PreferKey      = "key"
	PreferPassword = "password"
)

// authObserver records which auth method crypto/ssh last attempted during
// a handshake. The note fires when a method is ATTEMPTED (its callback is
// invoked), not when it is accepted. For SINGLE-FACTOR auth — OpenWatch's
// model, where key/password/both are ALTERNATIVE methods, never a required
// sequence — the client stops at the first method the server accepts
// (authSuccess), so the last-attempted method after a SUCCESSFUL handshake
// is the one that authenticated. Under true SSH multi-factor (e.g. sshd
// AuthenticationMethods "publickey,password") Last() would record only the
// final factor; OpenWatch does not use SSH MFA, and even then a wrong hint
// would at worst reorder the next dial (both methods stay offered) — never
// a failure, and nothing is persisted on an unsuccessful handshake.
// Concurrency-safe: a single ClientConfig is only used by one handshake,
// but the callbacks may fire from the handshake goroutine.
type authObserver struct {
	mu   sync.Mutex
	last string
}

func (o *authObserver) note(m string) {
	o.mu.Lock()
	o.last = m
	o.mu.Unlock()
}

// Last returns the method that authenticated ("key" | "password"), or ""
// if no method-bearing callback fired (e.g. no auth attempted).
func (o *authObserver) Last() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.last
}

// orderedAuthMethods builds the crypto/ssh auth-method list from cred,
// leading with `prefer` when that method's material is present, and wraps
// each method in a callback that records its attempt on obs.
//
// Both available methods are ALWAYS offered — `prefer` controls order, not
// inclusion. A stale preference (e.g. the host's key was rotated out) still
// falls back to the other method within the same handshake; the observer
// then records the method that actually worked so the next connection
// leads with it. This is the "preference, not a lock" property: the hint
// optimizes the common case and self-heals when the host changes.
func orderedAuthMethods(cred *credential.Credential, prefer string, obs *authObserver) ([]ssh.AuthMethod, error) {
	var keyM, pwM ssh.AuthMethod

	if cred.PrivateKey != "" {
		signer, err := parseSigner([]byte(cred.PrivateKey), cred.PrivateKeyPassphrase)
		if err != nil {
			return nil, err
		}
		keyM = ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
			obs.note(PreferKey)
			return []ssh.Signer{signer}, nil
		})
	}
	if cred.Password != "" {
		pw := cred.Password
		pwM = ssh.PasswordCallback(func() (string, error) {
			obs.note(PreferPassword)
			return pw, nil
		})
	}

	out := make([]ssh.AuthMethod, 0, 2)
	if prefer == PreferPassword {
		// Lead with password, then key as fallback.
		if pwM != nil {
			out = append(out, pwM)
		}
		if keyM != nil {
			out = append(out, keyM)
		}
		return out, nil
	}
	// Default order (prefer == "key" or unset): key first, then password.
	// Matches the historical pre-learning behaviour.
	if keyM != nil {
		out = append(out, keyM)
	}
	if pwM != nil {
		out = append(out, pwM)
	}
	return out, nil
}
