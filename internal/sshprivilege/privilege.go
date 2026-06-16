// Package sshprivilege implements liveness.PrivilegeProbeFunc: dial
// SSH with the host's resolved credential, run `sudo -n true`, and
// report whether passwordless privilege escalation is configured.
//
// Per system-ssh-connectivity v1.2.0 the probe ALSO consults
// systemconfig.SecurityConfig.AllowCredentialSudoPassword; when the
// initial `sudo -n true` returns non-zero AND the credential carries
// a non-empty Password AND the policy is on, the probe retries via
// `sudo -S -k -p ” true` with the password fed through stdin. The
// retry shape is identical across the THREE inline-retry call sites —
// this probe, the collector's ssh.RunSudo, and discovery.probeFirewall —
// and drift between them is forbidden by the spec's C-09. (The compliance
// scan also supports password sudo, but via a different shape — a
// per-connection sudo-mode probe in internal/kensa, see
// system-connection-profile — so it is intentionally not part of this
// trio; it consults the SAME kill-switch + auth-method gate.)
//
// This package is kept OUT of internal/liveness because the liveness
// package's AC-14 invariant forbids credential + crypto/ssh imports.
// The PrivilegeProbeFunc is wired in cmd/openwatch/main.go where both
// the credential resolver and the liveness service are already in
// scope.
package sshprivilege

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Hanalyx/openwatch/internal/connprofile"
	"github.com/Hanalyx/openwatch/internal/credential"
	"github.com/Hanalyx/openwatch/internal/liveness"
	"github.com/Hanalyx/openwatch/internal/systemconfig"
	"github.com/google/uuid"
)

// Resolver returns the credential to use for a host. Implementations
// typically wrap credential.Service.Resolve. ErrNoCredential is the
// "no auth configured" signal — the probe records attempted=false and
// returns without touching SSH.
type Resolver interface {
	Resolve(ctx context.Context, hostID uuid.UUID) (*credential.Credential, error)
}

// PolicyLoader returns the current SecurityConfig — specifically the
// AllowCredentialSudoPassword flag that gates the sudo -S fallback.
// Implementations typically wrap systemconfig.Store.LoadSecurity. A
// nil loader OR an error from the loader defaults to "policy off"
// so the fallback path stays opt-in.
type PolicyLoader interface {
	LoadSecurity(ctx context.Context) (systemconfig.SecurityConfig, error)
}

// SessionExecutor is the seam between the probe and the SSH session.
// Production wraps a real *ssh.Client (see realSession below); tests
// stub it directly to verify the call ordering without standing up an
// SSH server.
//
// RunWithStdin feeds the reader's content into the remote process's
// stdin — used to deliver the credential password to `sudo -S`. The
// reader is consumed once.
type SessionExecutor interface {
	Run(ctx context.Context, cmd string) ([]byte, int, error)
	RunWithStdin(ctx context.Context, cmd string, stdin io.Reader) ([]byte, int, error)
	Close() error
}

// Dialer opens an SSH session against a host. Production uses
// realDialer (crypto/ssh.Dial); tests inject a stub.
//
// prefer is the host's learned SSH auth method (connprofile.AuthUnknown
// when none): the dialer leads with it but still offers the other method.
// The returned method is the one that authenticated, for the caller to
// record. Both are best-effort learning, never a hard requirement.
type Dialer interface {
	Dial(ctx context.Context, cred *credential.Credential, addr string, timeout time.Duration, prefer connprofile.SSHAuthMethod) (SessionExecutor, connprofile.SSHAuthMethod, error)
}

// ConnProfileStore is the subset of connprofile the probe uses to lead the
// dial with the host's known-good SSH auth method and record what
// authenticated. nil (the default) disables learning.
type ConnProfileStore interface {
	Get(ctx context.Context, hostID uuid.UUID) (connprofile.Profile, error)
	RecordSSHAuth(ctx context.Context, hostID uuid.UUID, m connprofile.SSHAuthMethod) error
}

// probeConfig accumulates the optional dependencies a Probe needs.
// Constructed by Probe(...) and the With* options.
type probeConfig struct {
	dialer   Dialer
	policy   PolicyLoader
	profiles ConnProfileStore
}

// ProbeOption configures the probe at construction time. Use
// WithDialer / WithPolicyLoader.
type ProbeOption func(*probeConfig)

// WithDialer overrides the production SSH dialer. Tests pass a stub
// that doesn't open real connections.
func WithDialer(d Dialer) ProbeOption {
	return func(c *probeConfig) { c.dialer = d }
}

// WithPolicyLoader wires the systemconfig reader the probe consults
// to decide whether to engage the sudo -S fallback. A nil loader
// (the default) is equivalent to "policy off".
//
// Spec system-ssh-connectivity v1.2.0 C-09 / AC-18.
func WithPolicyLoader(p PolicyLoader) ProbeOption {
	return func(c *probeConfig) { c.policy = p }
}

// WithProfiles enables per-host SSH auth-method learning: the probe leads
// the dial with the host's recorded method and records which method
// authenticated. nil (the default) keeps the historical key-first,
// no-learning order. See system-connection-profile.
func WithProfiles(p ConnProfileStore) ProbeOption {
	return func(c *probeConfig) { c.profiles = p }
}

// Probe builds a liveness.PrivilegeProbeFunc backed by the given
// resolver. The returned function:
//
//  1. Looks up the host's credential. On ErrNoCredential it returns
//     attempted=false (the multi-layer state machine leaves the
//     privilege axis untouched).
//  2. Dials TCP-22 with cfg.Timeout = timeout.
//  3. Runs `sudo -n true`. Exit 0 → ok=true.
//  4. Non-zero exit AND AllowCredentialSudoPassword AND cred.Password
//     non-empty AND cred.AuthMethod ∈ {password, both} → retries as
//     `sudo -S -k -p ” true` with the password fed via stdin. Exit 0
//     from the retry → ok=true. Any other outcome → ok=false.
//
// Spec system-ssh-connectivity v1.2.0 C-09, AC-18, AC-19, AC-21.
//
// Host key verification is intentionally permissive (InsecureIgnoreHostKey)
// because this probe is just answering "would sudo work today?" — the
// real scan path validates host keys via internal/ssh.
func Probe(resolver Resolver, opts ...ProbeOption) liveness.PrivilegeProbeFunc {
	cfg := probeConfig{dialer: realDialer{}}
	for _, o := range opts {
		o(&cfg)
	}
	return func(ctx context.Context, hostID liveness.HostID, addr string, timeout time.Duration) (attempted, ok bool, err error) {
		id, perr := uuid.Parse(string(hostID))
		if perr != nil {
			return false, false, fmt.Errorf("hostID parse: %w", perr)
		}
		cred, rerr := resolver.Resolve(ctx, id)
		if errors.Is(rerr, credential.ErrNoCredential) || cred == nil {
			return false, false, nil
		}
		if rerr != nil {
			return true, false, fmt.Errorf("resolve credential: %w", rerr)
		}

		// Learning: lead the dial with the host's recorded auth method
		// (if a profile store is wired and a row exists), then record the
		// method that actually authenticated. Both are best-effort: a
		// lookup miss just dials in the default order.
		var prefer connprofile.SSHAuthMethod
		if cfg.profiles != nil {
			if p, gerr := cfg.profiles.Get(ctx, id); gerr == nil {
				prefer = p.SSHAuthMethod
			}
		}

		exec, observed, derr := cfg.dialer.Dial(ctx, cred, addr, timeout, prefer)
		if derr != nil {
			return true, false, fmt.Errorf("ssh dial: %w", derr)
		}
		defer func() { _ = exec.Close() }()

		if cfg.profiles != nil && observed != "" {
			_ = cfg.profiles.RecordSSHAuth(ctx, id, observed)
		}

		// Layer 1: sudo -n true. The 80% case where NOPASSWD is set.
		out, code, runErr := exec.Run(ctx, "sudo -n true")
		if runErr == nil && code == 0 {
			return true, true, nil
		}

		// Layer 2 (v1.2.0): sudo -S -k -p '' true. Only when the
		// policy + credential permit. Per spec C-09 / AC-19, the
		// auth method must allow password material AND the password
		// field must be populated.
		if !canFallback(ctx, cfg.policy, cred) {
			return true, false, fmt.Errorf("sudo -n true: exit %d: %s", code, strings.TrimSpace(string(out)))
		}

		stdin := bytes.NewReader([]byte(cred.Password + "\n"))
		out2, code2, runErr2 := exec.RunWithStdin(ctx, "sudo -S -k -p '' true", stdin)
		if runErr2 == nil && code2 == 0 {
			return true, true, nil
		}
		return true, false, fmt.Errorf("sudo -S -k -p '' true: exit %d: %s", code2, strings.TrimSpace(string(out2)))
	}
}

// canFallback returns true iff the policy is on AND the credential is
// shaped to provide a password (auth method password or both, password
// non-empty). Spec C-09 / AC-19.
func canFallback(ctx context.Context, loader PolicyLoader, cred *credential.Credential) bool {
	if loader == nil {
		return false
	}
	sec, lerr := loader.LoadSecurity(ctx)
	if lerr != nil || !sec.AllowCredentialSudoPassword {
		return false
	}
	if cred.Password == "" {
		return false
	}
	if cred.AuthMethod != credential.AuthPassword && cred.AuthMethod != credential.AuthBoth {
		return false
	}
	return true
}

// ---------------------------------------------------------------------
// Production dialer + session executor.
// ---------------------------------------------------------------------

type realDialer struct{}

func (realDialer) Dial(_ context.Context, cred *credential.Credential, addr string, timeout time.Duration, prefer connprofile.SSHAuthMethod) (SessionExecutor, connprofile.SSHAuthMethod, error) {
	obs := &authObserver{}
	methods, merr := buildAuthMethods(cred, prefer, obs)
	if merr != nil {
		return nil, "", merr
	}
	cfg := &ssh.ClientConfig{
		User:    cred.Username,
		Timeout: timeout,
		Auth:    methods,
		// #nosec G106 -- this probe answers "would sudo work
		// today?" and is decoupled from compliance scans. Host-key
		// pinning belongs on the real scan path (internal/ssh's
		// KnownHostsManager). Verifying here would require the
		// liveness loop to learn the host-key registry — exactly
		// the cross-cutting coupling we kept out of the package.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, derr := ssh.Dial("tcp", addr, cfg)
	if derr != nil {
		return nil, "", derr
	}
	// obs.Last() is the method that authenticated (single-factor: the
	// client stops at the first accepted method). "" when nothing fired.
	return &realSession{client: client}, obs.Last(), nil
}

// authObserver records which auth-method callback last fired during a
// handshake. For OpenWatch's single-factor model the client stops at the
// first accepted method, so the last-attempted method after a SUCCESSFUL
// handshake is the one that authenticated. Mirrors internal/ssh's observer
// (kept local so this package stays decoupled from the scan dial path,
// which pins host keys — see the package doc).
type authObserver struct {
	mu   sync.Mutex
	last connprofile.SSHAuthMethod
}

func (o *authObserver) note(m connprofile.SSHAuthMethod) {
	o.mu.Lock()
	o.last = m
	o.mu.Unlock()
}

func (o *authObserver) Last() connprofile.SSHAuthMethod {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.last
}

// buildAuthMethods translates the resolved credential into the ssh
// auth-method list crypto/ssh will try in order. For AuthBoth we offer
// BOTH the public key AND the password so a host that rejects the key
// (e.g. a sudoer where /home was mounted but ~/.ssh/authorized_keys is
// stale) still falls back to password auth. Returning a key-only list
// for AuthBoth was the dialer bug behind the post-v1.2.0 regression
// where the probe never made it past handshake on password-fallback
// hosts.
//
// prefer reorders the AuthBoth list to lead with the host's learned
// method; both methods stay offered (a hint, not a lock). Each method is
// wrapped so obs records which one authenticated.
func buildAuthMethods(cred *credential.Credential, prefer connprofile.SSHAuthMethod, obs *authObserver) ([]ssh.AuthMethod, error) {
	mkKey := func() (ssh.AuthMethod, error) {
		signer, perr := parseSigner(cred)
		if perr != nil {
			return nil, perr
		}
		return ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
			obs.note(connprofile.AuthKey)
			return []ssh.Signer{signer}, nil
		}), nil
	}
	mkPassword := func() ssh.AuthMethod {
		pw := cred.Password
		return ssh.PasswordCallback(func() (string, error) {
			obs.note(connprofile.AuthPassword)
			return pw, nil
		})
	}

	switch cred.AuthMethod {
	case credential.AuthSSHKey:
		keyM, perr := mkKey()
		if perr != nil {
			return nil, perr
		}
		return []ssh.AuthMethod{keyM}, nil
	case credential.AuthPassword:
		return []ssh.AuthMethod{mkPassword()}, nil
	case credential.AuthBoth:
		var keyM, pwM ssh.AuthMethod
		if cred.PrivateKey != "" {
			k, perr := mkKey()
			if perr != nil {
				return nil, perr
			}
			keyM = k
		}
		if cred.Password != "" {
			pwM = mkPassword()
		}
		if keyM == nil && pwM == nil {
			return nil, fmt.Errorf("auth method 'both' but credential carries neither key nor password")
		}
		if prefer == connprofile.AuthPassword {
			return compactMethods(pwM, keyM), nil
		}
		return compactMethods(keyM, pwM), nil
	default:
		return nil, fmt.Errorf("unknown auth method %q", cred.AuthMethod)
	}
}

// compactMethods drops nil entries, preserving order.
func compactMethods(ms ...ssh.AuthMethod) []ssh.AuthMethod {
	out := make([]ssh.AuthMethod, 0, len(ms))
	for _, m := range ms {
		if m != nil {
			out = append(out, m)
		}
	}
	return out
}

type realSession struct {
	client *ssh.Client
}

func (s *realSession) Run(_ context.Context, cmd string) ([]byte, int, error) {
	sess, err := s.client.NewSession()
	if err != nil {
		return nil, -1, err
	}
	defer func() { _ = sess.Close() }()
	out, runErr := sess.CombinedOutput(cmd)
	if runErr != nil {
		var exitErr *ssh.ExitError
		if errors.As(runErr, &exitErr) {
			return out, exitErr.ExitStatus(), nil
		}
		return out, -1, runErr
	}
	return out, 0, nil
}

func (s *realSession) RunWithStdin(_ context.Context, cmd string, stdin io.Reader) ([]byte, int, error) {
	sess, err := s.client.NewSession()
	if err != nil {
		return nil, -1, err
	}
	defer func() { _ = sess.Close() }()

	pipe, perr := sess.StdinPipe()
	if perr != nil {
		return nil, -1, perr
	}
	go func() {
		_, _ = io.Copy(pipe, stdin)
		_ = pipe.Close()
	}()

	out, runErr := sess.CombinedOutput(cmd)
	if runErr != nil {
		var exitErr *ssh.ExitError
		if errors.As(runErr, &exitErr) {
			return out, exitErr.ExitStatus(), nil
		}
		return out, -1, runErr
	}
	return out, 0, nil
}

func (s *realSession) Close() error {
	if s.client == nil {
		return nil
	}
	return s.client.Close()
}

// parseSigner builds the ssh.Signer for a key-bearing credential,
// honoring the passphrase when present.
func parseSigner(cred *credential.Credential) (ssh.Signer, error) {
	if cred.PrivateKeyPassphrase != "" {
		return ssh.ParsePrivateKeyWithPassphrase([]byte(cred.PrivateKey), []byte(cred.PrivateKeyPassphrase))
	}
	return ssh.ParsePrivateKey([]byte(cred.PrivateKey))
}
