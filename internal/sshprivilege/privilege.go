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
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Hanalyx/openwatch/internal/connprofile"
	"github.com/Hanalyx/openwatch/internal/credential"
	"github.com/Hanalyx/openwatch/internal/liveness"
	owssh "github.com/Hanalyx/openwatch/internal/ssh"
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
// dial with the host's known-good SSH auth method AND its sudo mode, and
// to record what actually worked. nil (the default) disables learning.
//
// The liveness probe is the authoritative sudo-mode learner: it runs an
// innocuous `true` sentinel every cycle (~5 min), so unlike the
// opportunistic discovery/collector paths it reliably confirms the mode.
type ConnProfileStore interface {
	Get(ctx context.Context, hostID uuid.UUID) (connprofile.Profile, error)
	RecordSSHAuth(ctx context.Context, hostID uuid.UUID, m connprofile.SSHAuthMethod) error
	RecordSudoMode(ctx context.Context, hostID uuid.UUID, m connprofile.SudoMode) error
}

// probeConfig accumulates the optional dependencies a Probe needs.
// Constructed by Probe(...) and the With* options.
type probeConfig struct {
	dialer     Dialer
	policy     PolicyLoader
	profiles   ConnProfileStore
	knownHosts owssh.KnownHostsStore
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

// WithKnownHosts pins the probe's SSH dial to the shared host-key registry
// (TOFU), so the liveness probe verifies host keys exactly like the scan and
// discovery paths instead of ignoring them. Pass the same pool-backed store
// the other paths use (knownhosts.NewStore(pool)). nil (the default) still
// uses TOFU but against an in-process memory store (no cross-restart
// persistence) — fine for tests, not for production.
func WithKnownHosts(store owssh.KnownHostsStore) ProbeOption {
	return func(c *probeConfig) { c.knownHosts = store }
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
// The probe dials through internal/ssh.Dial — the SAME path the compliance
// scan and discovery use — so its auth-method handling (key, password, AND
// PAM keyboard-interactive) and host-key verification stay identical and
// cannot drift. In particular it offers keyboard-interactive, so a hardened
// host (PasswordAuthentication no + UsePAM keyboard-interactive) authenticates
// here exactly as it does for a scan. Host keys are verified via TOFU against
// the shared registry when WithKnownHosts is wired.
func Probe(resolver Resolver, opts ...ProbeOption) liveness.PrivilegeProbeFunc {
	cfg := probeConfig{}
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.dialer == nil {
		cfg.dialer = realDialer{mode: owssh.ModeTOFU, store: cfg.knownHosts}
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

		// Learning: lead the dial with the host's recorded auth method AND
		// sudo mode (if a profile store is wired and a row exists), then
		// record what actually worked. Both are best-effort: a lookup miss
		// just dials/escalates in the default order.
		var prefer connprofile.SSHAuthMethod
		var knownSudo connprofile.SudoMode
		if cfg.profiles != nil {
			if p, gerr := cfg.profiles.Get(ctx, id); gerr == nil {
				prefer = p.SSHAuthMethod
				knownSudo = p.SudoMode
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

		ok, sudoMode, sudoErr := probeSudo(ctx, exec, cred, cfg.policy, knownSudo)
		if cfg.profiles != nil && sudoMode != connprofile.SudoUnknown && sudoMode != knownSudo {
			_ = cfg.profiles.RecordSudoMode(ctx, id, sudoMode)
		}
		return true, ok, sudoErr
	}
}

// probeSudo determines whether sudo works and in which mode, by running
// the innocuous `true` sentinel under each form. It leads with `sudo -S`
// when the host is known to need a password (knownSudo == SudoPassword)
// and the policy + credential permit one — skipping the doomed `sudo -n`.
// Otherwise it keeps the historical `sudo -n` first order. Both forms are
// still attempted on a miss (a hint, not a lock), so a stale mode self-
// heals on the next probe.
//
// Returns ok (sudo usable), the mode CONFIRMED to work (SudoUnknown when
// neither did), and on failure the same diagnostic error the pre-learning
// probe returned (preserving spec AC-18/AC-19/AC-21 behaviour). Spec
// system-connection-profile v1.2.0 C-07.
func probeSudo(
	ctx context.Context,
	exec SessionExecutor,
	cred *credential.Credential,
	policy PolicyLoader,
	knownSudo connprofile.SudoMode,
) (ok bool, mode connprofile.SudoMode, err error) {
	canPassword := canFallback(ctx, policy, cred)

	runN := func() (bool, []byte, int) {
		out, code, runErr := exec.Run(ctx, "sudo -n true")
		return runErr == nil && code == 0, out, code
	}
	runS := func() (bool, []byte, int) {
		stdin := bytes.NewReader([]byte(cred.Password + "\n"))
		out, code, runErr := exec.RunWithStdin(ctx, "sudo -S -k -p '' true", stdin)
		return runErr == nil && code == 0, out, code
	}

	// Lead with sudo -S on a known password-sudo host.
	if knownSudo == connprofile.SudoPassword && canPassword {
		if good, _, _ := runS(); good {
			return true, connprofile.SudoPassword, nil
		}
		// sudo -S did not confirm; the host may have gained NOPASSWD.
		good, out, code := runN()
		if good {
			return true, connprofile.SudoNopasswd, nil
		}
		return false, connprofile.SudoUnknown,
			fmt.Errorf("sudo -n true: exit %d: %s", code, strings.TrimSpace(string(out)))
	}

	// Default order — Layer 1: sudo -n true. The 80% case where NOPASSWD
	// is set.
	good, out, code := runN()
	if good {
		return true, connprofile.SudoNopasswd, nil
	}

	// Layer 2 (v1.2.0): sudo -S -k -p '' true. Only when the policy +
	// credential permit. Per spec C-09 / AC-19, the auth method must allow
	// password material AND the password field must be populated.
	if !canPassword {
		return false, connprofile.SudoUnknown,
			fmt.Errorf("sudo -n true: exit %d: %s", code, strings.TrimSpace(string(out)))
	}

	good2, out2, code2 := runS()
	if good2 {
		return true, connprofile.SudoPassword, nil
	}
	return false, connprofile.SudoUnknown,
		fmt.Errorf("sudo -S -k -p '' true: exit %d: %s", code2, strings.TrimSpace(string(out2)))
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

// realDialer is the production Dialer. It delegates to internal/ssh.Dial —
// the SAME dial the compliance scan and discovery use — so the probe inherits
// that path's auth-method handling (key, password, AND PAM keyboard-interactive)
// and host-key verification instead of forking its own. A forked auth list was
// the bug behind the "[none publickey], no supported methods remain" failures
// on hardened hosts (PasswordAuthentication no + PAM keyboard-interactive): the
// old probe offered only the bare password method, which such a server never
// advertises, so a password-fallback host that scanned fine showed degraded.
type realDialer struct {
	mode  owssh.Mode
	store owssh.KnownHostsStore
}

func (d realDialer) Dial(ctx context.Context, cred *credential.Credential, addr string, timeout time.Duration, prefer connprofile.SSHAuthMethod) (SessionExecutor, connprofile.SSHAuthMethod, error) {
	host, portStr, serr := net.SplitHostPort(addr)
	if serr != nil {
		return nil, "", fmt.Errorf("invalid addr %q: %w", addr, serr)
	}
	port, perr := strconv.Atoi(portStr)
	if perr != nil {
		return nil, "", fmt.Errorf("invalid port in %q: %w", addr, perr)
	}

	// PreferAuth / ObservedAuth speak the same "key"/"password" string values
	// as connprofile.SSHAuthMethod, so the mapping is a direct cast.
	var observed string
	client, derr := owssh.Dial(ctx, host, port, cred, owssh.DialOptions{
		Mode:         d.mode,
		Store:        d.store,
		Timeout:      timeout,
		PreferAuth:   string(prefer),
		ObservedAuth: &observed,
	})
	if derr != nil {
		// The Probe caller prefixes "ssh dial:"; return the internal/ssh
		// sentinel (ErrAuthFailed / ErrHostKeyUnknown / ...) unwrapped so it
		// stays errors.Is-inspectable and isn't double-prefixed.
		return nil, "", derr
	}
	return &realSession{client: client}, connprofile.SSHAuthMethod(observed), nil
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
