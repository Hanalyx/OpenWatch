// SSH transport adapter — implements kensa api.Transport over
// OpenWatch's internal/ssh dial layer.
//
// Kensa's bundled transports authenticate from key files on disk
// (HostConfig.KeyPath) or ssh-agent; OpenWatch's security model keeps
// decrypted credentials in memory only. This adapter bridges the two:
// the factory carries an already-resolved *credential.Credential and
// dials with internal/ssh.Dial (golang.org/x/crypto/ssh — the same
// stack every other OpenWatch host-communication path uses: liveness,
// discovery, intelligence). HostConfig.KeyPath is deliberately ignored.
//
// Scope: the scan path only ever calls Run. Put and Get are used by
// Kensa's agent-bootstrap flow, not by Kensa.Scan, so they return
// ErrTransportOpNotSupported until remediation (which may upload
// helper payloads) needs them.
//
// Spec: system-kensa-executor v2.2.0 C-15 (AC-19, AC-20, AC-21).
package kensa

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"

	kensaapi "github.com/Hanalyx/kensa/api"
	"github.com/google/uuid"
	cryptossh "golang.org/x/crypto/ssh"

	"github.com/Hanalyx/openwatch/internal/connprofile"
	"github.com/Hanalyx/openwatch/internal/credential"
	owssh "github.com/Hanalyx/openwatch/internal/ssh"
)

// ErrTransportOpNotSupported is returned by Transport operations the
// scan-only transport does not implement (Put, Get). Spec AC-21.
var ErrTransportOpNotSupported = errors.New("kensa transport: operation not supported by the scan transport")

// Compile-time interface conformance.
var (
	_ kensaapi.TransportFactory = (*TransportFactory)(nil)
	_ kensaapi.Transport        = (*sshTransport)(nil)
)

// CredentialResolver resolves a host's credential into in-memory
// plaintext fields (username, key material, password, passphrase).
// Production wires credential.Service.Resolve; tests inject fakes.
type CredentialResolver func(ctx context.Context, hostID uuid.UUID) (*credential.Credential, error)

// ConnProfile is the per-host connection memory the scan transport reads
// to lead with the known-good SSH auth method + sudo mode, and writes when
// it learns (or re-learns) them. nil disables learning — the transport
// then behaves statelessly (key-first auth, probe sudo every connection).
// *connprofile.Store satisfies it; tests pass a fake or nil.
type ConnProfile interface {
	Get(ctx context.Context, hostID uuid.UUID) (connprofile.Profile, error)
	RecordSSHAuth(ctx context.Context, hostID uuid.UUID, m connprofile.SSHAuthMethod) error
	RecordSudoMode(ctx context.Context, hostID uuid.UUID, m connprofile.SudoMode) error
}

// SudoPasswordPolicy reports whether the operator permits feeding the
// credential password to remote sudo (systemconfig
// SecurityConfig.AllowCredentialSudoPassword — the kill-switch). It is the
// SAME gate the collector / liveness / discovery paths consult; the scan
// MUST honor it too or the switch silently fails open on the busiest path.
// Returning an error is treated as "allowed" to match LoadSecurity's
// missing-row fallback (default-on).
type SudoPasswordPolicy func(ctx context.Context) (allowed bool, err error)

// sudoPasswordFor returns the password the transport may use for `sudo -S`,
// or "" when password-sudo is not permitted. It applies the SAME two gates
// the other SSH paths enforce: (1) the kill-switch, (2) the credential's
// auth method must allow password material. Note this gates only the SUDO
// use of the password — SSH password AUTH is independent and still uses
// cred.Password directly in the dial.
func sudoPasswordFor(cred *credential.Credential, allowed bool) string {
	if !allowed || cred == nil || cred.Password == "" {
		return ""
	}
	if cred.AuthMethod != credential.AuthPassword && cred.AuthMethod != credential.AuthBoth {
		return ""
	}
	return cred.Password
}

// TransportFactory implements kensa api.TransportFactory for the
// long-lived Kensa instance. One factory serves every scan: Connect
// resolves the target host's credential per call, keyed by the host id
// the ScanFunc smuggles through HostConfig.FleetID (kensa treats
// FleetID as opaque context, which is exactly what a per-host UUID is).
type TransportFactory struct {
	// Resolve maps host id -> in-memory credential per connection.
	// HostConfig.KeyPath is ignored — key material never touches disk.
	Resolve CredentialResolver
	// Mode is the host-key verification policy (internal/ssh.Mode).
	Mode owssh.Mode
	// Store is the known-hosts store backing Mode.
	Store owssh.KnownHostsStore
	// Profiles is the per-host connection memory (nil disables learning).
	Profiles ConnProfile
	// Policy gates whether the credential password may be used for sudo -S
	// (the AllowCredentialSudoPassword kill-switch). nil => allowed
	// (default-on, matching DefaultSecurity); production wires the real
	// systemconfig loader so a flipped switch disables scan password-sudo.
	Policy SudoPasswordPolicy
	// Apply makes the produced transport report ControlChannelSensitive()
	// true, so the Kensa engine permits APPLY steps (host mutation). The
	// scan path leaves this false (read-only); only the remediation factory
	// sets it true. This is the load-bearing gate that keeps a scan
	// connection from ever changing a host.
	Apply bool
}

// Connect resolves the host's credential and dials
// host.Hostname:host.Port. host.User, when non-empty, overrides the
// credential's username (the hosts.username per-host override).
// host.Sudo requests sudo wrapping; it is downgraded when the
// effective user is already root (sudo would be a no-op that some
// hardened hosts reject for root anyway).
func (f *TransportFactory) Connect(ctx context.Context, host kensaapi.HostConfig) (kensaapi.Transport, error) {
	if f.Resolve == nil {
		return nil, errors.New("kensa transport: factory requires a credential resolver")
	}
	hostID, err := uuid.Parse(host.FleetID)
	if err != nil {
		return nil, fmt.Errorf("kensa transport: HostConfig.FleetID must carry the host id: %w", err)
	}
	cred, err := f.Resolve(ctx, hostID)
	if err != nil {
		return nil, fmt.Errorf("kensa transport: resolve credential: %w", err)
	}
	cred, sudo := effectiveCredAndSudo(cred, host)
	port := host.Port
	if port == 0 {
		port = 22
	}

	// Lead with the host's recorded SSH auth method + sudo mode so the
	// common case is one publickey-or-password attempt and one sudo form,
	// not a doomed key attempt or a wasted `sudo -n` round-trip.
	var prefer string
	var knownSudo connprofile.SudoMode
	if f.Profiles != nil {
		if p, perr := f.Profiles.Get(ctx, hostID); perr == nil {
			prefer = sshPrefer(p.SSHAuthMethod)
			knownSudo = p.SudoMode
		}
	}

	var observed string
	client, err := owssh.Dial(ctx, host.Hostname, port, cred, owssh.DialOptions{
		Mode:         f.Mode,
		Store:        f.Store,
		Timeout:      owssh.DefaultDialTimeout,
		PreferAuth:   prefer,
		ObservedAuth: &observed,
	})
	if err != nil {
		return nil, fmt.Errorf("kensa transport: dial %s: %w", host.Hostname, err)
	}
	if f.Profiles != nil && observed != "" {
		_ = f.Profiles.RecordSSHAuth(ctx, hostID, connprofile.SSHAuthMethod(observed))
	}

	// Gate the SUDO use of the password on the kill-switch + auth method —
	// the same two conditions the collector / liveness / discovery paths
	// enforce. When disallowed the transport gets no sudo password, so the
	// probe never attempts sudo -S and the connection degrades to sudo -n.
	// (SSH password AUTH above is unaffected: the dial already used the
	// full credential.)
	sudoAllowed := true
	if f.Policy != nil {
		if v, perr := f.Policy(ctx); perr == nil {
			sudoAllowed = v
		}
	}
	sudoPassword := sudoPasswordFor(cred, sudoAllowed)

	t := &sshTransport{client: client, sudo: sudo, password: sudoPassword, apply: f.Apply}

	// Decide how to reach root, once per connection, and reuse it for
	// every command. We cannot infer "sudo refused" from a real check's
	// non-zero exit (checks branch on exit codes), so a dedicated `true`
	// sentinel removes the ambiguity. The recorded mode only picks which
	// form to try first — the probe still confirms it, so a stale hint
	// (sudoers changed) self-heals.
	switch {
	case sudo:
		// probe with the GATED password: when password-sudo is disallowed
		// sudoPassword is "", so probeSudoMode never attempts sudo -S.
		t.mode = probeSudoMode(ctx, client, sudoPassword, knownSudo)
	case host.Sudo: // requested, but the login user is already root
		t.mode = connprofile.SudoRoot
	default: // no escalation requested — nothing to learn
		t.mode = connprofile.SudoUnknown
	}
	if f.Profiles != nil && t.mode != connprofile.SudoUnknown && t.mode != knownSudo {
		_ = f.Profiles.RecordSudoMode(ctx, hostID, t.mode)
	}
	return t, nil
}

// sshPrefer maps a recorded SSH auth method to the ssh dial-layer
// preference token. Unknown -> "" (historical key-first order).
func sshPrefer(m connprofile.SSHAuthMethod) string {
	switch m {
	case connprofile.AuthKey:
		return owssh.PreferKey
	case connprofile.AuthPassword:
		return owssh.PreferPassword
	}
	return ""
}

// probeSudoMode determines how the connection reaches root by running the
// innocuous `true` under each sudo form, leading with `prefer` so a host
// with a recorded mode usually needs a single round-trip. Returns
// SudoUnknown when neither form works (no NOPASSWD and no usable password)
// — the transport then degrades to `sudo -n`, exactly as before.
func probeSudoMode(ctx context.Context, client *cryptossh.Client, password string, prefer connprofile.SudoMode) connprofile.SudoMode {
	tryN := func() bool {
		res, err := runRaw(ctx, client, "sudo -n true", nil)
		return err == nil && res != nil && res.ExitCode == 0
	}
	tryS := func() bool {
		if password == "" {
			return false
		}
		res, err := runRaw(ctx, client, "sudo -S -p '' true", []byte(password+"\n"))
		return err == nil && res != nil && res.ExitCode == 0
	}
	if prefer == connprofile.SudoPassword {
		if tryS() {
			return connprofile.SudoPassword
		}
		if tryN() {
			return connprofile.SudoNopasswd
		}
		return connprofile.SudoUnknown
	}
	if tryN() {
		return connprofile.SudoNopasswd
	}
	if tryS() {
		return connprofile.SudoPassword
	}
	return connprofile.SudoUnknown
}

// effectiveCredAndSudo applies the per-host username override
// (HostConfig.User, from hosts.username) via a shallow copy — the
// cached credential object is never mutated — and downgrades sudo when
// the effective user is already root. Spec AC-22.
func effectiveCredAndSudo(cred *credential.Credential, host kensaapi.HostConfig) (*credential.Credential, bool) {
	if host.User != "" && host.User != cred.Username {
		c := *cred
		c.Username = host.User
		cred = &c
	}
	return cred, host.Sudo && cred.Username != "root"
}

// sshTransport is one live SSH connection; each Run opens a fresh
// session on it (sessions are cheap; the TCP+handshake is shared).
//
// mode + password are set once at Connect and read-only thereafter, so
// concurrent Run calls (Kensa may parallelize rule checks on one host)
// need no synchronization.
type sshTransport struct {
	client   *cryptossh.Client
	sudo     bool
	password string
	mode     connprofile.SudoMode
	// apply mirrors TransportFactory.Apply: true only for remediation
	// connections, gating ControlChannelSensitive (host mutation).
	apply bool
}

// Run executes cmd on the host, wrapping it for privilege escalation per
// the connection's determined sudo mode. A non-zero remote exit code is a
// valid *CommandResult (checks branch on exit codes); only transport-level
// failures (session open, missing exit status, ctx cancellation) return a
// non-nil error. Spec AC-19, AC-20.
func (t *sshTransport) Run(ctx context.Context, cmd string) (*kensaapi.CommandResult, error) {
	line, stdin := t.wrap(cmd)
	return runRaw(ctx, t.client, line, stdin)
}

// wrap renders the remote command line and the optional stdin payload for
// the connection's privilege mode:
//   - no sudo (root login, or escalation not requested): command verbatim.
//   - password sudo: `sudo -S -p ” sh -c '<cmd>'` with the credential
//     password (newline-terminated) on stdin. No `-k`: the scan issues
//     many commands per host, so we let sudo's own timestamp cache short-
//     circuit when it can and simply re-supply the password otherwise —
//     unlike the single-shot liveness/discovery probes, which `-k` to fail
//     a stale wrong password fast.
//   - otherwise (nopasswd / unknown): `sudo -n sh -c '<cmd>'`. On unknown
//     this is the historical degrade-gracefully behaviour.
func (t *sshTransport) wrap(cmd string) (line string, stdin []byte) {
	if !t.sudo {
		return cmd, nil
	}
	if t.mode == connprofile.SudoPassword {
		return "sudo -S -p '' sh -c '" + escapeSingleQuotes(cmd) + "'", []byte(t.password + "\n")
	}
	return "sudo -n sh -c '" + escapeSingleQuotes(cmd) + "'", nil
}

// runRaw executes line on a fresh session of client, optionally feeding
// stdin (the sudo -S password) to the remote process. Shared by Run and
// the connection-time sudo probe.
func runRaw(ctx context.Context, client *cryptossh.Client, line string, stdin []byte) (*kensaapi.CommandResult, error) {
	sess, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("kensa transport: new session: %w", err)
	}
	defer func() { _ = sess.Close() }()

	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr
	if stdin != nil {
		sess.Stdin = bytes.NewReader(stdin)
	}

	start := time.Now()
	if err := sess.Start(line); err != nil {
		return nil, fmt.Errorf("kensa transport: start: %w", err)
	}

	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()

	select {
	case <-ctx.Done():
		// Best-effort teardown; Wait's goroutine drains via the
		// buffered channel after Close unblocks it.
		_ = sess.Signal(cryptossh.SIGKILL)
		_ = sess.Close()
		return nil, ctx.Err()
	case werr := <-done:
		res := &kensaapi.CommandResult{
			ExitCode: 0,
			Stdout:   trimOneTrailingNewline(stdout.String()),
			Stderr:   trimOneTrailingNewline(stderr.String()),
			Duration: time.Since(start),
		}
		if werr != nil {
			var exitErr *cryptossh.ExitError
			if errors.As(werr, &exitErr) {
				// Remote command ran and exited non-zero: a result,
				// not an error (AC-20).
				res.ExitCode = exitErr.ExitStatus()
				return res, nil
			}
			return nil, fmt.Errorf("kensa transport: wait: %w", werr)
		}
		return res, nil
	}
}

// Put is not implemented by the scan transport (agent-bootstrap /
// remediation surface). Spec AC-21.
func (t *sshTransport) Put(_ context.Context, _, remotePath string, _ fs.FileMode) error {
	return fmt.Errorf("Put %s: %w", remotePath, ErrTransportOpNotSupported)
}

// Get is not implemented by the scan transport. Spec AC-21.
func (t *sshTransport) Get(_ context.Context, remotePath, _ string) error {
	return fmt.Errorf("Get %s: %w", remotePath, ErrTransportOpNotSupported)
}

// ControlChannelSensitive reports false: the scan transport never
// applies changes, so no in-flight change can disrupt it. Spec AC-21.
func (t *sshTransport) ControlChannelSensitive() bool { return t.apply }

// Close terminates the underlying SSH connection.
func (t *sshTransport) Close() error { return t.client.Close() }

// escapeSingleQuotes renders cmd safe to embed inside a single-quoted
// `sh -c '...'` wrapper: each embedded single quote becomes the
// quote / backslash-quote / quote idiom. Spec AC-19.
func escapeSingleQuotes(cmd string) string {
	return strings.ReplaceAll(cmd, "'", `'\''`)
}

// trimOneTrailingNewline removes exactly one trailing newline (LF or
// CRLF) from captured output, per the CommandResult contract. Spec
// AC-20.
func trimOneTrailingNewline(s string) string {
	s = strings.TrimSuffix(s, "\n")
	return strings.TrimSuffix(s, "\r")
}
