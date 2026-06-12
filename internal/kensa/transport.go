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
	cryptossh "golang.org/x/crypto/ssh"

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

// TransportFactory implements kensa api.TransportFactory for one scan.
// It is constructed per scan with the host's already-resolved,
// in-memory credential; the caller owns the credential's lifecycle
// (wipe-after-scan), mirroring the CredentialBridge contract.
type TransportFactory struct {
	// Cred is the resolved credential used for authentication.
	// HostConfig.KeyPath is ignored — key material never touches disk.
	Cred *credential.Credential
	// Mode is the host-key verification policy (internal/ssh.Mode).
	Mode owssh.Mode
	// Store is the known-hosts store backing Mode.
	Store owssh.KnownHostsStore
}

// Connect dials host.Hostname:host.Port with the factory's in-memory
// credential and returns a live Transport. host.Sudo selects sudo
// command wrapping per the api.Transport contract.
func (f *TransportFactory) Connect(ctx context.Context, host kensaapi.HostConfig) (kensaapi.Transport, error) {
	if f.Cred == nil {
		return nil, errors.New("kensa transport: factory requires a resolved credential")
	}
	port := host.Port
	if port == 0 {
		port = 22
	}
	client, err := owssh.Dial(ctx, host.Hostname, port, f.Cred, owssh.DialOptions{
		Mode:    f.Mode,
		Store:   f.Store,
		Timeout: owssh.DefaultDialTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("kensa transport: dial %s: %w", host.Hostname, err)
	}
	return &sshTransport{client: client, sudo: host.Sudo}, nil
}

// sshTransport is one live SSH connection; each Run opens a fresh
// session on it (sessions are cheap; the TCP+handshake is shared).
type sshTransport struct {
	client *cryptossh.Client
	sudo   bool
}

// Run executes cmd on the host. A non-zero remote exit code is a valid
// *CommandResult (checks branch on exit codes); only transport-level
// failures (session open, missing exit status, ctx cancellation)
// return a non-nil error. Spec AC-20.
func (t *sshTransport) Run(ctx context.Context, cmd string) (*kensaapi.CommandResult, error) {
	sess, err := t.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("kensa transport: new session: %w", err)
	}
	defer func() { _ = sess.Close() }()

	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr

	start := time.Now()
	if err := sess.Start(commandLine(cmd, t.sudo)); err != nil {
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
func (t *sshTransport) ControlChannelSensitive() bool { return false }

// Close terminates the underlying SSH connection.
func (t *sshTransport) Close() error { return t.client.Close() }

// commandLine renders the remote command per the api.Transport
// contract: with sudo, wrap as sudo -n sh -c with the command
// single-quoted and embedded single quotes escaped (quote, backslash
// quote, quote); without sudo, the command passes through unmodified.
// Spec AC-19.
func commandLine(cmd string, sudo bool) string {
	if !sudo {
		return cmd
	}
	return "sudo -n sh -c '" + strings.ReplaceAll(cmd, "'", `'\''`) + "'"
}

// trimOneTrailingNewline removes exactly one trailing newline (LF or
// CRLF) from captured output, per the CommandResult contract. Spec
// AC-20.
func trimOneTrailingNewline(s string) string {
	s = strings.TrimSuffix(s, "\n")
	return strings.TrimSuffix(s, "\r")
}
