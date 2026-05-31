// Package sshprivilege implements liveness.PrivilegeProbeFunc: dial
// SSH with the host's resolved credential, run `sudo -n true`, and
// report whether passwordless privilege escalation is configured.
//
// This package is kept OUT of internal/liveness because the liveness
// package's AC-14 invariant forbids credential + crypto/ssh imports.
// The PrivilegeProbeFunc is wired in cmd/openwatch/main.go where both
// the credential resolver and the liveness service are already in
// scope.

package sshprivilege

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Hanalyx/openwatch/internal/credential"
	"github.com/Hanalyx/openwatch/internal/liveness"
	"github.com/google/uuid"
)

// Resolver returns the credential to use for a host. Implementations
// typically wrap credential.Service.Resolve. ErrNoCredential is the
// "no auth configured" signal — the probe records attempted=false and
// returns without touching SSH.
type Resolver interface {
	Resolve(ctx context.Context, hostID uuid.UUID) (*credential.Credential, error)
}

// Probe builds a liveness.PrivilegeProbeFunc backed by the given
// resolver. The returned function:
//
//  1. Looks up the host's credential. On ErrNoCredential it returns
//     attempted=false (the multi-layer state machine leaves the
//     privilege axis untouched).
//  2. Dials TCP-22 with cfg.Timeout = timeout.
//  3. Runs `sudo -n true`. Exit 0 → ok=true; any other exit → ok=false
//     with the exit code in the error.
//
// Host key verification is intentionally permissive (InsecureIgnoreHostKey)
// because this probe is just answering "would sudo work today?" — the
// real scan path validates host keys via internal/ssh.
func Probe(resolver Resolver) liveness.PrivilegeProbeFunc {
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

		cfg := &ssh.ClientConfig{
			User:            cred.Username,
			Timeout:         timeout,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
		switch cred.AuthMethod {
		case credential.AuthSSHKey, credential.AuthBoth:
			signer, perr := parseSigner(cred)
			if perr != nil {
				return true, false, perr
			}
			cfg.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
		case credential.AuthPassword:
			cfg.Auth = []ssh.AuthMethod{ssh.Password(cred.Password)}
		default:
			return true, false, fmt.Errorf("unknown auth method %q", cred.AuthMethod)
		}

		client, derr := ssh.Dial("tcp", addr, cfg)
		if derr != nil {
			return true, false, fmt.Errorf("ssh dial: %w", derr)
		}
		defer func() { _ = client.Close() }()

		session, serr := client.NewSession()
		if serr != nil {
			return true, false, fmt.Errorf("ssh session: %w", serr)
		}
		defer func() { _ = session.Close() }()

		out, runErr := session.CombinedOutput("sudo -n true")
		if runErr != nil {
			var exitErr *ssh.ExitError
			if errors.As(runErr, &exitErr) {
				return true, false, fmt.Errorf("sudo -n true: exit %d: %s", exitErr.ExitStatus(), strings.TrimSpace(string(out)))
			}
			return true, false, fmt.Errorf("run sudo: %w", runErr)
		}
		return true, true, nil
	}
}

// parseSigner builds the ssh.Signer for a key-bearing credential,
// honoring the passphrase when present.
func parseSigner(cred *credential.Credential) (ssh.Signer, error) {
	if cred.PrivateKeyPassphrase != "" {
		return ssh.ParsePrivateKeyWithPassphrase([]byte(cred.PrivateKey), []byte(cred.PrivateKeyPassphrase))
	}
	return ssh.ParsePrivateKey([]byte(cred.PrivateKey))
}
