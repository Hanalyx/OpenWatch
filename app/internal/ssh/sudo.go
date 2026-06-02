package ssh

import (
	"context"

	"github.com/Hanalyx/openwatch/internal/credential"
)

// SudoSession is the subset of an SSH session that RunSudo needs. The
// stdin pipe path is the security-critical method: it lets RunSudo
// deliver the credential password to sudo without putting it in the
// remote process argv.
//
// Both collector.SSHSession and discovery.SSHSession satisfy this
// interface once their RunWithStdin methods are added.
type SudoSession interface {
	// Run is the no-stdin path. Used for the initial `sudo -n` attempt
	// (NOPASSWD: never needs a password) and for any command that is
	// not gated on sudo.
	Run(ctx context.Context, cmd string) (stdout []byte, exitCode int, err error)

	// RunWithStdin is the password-fallback path. The caller passes the
	// credential password as the stdin payload — never as part of cmd.
	// Implementations MUST send `stdin` to the remote process's stdin
	// and close the pipe before returning.
	RunWithStdin(ctx context.Context, cmd string, stdin []byte) (stdout []byte, exitCode int, err error)
}

// SudoPolicy lets the caller (collector / discovery) inject the system
// policy without importing the systemconfig package. Keeps this dial-
// layer file policy-agnostic and trivially testable.
//
// AllowCredentialPassword corresponds to
// systemconfig.SecurityConfig.AllowCredentialSudoPassword. Set to false
// for the v1.0.0-compatible "sudo -n only" behavior.
type SudoPolicy struct {
	AllowCredentialPassword bool
}

// RunSudo executes `cmd` as root via sudo. The pipeline is:
//
//  1. Always try `sudo -n <cmd>` first. NOPASSWD hosts return exit 0
//     here and the function returns immediately. The credential
//     password is NOT touched.
//  2. If `sudo -n` returns non-zero AND all of the following hold —
//     - policy.AllowCredentialPassword is true,
//     - cred is non-nil,
//     - cred.AuthMethod is "password" or "both",
//     - cred.Password is non-empty —
//     re-execute as `sudo -S -k -p ” <cmd>` with the password fed via
//     the session's stdin pipe. `-k` invalidates the remote sudo
//     credential cache before each attempt so a wrong password fails
//     fast (no PAM retry counter increment, no host-side lockout).
//
// Returns the final stdout, the final exit code, a bool indicating
// whether the password fallback was used (callers aggregate this for
// the per-cycle audit emission), and any transport error.
//
// Source-inspection-friendly: the password is taken from cred.Password
// and passed as the `stdin` argument of RunWithStdin. It does NOT
// appear in the `cmd` string anywhere — see ssh_test.go AC-15.
//
// Spec: system-ssh-connectivity v1.1.0 C-09 / C-10 / C-11 / C-12,
// AC-11..AC-17.
func RunSudo(
	ctx context.Context,
	sess SudoSession,
	cred *credential.Credential,
	policy SudoPolicy,
	cmd string,
) (stdout []byte, exitCode int, usedFallback bool, err error) {
	// Phase 1: sudo -n. The exact wire-shape predates v1.1.0 — every
	// existing collector / discovery call site sent this same prefix.
	out, code, err := sess.Run(ctx, "sudo -n "+cmd)
	if err != nil {
		return out, code, false, err
	}
	if code == 0 {
		// NOPASSWD path. C-12: password fallback MUST NOT execute.
		return out, code, false, nil
	}

	// Phase 2 gating. Any miss → return the sudo -n failure verbatim.
	if !policy.AllowCredentialPassword {
		return out, code, false, nil
	}
	if cred == nil || cred.Password == "" {
		return out, code, false, nil
	}
	if cred.AuthMethod != credential.AuthPassword && cred.AuthMethod != credential.AuthBoth {
		return out, code, false, nil
	}

	// Phase 3: `sudo -S -k -p '' <cmd>`. The password is appended with
	// a newline so sudo's getpass() loop sees a complete line. `-p ''`
	// suppresses the prompt from polluting stdout. `-k` blanks the
	// remote sudo timestamp cache so a stale wrong-password attempt
	// fails on the FIRST sudo call this cycle, not after pam_tally2
	// retries that would lock the host user.
	pwIn := append([]byte(cred.Password), '\n')
	fOut, fCode, fErr := sess.RunWithStdin(ctx, "sudo -S -k -p '' "+cmd, pwIn)
	return fOut, fCode, true, fErr
}
