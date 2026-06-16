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

// Sudo-mode tokens for RunSudo's prefer (in) and observed (out). Plain
// strings — not connprofile's typed enum — so this dial-layer file stays
// decoupled from connprofile, exactly as PreferKey/PreferPassword do for
// the auth method. The values match connprofile.SudoNopasswd /
// connprofile.SudoPassword, so a string()/SudoMode() cast round-trips at
// the call site. An empty prefer/observed means "unknown — no preference".
const (
	SudoNopasswd = "nopasswd"
	SudoPassword = "password"
)

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
// prefer (a Sudo* token, or "" for unknown) is the host's learned sudo
// mode: when it is SudoPassword AND the credential can supply a password,
// RunSudo leads with `sudo -S` and skips the doomed `sudo -n` round-trip.
// Both forms are still attempted on a miss (a hint, not a lock), so a
// stale preference self-heals.
//
// Returns the final stdout, the final exit code, a bool indicating
// whether the password fallback was used (callers aggregate this for
// the per-cycle audit emission), the sudo mode OBSERVED to work this
// call (a Sudo* token, or "" when neither form was confirmed), and any
// transport error. observed is set ONLY on a confirmed exit-0 of a given
// form — a real command that exits non-zero for its own reasons never
// produces a (mis)observation, so callers can safely record it.
//
// Source-inspection-friendly: the password is taken from cred.Password
// and passed as the `stdin` argument of RunWithStdin. It does NOT
// appear in the `cmd` string anywhere — see ssh_test.go AC-15.
//
// Spec: system-ssh-connectivity v1.1.0 C-09 / C-10 / C-11 / C-12,
// AC-11..AC-17; system-connection-profile v1.2.0 C-07 (sudo-mode learning).
func RunSudo(
	ctx context.Context,
	sess SudoSession,
	cred *credential.Credential,
	policy SudoPolicy,
	prefer string,
	cmd string,
) (stdout []byte, exitCode int, usedFallback bool, observed string, err error) {
	canPassword := policy.AllowCredentialPassword &&
		cred != nil && cred.Password != "" &&
		(cred.AuthMethod == credential.AuthPassword || cred.AuthMethod == credential.AuthBoth)

	// Lead with `sudo -S` when the host is known to need a password and we
	// can supply one — the common steady-state case for a password-sudo
	// host, where `sudo -n` would just waste a round-trip. On a miss we
	// still fall back to `sudo -n` (the host may have gained NOPASSWD).
	if prefer == SudoPassword && canPassword {
		pwIn := append([]byte(cred.Password), '\n')
		fOut, fCode, fErr := sess.RunWithStdin(ctx, "sudo -S -k -p '' "+cmd, pwIn)
		if fErr != nil {
			return fOut, fCode, true, "", fErr
		}
		if fCode == 0 {
			return fOut, fCode, true, SudoPassword, nil
		}
		// sudo -S did not succeed; try NOPASSWD in case the host changed.
		nOut, nCode, nErr := sess.Run(ctx, "sudo -n "+cmd)
		if nErr == nil && nCode == 0 {
			return nOut, nCode, true, SudoNopasswd, nil
		}
		// Neither confirmed; surface the password attempt (more
		// informative) with no observation to record.
		return fOut, fCode, true, "", nil
	}

	// Default order — Phase 1: sudo -n. The exact wire-shape predates
	// v1.1.0 — every existing collector / discovery call site sent this
	// same prefix.
	out, code, err := sess.Run(ctx, "sudo -n "+cmd)
	if err != nil {
		return out, code, false, "", err
	}
	if code == 0 {
		// NOPASSWD path. C-12: password fallback MUST NOT execute.
		return out, code, false, SudoNopasswd, nil
	}

	// Phase 2 gating. Any miss → return the sudo -n failure verbatim.
	if !canPassword {
		return out, code, false, "", nil
	}

	// Phase 3: `sudo -S -k -p '' <cmd>`. The password is appended with
	// a newline so sudo's getpass() loop sees a complete line. `-p ''`
	// suppresses the prompt from polluting stdout. `-k` blanks the
	// remote sudo timestamp cache so a stale wrong-password attempt
	// fails on the FIRST sudo call this cycle, not after pam_tally2
	// retries that would lock the host user.
	pwIn := append([]byte(cred.Password), '\n')
	fOut, fCode, fErr := sess.RunWithStdin(ctx, "sudo -S -k -p '' "+cmd, pwIn)
	obs := ""
	if fErr == nil && fCode == 0 {
		obs = SudoPassword
	}
	return fOut, fCode, true, obs, fErr
}
