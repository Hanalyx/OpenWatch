package ssh

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	cryptossh "golang.org/x/crypto/ssh"

	"github.com/Hanalyx/openwatch/internal/credential"
	"github.com/Hanalyx/openwatch/internal/credprotect"
)

// ProtectedSudoMode selects execution before any remote command starts.
type ProtectedSudoMode string

const (
	// SudoCachedOnly sends no password and never falls back.
	SudoCachedOnly ProtectedSudoMode = "cached"
	// SudoPasswordOnly reserves one password invocation, without fallback.
	SudoPasswordOnly ProtectedSudoMode = "password"
	// SudoReadOnlyFallback permits fallback only before the command has started.
	SudoReadOnlyFallback ProtectedSudoMode = "read_only"
	// SudoVerifyPassword checks a fresh password without running a command.
	SudoVerifyPassword ProtectedSudoMode = "verify"
)

// ErrSudoProfile means the invocation has no valid single-attempt profile.
var ErrSudoProfile = errors.New("ssh: password sudo needs a validated single-attempt profile")

// ValidatedSudoProfile is trusted configuration for this exact invocation.
// It must come from policy validation, never from a login or a caller's
// guess. Slice 6 supplies it; this adapter does not discover or change sudoers.
// Evidence must cover sudoers, PAM, the invoking account, and this command.
// A profile is invalid after any change to those inputs, even before expiry.
// One submission does not imply one PAM failure on an unvalidated host.
type ValidatedSudoProfile struct {
	HostID   uuid.UUID
	Username string
	// Command is empty for verification, otherwise the exact command string.
	Command        string
	EvidenceID     string
	ExpiresAt      time.Time
	PasswordTries  int
	MaxPAMFailures int
	InvokingUser   bool
}

func (p *ValidatedSudoProfile) admits(host uuid.UUID, username, command string) bool {
	return p != nil && p.HostID == host && p.Username == username && p.Command == command &&
		strings.TrimSpace(p.EvidenceID) != "" && time.Now().Before(p.ExpiresAt) &&
		p.PasswordTries == 1 && p.MaxPAMFailures == 1 && p.InvokingUser // pragma: allowlist secret (policy counts)
}

// ProtectedSudoOptions configures one invocation. Auth supplies the same
// reservation, keyring and transaction-bound Current reader as ProtectedDial.
// Password modes share SSH's password protection state; Stage is attribution.
type ProtectedSudoOptions struct {
	Mode    ProtectedSudoMode
	Auth    ProtectedOptions
	Profile *ValidatedSudoProfile
	Timeout time.Duration
	// CaptureLimit bounds each output stream. Zero selects one MiB.
	CaptureLimit int
}

// SudoResult separates command execution, password submission and protection.
// Output may be truncated; incomplete capture never permits fallback or recovery.
// There are no password or fingerprint fields in the result.
type SudoResult struct {
	Stdout         []byte
	Stderr         []byte
	ExitCode       int
	Complete       bool
	CommandStarted bool
	PromptSeen     bool
	Submitted      bool
	Attempt        ProtectedResult
}

// ProtectedSudo executes on an established SSH connection. The caller must
// give it exclusive use of that connection for the call: cancellation,
// refusal during authentication, and failed settlement close it. Ordinary
// command failures do not retry. No production consumer uses this adapter yet.
func ProtectedSudo(ctx context.Context, client *cryptossh.Client, cred *credential.Credential,
	command string, opts ProtectedSudoOptions) (SudoResult, error) {
	res := SudoResult{ExitCode: -1}
	if client == nil {
		return res, errors.New("ssh: protected sudo needs a client")
	}
	switch opts.Mode {
	case SudoCachedOnly, SudoPasswordOnly, SudoReadOnlyFallback:
		if strings.TrimSpace(command) == "" || strings.ContainsRune(command, 0) {
			return res, errors.New("ssh: sudo command is empty or contains NUL")
		}
	case SudoVerifyPassword:
		if command != "" {
			return res, errors.New("ssh: verification cannot run a command")
		}
	default:
		return res, errors.New("ssh: choose a sudo mode before execution")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = time.Minute
	}
	if opts.CaptureLimit <= 0 {
		opts.CaptureLimit = 1 << 20
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	if opts.Mode == SudoCachedOnly || opts.Mode == SudoReadOnlyFallback {
		attempt, err := sudoExec(ctx, client, command, false, false, opts.CaptureLimit, nil)
		res = attempt.result()
		if opts.Mode == SudoCachedOnly || !attempt.fallback() {
			return res, err
		}
	}
	if cred == nil || client.User() != cred.Username || !opts.Profile.admits(opts.Auth.HostID, cred.Username, command) {
		return res, ErrSudoProfile
	}
	// A line is the entire response. Embedded delimiters would add responses.
	if cred.Password == "" || len(cred.Password) > 16384 || strings.ContainsAny(cred.Password, "\r\n\x00") {
		return res, errors.New("ssh: sudo password is not a single supported line")
	}
	auth := opts.Auth
	auth.Secret = SecretKindPassword // pragma: allowlist secret (method name)
	if opts.Mode == SudoVerifyPassword {
		auth.Kind = credprotect.KindVerification
	}
	if auth.Kind == credprotect.KindVerification && opts.Mode != SudoVerifyPassword {
		return res, errors.New("ssh: recovery must use a dedicated sudo verification")
	}
	var err error
	auth, err = auth.complete(cred)
	if err != nil {
		return res, err
	}
	// A privileged command holds its reservation until it ends, not just auth.
	auth.TTL = opts.Timeout + DefaultReservationMargin
	g := &gate{opts: auth, ctx: ctx}
	g.cred, _, g.secret, err = identify(cred, auth)
	if err != nil {
		return res, err
	}
	sub, err := auth.Protection.Reserve(ctx, credprotect.Request{
		CredentialID: auth.CredentialID, HostID: auth.HostID, Secret: g.secret,
		Kind: auth.Kind, Stage: "sudo", Owner: auth.Owner, TTL: auth.TTL,
	})
	if err != nil {
		return res, fmt.Errorf("%w: %w", ErrProtected, err)
	}
	g.sub = sub.ID
	attempt := &sudoExchange{exit: -1}
	var runErr error
	if !opts.Profile.admits(auth.HostID, g.cred.Username, command) {
		runErr = ErrSudoProfile
	} else {
		attempt, runErr = sudoExec(ctx, client, command, true, opts.Mode == SudoVerifyPassword, opts.CaptureLimit,
			func() (string, error) {
				if !opts.Profile.admits(auth.HostID, g.cred.Username, command) {
					return "", ErrSudoProfile
				}
				if err := g.fence(); err != nil {
					return "", err
				}
				return g.cred.Password, nil
			})
	}
	res = attempt.result()
	res.Attempt = ProtectedResult{Reserved: true, Submission: sub.ID, Outcome: attempt.outcome()}
	if res.Submitted {
		res.Attempt.Method = "sudo"
	}
	sctx, stop := context.WithTimeout(context.WithoutCancel(ctx), settleTimeout)
	defer stop()
	res.Attempt.Settled, err = auth.Protection.Settle(sctx, sub.ID, res.Attempt.Outcome)
	if err != nil {
		_ = client.Close()
		return res, fmt.Errorf("%w: %w", ErrNotRecorded, err)
	}
	return res, runErr
}

// sudoArgv quotes each argument. The marker script is constant; user command
// text reaches it only as a positional argument, never as script source.
func sudoArgv(args ...string) string {
	quoted := make([]string, len(args))
	for i, arg := range args {
		quoted[i] = "'" + strings.ReplaceAll(arg, "'", "'\"'\"'") + "'"
	}
	return strings.Join(quoted, " ")
}

const sudoMarkerScript = `printf 'OWEXEC-%s\n' "$1" >&2 && shift && exec /bin/sh -c "$1"`

func sudoNonce() (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(nonce[:]), nil
}
