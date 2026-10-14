package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Hanalyx/openwatch/internal/credential"
	"golang.org/x/crypto/ssh"
)

// DefaultDialTimeout is the upper bound on connect+handshake. Callers
// may supply a tighter ctx deadline; can't loosen.
//
// Spec C-01.
const DefaultDialTimeout = 10 * time.Second

// Dial-layer errors. Distinct sentinels per failure mode so callers
// (audit emitter, connectivity-check handler) can map to specific
// reason strings without parsing error text.
//
// Spec C-06.
var (
	ErrConnect      = errors.New("ssh: tcp connect failed")
	ErrAuthFailed   = errors.New("ssh: authentication failed")
	ErrDialTimeout  = errors.New("ssh: dial timed out")
	ErrNoAuthMethod = errors.New("ssh: credential has no usable auth method")
)

// DialOptions configures one Dial. Mode + Store cover host-key
// verification; Timeout bounds the connect+handshake.
type DialOptions struct {
	Mode    Mode
	Store   KnownHostsStore
	Timeout time.Duration

	// PreferAuth, when "key" or "password", offers that auth method
	// FIRST (the other is still offered as fallback). Empty preserves the
	// historical key-first order. Callers set this from the host's
	// recorded connection profile to avoid a doomed publickey attempt on
	// a password-only host (which counts against MaxAuthTries / trips
	// fail2ban).
	PreferAuth string

	// ObservedAuth, when non-nil, receives the auth method that actually
	// authenticated ("key" | "password") after a successful dial. Callers
	// persist it so the next connection leads with it. Untouched on dial
	// failure.
	ObservedAuth *string
}

// netDial is the network-level dial function. Production uses
// net.Dialer; tests override to assert no-network code paths
// (spec AC-10).
var netDial = func(ctx context.Context, network, address string) (net.Conn, error) {
	d := net.Dialer{}
	return d.DialContext(ctx, network, address)
}

// Dial opens an SSH connection to host:port using cred. On success
// returns a live *ssh.Client; caller must Close it. On failure returns
// a sentinel error from the package's error set (never raw network or
// crypto errors that might leak credential material).
//
// The TCP connect AND the SSH handshake are both bounded by
// min(ctx deadline, opts.Timeout), and canceling ctx aborts either.
// crypto/ssh's ClientConfig.Timeout covers only the TCP dial inside
// ssh.Dial, not ssh.NewClientConn, so the handshake is bounded here by
// closing the connection when that bound passes.
//
// Spec AC-01, AC-02, AC-03, AC-04, AC-06, AC-07, AC-08, AC-09, AC-19, C-01, C-03.
func Dial(ctx context.Context, host string, port int, cred *credential.Credential, opts DialOptions) (*ssh.Client, error) {
	cfg, obs, opts, err := clientConfig(host, cred, opts)
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	dialCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	conn, err := netDial(dialCtx, "tcp", addr)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isNetTimeout(err) {
			return nil, ErrDialTimeout
		}
		return nil, fmt.Errorf("%w: %v", ErrConnect, sanitizeNetErr(err))
	}
	return handshake(dialCtx, conn, addr, cfg, obs, opts)
}

// DialConn runs the SSH handshake for cred over an already-connected conn,
// with the same bounds, host-key policy and auth ordering as Dial. It takes
// ownership of conn: on failure conn is closed. host names the server for
// host-key verification. Spec AC-19.
func DialConn(ctx context.Context, conn net.Conn, host string, cred *credential.Credential, opts DialOptions) (*ssh.Client, error) {
	cfg, obs, opts, err := clientConfig(host, cred, opts)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	hsCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	return handshake(hsCtx, conn, host, cfg, obs, opts)
}

// clientConfig validates the credential and builds the client config.
func clientConfig(host string, cred *credential.Credential, opts DialOptions) (*ssh.ClientConfig, *authObserver, DialOptions, error) {
	if opts.Timeout <= 0 || opts.Timeout > DefaultDialTimeout {
		opts.Timeout = DefaultDialTimeout
	}
	if opts.Store == nil {
		opts.Store = NewMemoryStore()
	}
	if cred == nil {
		return nil, nil, opts, ErrNoAuthMethod
	}
	obs := &authObserver{}
	authMethods, err := orderedAuthMethods(cred, opts.PreferAuth, obs)
	if err != nil {
		return nil, nil, opts, err
	}
	if len(authMethods) == 0 {
		return nil, nil, opts, ErrNoAuthMethod
	}
	// Pre-validate the key (if any) so a weak/malformed key fails
	// before we even hit the network.
	if cred.PrivateKey != "" {
		if err := ValidateAuthKey([]byte(cred.PrivateKey), cred.PrivateKeyPassphrase); err != nil {
			return nil, nil, opts, err
		}
	}
	cfg := &ssh.ClientConfig{
		User:            cred.Username,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback(opts.Mode, opts.Store, host),
		Timeout:         opts.Timeout,
	}
	return cfg, obs, opts, nil
}

// handshake runs ssh.NewClientConn on conn, bounded by ctx: when ctx
// reaches its deadline or is canceled, the watcher closes conn, which ends
// any read or write the handshake is blocked in. The watcher is removed
// once the handshake returns, so it never affects the live client.
func handshake(ctx context.Context, conn net.Conn, addr string, cfg *ssh.ClientConfig, obs *authObserver, opts DialOptions) (*ssh.Client, error) {
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	stopped := stop()
	if err != nil {
		_ = conn.Close()
		if !stopped || ctx.Err() != nil {
			// The handshake ended because ctx expired or was canceled.
			return nil, ErrDialTimeout
		}
		return nil, classifyHandshakeErr(err)
	}
	if !stopped {
		// ctx fired as the handshake finished: the watcher has closed conn.
		_ = sshConn.Close()
		return nil, ErrDialTimeout
	}
	// Handshake succeeded: the last method the observer saw is the one
	// that authenticated (for single-factor auth — see authObserver). Report
	// it so the caller can persist the hint.
	if opts.ObservedAuth != nil {
		*opts.ObservedAuth = obs.Last()
	}
	return ssh.NewClient(sshConn, chans, reqs), nil
}

// classifyHandshakeErr maps ssh.NewClientConn errors to the package's
// sentinel set. Host-key errors come straight through unmodified
// (they're already our sentinels via the callback).
func classifyHandshakeErr(err error) error {
	if err == nil {
		return nil
	}
	// Our own callback errors come through wrapped — unwrap to the
	// sentinels so callers can errors.Is them.
	if errors.Is(err, ErrHostKeyUnknown) {
		return ErrHostKeyUnknown
	}
	if errors.Is(err, ErrHostKeyMismatch) {
		return ErrHostKeyMismatch
	}
	// crypto/ssh wraps auth failures with "unable to authenticate".
	msg := err.Error()
	if strings.Contains(msg, "unable to authenticate") ||
		strings.Contains(msg, "no supported methods") ||
		strings.Contains(msg, "auth failed") {
		return ErrAuthFailed
	}
	if strings.Contains(msg, "host key") {
		// Fall back if the callback path is bypassed.
		return ErrHostKeyUnknown
	}
	// Unknown handshake failure — return a sanitized ErrConnect so we
	// never leak credential material that crypto/ssh might have included.
	return fmt.Errorf("%w: %s", ErrConnect, sanitizeMsg(msg))
}

// isNetTimeout matches the net package's timeout interface so we
// recognize Go-stdlib timeout errors without importing every err type.
func isNetTimeout(err error) bool {
	var te interface{ Timeout() bool }
	return errors.As(err, &te) && te.Timeout()
}

// sanitizeNetErr / sanitizeMsg defensively redact possible credential
// material from error strings. Crypto/ssh and net almost never leak
// credentials, but the cost of "what if" is low and the cost of a
// leaked password in a log is high.
//
// Spec C-03, AC-08.
func sanitizeNetErr(err error) string {
	return sanitizeMsg(err.Error())
}

func sanitizeMsg(msg string) string {
	// crypto/ssh doesn't include passwords in its error strings as of
	// 1.25, but we still rune-scrub anything that looks like a private
	// key block just in case (e.g., a future version logs the key).
	msg = strings.ReplaceAll(msg, "BEGIN OPENSSH PRIVATE KEY", "[REDACTED]")
	msg = strings.ReplaceAll(msg, "BEGIN RSA PRIVATE KEY", "[REDACTED]")
	return msg
}
