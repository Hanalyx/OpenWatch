package ssh

import (
	"crypto/x509"
	"errors"
	"net"
	"slices"
	"sync"

	"golang.org/x/crypto/ssh"
)

// What a dial established about each secret it holds, from evidence on the
// wire rather than from error text (bugs/OW-122 slice 1, spec C-14). The
// classification is reported alongside Dial's error, which is unchanged:
// consumers adopt the typed outcome in later slices.

// Secret kinds a credential can present.
const (
	SecretKindPassword = "password" // pragma: allowlist secret
	SecretKindKey      = "key"      // pragma: allowlist secret
)

// OutcomeKind is what one dial established about one secret.
type OutcomeKind string

const (
	// OutcomeVerified: the server accepted a method that carried the
	// secret: USERAUTH_SUCCESS, or USERAUTH_FAILURE with partial success.
	// A partial success accepts the secret, not the login (RFC 4252
	// section 5.1): the dial still fails, and its report keeps
	// ResultPartial. It is not a usable connection, and later slices must
	// not take it alone as grounds for recovery.
	OutcomeVerified OutcomeKind = "verified"
	// OutcomeUnsuccessful: a method sent the secret and ended without
	// success over a connection still intact, but what the server
	// answered is not established. crypto/ssh's client treats
	// USERAUTH_FAILURE and an unexpected reply (for example
	// SSH_MSG_USERAUTH_PASSWD_CHANGEREQ, RFC 4252 section 8) alike and
	// does not say which it saw, so this classifier never reports a
	// rejection for SSH.
	OutcomeUnsuccessful OutcomeKind = "unsuccessful"
	// OutcomeAmbiguous: the secret was sent and no answer to it was
	// observed. The connection failed, the server disconnected, or the
	// dial timed out during user authentication.
	OutcomeAmbiguous OutcomeKind = "ambiguous"
	// OutcomeUnsupportedProfile: a keyboard-interactive exchange left the
	// supported profile: across the whole exchange, at most one hidden
	// prompt, which the password answers, and no visible prompt.
	// Prompt-free rounds are information. A further hidden prompt is
	// outside the profile, whatever it asks: its count or wording cannot
	// show that the password was refused.
	OutcomeUnsupportedProfile OutcomeKind = "unsupported_profile"
	// OutcomeNotSubmitted: the secret was never sent. The server did not
	// offer a method for it, or the dial ended before user authentication.
	OutcomeNotSubmitted OutcomeKind = "not_submitted"
	// OutcomeLocalDecryptFailed: the private key could not be decrypted
	// with the stored passphrase, so nothing was sent.
	OutcomeLocalDecryptFailed OutcomeKind = "local_decrypt_failed"
)

// MethodResult is what happened to one authentication method.
type MethodResult string

const (
	ResultAccepted MethodResult = "accepted" // USERAUTH_SUCCESS
	ResultPartial  MethodResult = "partial"  // USERAUTH_FAILURE with partial success
	// ResultEnded: the method ended without success over an intact
	// connection. The server answered USERAUTH_FAILURE or something else
	// crypto/ssh does not accept; the client cannot tell which.
	ResultEnded    MethodResult = "ended"
	ResultNoAnswer MethodResult = "no_answer" // the method ended without an answer the client could see
)

// MethodAttempt is one authentication method the client ran.
type MethodAttempt struct {
	Method string // "none", "publickey", "password" or "keyboard-interactive"
	// Secret is the kind of secret the method sent, or "" if it sent none.
	Secret string
	// Submissions counts how many times the secret was sent in this
	// method: one for publickey and password, one per hidden prompt for
	// keyboard-interactive.
	Submissions int
	Result      MethodResult
	// Unsupported: keyboard-interactive asked for something outside the
	// supported profile.
	Unsupported bool
}

// AuthReport is the evidence of one dial and the outcome it supports for
// each secret the credential holds. Fill it by passing
// DialOptions.Report; Dial sets it however the dial ends.
type AuthReport struct {
	Attempts []MethodAttempt
	// Outcomes holds an entry for every secret the credential carries,
	// keyed by SecretKindPassword or SecretKindKey.
	Outcomes map[string]OutcomeKind
}

// authRecorder collects the evidence as the handshake runs. crypto/ssh
// calls every callback from the goroutine running the handshake, and the
// connection wrapper may be read from crypto/ssh's reader goroutine, so
// the shared state is guarded.
type authRecorder struct {
	mu       sync.Mutex
	attempts []MethodAttempt
	open     int // index of the attempt in progress, or -1
	tried    int // len(TriedMethods) at the last callback
	partial  int // len(PartialSuccessMethods) at the last callback
	hidden   int // hidden keyboard-interactive prompts in the whole exchange
	conn     *evidenceConn
}

func newAuthRecorder() *authRecorder { return &authRecorder{open: -1} }

// sent records that method sent its secret once.
func (r *authRecorder) sent(method, secret string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a := r.current(method)
	a.Secret = secret // pragma: allowlist secret
	a.Submissions++
}

// kbdRound records one keyboard-interactive round, in which the client
// gives the password to each of the hidden prompts. It only records: what
// the client answers is decided elsewhere and is unchanged. The supported
// profile spans the whole exchange: at most one hidden prompt, and no
// visible one. Prompt-free rounds are information.
func (r *authRecorder) kbdRound(echos []bool) {
	hidden, visible := 0, 0
	for _, e := range echos {
		if e {
			visible++
		} else {
			hidden++
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	a := r.current("keyboard-interactive")
	r.hidden += hidden
	if r.hidden > 1 || visible > 0 {
		a.Unsupported = true
	}
	if hidden > 0 {
		a.Secret = SecretKindPassword // pragma: allowlist secret
		a.Submissions += hidden
	}
}

// kbdRefused records a keyboard-interactive round the protected dial
// refused to answer because it left the supported profile. Nothing was
// sent in it, so it adds no submission.
func (r *authRecorder) kbdRefused() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.current("keyboard-interactive").Unsupported = true
}

// current returns the attempt in progress for method, opening it if the
// previous one has ended. The caller holds mu.
func (r *authRecorder) current(method string) *MethodAttempt {
	if r.open >= 0 && r.attempts[r.open].Method == method {
		return &r.attempts[r.open]
	}
	r.attempts = append(r.attempts, MethodAttempt{Method: method})
	r.open = len(r.attempts) - 1
	return &r.attempts[r.open]
}

// afterMethod is the ClientConfig.AuthCallback. crypto/ssh calls it after
// every method that did not succeed and did not end in a disconnect,
// with the methods tried and partly accepted so far. It only observes:
// returning (nil, nil) leaves the choice of the next method to crypto/ssh,
// so authentication order and policy are unchanged.
func (r *authRecorder) afterMethod(ctx *ssh.ClientAuthContext) (ssh.AuthMethod, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var method string
	result := ResultEnded
	switch {
	case len(ctx.TriedMethods) > r.tried:
		method = ctx.TriedMethods[len(ctx.TriedMethods)-1]
	case len(ctx.PartialSuccessMethods) > r.partial:
		method = ctx.PartialSuccessMethods[len(ctx.PartialSuccessMethods)-1]
		result = ResultPartial
	default:
		return nil, nil
	}
	r.tried, r.partial = len(ctx.TriedMethods), len(ctx.PartialSuccessMethods)
	// crypto/ssh also counts a method as tried when its exchange ended in
	// a transport error. If the connection has failed, the client saw no
	// answer from the server.
	if r.conn != nil && r.conn.failed() {
		result = ResultNoAnswer
	}
	a := r.current(method)
	a.Result = result
	r.open = -1
	return nil, nil
}

// finish closes the evidence once the handshake has returned. A method
// still in progress was accepted if the handshake succeeded, and saw no
// answer otherwise.
func (r *authRecorder) finish(succeeded bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.open >= 0 {
		if succeeded {
			r.attempts[r.open].Result = ResultAccepted
		} else {
			r.attempts[r.open].Result = ResultNoAnswer
		}
		r.open = -1
	}
}

// report builds the AuthReport for a credential carrying the given
// secrets.
func (r *authRecorder) report(secrets []string) AuthReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	rep := AuthReport{Attempts: slices.Clone(r.attempts), Outcomes: map[string]OutcomeKind{}}
	for _, s := range secrets {
		rep.Outcomes[s] = classifySecret(rep.Attempts, s)
	}
	return rep
}

// classifySecret applies the rules in order: a secret the server accepted
// is verified; an exchange outside the profile is unsupported; a secret
// sent with no answer seen is ambiguous; a secret sent whose method ended
// without success is unsuccessful; otherwise it was not sent. Ambiguous
// comes before unsuccessful because its effect is the broader one.
func classifySecret(attempts []MethodAttempt, secret string) OutcomeKind {
	var unsupported, ended, unanswered bool
	for _, a := range attempts {
		if a.Secret != secret && !(a.Method == "keyboard-interactive" && secret == SecretKindPassword) { // pragma: allowlist secret
			continue
		}
		if a.Submissions > 0 && (a.Result == ResultAccepted || a.Result == ResultPartial) {
			return OutcomeVerified
		}
		if a.Unsupported {
			unsupported = true
		}
		if a.Submissions > 0 && a.Result == ResultEnded {
			ended = true
		}
		if a.Submissions > 0 && a.Result == ResultNoAnswer {
			unanswered = true
		}
	}
	switch {
	case unsupported:
		return OutcomeUnsupportedProfile
	case unanswered:
		return OutcomeAmbiguous
	case ended:
		return OutcomeUnsuccessful
	}
	return OutcomeNotSubmitted
}

// secretsOf lists the secret kinds a credential carries.
func secretsOf(password, privateKey string) []string {
	var out []string
	if password != "" {
		out = append(out, SecretKindPassword)
	}
	if privateKey != "" {
		out = append(out, SecretKindKey)
	}
	return out
}

// isLocalDecryptFailure reports whether a key failed to load because of
// its passphrase: a wrong one, or none given for an encrypted key.
func isLocalDecryptFailure(err error) bool {
	var missing *ssh.PassphraseMissingError
	return errors.Is(err, x509.IncorrectPasswordError) || errors.As(err, &missing)
}

// evidenceConn records the first error the connection returns, so a
// method that ended in a transport error is not taken for a server's
// answer.
type evidenceConn struct {
	net.Conn
	mu  sync.Mutex
	err error
}

func (c *evidenceConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.note(err)
	return n, err
}

func (c *evidenceConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.note(err)
	return n, err
}

func (c *evidenceConn) note(err error) {
	if err == nil {
		return
	}
	c.mu.Lock()
	if c.err == nil {
		c.err = err
	}
	c.mu.Unlock()
}

func (c *evidenceConn) failed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err != nil
}
