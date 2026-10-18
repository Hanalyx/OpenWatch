package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/Hanalyx/openwatch/internal/credential"
	"github.com/Hanalyx/openwatch/internal/credprotect"
	"github.com/Hanalyx/openwatch/internal/credprotect/fingerprint"
)

// The protected dial submits one secret under credential protection
// (bugs/OW-122 slice 4, spec C-15). It reserves the submission before any
// network I/O, offers exactly one secret-bearing method, runs the fence
// immediately before the secret leaves, and settles the outcome however
// the dial ends. The bound is enforced here, at the transport: the method
// callbacks are the only place a secret is handed to crypto/ssh, and each
// returns an error, so crypto/ssh writes nothing, unless the fence passed.

// Protection is the part of credential protection a protected dial uses.
// *credprotect.Store implements it.
type Protection interface {
	Reserve(ctx context.Context, r credprotect.Request) (credprotect.Submission, error)
	// Fence calls read under its own lock on the credential, on its own
	// transaction, so the credential it checks is the one as it stands at
	// the fence.
	Fence(ctx context.Context, id uuid.UUID, read func(context.Context, credprotect.Reader) (credprotect.Current, error)) error
	Settle(ctx context.Context, id uuid.UUID, outcome credprotect.Outcome) (credprotect.Result, error)
}

// Protected-dial errors. Each means nothing further was sent.
var (
	// ErrProtected: credential protection did not admit the submission. It
	// refused at reservation or at the fence, or it could not be reached.
	// It wraps the reason, a credprotect error where there is one.
	ErrProtected = errors.New("ssh: credential protection did not admit the submission")
	// ErrMethodNotOffered: the server does not offer a method for this
	// secret.
	ErrMethodNotOffered = errors.New("ssh: the server does not offer a method for this secret")
	// ErrUnsupportedExchange: the server asked for a login exchange outside
	// the supported profile: a keyboard-interactive round other than one
	// hidden prompt, or a further step after a partial success.
	ErrUnsupportedExchange = errors.New("ssh: the server requires an unsupported login exchange")
	// ErrNotRecorded: the outcome could not be recorded. The reservation
	// is left to expire, which records unknown and keeps the slot held.
	ErrNotRecorded = errors.New("ssh: the authentication outcome could not be recorded")
)

// errOneMethod ends the exchange after its one secret-bearing method.
var errOneMethod = errors.New("ssh: one secret-bearing method per dial")

// Methods a protected dial may submit a password with.
const (
	MethodPassword            = "password" // pragma: allowlist secret
	MethodKeyboardInteractive = "keyboard-interactive"
)

// DefaultReservationMargin is how long a reservation outlasts the dial's
// own bound, to cover the fence and settlement.
const DefaultReservationMargin = 15 * time.Second

// settleTimeout bounds recording the outcome. It runs on a context that
// the dial's cancellation does not reach, so an outcome is recorded even
// when the dial was canceled.
const settleTimeout = 10 * time.Second

// ProtectedOptions configures one protected dial.
type ProtectedOptions struct {
	Mode    Mode
	Store   KnownHostsStore
	Timeout time.Duration

	Protection   Protection
	CredentialID uuid.UUID
	HostID       uuid.UUID
	// Secret is the one secret this dial submits: SecretKindPassword or
	// SecretKindKey. A key that fails never falls through to the password;
	// a password attempt is a dial of its own.
	Secret string
	// Keyring identifies a password: the loaded fingerprint.Keyring.
	// Required when Secret is a password.
	Keyring credprotect.PasswordKeyring
	// PasswordMethod is the host's learned password method,
	// MethodPassword or MethodKeyboardInteractive. It is tried first when
	// the server offers it; otherwise the other one is, if offered. Empty
	// on first contact, which prefers MethodPassword.
	PasswordMethod string
	// Kind is the submission's kind; empty means credprotect.KindOrdinary.
	Kind credprotect.Kind
	// Owner holds the reservation; empty means this process.
	Owner credprotect.Owner
	// TTL is the reservation's lifetime; zero means Timeout plus
	// DefaultReservationMargin. It never ends before the dial's bound.
	TTL time.Duration
	// Current reads the credential again through db, the fence's own
	// transaction, for example with credential.GetByIDWith. The fence
	// calls it under its lock on the credential row, and refuses unless
	// the record is active, still has this username, and still holds the
	// secret being sent. Reading through anything but db would take a
	// second connection while the fence holds one.
	Current func(ctx context.Context, db credprotect.Reader) (*credential.Credential, error)
}

// ProtectedResult is what a protected dial reserved, sent and recorded.
type ProtectedResult struct {
	// Reserved: a submission was reserved. If false, nothing was sent and
	// nothing was recorded.
	Reserved   bool
	Submission uuid.UUID
	// Method is the method that carried the secret, or "" if none did.
	Method string
	// Outcome is the outcome settled, or would have been had ErrNotRecorded
	// not occurred. Empty when nothing was reserved.
	Outcome credprotect.Outcome
	Settled credprotect.Result
	Report  AuthReport
}

// ProtectedDial dials host:port and submits one of cred's secrets under
// credential protection. On success it returns a live client, which the
// caller must close. Every reserved submission is settled before it
// returns; if settlement fails, the client is closed and the error wraps
// ErrNotRecorded.
//
// Spec C-15.
func ProtectedDial(ctx context.Context, host string, port int, cred *credential.Credential, opts ProtectedOptions) (*ssh.Client, ProtectedResult, error) {
	var res ProtectedResult
	opts, err := opts.complete(cred)
	if err != nil {
		return nil, res, err
	}
	g := &gate{opts: opts, rec: newAuthRecorder()}
	g.obs = &authObserver{rec: g.rec}
	g.cred, g.signer, g.secret, err = identify(cred, opts)
	if err != nil {
		// Nothing was reserved and nothing sent; a key that cannot be
		// decrypted is local_decrypt_failed, which changes nothing.
		res.Report = AuthReport{Outcomes: map[string]OutcomeKind{opts.Secret: OutcomeNotSubmitted}}
		if isLocalDecryptFailure(err) {
			res.Report.Outcomes[opts.Secret] = OutcomeLocalDecryptFailed
		}
		return nil, res, err
	}

	sub, err := opts.Protection.Reserve(ctx, credprotect.Request{
		CredentialID: opts.CredentialID, HostID: opts.HostID, Secret: g.secret,
		Kind: opts.Kind, Stage: "ssh", Owner: opts.Owner, TTL: opts.TTL,
	})
	if err != nil {
		return nil, res, fmt.Errorf("%w: %w", ErrProtected, err)
	}
	res.Reserved, res.Submission = true, sub.ID
	g.sub = sub.ID

	client, herr := g.dial(ctx, host, port)

	res.Report = g.rec.report([]string{opts.Secret})
	res.Outcome = g.outcome(res.Report)
	if sentWith(res.Report) {
		res.Method = g.method
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), settleTimeout)
	defer cancel()
	res.Settled, err = opts.Protection.Settle(sctx, sub.ID, res.Outcome)
	if err != nil {
		if client != nil {
			_ = client.Close()
		}
		return nil, res, fmt.Errorf("%w: %w", ErrNotRecorded, err)
	}
	if herr != nil {
		return nil, res, g.dialErr(herr, res.Outcome)
	}
	return client, res, nil
}

// complete validates opts for cred and fills the defaults.
func (o ProtectedOptions) complete(cred *credential.Credential) (ProtectedOptions, error) {
	switch {
	case o.Protection == nil || o.Current == nil:
		return o, errors.New("ssh: protected dial needs Protection and Current")
	case o.CredentialID == uuid.Nil || o.HostID == uuid.Nil:
		return o, errors.New("ssh: protected dial needs a credential and a host")
	case cred == nil:
		return o, ErrNoAuthMethod
	}
	switch o.Secret {
	case SecretKindPassword:
		if cred.Password == "" {
			return o, ErrNoAuthMethod
		}
		if o.Keyring == nil || o.Keyring.Snapshot() == (fingerprint.Snapshot{}) {
			return o, errors.New("ssh: protected dial of a password needs a loaded keyring")
		}
	case SecretKindKey:
		if cred.PrivateKey == "" {
			return o, ErrNoAuthMethod
		}
	default:
		return o, fmt.Errorf("ssh: protected dial: unknown secret %q", o.Secret)
	}
	if o.PasswordMethod != "" && o.PasswordMethod != MethodPassword && o.PasswordMethod != MethodKeyboardInteractive {
		return o, fmt.Errorf("ssh: protected dial: unknown password method %q", o.PasswordMethod)
	}
	if o.Timeout <= 0 || o.Timeout > DefaultDialTimeout {
		o.Timeout = DefaultDialTimeout
	}
	if o.Store == nil {
		o.Store = NewMemoryStore()
	}
	if o.Kind == "" {
		o.Kind = credprotect.KindOrdinary
	}
	if o.TTL < o.Timeout {
		o.TTL = o.Timeout + DefaultReservationMargin
	}
	if o.Owner == (credprotect.Owner{}) {
		owner, err := credprotect.SelfOwner()
		if err != nil {
			return o, err
		}
		o.Owner = owner
	}
	return o, nil
}

// identify returns the credential reduced to the one secret being sent,
// its signer for a key, and the secret's identifier, computed from the
// very material the dial sends.
func identify(cred *credential.Credential, o ProtectedOptions) (*credential.Credential, ssh.Signer, credprotect.Secret, error) {
	one := &credential.Credential{Username: cred.Username, AuthMethod: cred.AuthMethod}
	if o.Secret == SecretKindPassword {
		one.Password = cred.Password
		return one, nil, credprotect.PasswordSecret(o.Keyring, cred.Username, cred.Password), nil
	}
	one.PrivateKey, one.PrivateKeyPassphrase = cred.PrivateKey, cred.PrivateKeyPassphrase
	if err := ValidateAuthKey([]byte(cred.PrivateKey), cred.PrivateKeyPassphrase); err != nil {
		return nil, nil, credprotect.Secret{}, err
	}
	signer, err := parseSigner([]byte(cred.PrivateKey), cred.PrivateKeyPassphrase)
	if err != nil {
		return nil, nil, credprotect.Secret{}, err
	}
	return one, signer, credprotect.KeySecret(signer.PublicKey().Marshal()), nil
}

// gate runs one protected dial's authentication. crypto/ssh calls its
// methods from the goroutine running the handshake, one at a time, and
// the dial reads it only after the handshake has returned.
type gate struct {
	opts   ProtectedOptions
	ctx    context.Context
	sub    uuid.UUID
	cred   *credential.Credential // only the secret being sent
	signer ssh.Signer
	secret credprotect.Secret
	rec    *authRecorder
	obs    *authObserver

	offered  bool   // the one method was handed to crypto/ssh
	method   string // that method
	answered bool   // keyboard-interactive answered its hidden prompt
	partial  bool   // the server accepted the secret as one step of several
	abort    error  // why the gate ended the exchange
}

// dial connects and runs the handshake, bounded by opts.Timeout.
func (g *gate) dial(ctx context.Context, host string, port int) (*ssh.Client, error) {
	dctx, cancel := context.WithTimeout(ctx, g.opts.Timeout)
	defer cancel()
	g.ctx = dctx
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := netDial(dctx, "tcp", addr)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isNetTimeout(err) {
			return nil, ErrDialTimeout
		}
		return nil, fmt.Errorf("%w: %v", ErrConnect, sanitizeNetErr(err))
	}
	cfg := &ssh.ClientConfig{
		User:            g.cred.Username,
		HostKeyCallback: hostKeyCallback(g.opts.Mode, g.opts.Store, host),
		Timeout:         g.opts.Timeout,
		// No Auth list: the gate chooses every method, and only one.
		AuthCallback: g.next,
	}
	return handshake(dctx, conn, addr, cfg, g.obs, DialOptions{}, g.cred)
}

// next is the ClientConfig.AuthCallback. After "none" it hands crypto/ssh
// the one method for the secret, if the server offers it; after that
// method it ends the exchange, whatever the method's result.
func (g *gate) next(ac *ssh.ClientAuthContext) (ssh.AuthMethod, error) {
	_, _ = g.rec.afterMethod(ac)
	if g.offered {
		if len(ac.PartialSuccessMethods) > 0 {
			// The secret was accepted as one step of a multi-step login
			// (RFC 4252 section 5.1), which is unsupported.
			g.partial = true
			if g.abort == nil {
				g.abort = ErrUnsupportedExchange
			}
		}
		if g.abort == nil {
			g.abort = errOneMethod
		}
		return nil, g.abort
	}
	g.offered = true
	g.method = g.pick(ac.AllowedMethods)
	switch g.method {
	case "publickey":
		return ssh.PublicKeysCallback(g.signers), nil
	case MethodPassword:
		return ssh.PasswordCallback(g.password), nil
	case MethodKeyboardInteractive:
		return ssh.KeyboardInteractive(g.challenge), nil
	}
	g.abort = ErrMethodNotOffered
	return nil, g.abort
}

// pick chooses the method for the secret among those the server offers,
// or "" when it offers none.
func (g *gate) pick(offered []string) string {
	order := []string{"publickey"}
	if g.opts.Secret == SecretKindPassword {
		order = []string{MethodPassword, MethodKeyboardInteractive}
		if g.opts.PasswordMethod == MethodKeyboardInteractive {
			order = []string{MethodKeyboardInteractive, MethodPassword}
		}
	}
	for _, m := range order {
		if slices.Contains(offered, m) {
			return m
		}
	}
	return ""
}

// fence runs credential protection's fence immediately before the secret
// is handed to crypto/ssh. The fence reads the credential again through
// opts.Current, on its own transaction, while it holds its lock on the
// credential, so an edit that committed before the fence is seen. Each method reaches it once:
// password and publickey call it once per method, and keyboard-interactive
// answers one hidden prompt and ends the exchange on a refusal. Any error
// means: send nothing.
func (g *gate) fence() error {
	read := func(ctx context.Context, db credprotect.Reader) (credprotect.Current, error) {
		fresh, err := g.opts.Current(ctx, db)
		if err != nil || fresh == nil {
			return credprotect.Current{}, err
		}
		return credprotect.Current{Active: fresh.IsActive, Secret: g.stillHeld(fresh)}, nil
	}
	if err := g.opts.Protection.Fence(g.ctx, g.sub, read); err != nil {
		g.abort = fmt.Errorf("%w: %w", ErrProtected, err)
		return g.abort
	}
	return nil
}

// stillHeld identifies the secret fresh holds, if it is the account and
// secret this dial sends; otherwise it returns no secret, which the fence
// refuses. The username must match exactly: it is what goes on the wire.
func (g *gate) stillHeld(fresh *credential.Credential) credprotect.Secret {
	if fresh.Username != g.cred.Username {
		return credprotect.Secret{}
	}
	if g.opts.Secret == SecretKindPassword {
		if fresh.Password == "" {
			return credprotect.Secret{}
		}
		return credprotect.PasswordSecret(g.opts.Keyring, fresh.Username, fresh.Password)
	}
	signer, err := parseSigner([]byte(fresh.PrivateKey), fresh.PrivateKeyPassphrase)
	if err != nil {
		return credprotect.Secret{}
	}
	return credprotect.KeySecret(signer.PublicKey().Marshal())
}

// password is the password method's callback.
func (g *gate) password() (string, error) {
	if err := g.fence(); err != nil {
		return "", err
	}
	g.obs.note(PreferPassword)
	g.rec.sent(MethodPassword, SecretKindPassword)
	return g.cred.Password, nil
}

// signers is the publickey method's callback. The key's query and its
// signature both follow it, so the fence runs before either.
func (g *gate) signers() ([]ssh.Signer, error) {
	if err := g.fence(); err != nil {
		return nil, err
	}
	g.obs.note(PreferKey)
	g.rec.sent("publickey", SecretKindKey)
	return []ssh.Signer{g.signer}, nil
}

// challenge answers keyboard-interactive rounds within the supported
// profile: across the whole exchange, one hidden prompt, which the
// password answers, and rounds with no prompt. Any other round is refused
// before anything is written: a visible prompt, a round of several
// prompts, or a second hidden prompt.
func (g *gate) challenge(_, _ string, questions []string, echos []bool) ([]string, error) {
	hidden, visible := 0, 0
	for _, e := range echos {
		if e {
			visible++
		} else {
			hidden++
		}
	}
	if visible > 0 || hidden > 1 || (hidden == 1 && g.answered) || len(echos) != len(questions) {
		g.rec.kbdRefused()
		g.abort = ErrUnsupportedExchange
		return nil, g.abort
	}
	if hidden == 0 {
		return []string{}, nil
	}
	if err := g.fence(); err != nil {
		return nil, err
	}
	g.answered = true
	g.obs.note(PreferPassword)
	g.rec.sent(MethodKeyboardInteractive, SecretKindPassword)
	return []string{g.cred.Password}, nil
}

// outcome is the outcome to settle for the dial's report. A partial
// success is unsupported_profile: the secret was accepted, but the login
// needs a step this dial does not take, so it is neither a failure nor
// grounds for recovery. An outcome the dial cannot name is unknown, which
// blocks: it never admits.
func (g *gate) outcome(rep AuthReport) credprotect.Outcome {
	if g.partial {
		return credprotect.OutcomeUnsupportedProfile
	}
	switch rep.Outcomes[g.opts.Secret] {
	case OutcomeVerified:
		return credprotect.OutcomeVerified
	case OutcomeUnsuccessful:
		return credprotect.OutcomeUnsuccessful
	case OutcomeAmbiguous:
		return credprotect.OutcomeAmbiguous
	case OutcomeUnsupportedProfile:
		return credprotect.OutcomeUnsupportedProfile
	case OutcomeNotSubmitted:
		return credprotect.OutcomeNotSubmitted
	case OutcomeLocalDecryptFailed:
		return credprotect.OutcomeLocalDecryptFailed
	}
	return credprotect.OutcomeUnknown
}

// dialErr is the error a failed protected dial returns: the gate's own
// reason where it ended the exchange, otherwise the dial's.
func (g *gate) dialErr(herr error, outcome credprotect.Outcome) error {
	switch {
	case errors.Is(g.abort, ErrProtected):
		return g.abort
	case outcome == credprotect.OutcomeUnsupportedProfile:
		return ErrUnsupportedExchange
	case errors.Is(g.abort, ErrMethodNotOffered):
		return ErrMethodNotOffered
	case outcome == credprotect.OutcomeUnsuccessful:
		return ErrAuthFailed
	}
	return herr
}

// sentWith reports whether any method sent the secret.
func sentWith(rep AuthReport) bool {
	for _, a := range rep.Attempts {
		if a.Submissions > 0 {
			return true
		}
	}
	return false
}
