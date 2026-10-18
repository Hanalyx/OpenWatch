// @spec system-ssh-connectivity
//
// The protected dial (spec C-15) against an in-process server that counts
// what it received: every password, every keyboard-interactive response
// and every publickey request. Credential protection is a fake that
// records each call, so these tests isolate the adapter; the bound with
// the real store is in protected_db_test.go.

package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	cryptossh "golang.org/x/crypto/ssh"

	"github.com/Hanalyx/openwatch/internal/credential"
	"github.com/Hanalyx/openwatch/internal/credprotect"
	"github.com/Hanalyx/openwatch/internal/credprotect/fingerprint"
)

// countingServer describes the test host. A method is offered when its
// field is set.
type countingServer struct {
	password        string // accepted by the password method
	offerPassword   bool
	passwordPartial bool // a correct password is a partial success
	dropOnPassword  bool // close the connection when a password arrives
	kbdRounds       []kbdRound
	kbdPassword     string // the answer every hidden prompt wants
	authorizedKey   cryptossh.PublicKey
	offerPublicKey  bool
}

// received is what the server was sent.
type received struct {
	mu           sync.Mutex
	passwords    []string
	kbdResponses [][]string // one entry per answered round
	publickey    int        // PublicKeyCallback calls: queries and signatures
}

func (r *received) snapshot() (pw []string, kbd [][]string, pk int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.passwords...), append([][]string(nil), r.kbdResponses...), r.publickey
}

// secretBearing counts the requests that carried a secret.
func (r *received) secretBearing() int {
	pw, kbd, pk := r.snapshot()
	return len(pw) + len(kbd) + pk
}

func startCountingServer(t *testing.T, s countingServer) (string, int, *received) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptossh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	got := &received{}
	go func() {
		for {
			raw, err := lis.Accept()
			if err != nil {
				return
			}
			cfg := &cryptossh.ServerConfig{}
			cfg.AddHostKey(signer)
			if s.offerPassword {
				cfg.PasswordCallback = func(_ cryptossh.ConnMetadata, pw []byte) (*cryptossh.Permissions, error) {
					got.mu.Lock()
					got.passwords = append(got.passwords, string(pw))
					got.mu.Unlock()
					if s.dropOnPassword {
						_ = raw.Close()
						return nil, errors.New("dropped")
					}
					if string(pw) != s.password {
						return nil, errors.New("wrong password")
					}
					if s.passwordPartial {
						return nil, &cryptossh.PartialSuccessError{Next: cryptossh.ServerAuthCallbacks{
							PublicKeyCallback: func(cryptossh.ConnMetadata, cryptossh.PublicKey) (*cryptossh.Permissions, error) {
								return nil, errors.New("no key")
							},
						}}
					}
					return &cryptossh.Permissions{}, nil
				}
			}
			if len(s.kbdRounds) > 0 {
				cfg.KeyboardInteractiveCallback = func(_ cryptossh.ConnMetadata, ch cryptossh.KeyboardInteractiveChallenge) (*cryptossh.Permissions, error) {
					ok := true
					for _, r := range s.kbdRounds {
						answers, err := ch("", "", r.prompts, r.echos)
						if err != nil {
							return nil, err
						}
						got.mu.Lock()
						got.kbdResponses = append(got.kbdResponses, answers)
						got.mu.Unlock()
						for i, a := range answers {
							if !r.echos[i] && a != s.kbdPassword {
								ok = false
							}
						}
					}
					if !ok {
						return nil, errors.New("wrong answer")
					}
					return &cryptossh.Permissions{}, nil
				}
			}
			if s.offerPublicKey {
				cfg.PublicKeyCallback = func(_ cryptossh.ConnMetadata, k cryptossh.PublicKey) (*cryptossh.Permissions, error) {
					got.mu.Lock()
					got.publickey++
					got.mu.Unlock()
					if s.authorizedKey != nil && string(k.Marshal()) == string(s.authorizedKey.Marshal()) {
						return &cryptossh.Permissions{}, nil
					}
					return nil, errors.New("unknown key")
				}
			}
			go func() {
				conn, chans, reqs, err := cryptossh.NewServerConn(raw, cfg)
				if err != nil {
					_ = raw.Close()
					return
				}
				go cryptossh.DiscardRequests(reqs)
				go func() {
					for c := range chans {
						_ = c.Reject(cryptossh.Prohibited, "no channels")
					}
				}()
				_ = conn.Wait()
			}()
		}
	}()
	return "127.0.0.1", lis.Addr().(*net.TCPAddr).Port, got
}

// fakeProtection records every call. Unset errors admit.
type fakeProtection struct {
	mu         sync.Mutex
	reserveErr error
	fenceErr   error
	settleErr  error
	onFence    func() // runs inside Fence, before it answers
	reserved   []credprotect.Request
	fenced     []credprotect.Current
	settled    []credprotect.Outcome
	settleCtx  []error // the context's error when Settle was called
}

func (p *fakeProtection) Reserve(_ context.Context, r credprotect.Request) (credprotect.Submission, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reserved = append(p.reserved, r)
	if p.reserveErr != nil {
		return credprotect.Submission{}, p.reserveErr
	}
	return credprotect.Submission{ID: uuid.Must(uuid.NewV7()), Kind: r.Kind}, nil
}

// Fence calls read as the real store does, and records what it found.
func (p *fakeProtection) Fence(ctx context.Context, _ uuid.UUID, read func(context.Context, credprotect.Reader) (credprotect.Current, error)) error {
	if p.onFence != nil {
		p.onFence()
	}
	cur, err := read(ctx, nil)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fenced = append(p.fenced, cur)
	return p.fenceErr
}

func (p *fakeProtection) Settle(ctx context.Context, _ uuid.UUID, o credprotect.Outcome) (credprotect.Result, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.settled = append(p.settled, o)
	p.settleCtx = append(p.settleCtx, ctx.Err())
	return credprotect.Result{}, p.settleErr
}

func (p *fakeProtection) calls() (reserved, fenced, settled int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.reserved), len(p.fenced), len(p.settled)
}

// stubKeyring identifies passwords deterministically, with a fixed
// snapshot. Like the real keyring it normalizes the username, so "Ops" and
// "ops" share an identifier and only the dial's own username check tells
// them apart. The fake protection never checks a keyring; the real store
// does, in protected_db_test.go, with a loaded one.
type stubKeyring struct{}

func (stubKeyring) Snapshot() fingerprint.Snapshot {
	return fingerprint.Snapshot{Generation: 1, Digest: [32]byte{1}}
}

func (stubKeyring) Password(username, password string) []fingerprint.Alias {
	return []fingerprint.Alias{{KeyID: "stub", ID: sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(username)) + "\x00" + password))}}
}

var testKeyring = stubKeyring{}

func protectedOpts(p Protection, secret string, current *credential.Credential) ProtectedOptions {
	return ProtectedOptions{
		Mode: ModeTOFU, Timeout: 3 * time.Second,
		Protection: p, CredentialID: uuid.Must(uuid.NewV7()), HostID: uuid.Must(uuid.NewV7()),
		Secret: secret, Keyring: testKeyring,
		Owner: credprotect.Owner{Machine: "m", PID: 1, Start: "1"},
		Current: func(context.Context, credprotect.Reader) (*credential.Credential, error) {
			c := *current
			return &c, nil
		},
	}
}

func activePassword(user, pw string) *credential.Credential {
	return &credential.Credential{Username: user, AuthMethod: credential.AuthPassword, Password: pw, IsActive: true}
}

func protectedDial(t *testing.T, host string, port int, cred *credential.Credential, opts ProtectedOptions) (ProtectedResult, error) {
	t.Helper()
	c, res, err := ProtectedDial(context.Background(), host, port, cred, opts)
	if err == nil {
		_ = c.Close()
	}
	return res, err
}

func wantSettled(t *testing.T, p *fakeProtection, want credprotect.Outcome) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.settled) != 1 || p.settled[0] != want {
		t.Fatalf("settled %v, want exactly [%s]", p.settled, want)
	}
}

// @ac AC-28
// AC-28: a protected dial offers exactly one secret-bearing method, chosen
// among those the server offers, and ends the exchange after it.
func TestProtectedDial_OneSecretBearingMethod(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-28", func(t *testing.T) {
		both := countingServer{password: "right", offerPassword: true,
			kbdRounds: []kbdRound{hiddenPrompt}, kbdPassword: "right"}

		t.Run("a wrong password is sent once, never replayed through keyboard-interactive", func(t *testing.T) {
			host, port, got := startCountingServer(t, both)
			cred := activePassword("ops", "stale")
			p := &fakeProtection{}
			res, err := protectedDial(t, host, port, cred, protectedOpts(p, SecretKindPassword, cred))
			if !errors.Is(err, ErrAuthFailed) {
				t.Fatalf("err = %v, want ErrAuthFailed", err)
			}
			pw, kbd, _ := got.snapshot()
			if len(pw) != 1 || len(kbd) != 0 {
				t.Fatalf("server received %d passwords and %d keyboard-interactive responses, want 1 and 0", len(pw), len(kbd))
			}
			if res.Method != MethodPassword {
				t.Errorf("method = %q", res.Method)
			}
			wantSettled(t, p, credprotect.OutcomeUnsuccessful)
		})

		t.Run("a correct password is verified with one request", func(t *testing.T) {
			host, port, got := startCountingServer(t, both)
			cred := activePassword("ops", "right")
			p := &fakeProtection{}
			if _, err := protectedDial(t, host, port, cred, protectedOpts(p, SecretKindPassword, cred)); err != nil {
				t.Fatal(err)
			}
			if n := got.secretBearing(); n != 1 {
				t.Fatalf("server received %d secret-bearing requests, want 1", n)
			}
			wantSettled(t, p, credprotect.OutcomeVerified)
		})

		t.Run("the learned method leads; the other is used only when the learned one is not offered", func(t *testing.T) {
			host, port, got := startCountingServer(t, both)
			cred := activePassword("ops", "right")
			p := &fakeProtection{}
			o := protectedOpts(p, SecretKindPassword, cred)
			o.PasswordMethod = MethodKeyboardInteractive
			res, err := protectedDial(t, host, port, cred, o)
			if err != nil {
				t.Fatal(err)
			}
			if pw, kbd, _ := got.snapshot(); len(pw) != 0 || len(kbd) != 1 || res.Method != MethodKeyboardInteractive {
				t.Fatalf("passwords %d, kbd responses %d, method %q; want 0, 1, keyboard-interactive", len(pw), len(kbd), res.Method)
			}

			kbdOnly := both
			kbdOnly.offerPassword = false
			host, port, got = startCountingServer(t, kbdOnly)
			p = &fakeProtection{}
			res, err = protectedDial(t, host, port, cred, protectedOpts(p, SecretKindPassword, cred))
			if err != nil {
				t.Fatal(err)
			}
			if pw, kbd, _ := got.snapshot(); len(pw) != 0 || len(kbd) != 1 || res.Method != MethodKeyboardInteractive {
				t.Fatalf("first contact on a keyboard-interactive host: passwords %d, kbd %d, method %q", len(pw), len(kbd), res.Method)
			}
		})

		t.Run("a key that fails never falls through to the password", func(t *testing.T) {
			cred, _ := keyCred(t, "")
			cred.Password, cred.IsActive = "right", true
			host, port, got := startCountingServer(t, countingServer{password: "right", offerPassword: true,
				offerPublicKey: true, kbdRounds: []kbdRound{hiddenPrompt}, kbdPassword: "right"})
			p := &fakeProtection{}
			_, err := protectedDial(t, host, port, cred, protectedOpts(p, SecretKindKey, cred))
			if !errors.Is(err, ErrAuthFailed) {
				t.Fatalf("err = %v, want ErrAuthFailed", err)
			}
			pw, kbd, pk := got.snapshot()
			if len(pw) != 0 || len(kbd) != 0 || pk != 1 {
				t.Fatalf("server received %d passwords, %d kbd responses, %d publickey requests; want 0, 0, 1", len(pw), len(kbd), pk)
			}
			if r := p.reserved[0]; r.Secret.Kind != credprotect.SecretKey {
				t.Errorf("reserved a %s, want the key", r.Secret)
			}
			wantSettled(t, p, credprotect.OutcomeUnsuccessful)
		})

		t.Run("a method the server does not offer is not sent", func(t *testing.T) {
			_, pub := keyCred(t, "")
			host, port, got := startCountingServer(t, countingServer{offerPublicKey: true, authorizedKey: pub})
			cred := activePassword("ops", "right")
			p := &fakeProtection{}
			_, err := protectedDial(t, host, port, cred, protectedOpts(p, SecretKindPassword, cred))
			if !errors.Is(err, ErrMethodNotOffered) {
				t.Fatalf("err = %v, want ErrMethodNotOffered", err)
			}
			if n := got.secretBearing(); n != 0 {
				t.Fatalf("server received %d secret-bearing requests", n)
			}
			if _, fenced, _ := p.calls(); fenced != 0 {
				t.Errorf("fence ran %d times for a secret never sent", fenced)
			}
			wantSettled(t, p, credprotect.OutcomeNotSubmitted)
		})
	})
}

// @ac AC-29
// AC-29: the submission is reserved before any network I/O, and the fence,
// run with the credential as stored now, gates the secret: a refusal at
// either sends nothing.
func TestProtectedDial_ReserveAndFenceGateTheSecret(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-29", func(t *testing.T) {
		server := countingServer{password: "right", offerPassword: true,
			kbdRounds: []kbdRound{hiddenPrompt}, kbdPassword: "right"}

		t.Run("a refused reservation opens no connection", func(t *testing.T) {
			dials := 0
			orig := netDial
			netDial = func(context.Context, string, string) (net.Conn, error) {
				dials++
				return nil, errors.New("must not dial")
			}
			t.Cleanup(func() { netDial = orig })
			cred := activePassword("ops", "right")
			p := &fakeProtection{reserveErr: credprotect.ErrBlocked}
			res, err := protectedDial(t, "192.0.2.1", 22, cred, protectedOpts(p, SecretKindPassword, cred))
			if !errors.Is(err, ErrProtected) || !errors.Is(err, credprotect.ErrBlocked) {
				t.Fatalf("err = %v, want ErrProtected wrapping ErrBlocked", err)
			}
			if dials != 0 || res.Reserved {
				t.Fatalf("dials = %d, reserved = %v", dials, res.Reserved)
			}
			if _, fenced, settled := p.calls(); fenced != 0 || settled != 0 {
				t.Errorf("fence %d, settle %d after a refused reservation", fenced, settled)
			}
		})

		for _, method := range []string{MethodPassword, MethodKeyboardInteractive} {
			t.Run("a refused fence sends nothing over "+method, func(t *testing.T) {
				host, port, got := startCountingServer(t, server)
				cred := activePassword("ops", "right")
				p := &fakeProtection{fenceErr: credprotect.ErrFenceRefused}
				o := protectedOpts(p, SecretKindPassword, cred)
				o.PasswordMethod = method
				_, err := protectedDial(t, host, port, cred, o)
				if !errors.Is(err, ErrProtected) || !errors.Is(err, credprotect.ErrFenceRefused) {
					t.Fatalf("err = %v, want ErrProtected wrapping ErrFenceRefused", err)
				}
				if n := got.secretBearing(); n != 0 {
					t.Fatalf("server received %d secret-bearing requests after the fence refused", n)
				}
				wantSettled(t, p, credprotect.OutcomeNotSubmitted)
			})
		}

		t.Run("a refused fence sends no key", func(t *testing.T) {
			cred, pub := keyCred(t, "")
			cred.IsActive = true
			host, port, got := startCountingServer(t, countingServer{offerPublicKey: true, authorizedKey: pub})
			p := &fakeProtection{fenceErr: credprotect.ErrFenceRefused}
			if _, err := protectedDial(t, host, port, cred, protectedOpts(p, SecretKindKey, cred)); !errors.Is(err, ErrProtected) {
				t.Fatalf("err = %v", err)
			}
			if n := got.secretBearing(); n != 0 {
				t.Fatalf("server received %d publickey requests", n)
			}
			wantSettled(t, p, credprotect.OutcomeNotSubmitted)
		})

		t.Run("the fence sees the credential as stored now", func(t *testing.T) {
			sent := activePassword("ops", "right")
			sentID := credprotect.PasswordSecret(testKeyring, "ops", "right")
			for name, c := range map[string]struct {
				stored     *credential.Credential
				wantActive bool
				wantSame   bool
			}{
				"unchanged":        {activePassword("ops", "right"), true, true},
				"password changed": {activePassword("ops", "rotated"), true, false},
				"username changed": {activePassword("Ops", "right"), true, false},
				"deactivated":      {&credential.Credential{Username: "ops", Password: "right"}, false, true},
			} {
				t.Run(name, func(t *testing.T) {
					host, port, _ := startCountingServer(t, server)
					p := &fakeProtection{}
					o := protectedOpts(p, SecretKindPassword, c.stored)
					_, _ = protectedDial(t, host, port, sent, o)
					if len(p.fenced) != 1 {
						t.Fatalf("fence ran %d times", len(p.fenced))
					}
					cur := p.fenced[0]
					if cur.Active != c.wantActive || cur.Secret.Same(sentID) != c.wantSame {
						t.Fatalf("fence saw active=%v same=%v, want %v %v", cur.Active, cur.Secret.Same(sentID), c.wantActive, c.wantSame)
					}
				})
			}
			t.Run("an unreadable credential sends nothing", func(t *testing.T) {
				host, port, got := startCountingServer(t, server)
				p := &fakeProtection{}
				o := protectedOpts(p, SecretKindPassword, sent)
				o.Current = func(context.Context, credprotect.Reader) (*credential.Credential, error) {
					return nil, errors.New("store down")
				}
				if _, err := protectedDial(t, host, port, sent, o); !errors.Is(err, ErrProtected) {
					t.Fatalf("err = %v", err)
				}
				if n := got.secretBearing(); n != 0 || len(p.fenced) != 0 {
					t.Fatalf("sent %d, fenced %d", n, len(p.fenced))
				}
				wantSettled(t, p, credprotect.OutcomeNotSubmitted)
			})
		})

		t.Run("the reserved identifier is computed from the material sent", func(t *testing.T) {
			cred := activePassword("ops", "right")
			p := &fakeProtection{reserveErr: credprotect.ErrBlocked}
			_, _ = protectedDial(t, "192.0.2.1", 22, cred, protectedOpts(p, SecretKindPassword, cred))
			if !p.reserved[0].Secret.Same(credprotect.PasswordSecret(testKeyring, "ops", "right")) {
				t.Fatal("the reservation does not identify the password being sent")
			}
			// A key is identified by its public key.
			key, pub := keyCred(t, "one")
			key.PrivateKeyPassphrase = "one"
			p = &fakeProtection{reserveErr: credprotect.ErrBlocked}
			_, _ = protectedDial(t, "192.0.2.1", 22, key, protectedOpts(p, SecretKindKey, key))
			if !p.reserved[0].Secret.Same(credprotect.KeySecret(pub.Marshal())) {
				t.Fatal("the reservation does not identify the key by its public key")
			}
			// Independently: the identifier is the digest behind OpenSSH's
			// SHA256: fingerprint of the key.
			want, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(cryptossh.FingerprintSHA256(pub), "SHA256:"))
			if err != nil {
				t.Fatal(err)
			}
			if a := p.reserved[0].Secret.Aliases; len(a) != 1 || string(a[0].ID[:]) != string(want) {
				t.Fatal("the key identifier is not the SHA-256 of the public key")
			}
		})
	})
}

// @ac AC-30
// AC-30: keyboard-interactive is answered only inside the supported
// profile. A round outside it gets no response at all, and a partial
// success is unsupported_profile, never verified.
func TestProtectedDial_KeyboardInteractiveProfileIsEnforced(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-30", func(t *testing.T) {
		visible := kbdRound{prompts: []string{"Code: "}, echos: []bool{true}}
		twoHidden := kbdRound{prompts: []string{"Password: ", "PIN: "}, echos: []bool{false, false}}
		mixed := kbdRound{prompts: []string{"Password: ", "Code: "}, echos: []bool{false, true}}
		empty := kbdRound{}
		for name, c := range map[string]struct {
			rounds        []kbdRound
			wantResponses int // rounds the server got an answer to
		}{
			"a visible prompt":                  {[]kbdRound{visible}, 0},
			"two hidden prompts in one round":   {[]kbdRound{twoHidden}, 0},
			"a hidden and a visible prompt":     {[]kbdRound{mixed}, 0},
			"a second hidden prompt, later":     {[]kbdRound{hiddenPrompt, hiddenPrompt}, 1},
			"a visible prompt after a password": {[]kbdRound{hiddenPrompt, visible}, 1},
		} {
			t.Run(name, func(t *testing.T) {
				host, port, got := startCountingServer(t, countingServer{kbdRounds: c.rounds, kbdPassword: "right"})
				cred := activePassword("ops", "right")
				p := &fakeProtection{}
				_, err := protectedDial(t, host, port, cred, protectedOpts(p, SecretKindPassword, cred))
				if !errors.Is(err, ErrUnsupportedExchange) {
					t.Fatalf("err = %v, want ErrUnsupportedExchange", err)
				}
				if _, kbd, _ := got.snapshot(); len(kbd) != c.wantResponses {
					t.Fatalf("server got %d responses, want %d", len(kbd), c.wantResponses)
				}
				wantSettled(t, p, credprotect.OutcomeUnsupportedProfile)
			})
		}

		t.Run("prompt-free rounds are answered and need no fence", func(t *testing.T) {
			host, port, got := startCountingServer(t, countingServer{kbdRounds: []kbdRound{empty, hiddenPrompt, empty}, kbdPassword: "right"})
			cred := activePassword("ops", "right")
			p := &fakeProtection{}
			if _, err := protectedDial(t, host, port, cred, protectedOpts(p, SecretKindPassword, cred)); err != nil {
				t.Fatal(err)
			}
			_, kbd, _ := got.snapshot()
			hidden := 0
			for _, r := range kbd {
				hidden += len(r)
			}
			if len(kbd) != 3 || hidden != 1 || len(p.fenced) != 1 {
				t.Fatalf("rounds %d, hidden answers %d, fences %d; want 3, 1, 1", len(kbd), hidden, len(p.fenced))
			}
			wantSettled(t, p, credprotect.OutcomeVerified)
		})

		t.Run("a partial success is unsupported_profile", func(t *testing.T) {
			host, port, got := startCountingServer(t, countingServer{password: "right", offerPassword: true, passwordPartial: true})
			cred := activePassword("ops", "right")
			p := &fakeProtection{}
			_, err := protectedDial(t, host, port, cred, protectedOpts(p, SecretKindPassword, cred))
			if !errors.Is(err, ErrUnsupportedExchange) {
				t.Fatalf("err = %v", err)
			}
			if _, _, pk := got.snapshot(); pk != 0 {
				t.Errorf("the dial went on to %d publickey requests after the partial success", pk)
			}
			wantSettled(t, p, credprotect.OutcomeUnsupportedProfile)
		})
	})
}

// @ac AC-31
// AC-31: every reserved submission is settled exactly once, however the
// dial ends, on a context the dial's cancellation does not reach; a key
// that cannot be decrypted reserves nothing; and an outcome that cannot be
// recorded closes the connection.
func TestProtectedDial_EverySubmissionIsSettled(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-31", func(t *testing.T) {
		cred := activePassword("ops", "right")

		t.Run("a refused connection is not_submitted", func(t *testing.T) {
			lis, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := lis.Addr().(*net.TCPAddr).Port
			_ = lis.Close()
			p := &fakeProtection{}
			if _, err := protectedDial(t, "127.0.0.1", port, cred, protectedOpts(p, SecretKindPassword, cred)); !errors.Is(err, ErrConnect) {
				t.Fatalf("err = %v", err)
			}
			wantSettled(t, p, credprotect.OutcomeNotSubmitted)
		})

		t.Run("a refused host key is not_submitted", func(t *testing.T) {
			host, port, got := startCountingServer(t, countingServer{password: "right", offerPassword: true})
			p := &fakeProtection{}
			o := protectedOpts(p, SecretKindPassword, cred)
			o.Mode = ModeStrict
			if _, err := protectedDial(t, host, port, cred, o); !errors.Is(err, ErrHostKeyUnknown) {
				t.Fatalf("err = %v", err)
			}
			if got.secretBearing() != 0 {
				t.Fatal("a password went to an unverified host")
			}
			wantSettled(t, p, credprotect.OutcomeNotSubmitted)
		})

		t.Run("a password with no answer is ambiguous", func(t *testing.T) {
			host, port, _ := startCountingServer(t, countingServer{offerPassword: true, dropOnPassword: true})
			p := &fakeProtection{}
			if _, err := protectedDial(t, host, port, cred, protectedOpts(p, SecretKindPassword, cred)); err == nil {
				t.Fatal("dial succeeded")
			}
			wantSettled(t, p, credprotect.OutcomeAmbiguous)
		})

		t.Run("a canceled dial still settles", func(t *testing.T) {
			host, port, _ := startCountingServer(t, countingServer{password: "right", offerPassword: true})
			ctx, cancel := context.WithCancel(context.Background())
			p := &fakeProtection{onFence: cancel}
			_, _, err := ProtectedDial(ctx, host, port, cred, protectedOpts(p, SecretKindPassword, cred))
			if err == nil {
				t.Fatal("dial succeeded after cancel")
			}
			if len(p.settled) != 1 || p.settleCtx[0] != nil {
				t.Fatalf("settled %v with context error %v", p.settled, p.settleCtx)
			}
		})

		t.Run("an outcome that cannot be recorded closes the connection", func(t *testing.T) {
			host, port, _ := startCountingServer(t, countingServer{password: "right", offerPassword: true})
			p := &fakeProtection{settleErr: errors.New("store down")}
			c, res, err := ProtectedDial(context.Background(), host, port, cred, protectedOpts(p, SecretKindPassword, cred))
			if !errors.Is(err, ErrNotRecorded) || c != nil {
				t.Fatalf("client %v, err %v; want no client and ErrNotRecorded", c, err)
			}
			if res.Outcome != credprotect.OutcomeVerified {
				t.Errorf("outcome = %s", res.Outcome)
			}
		})

		t.Run("a key that cannot be decrypted reserves nothing", func(t *testing.T) {
			key, _ := keyCred(t, "right")
			key.PrivateKeyPassphrase, key.IsActive = "wrong", true
			p := &fakeProtection{}
			res, err := protectedDial(t, "192.0.2.1", 22, key, protectedOpts(p, SecretKindKey, key))
			if err == nil || res.Reserved {
				t.Fatalf("err %v, reserved %v", err, res.Reserved)
			}
			if res.Report.Outcomes[SecretKindKey] != OutcomeLocalDecryptFailed {
				t.Errorf("outcome %v", res.Report.Outcomes)
			}
			if r, _, _ := p.calls(); r != 0 {
				t.Errorf("reserved %d times", r)
			}
		})

		t.Run("every outcome kind maps to the outcome of its name, and nothing else admits", func(t *testing.T) {
			g := &gate{opts: ProtectedOptions{Secret: SecretKindPassword}}
			for _, k := range []OutcomeKind{OutcomeVerified, OutcomeUnsuccessful, OutcomeAmbiguous,
				OutcomeUnsupportedProfile, OutcomeNotSubmitted, OutcomeLocalDecryptFailed} {
				if got := g.outcome(AuthReport{Outcomes: map[string]OutcomeKind{SecretKindPassword: k}}); string(got) != string(k) {
					t.Errorf("%s settles as %s", k, got)
				}
			}
			for _, rep := range []AuthReport{{}, {Outcomes: map[string]OutcomeKind{SecretKindPassword: "new_kind"}}} {
				if got := g.outcome(rep); got != credprotect.OutcomeUnknown {
					t.Errorf("an unnamed outcome settles as %s, want unknown", got)
				}
			}
		})
	})
}
