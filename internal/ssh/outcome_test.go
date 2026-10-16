// @spec system-ssh-connectivity
//
// Typed authentication outcomes (spec C-14): what a dial established about
// each secret, from evidence on the wire. A raw crypto/ssh server stands in
// for the host, so a test can reject, re-prompt, partly accept, drop the
// connection mid-method, disconnect or stall.

package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/credential"
	cryptossh "golang.org/x/crypto/ssh"
)

// kbdRound is one keyboard-interactive round the test server sends.
type kbdRound struct {
	prompts []string
	echos   []bool
}

// outcomeServer describes how the test host treats each method. Unset
// fields leave the method unoffered.
type outcomeServer struct {
	password string // accepted by the password method
	// passwordPartial: a correct password is a partial success that asks
	// for publickey next.
	passwordPartial bool
	// dropOnPassword closes the connection when the password arrives,
	// without answering.
	dropOnPassword bool
	// stallOnPassword holds the password attempt longer than the dial.
	stallOnPassword time.Duration
	// dropAfterKbdRounds closes the connection after that many
	// keyboard-interactive rounds were answered, without a verdict.
	dropAfterKbdRounds int
	kbdRounds          []kbdRound // keyboard-interactive script; accepted when every hidden answer is kbdPassword and every visible one is the code "000000"
	kbdPassword        string
	authorizedKey      cryptossh.PublicKey // accepted by publickey; offered whenever offerPublicKey
	offerPublicKey     bool
	maxAuthTries       int
}

// startOutcomeServer serves one SSH connection at a time with s's rules
// and records the methods the server saw, in order.
func startOutcomeServer(t *testing.T, s outcomeServer) (host string, port int, seen func() []string) {
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
	var mu sync.Mutex
	var methods []string
	note := func(m string) {
		mu.Lock()
		methods = append(methods, m)
		mu.Unlock()
	}
	go func() {
		for {
			raw, err := lis.Accept()
			if err != nil {
				return
			}
			cfg := &cryptossh.ServerConfig{MaxAuthTries: s.maxAuthTries}
			cfg.AddHostKey(signer)
			if s.password != "" || s.dropOnPassword || s.stallOnPassword > 0 {
				cfg.PasswordCallback = func(_ cryptossh.ConnMetadata, pw []byte) (*cryptossh.Permissions, error) {
					note("password")
					if s.dropOnPassword {
						_ = raw.Close()
						return nil, errors.New("dropped")
					}
					if s.stallOnPassword > 0 {
						time.Sleep(s.stallOnPassword)
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
					note("keyboard-interactive")
					ok := true
					for i, r := range s.kbdRounds {
						answers, err := ch("", "", r.prompts, r.echos)
						if err != nil {
							return nil, err
						}
						if s.dropAfterKbdRounds > 0 && i+1 == s.dropAfterKbdRounds {
							_ = raw.Close()
							return nil, errors.New("dropped")
						}
						for i, a := range answers {
							// A hidden prompt wants the password; a visible
							// one, a one-time code the client cannot know.
							if (!r.echos[i] && a != s.kbdPassword) || (r.echos[i] && a != "000000") {
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
					note("publickey")
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
	addr := lis.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(methods)
	}
}

// dialReport dials with a report and returns it with the dial's error.
func dialReport(t *testing.T, host string, port int, cred *credential.Credential, timeout time.Duration) (AuthReport, error) {
	t.Helper()
	var rep AuthReport
	c, err := Dial(context.Background(), host, port, cred, DialOptions{Mode: ModeTOFU, Timeout: timeout, Report: &rep})
	if err == nil {
		_ = c.Close()
	}
	return rep, err
}

func keyCred(t *testing.T, passphrase string) (*credential.Credential, cryptossh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		block = &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	} else {
		block, err = cryptossh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
		if err != nil {
			t.Fatal(err)
		}
	}
	sshPub, err := cryptossh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return &credential.Credential{Username: "testuser", AuthMethod: credential.AuthSSHKey,
		PrivateKey: string(pem.EncodeToMemory(block))}, sshPub
}

var hiddenPrompt = kbdRound{prompts: []string{"Password: "}, echos: []bool{false}}

func attemptsString(r AuthReport) string {
	s := ""
	for _, a := range r.Attempts {
		s += fmt.Sprintf("[%s secret=%q n=%d %s reprompt=%v unsupported=%v] ", a.Method, a.Secret, a.Submissions, a.Result, a.Reprompted, a.Unsupported)
	}
	return s
}

// @ac AC-24
func TestOutcome_PasswordAndKeyboardInteractive(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-24", func(t *testing.T) {
		cases := []struct {
			name   string
			server outcomeServer
			pw     string
			want   OutcomeKind
			// wantErr is the sentinel Dial already returned before this
			// change; the report must not alter it.
			wantErr error
		}{
			{"password accepted", outcomeServer{password: "right"}, "right", OutcomeVerified, nil},
			{"password rejected", outcomeServer{password: "right"}, "wrong", OutcomeRejected, ErrAuthFailed},
			{"keyboard-interactive accepted", outcomeServer{kbdRounds: []kbdRound{hiddenPrompt}, kbdPassword: "right"}, "right", OutcomeVerified, nil},
			{"keyboard-interactive rejected", outcomeServer{kbdRounds: []kbdRound{hiddenPrompt}, kbdPassword: "right"}, "wrong", OutcomeRejected, ErrAuthFailed},
			{"keyboard-interactive re-prompt", outcomeServer{kbdRounds: []kbdRound{hiddenPrompt, hiddenPrompt}, kbdPassword: "right"}, "wrong", OutcomeRejected, ErrAuthFailed},
			{"information round, then the prompt", outcomeServer{kbdRounds: []kbdRound{{}, hiddenPrompt}, kbdPassword: "right"}, "right", OutcomeVerified, nil},
			{"visible prompt only", outcomeServer{kbdRounds: []kbdRound{{prompts: []string{"Code: "}, echos: []bool{true}}}, kbdPassword: "right"}, "right", OutcomeUnsupportedProfile, ErrAuthFailed},
			{"two hidden prompts in a round", outcomeServer{kbdRounds: []kbdRound{{prompts: []string{"Password: ", "Token: "}, echos: []bool{false, false}}}, kbdPassword: "right"}, "wrong", OutcomeUnsupportedProfile, ErrAuthFailed},
			{"no method for a password", outcomeServer{offerPublicKey: true}, "right", OutcomeNotSubmitted, ErrAuthFailed},
			{"partial success", outcomeServer{password: "right", passwordPartial: true}, "right", OutcomeVerified, ErrAuthFailed},
			// The host let the client in without asking for the password,
			// so the password was neither sent nor verified.
			{"keyboard-interactive accepted without a prompt", outcomeServer{kbdRounds: []kbdRound{{}}, kbdPassword: "right"}, "right", OutcomeNotSubmitted, nil},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				host, port, _ := startOutcomeServer(t, c.server)
				rep, err := dialReport(t, host, port, passwordCred(c.pw), 5*time.Second)
				if got := rep.Outcomes[SecretKindPassword]; got != c.want {
					t.Errorf("password outcome %q, want %q: %s", got, c.want, attemptsString(rep))
				}
				if !errors.Is(err, c.wantErr) && !(c.wantErr == nil && err == nil) {
					t.Errorf("Dial error %v, want %v", err, c.wantErr)
				}
				if len(rep.Outcomes) != 1 {
					t.Errorf("outcomes for secrets the credential does not hold: %v", rep.Outcomes)
				}
			})
		}
	})
}

// @ac AC-25
func TestOutcome_NoAnswerIsAmbiguousNotRejected(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-25", func(t *testing.T) {
		t.Run("connection dropped after the password", func(t *testing.T) {
			host, port, _ := startOutcomeServer(t, outcomeServer{dropOnPassword: true})
			rep, err := dialReport(t, host, port, passwordCred("pw"), 5*time.Second)
			if got := rep.Outcomes[SecretKindPassword]; got != OutcomeAmbiguous {
				t.Errorf("outcome %q, want ambiguous: %s", got, attemptsString(rep))
			}
			if err == nil {
				t.Error("Dial succeeded")
			}
		})
		t.Run("dial timed out during the password", func(t *testing.T) {
			host, port, _ := startOutcomeServer(t, outcomeServer{password: "pw", stallOnPassword: 3 * time.Second})
			rep, err := dialReport(t, host, port, passwordCred("pw"), time.Second)
			if got := rep.Outcomes[SecretKindPassword]; got != OutcomeAmbiguous {
				t.Errorf("outcome %q, want ambiguous: %s", got, attemptsString(rep))
			}
			if !errors.Is(err, ErrDialTimeout) {
				t.Errorf("Dial error %v, want ErrDialTimeout as before", err)
			}
		})
		t.Run("connection dropped after a re-prompt", func(t *testing.T) {
			// The host asked for the password a second time, which it
			// does only after a wrong one, then dropped the connection.
			// The re-prompt is the answer to the first submission.
			host, port, _ := startOutcomeServer(t, outcomeServer{kbdRounds: []kbdRound{hiddenPrompt, hiddenPrompt}, kbdPassword: "right", dropAfterKbdRounds: 2})
			rep, _ := dialReport(t, host, port, passwordCred("wrong"), 5*time.Second)
			if got := rep.Outcomes[SecretKindPassword]; got != OutcomeRejected {
				t.Errorf("outcome %q, want rejected: %s", got, attemptsString(rep))
			}
		})
		t.Run("server disconnects when the next attempt arrives", func(t *testing.T) {
			// MaxAuthTries 1: the password fails and is answered; the
			// keyboard-interactive request that follows is met with a
			// disconnect. The password was answered, so it is rejected;
			// nothing was sent through keyboard-interactive.
			host, port, _ := startOutcomeServer(t, outcomeServer{password: "right", kbdRounds: []kbdRound{hiddenPrompt}, kbdPassword: "right", maxAuthTries: 1})
			rep, _ := dialReport(t, host, port, passwordCred("wrong"), 5*time.Second)
			if got := rep.Outcomes[SecretKindPassword]; got != OutcomeRejected && got != OutcomeAmbiguous {
				t.Errorf("outcome %q, want rejected or ambiguous: %s", got, attemptsString(rep))
			}
			for _, a := range rep.Attempts {
				if a.Result == ResultFailure && a.Submissions > 0 && a.Method == "keyboard-interactive" {
					t.Errorf("keyboard-interactive recorded as answered after a disconnect: %s", attemptsString(rep))
				}
			}
		})
	})
}

// @ac AC-26
func TestOutcome_KeysAndBothSecrets(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-26", func(t *testing.T) {
		t.Run("key accepted", func(t *testing.T) {
			cred, pub := keyCred(t, "")
			host, port, _ := startOutcomeServer(t, outcomeServer{offerPublicKey: true, authorizedKey: pub})
			rep, err := dialReport(t, host, port, cred, 5*time.Second)
			if err != nil || rep.Outcomes[SecretKindKey] != OutcomeVerified { // pragma: allowlist secret
				t.Errorf("err %v, outcome %q: %s", err, rep.Outcomes[SecretKindKey], attemptsString(rep))
			}
		})
		t.Run("key rejected", func(t *testing.T) {
			cred, _ := keyCred(t, "")
			host, port, _ := startOutcomeServer(t, outcomeServer{offerPublicKey: true})
			rep, err := dialReport(t, host, port, cred, 5*time.Second)
			if !errors.Is(err, ErrAuthFailed) || rep.Outcomes[SecretKindKey] != OutcomeRejected {
				t.Errorf("err %v, outcome %q: %s", err, rep.Outcomes[SecretKindKey], attemptsString(rep))
			}
		})
		t.Run("key rejected, then the password accepted", func(t *testing.T) {
			cred, _ := keyCred(t, "")
			cred.Password = "right" // pragma: allowlist secret
			host, port, seen := startOutcomeServer(t, outcomeServer{offerPublicKey: true, password: "right"})
			rep, err := dialReport(t, host, port, cred, 5*time.Second)
			if err != nil || rep.Outcomes[SecretKindKey] != OutcomeRejected || rep.Outcomes[SecretKindPassword] != OutcomeVerified { // pragma: allowlist secret
				t.Errorf("err %v, outcomes %v: %s", err, rep.Outcomes, attemptsString(rep))
			}
			// The observer chooses nothing: the order is the historical
			// one, key first.
			if s := seen(); len(s) < 2 || s[0] != "publickey" || s[1] != "password" {
				t.Errorf("server saw methods %v, want publickey then password", s)
			}
		})
		t.Run("keyboard-interactive outside the profile does not touch the key", func(t *testing.T) {
			cred, _ := keyCred(t, "")
			cred.Password = "pw" // pragma: allowlist secret
			host, port, _ := startOutcomeServer(t, outcomeServer{offerPublicKey: true, kbdRounds: []kbdRound{{prompts: []string{"Code: "}, echos: []bool{true}}}, kbdPassword: "pw"})
			rep, _ := dialReport(t, host, port, cred, 5*time.Second)
			if rep.Outcomes[SecretKindKey] != OutcomeRejected || rep.Outcomes[SecretKindPassword] != OutcomeUnsupportedProfile { // pragma: allowlist secret
				t.Errorf("outcomes %v, want key rejected and password unsupported_profile: %s", rep.Outcomes, attemptsString(rep))
			}
		})
		t.Run("wrong and missing passphrase", func(t *testing.T) {
			for _, given := range []string{"wrong", ""} {
				cred, _ := keyCred(t, "right")
				cred.PrivateKeyPassphrase = given // pragma: allowlist secret
				dialed := false
				saved := netDial
				netDial = func(ctx context.Context, n, a string) (net.Conn, error) {
					dialed = true
					return saved(ctx, n, a)
				}
				var rep AuthReport
				_, err := Dial(context.Background(), "127.0.0.1", 1, cred, DialOptions{Report: &rep})
				netDial = saved
				if err == nil || dialed {
					t.Errorf("passphrase %q: err %v, dialed %v", given, err, dialed)
				}
				if rep.Outcomes[SecretKindKey] != OutcomeLocalDecryptFailed { // pragma: allowlist secret
					t.Errorf("passphrase %q: outcome %q, want local_decrypt_failed", given, rep.Outcomes[SecretKindKey])
				}
			}
		})
	})
}

// @ac AC-27
func TestOutcome_NothingSentBeforeAuthentication(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-27", func(t *testing.T) {
		t.Run("connection refused", func(t *testing.T) {
			lis, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := lis.Addr().(*net.TCPAddr).Port
			_ = lis.Close()
			rep, err := dialReport(t, "127.0.0.1", port, passwordCred("pw"), time.Second)
			if err == nil || rep.Outcomes[SecretKindPassword] != OutcomeNotSubmitted || len(rep.Attempts) != 0 { // pragma: allowlist secret
				t.Errorf("err %v, report %v %s", err, rep.Outcomes, attemptsString(rep))
			}
		})
		t.Run("host key refused", func(t *testing.T) {
			host, port, seen := startOutcomeServer(t, outcomeServer{password: "pw"})
			var rep AuthReport
			_, err := Dial(context.Background(), host, port, passwordCred("pw"), DialOptions{Mode: ModeStrict, Report: &rep})
			if !errors.Is(err, ErrHostKeyUnknown) || rep.Outcomes[SecretKindPassword] != OutcomeNotSubmitted {
				t.Errorf("err %v, outcome %q", err, rep.Outcomes[SecretKindPassword])
			}
			if len(seen()) != 0 {
				t.Errorf("the server saw %v before the host key was accepted", seen())
			}
		})
		t.Run("no report asked for", func(t *testing.T) {
			host, port, _ := startOutcomeServer(t, outcomeServer{password: "right"})
			_, err := Dial(context.Background(), host, port, passwordCred("wrong"), DialOptions{Mode: ModeTOFU})
			if !errors.Is(err, ErrAuthFailed) {
				t.Errorf("err %v", err)
			}
		})
	})
}

// The report's classification, for the evidence shapes the dial produces.
func TestClassifySecret(t *testing.T) {
	pw := SecretKindPassword
	for _, c := range []struct {
		name     string
		attempts []MethodAttempt
		want     OutcomeKind
	}{
		{"none only", []MethodAttempt{{Method: "none", Result: ResultFailure}}, OutcomeNotSubmitted},
		{"accepted after a rejection", []MethodAttempt{{Method: "password", Secret: pw, Submissions: 1, Result: ResultFailure}, {Method: "keyboard-interactive", Secret: pw, Submissions: 1, Result: ResultAccepted}}, OutcomeVerified},
		{"rejected beats unanswered", []MethodAttempt{{Method: "password", Secret: pw, Submissions: 1, Result: ResultFailure}, {Method: "keyboard-interactive", Secret: pw, Submissions: 1, Result: ResultNoAnswer}}, OutcomeRejected},
		{"unanswered", []MethodAttempt{{Method: "password", Secret: pw, Submissions: 1, Result: ResultNoAnswer}}, OutcomeAmbiguous},
		{"failure with nothing sent", []MethodAttempt{{Method: "keyboard-interactive", Result: ResultFailure}}, OutcomeNotSubmitted},
		{"unsupported beats rejected", []MethodAttempt{{Method: "password", Secret: pw, Submissions: 1, Result: ResultFailure}, {Method: "keyboard-interactive", Unsupported: true, Result: ResultFailure}}, OutcomeUnsupportedProfile},
		{"re-prompt then success", []MethodAttempt{{Method: "keyboard-interactive", Secret: pw, Submissions: 2, Reprompted: true, Result: ResultAccepted}}, OutcomeVerified},
		{"re-prompt then no answer", []MethodAttempt{{Method: "keyboard-interactive", Secret: pw, Submissions: 2, Reprompted: true, Result: ResultNoAnswer}}, OutcomeRejected},
		{"accepted with nothing sent", []MethodAttempt{{Method: "keyboard-interactive", Result: ResultAccepted}}, OutcomeNotSubmitted},
		{"key evidence does not count for the password", []MethodAttempt{{Method: "publickey", Secret: SecretKindKey, Submissions: 1, Result: ResultFailure}}, OutcomeNotSubmitted},
	} {
		if got := classifySecret(c.attempts, pw); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
