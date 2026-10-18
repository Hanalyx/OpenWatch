// @spec system-ssh-connectivity

package ssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gossh "github.com/gliderlabs/ssh"
	cryptossh "golang.org/x/crypto/ssh"

	"github.com/Hanalyx/openwatch/internal/credprotect"
)

func sudoTestClient(t *testing.T, handler gossh.Handler) *cryptossh.Client {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &gossh.Server{Handler: handler, PasswordHandler: func(gossh.Context, string) bool { return true }}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptossh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	server.AddHostKey(signer)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close(); _ = listener.Close() })
	client, err := cryptossh.Dial("tcp", listener.Addr().String(), &cryptossh.ClientConfig{
		User: "ops", Auth: []cryptossh.AuthMethod{cryptossh.Password("synthetic-login")},
		HostKeyCallback: cryptossh.FixedHostKey(signer.PublicKey()), Timeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func sudoTestOptions(p *fakeProtection, command string, mode ProtectedSudoMode) ProtectedSudoOptions {
	auth := protectedOpts(p, SecretKindPassword, activePassword("ops", "P1"))
	return ProtectedSudoOptions{Mode: mode, Auth: auth, Timeout: 3 * time.Second,
		Profile: &ValidatedSudoProfile{HostID: auth.HostID, Username: "ops", Command: command,
			EvidenceID: "synthetic-profile", ExpiresAt: time.Now().Add(time.Hour), PasswordTries: 1, MaxPAMFailures: 1, InvokingUser: true}}
}

func sudoTestPrompt(s gossh.Session) string {
	args := s.Command()
	for i, a := range args {
		if a == "-p" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}
func sudoTestMarker(s gossh.Session) string {
	args := s.Command()
	for i, a := range args {
		if a == "ow-exec" && i+1 < len(args) {
			return "OWEXEC-" + args[i+1] + "\n"
		}
	}
	return ""
}
func sudoTestReply(s gossh.Session, prompt bool, marker bool, exit int) {
	if prompt {
		_, _ = io.WriteString(s.Stderr(), sudoTestPrompt(s))
		_, _ = io.ReadAll(s)
	}
	if marker {
		_, _ = io.WriteString(s.Stderr(), sudoTestMarker(s))
	}
	_ = s.Exit(exit)
}

// @ac AC-35
func TestProtectedSudo_Admission(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-35", func(t *testing.T) {
		for _, name := range []string{"missing profile", "expired", "wrong host", "wrong command", "tries", "bound", "account", "no evidence", "reservation", "multiline", "connection account"} {
			t.Run(name, func(t *testing.T) {
				var calls atomic.Int32
				client := sudoTestClient(t, func(s gossh.Session) { calls.Add(1); _ = s.Exit(0) })
				p := &fakeProtection{}
				o := sudoTestOptions(p, "true", SudoPasswordOnly)
				c := activePassword("ops", "P1")
				switch name {
				case "connection account":
					c.Username = "different"
					o.Profile.Username = c.Username
				case "missing profile":
					o.Profile = nil
				case "expired":
					o.Profile.ExpiresAt = time.Now().Add(-time.Second)
				case "wrong host":
					o.Profile.HostID = o.Auth.CredentialID
				case "wrong command":
					o.Profile.Command = "false"
				case "tries":
					o.Profile.PasswordTries = 3
				case "bound":
					o.Profile.MaxPAMFailures = 2
				case "account":
					o.Profile.InvokingUser = false
				case "no evidence":
					o.Profile.EvidenceID = ""
				case "reservation":
					p.reserveErr = credprotect.ErrBlocked
				case "multiline":
					c.Password = "P1\nP2" // pragma: allowlist secret (synthetic fixture)
				}
				res, err := ProtectedSudo(context.Background(), client, c, "true", o)
				if err == nil || calls.Load() != 0 || res.Attempt.Reserved {
					t.Fatalf("err=%v executions=%d", err, calls.Load())
				}
			})
		}
	})
}

// @ac AC-36
func TestProtectedSudo_PromptAndFence(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-36", func(t *testing.T) {
		for _, test := range []struct {
			name                   string
			noprompt, deny, repeat bool
			want                   credprotect.Outcome
		}{
			{name: "split nonce", want: credprotect.OutcomeVerified},
			{name: "no prompt", noprompt: true, want: credprotect.OutcomeNotSubmitted},
			{name: "fence refused", deny: true, want: credprotect.OutcomeUnknown},
			{name: "second prompt", repeat: true, want: credprotect.OutcomeUnknown},
		} {
			t.Run(test.name, func(t *testing.T) {
				received := make(chan string, 1)
				client := sudoTestClient(t, func(s gossh.Session) {
					_, _ = io.WriteString(s.Stderr(), "Lecture: do not confuse this with a prompt.\n")
					if !test.noprompt {
						for _, b := range []byte(sudoTestPrompt(s)) {
							_, _ = s.Stderr().Write([]byte{b})
						}
					}
					if test.noprompt {
						received <- ""
						_ = s.Exit(0)
						return
					}
					b, _ := io.ReadAll(s)
					received <- string(b)
					if test.repeat {
						_, _ = io.WriteString(s.Stderr(), sudoTestPrompt(s))
						_ = s.Exit(1)
						return
					}
					_ = s.Exit(0)
				})
				p := &fakeProtection{}
				if test.deny {
					p.fenceErr = credprotect.ErrFenceRefused
				}
				o := sudoTestOptions(p, "", SudoVerifyPassword)
				res, err := ProtectedSudo(context.Background(), client, activePassword("ops", "P1"), "", o)
				got := <-received
				want := "P1\n"
				if test.deny || test.noprompt {
					want = ""
				}
				if got != want {
					t.Fatalf("received %q, want %q", got, want)
				}
				if res.Attempt.Outcome != test.want {
					t.Fatalf("outcome=%s err=%v", res.Attempt.Outcome, err)
				}
				wantSettled(t, p, test.want)
				if test.deny && !errors.Is(err, ErrProtected) {
					t.Fatalf("err=%v", err)
				}
			})
		}
	})
}

// @ac AC-37
func TestProtectedSudo_ExecutionAndFallback(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-37", func(t *testing.T) {
		for _, name := range []string{"command failed", "safe fallback", "truncated", "transport lost", "exit then disconnect", "exit signal", "mutating cached", "mutating password"} {
			t.Run(name, func(t *testing.T) {
				var calls atomic.Int32
				client := sudoTestClient(t, func(s gossh.Session) {
					n := calls.Add(1)
					switch name {
					case "command failed":
						_, _ = io.WriteString(s.Stderr(), sudoTestMarker(s)+"a password is required\n")
						_ = s.Exit(1)
					case "truncated":
						_, _ = io.WriteString(s.Stderr(), strings.Repeat("x", 256))
						_ = s.Exit(1)
					case "transport lost":
						_ = s.Close()
					case "exit then disconnect":
						_, _ = s.SendRequest("exit-status", false, cryptossh.Marshal(struct{ Status uint32 }{1}))
						_ = s.Context().Value(gossh.ContextKeyConn).(*cryptossh.ServerConn).Close()
					case "exit signal":
						_, _ = s.SendRequest("exit-signal", false, cryptossh.Marshal(struct {
							Signal   string
							Core     bool
							Message  string
							Language string
						}{"TERM", false, "", ""}))
						_ = s.Exit(1)
					default:
						if name == "mutating password" || n == 2 {
							sudoTestReply(s, true, true, 1)
						} else {
							sudoTestReply(s, false, false, 1)
						}
					}
				})
				p := &fakeProtection{}
				o := sudoTestOptions(p, "printf 'a password is required'; exit 1", SudoReadOnlyFallback)
				if name == "truncated" {
					o.CaptureLimit = 32
				}
				if name == "mutating cached" {
					o.Mode = SudoCachedOnly
				}
				if name == "mutating password" {
					o.Mode = SudoPasswordOnly
				}
				res, err := ProtectedSudo(context.Background(), client, activePassword("ops", "P1"), o.Profile.Command, o)
				want := int32(1)
				if name == "safe fallback" {
					want = 2
				}
				if calls.Load() != want || err == nil {
					t.Fatalf("calls=%d want=%d err=%v", calls.Load(), want, err)
				}
				if name == "safe fallback" || name == "mutating password" {
					if !res.CommandStarted || res.Attempt.Outcome != credprotect.OutcomeVerified {
						t.Fatalf("result=%+v", res)
					}
				} else if r, _, _ := p.calls(); r != 0 {
					t.Fatal("unsafe fallback reserved a password")
				}
			})
		}
	})
}

// @ac AC-38
func TestProtectedSudo_OutcomesAndCancellation(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-38", func(t *testing.T) {
		for _, name := range []string{"wrong password", "no prompt failure", "cancel", "settlement failed"} {
			t.Run(name, func(t *testing.T) {
				ready := make(chan struct{})
				client := sudoTestClient(t, func(s gossh.Session) {
					if name == "no prompt failure" {
						_ = s.Exit(1)
						return
					}
					_, _ = io.WriteString(s.Stderr(), sudoTestPrompt(s))
					_, _ = io.ReadAll(s)
					if name == "cancel" {
						close(ready)
						<-s.Context().Done()
						return
					}
					code := 1
					if name == "settlement failed" {
						code = 0
					}
					_ = s.Exit(code)
				})
				p := &fakeProtection{}
				if name == "settlement failed" {
					p.settleErr = errors.New("record unavailable")
				}
				o := sudoTestOptions(p, "", SudoVerifyPassword)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if name == "cancel" {
					go func() { <-ready; cancel() }()
				}
				res, err := ProtectedSudo(ctx, client, activePassword("ops", "P1"), "", o)
				want := credprotect.OutcomeUnsuccessful
				if name == "cancel" || name == "no prompt failure" {
					want = credprotect.OutcomeUnknown
				}
				if name == "settlement failed" {
					want = credprotect.OutcomeVerified
					if !errors.Is(err, ErrNotRecorded) {
						t.Fatalf("err=%v", err)
					}
				}
				if res.Attempt.Outcome != want || err == nil {
					t.Fatalf("outcome=%s err=%v", res.Attempt.Outcome, err)
				}
				if len(p.settleCtx) != 1 || p.settleCtx[0] != nil {
					t.Fatal("settlement used canceled context")
				}
			})
		}
	})
}

func TestSudoPromptDoesNotMatchLectureOrWriteTwice(t *testing.T) {
	var input bytes.Buffer
	var writes int
	p := sudoPrompt{capture: sudoCapture{limit: 4096}, token: "OWPROMPT-test:", stdin: writeCloseBuffer{&input},
		secret: func() (string, error) { writes++; return "P1", nil }, abort: func() {}}
	for _, s := range []string{"Lecture:", "OWPROM", "PT-test:"} {
		if _, err := p.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	if writes != 1 || input.String() != "P1\n" {
		t.Fatalf("writes=%d input=%q", writes, input.String())
	}
	if _, err := p.Write([]byte("OWPROMPT-test:")); err == nil {
		t.Fatal("second prompt accepted")
	}
	if writes != 1 {
		t.Fatal("password replayed")
	}
}

type writeCloseBuffer struct{ *bytes.Buffer }

func (writeCloseBuffer) Close() error { return nil }

func TestSudoArgvIsData(t *testing.T) {
	for _, command := range []string{"printf '%s' \"a'b\"", "$(false)", "`false`", "a\nb", "OWEXEC-forged\n"} {
		t.Run(command, func(t *testing.T) {
			observed := make(chan []string, 1)
			client := sudoTestClient(t, func(s gossh.Session) {
				observed <- s.Command()
				_, _ = io.WriteString(s.Stderr(), sudoTestMarker(s))
				_ = s.Exit(0)
			})
			res, err := ProtectedSudo(context.Background(), client, nil, command, ProtectedSudoOptions{Mode: SudoCachedOnly})
			if err != nil || !res.CommandStarted {
				t.Fatalf("err=%v started=%v", err, res.CommandStarted)
			}
			args := <-observed
			if len(args) != 9 || args[5] != sudoMarkerScript || args[8] != command {
				t.Fatalf("remote args changed: %q", args)
			}
		})
	}
}

type expireSudoProfile struct {
	*fakeProtection
	profile *ValidatedSudoProfile
}

func (p *expireSudoProfile) Reserve(ctx context.Context, r credprotect.Request) (credprotect.Submission, error) {
	s, err := p.fakeProtection.Reserve(ctx, r)
	p.profile.ExpiresAt = time.Now().Add(-time.Second)
	return s, err
}

// @ac AC-35
func TestProtectedSudo_ProfileExpiryDuringReservation(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-35", func(t *testing.T) {
		var calls atomic.Int32
		client := sudoTestClient(t, func(s gossh.Session) { calls.Add(1); _ = s.Exit(0) })
		p := &fakeProtection{}
		o := sudoTestOptions(p, "true", SudoPasswordOnly)
		o.Auth.Protection = &expireSudoProfile{fakeProtection: p, profile: o.Profile}
		res, err := ProtectedSudo(context.Background(), client, activePassword("ops", "P1"), "true", o)
		if !errors.Is(err, ErrSudoProfile) || calls.Load() != 0 || res.Attempt.Outcome != credprotect.OutcomeNotSubmitted {
			t.Fatalf("err=%v executions=%d outcome=%s", err, calls.Load(), res.Attempt.Outcome)
		}
		wantSettled(t, p, credprotect.OutcomeNotSubmitted)
	})
}
