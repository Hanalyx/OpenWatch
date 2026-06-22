package sshprivilege

// End-to-end regression guard for the production privilege probe against real
// in-process SSH servers. The incident: after a host set
// "PasswordAuthentication no", every host went 'degraded' with
// "ssh: handshake failed: ssh: unable to authenticate, attempted methods
// [none publickey], no supported methods remain" — even though the compliance
// scan still authenticated. Root cause: the probe forked its own auth-method
// list that offered only the bare "password" method (gated off by
// PasswordAuthentication no) and lacked PAM keyboard-interactive, while the
// scan's internal/ssh.Dial offered keyboard-interactive. The fix routes the
// probe through internal/ssh.Dial. These tests stand up the exact hardened
// server shape and drive the PRODUCTION probe (no stub dialer).

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strconv"
	"testing"
	"time"

	gossh "github.com/gliderlabs/ssh"
	"github.com/google/uuid"
	cryptossh "golang.org/x/crypto/ssh"

	"github.com/Hanalyx/openwatch/internal/credential"
	"github.com/Hanalyx/openwatch/internal/liveness"
)

type hardenedServerOpts struct {
	// kbdInteractivePassword, when set, accepts this password via a PAM-style
	// keyboard-interactive challenge. No PasswordHandler is set, so the server
	// advertises keyboard-interactive but NOT the bare "password" method —
	// i.e. PasswordAuthentication no + UsePAM keyboard-interactive.
	kbdInteractivePassword string
	// rejectAllKeys advertises publickey but rejects every key (so a client
	// with an unauthorized key attempts publickey, fails, and must fall back).
	rejectAllKeys bool
	// authorizedKey, when set (authorized-keys wire format), is the only key
	// the server accepts.
	authorizedKey []byte
}

// startHardenedSSHServer brings up an in-process SSH server and returns its
// host:port. The session handler exits 0 for any command, so the probe's
// `sudo -n true` reports passwordless sudo OK once authentication succeeds.
func startHardenedSSHServer(t *testing.T, opts hardenedServerOpts) (host string, port int) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port = lis.Addr().(*net.TCPAddr).Port

	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	signer, err := cryptossh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	srv := &gossh.Server{
		HostSigners: []gossh.Signer{signer},
		Handler:     func(s gossh.Session) { _ = s.Exit(0) },
	}
	if opts.kbdInteractivePassword != "" {
		srv.KeyboardInteractiveHandler = func(_ gossh.Context, challenge cryptossh.KeyboardInteractiveChallenge) bool {
			answers, cerr := challenge("", "", []string{"Password: "}, []bool{false})
			return cerr == nil && len(answers) == 1 && answers[0] == opts.kbdInteractivePassword
		}
	}
	if opts.rejectAllKeys {
		srv.PublicKeyHandler = func(_ gossh.Context, _ gossh.PublicKey) bool { return false }
	}
	if opts.authorizedKey != nil {
		want, _, _, _, perr := cryptossh.ParseAuthorizedKey(opts.authorizedKey)
		if perr != nil {
			t.Fatalf("parse authorized key: %v", perr)
		}
		srv.PublicKeyHandler = func(_ gossh.Context, presented gossh.PublicKey) bool {
			return string(presented.Marshal()) == string(want.Marshal())
		}
	}

	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() { _ = srv.Close(); _ = lis.Close() })
	return "127.0.0.1", port
}

// authorizedKeyFor derives the authorized-keys line for a private-key PEM.
func authorizedKeyFor(t *testing.T, keyPEM string) []byte {
	t.Helper()
	signer, err := cryptossh.ParsePrivateKey([]byte(keyPEM))
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}
	return cryptossh.MarshalAuthorizedKey(signer.PublicKey())
}

// runProbe dials the given server through the PRODUCTION probe (default
// realDialer, TOFU host-key acceptance) and returns the probe outcome.
func runProbe(t *testing.T, cred *credential.Credential, host string, port int) (attempted, ok bool, err error) {
	t.Helper()
	probe := Probe(stubResolver{cred: cred})
	hostID := liveness.HostID(uuid.Must(uuid.NewV7()).String())
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	return probe(context.Background(), hostID, addr, 5*time.Second)
}

// TestProbe_HardenedHost_StaysOnline is the direct regression for the incident:
// a hardened host (PasswordAuthentication no + PAM keyboard-interactive) whose
// key is NOT authorized must still authenticate via the replayed password, so
// the privilege probe succeeds and the host stays Online instead of degraded.
func TestProbe_HardenedHost_StaysOnline(t *testing.T) {
	const pw = "tester-pw-9"
	host, port := startHardenedSSHServer(t, hardenedServerOpts{
		kbdInteractivePassword: pw,
		rejectAllKeys:          true, // advertises publickey, rejects it -> the [none publickey] path
	})

	cred := &credential.Credential{
		Username:   "tester",
		AuthMethod: credential.AuthBoth,
		PrivateKey: testEd25519PEM(t), // present but unauthorized on the server
		Password:   pw,
	}

	attempted, ok, err := runProbe(t, cred, host, port)
	if !attempted {
		t.Fatal("attempted=false: the probe never reached the SSH dial")
	}
	if err != nil {
		t.Fatalf("probe error on a PasswordAuthentication-no PAM host (regression): %v", err)
	}
	if !ok {
		t.Fatal("ok=false: probe authenticated but the sudo check failed")
	}
}

// TestProbe_KeyOnlyHost_StaysOnline guards the plain key-only case
// (PasswordAuthentication no, key authorized, no password method offered): the
// probe authenticates with the key and stays Online.
func TestProbe_KeyOnlyHost_StaysOnline(t *testing.T) {
	keyPEM := testEd25519PEM(t)
	host, port := startHardenedSSHServer(t, hardenedServerOpts{
		authorizedKey: authorizedKeyFor(t, keyPEM),
	})

	cred := &credential.Credential{
		Username:   "tester",
		AuthMethod: credential.AuthSSHKey,
		PrivateKey: keyPEM,
	}

	attempted, ok, err := runProbe(t, cred, host, port)
	if !attempted {
		t.Fatal("attempted=false: the probe never reached the SSH dial")
	}
	if err != nil {
		t.Fatalf("probe error on a key-only host (regression): %v", err)
	}
	if !ok {
		t.Fatal("ok=false: probe authenticated but the sudo check failed")
	}
}
