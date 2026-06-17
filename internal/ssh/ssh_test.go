// @spec system-ssh-connectivity
//
// SSH dial + key validation + known-hosts tests. Uses
// gliderlabs/ssh to spin up an in-process SSH server so the dial path
// runs against real bytes-on-the-wire without needing a real host.

package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/credential"
	gossh "github.com/gliderlabs/ssh"
	cryptossh "golang.org/x/crypto/ssh"
)

// startTestServer spins up a gliderlabs SSH server that accepts the
// supplied credential. Returns the host:port and a stop function.
// Server uses an Ed25519 host key generated per call so each test has
// fresh host-key bytes.
type testServerOpts struct {
	password         string
	authorizedKeyPEM string
	// kbdInteractivePassword, when set (and password unset), makes the server
	// offer ONLY keyboard-interactive — no bare "password" method — mirroring a
	// hardened host with PasswordAuthentication no + PAM keyboard-interactive.
	kbdInteractivePassword string
}

func startTestServer(t *testing.T, opts testServerOpts) (host string, port int, hostKeyMarshalled []byte, stop func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := lis.Addr().(*net.TCPAddr)
	host = "127.0.0.1"
	port = addr.Port

	// Fresh Ed25519 host key.
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	signer, err := cryptossh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	hostKeyMarshalled = signer.PublicKey().Marshal()

	srv := &gossh.Server{
		Handler: func(s gossh.Session) {
			_, _ = s.Write([]byte("hello\n"))
		},
		HostSigners: []gossh.Signer{signer},
	}
	if opts.password != "" {
		srv.PasswordHandler = func(_ gossh.Context, pw string) bool { return pw == opts.password }
	}
	if opts.kbdInteractivePassword != "" {
		// PAM-style: challenge with a single hidden "Password:" prompt and
		// accept the answer. No PasswordHandler is set, so the server advertises
		// keyboard-interactive but NOT the bare password method.
		srv.KeyboardInteractiveHandler = func(_ gossh.Context, challenge cryptossh.KeyboardInteractiveChallenge) bool {
			answers, err := challenge("", "", []string{"Password: "}, []bool{false})
			return err == nil && len(answers) == 1 && answers[0] == opts.kbdInteractivePassword
		}
	}
	if opts.authorizedKeyPEM != "" {
		// Parse the authorized client public key.
		authorized, _, _, _, err := cryptossh.ParseAuthorizedKey([]byte(opts.authorizedKeyPEM))
		if err != nil {
			t.Fatalf("parse authorized key: %v", err)
		}
		// gliderlabs/ssh PublicKey marshal is comparable to cryptossh.
		authMarshalled := authorized.Marshal()
		srv.PublicKeyHandler = func(_ gossh.Context, presented gossh.PublicKey) bool {
			return bytesEqual(authMarshalled, presented.Marshal())
		}
	}

	go func() {
		_ = srv.Serve(lis)
	}()
	stop = func() {
		_ = srv.Close()
		_ = lis.Close()
	}
	t.Cleanup(stop)
	return host, port, hostKeyMarshalled, stop
}

// passwordCred is a synthetic credential with a password.
func passwordCred(pw string) *credential.Credential {
	return &credential.Credential{
		Username:   "testuser",
		AuthMethod: credential.AuthPassword,
		Password:   pw,
	}
}

// generateEd25519CredAndAuthKey returns (credential with private key,
// authorized-keys-line representation of the public part).
func generateEd25519CredAndAuthKey(t *testing.T) (*credential.Credential, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("pkcs8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	sshPub, err := cryptossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh pub: %v", err)
	}
	authLine := string(cryptossh.MarshalAuthorizedKey(sshPub))
	return &credential.Credential{
		Username:   "testuser",
		AuthMethod: credential.AuthSSHKey,
		PrivateKey: string(pemBytes),
	}, authLine
}

// generateRSACredAndAuthKey returns an RSA credential of the supplied
// bit size. Used by AC-05 to test the key-strength boundary.
func generateRSACred(t *testing.T, bits int) *credential.Credential {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("pkcs8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	return &credential.Credential{
		Username:   "testuser",
		AuthMethod: credential.AuthSSHKey,
		PrivateKey: string(pemBytes),
	}
}

// @ac AC-01
// AC-01: Dial against a test server with password creds completes
// the handshake within 1 second.
func TestDial_PasswordSucceeds(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-01", func(t *testing.T) {
		host, port, hostKey, _ := startTestServer(t, testServerOpts{password: "tester-pw-1"})
		store := NewMemoryStore()
		_ = store.Put(host, hostKey) // pre-seed: strict mode

		start := time.Now()
		client, err := Dial(context.Background(), host, port, passwordCred("tester-pw-1"),
			DialOptions{Mode: ModeStrict, Store: store, Timeout: 5 * time.Second})
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		defer client.Close()
		if time.Since(start) > 1*time.Second {
			t.Errorf("handshake took %v, want < 1s", time.Since(start))
		}
	})
}

// @ac AC-02
// AC-02: Dial with Ed25519 private key completes the handshake.
func TestDial_Ed25519KeySucceeds(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-02", func(t *testing.T) {
		cred, authKey := generateEd25519CredAndAuthKey(t)
		host, port, hostKey, _ := startTestServer(t, testServerOpts{authorizedKeyPEM: authKey})
		store := NewMemoryStore()
		_ = store.Put(host, hostKey)
		client, err := Dial(context.Background(), host, port, cred,
			DialOptions{Mode: ModeStrict, Store: store, Timeout: 5 * time.Second})
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		defer client.Close()
	})
}

// @ac AC-03
// AC-03: Dial against a port that refuses connections returns
// ErrConnect within DefaultDialTimeout.
func TestDial_ConnectRefused(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-03", func(t *testing.T) {
		// Listen + close to get a port that's guaranteed unused.
		lis, _ := net.Listen("tcp", "127.0.0.1:0")
		port := lis.Addr().(*net.TCPAddr).Port
		lis.Close()

		start := time.Now()
		_, err := Dial(context.Background(), "127.0.0.1", port, passwordCred("x"),
			DialOptions{Mode: ModeStrict, Timeout: 2 * time.Second})
		if !errors.Is(err, ErrConnect) {
			t.Errorf("err = %v, want ErrConnect", err)
		}
		if time.Since(start) > DefaultDialTimeout {
			t.Errorf("dial took %v, exceeded DefaultDialTimeout %v", time.Since(start), DefaultDialTimeout)
		}
	})
}

// @ac AC-04
// AC-04: ctx timeout before underlying dial completes returns
// ErrDialTimeout. Test against a non-routable address with a tight
// ctx deadline.
func TestDial_CtxTimeoutSurfacesAsErrDialTimeout(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-04", func(t *testing.T) {
		// Override netDial to block past the test's deadline.
		old := netDial
		defer func() { netDial = old }()
		netDial = func(ctx context.Context, network, address string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_, err := Dial(ctx, "203.0.113.1", 22, passwordCred("x"),
			DialOptions{Mode: ModeStrict, Timeout: 1 * time.Second})
		if !errors.Is(err, ErrDialTimeout) {
			t.Errorf("err = %v, want ErrDialTimeout", err)
		}
	})
}

// @ac AC-05
// AC-05: ValidateAuthKey accepts/rejects per NIST SP 800-57.
func TestValidateAuthKey_StrengthBoundary(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-05", func(t *testing.T) {
		// Ed25519 always accepted.
		ed25519Cred, _ := generateEd25519CredAndAuthKey(t)
		if err := ValidateAuthKey([]byte(ed25519Cred.PrivateKey), ""); err != nil {
			t.Errorf("Ed25519 rejected: %v", err)
		}
		// RSA 1024 rejected.
		rsa1024 := generateRSACred(t, 1024)
		if err := ValidateAuthKey([]byte(rsa1024.PrivateKey), ""); !errors.Is(err, ErrWeakKey) {
			t.Errorf("RSA-1024 err = %v, want ErrWeakKey", err)
		}
		// RSA 2048 accepted.
		rsa2048 := generateRSACred(t, 2048)
		if err := ValidateAuthKey([]byte(rsa2048.PrivateKey), ""); err != nil {
			t.Errorf("RSA-2048 rejected: %v", err)
		}
	})
}

// @ac AC-06
// AC-06: Strict mode rejects an unknown host key.
func TestKnownHosts_StrictRejectsUnknown(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-06", func(t *testing.T) {
		host, port, _, _ := startTestServer(t, testServerOpts{password: "any"})
		// Empty store → no entry for host.
		store := NewMemoryStore()
		_, err := Dial(context.Background(), host, port, passwordCred("any"),
			DialOptions{Mode: ModeStrict, Store: store, Timeout: 5 * time.Second})
		if !errors.Is(err, ErrHostKeyUnknown) {
			t.Errorf("err = %v, want ErrHostKeyUnknown", err)
		}
		// Store remains empty — strict-mode rejection MUST NOT cache.
		if _, ok := store.Get(host); ok {
			t.Error("strict-mode rejection cached the host key — should not have")
		}
	})
}

// @ac AC-07
// AC-07: TOFU mode accepts first connection, persists key; subsequent
// connections succeed (same key) or fail with ErrHostKeyMismatch (new key).
func TestKnownHosts_TOFU(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-07", func(t *testing.T) {
		host, port, hostKey, stop := startTestServer(t, testServerOpts{password: "any"})
		store := NewMemoryStore()
		// First connection: store empty, TOFU caches the key.
		c1, err := Dial(context.Background(), host, port, passwordCred("any"),
			DialOptions{Mode: ModeTOFU, Store: store, Timeout: 5 * time.Second})
		if err != nil {
			t.Fatalf("first dial: %v", err)
		}
		c1.Close()
		stored, ok := store.Get(host)
		if !ok {
			t.Fatal("TOFU did not persist key")
		}
		if string(stored) != string(hostKey) {
			t.Error("stored key != presented key")
		}
		// Second connection to same server: same key → succeeds.
		c2, err := Dial(context.Background(), host, port, passwordCred("any"),
			DialOptions{Mode: ModeTOFU, Store: store, Timeout: 5 * time.Second})
		if err != nil {
			t.Errorf("second dial (same key): %v", err)
		} else {
			c2.Close()
		}

		// Now spin up a NEW server (different host key) on a new port,
		// but reuse the same host in the store entry. We have to forge
		// the store key under "127.0.0.1" so the new server's key is
		// compared against the OLD stored key.
		stop()
		host2, port2, _, _ := startTestServer(t, testServerOpts{password: "any"})
		// Force the new server's host into the store as the old host so
		// the callback's lookup uses the old-key entry against the new
		// server's presentation.
		oldKey, _ := store.Get(host)
		_ = store.Put(host2, oldKey)
		_, err = Dial(context.Background(), host2, port2, passwordCred("any"),
			DialOptions{Mode: ModeTOFU, Store: store, Timeout: 5 * time.Second})
		if !errors.Is(err, ErrHostKeyMismatch) {
			t.Errorf("changed-key err = %v, want ErrHostKeyMismatch", err)
		}
	})
}

// @ac AC-08
// AC-08: Failed dial error MUST NOT contain the cleartext password or
// private key. Forced auth failure; inspect error text.
func TestDial_NoCredentialLeakInError(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-08", func(t *testing.T) {
		const secretPW = "super-secret-do-not-leak" // pragma: allowlist secret
		host, port, hostKey, _ := startTestServer(t, testServerOpts{password: "correct-pw"})
		store := NewMemoryStore()
		_ = store.Put(host, hostKey)
		_, err := Dial(context.Background(), host, port, passwordCred(secretPW),
			DialOptions{Mode: ModeStrict, Store: store, Timeout: 5 * time.Second})
		if err == nil {
			t.Fatal("expected auth failure")
		}
		if strings.Contains(err.Error(), secretPW) {
			t.Errorf("error contains the cleartext password: %v", err)
		}
		// Build a credential with a private-key PEM and confirm the PEM
		// header doesn't appear in the error either.
		cred, _ := generateEd25519CredAndAuthKey(t)
		_, err = Dial(context.Background(), host, port, cred,
			DialOptions{Mode: ModeStrict, Store: store, Timeout: 5 * time.Second})
		if err == nil {
			t.Fatal("expected key-auth failure (test server takes only password)")
		}
		if strings.Contains(err.Error(), "PRIVATE KEY") {
			t.Errorf("error leaked private-key header: %v", err)
		}
	})
}

// @ac AC-09
// AC-09: Wrong password returns ErrAuthFailed (distinct from ErrConnect
// or ErrHostKeyUnknown).
func TestDial_AuthFailureClassification(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-09", func(t *testing.T) {
		host, port, hostKey, _ := startTestServer(t, testServerOpts{password: "correct-pw"})
		store := NewMemoryStore()
		_ = store.Put(host, hostKey)
		_, err := Dial(context.Background(), host, port, passwordCred("wrong-pw"),
			DialOptions{Mode: ModeStrict, Store: store, Timeout: 5 * time.Second})
		if !errors.Is(err, ErrAuthFailed) {
			t.Errorf("err = %v, want ErrAuthFailed", err)
		}
	})
}

// @ac AC-10
// AC-10: Unparseable private key returns ErrInvalidKey BEFORE any
// network I/O. Override netDial to a panic-on-call so we'd see the
// failure if validation skipped.
func TestDial_InvalidKeyShortCircuits(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-10", func(t *testing.T) {
		old := netDial
		defer func() { netDial = old }()
		netDial = func(_ context.Context, _, _ string) (net.Conn, error) {
			return nil, fmt.Errorf("netDial called — validation should have short-circuited")
		}
		cred := &credential.Credential{
			Username:   "u",
			AuthMethod: credential.AuthSSHKey,
			PrivateKey: "not a real private key",
		}
		_, err := Dial(context.Background(), "127.0.0.1", 22, cred,
			DialOptions{Mode: ModeStrict, Timeout: 1 * time.Second})
		if !errors.Is(err, ErrInvalidKey) {
			t.Errorf("err = %v, want ErrInvalidKey", err)
		}
	})
}
