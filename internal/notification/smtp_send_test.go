// @spec system-notifications
//
// In-process SMTP relays (plaintext + self-signed TLS) that exercise the
// real sendSMTP delivery path — the postfix-style configurations.

package notification

import (
	"bufio"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// serveSMTP runs a minimal one-shot SMTP conversation over conn — just
// enough for a no-auth delivery (no STARTTLS/AUTH advertised) — capturing
// the DATA payload into body. It is the shape a trusted relay (a local
// postfix) presents; used over both a plaintext and a TLS-wrapped conn.
func serveSMTP(conn net.Conn, body *strings.Builder) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	send := func(s string) { _, _ = w.WriteString(s + "\r\n"); _ = w.Flush() }

	send("220 fake-relay ESMTP")
	inData := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if inData {
			if line == "." {
				inData = false
				send("250 2.0.0 Ok: queued")
				continue
			}
			body.WriteString(line + "\n")
			continue
		}
		switch {
		case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
			send("250-fake-relay")
			send("250 8BITMIME")
		case strings.HasPrefix(line, "MAIL FROM"), strings.HasPrefix(line, "RCPT TO"):
			send("250 2.1.0 Ok")
		case line == "DATA":
			send("354 End data with <CR><LF>.<CR><LF>")
			inData = true
		case line == "QUIT":
			send("221 2.0.0 Bye")
			return
		default:
			send("250 Ok")
		}
	}
}

// listenRelay accepts one connection, optionally wraps it in TLS with a
// self-signed cert (implicit TLS, like a relay on :465), then serves SMTP.
func listenRelay(t *testing.T, tlsCfg *tls.Config) (host string, port int, got *strings.Builder, wg *sync.WaitGroup) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var body strings.Builder
	var group sync.WaitGroup
	group.Add(1)
	go func() {
		defer group.Done()
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		var conn net.Conn = raw
		if tlsCfg != nil {
			conn = tls.Server(raw, tlsCfg)
		}
		serveSMTP(conn, &body)
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	pi, _ := strconv.Atoi(p)
	return h, pi, &body, &group
}

// selfSignedServerTLS returns a server tls.Config with a fresh self-signed
// cert for 127.0.0.1 — a stand-in for an internal relay whose cert no
// public CA chains to.
func selfSignedServerTLS(t *testing.T) *tls.Config {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	key, cert := genRSACert(t, tmpl)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{cert}, PrivateKey: key}}}
}

// @ac AC-21
// AC-21 (delivery side): sendSMTP delivers through a plaintext, no-auth
// relay when encryption is "none" — the configuration a trusted internal
// postfix relay uses. And the secure default (starttls, required) fails
// loudly against a relay that does not offer STARTTLS rather than silently
// downgrading. Proves the postfix path end to end.
func TestSendSMTP_PlaintextRelay(t *testing.T) {
	t.Run("system-notifications/AC-21", func(t *testing.T) {
		host, port, got, wg := listenRelay(t, nil)
		cfg := Config{
			SMTPHost: host, SMTPPort: port, SMTPEncryption: SMTPEncNone,
			From: "openwatch@corp.example", To: []string{"secops@corp.example"},
		}
		msg := buildEmailMessage(cfg.From, cfg.To, "test", "hello from openwatch")
		if err := sendSMTP(cfg, cfg.From, cfg.To, msg); err != nil {
			t.Fatalf("sendSMTP(none) to plaintext relay failed: %v", err)
		}
		wg.Wait()
		if !strings.Contains(got.String(), "hello from openwatch") {
			t.Errorf("relay did not receive the message body; got:\n%s", got.String())
		}

		// starttls-required against a relay that doesn't offer it → fail loudly.
		h2, p2, _, _ := listenRelay(t, nil)
		c2 := cfg
		c2.SMTPHost, c2.SMTPPort, c2.SMTPEncryption = h2, p2, SMTPEncSTARTTLS
		if err := sendSMTP(c2, c2.From, c2.To, msg); err == nil {
			t.Error("sendSMTP(starttls) should fail when the relay does not offer STARTTLS")
		}
	})
}

// @ac AC-23
// AC-23: SMTPInsecureSkipVerify governs whether an internal relay's
// self-signed cert is trusted. Implicit-TLS ("tls") delivery to a relay
// with a self-signed cert FAILS verification by default and SUCCEEDS when
// skip-verify is set — the toggle that makes a TLS-enabled internal postfix
// usable without leaking cert trust to the whole system.
func TestSendSMTP_SelfSignedTLS(t *testing.T) {
	t.Run("system-notifications/AC-23", func(t *testing.T) {
		base := Config{
			SMTPEncryption: SMTPEncTLS,
			From:           "openwatch@corp.example",
			To:             []string{"secops@corp.example"},
		}
		msg := buildEmailMessage(base.From, base.To, "test", "hello over self-signed tls")

		// Default (verify on): the self-signed cert is rejected.
		h1, p1, _, _ := listenRelay(t, selfSignedServerTLS(t))
		c1 := base
		c1.SMTPHost, c1.SMTPPort = h1, p1
		if err := sendSMTP(c1, c1.From, c1.To, msg); err == nil {
			t.Error("sendSMTP(tls) should reject a self-signed cert when skip-verify is off")
		}

		// skip-verify on: the handshake is accepted and the message delivers.
		h2, p2, got2, wg2 := listenRelay(t, selfSignedServerTLS(t))
		c2 := base
		c2.SMTPHost, c2.SMTPPort, c2.SMTPInsecureSkipVerify = h2, p2, true
		if err := sendSMTP(c2, c2.From, c2.To, msg); err != nil {
			t.Fatalf("sendSMTP(tls, skip-verify) to self-signed relay failed: %v", err)
		}
		wg2.Wait()
		if !strings.Contains(got2.String(), "hello over self-signed tls") {
			t.Errorf("self-signed relay did not receive the message; got:\n%s", got2.String())
		}
	})
}

// genRSACert generates a self-signed RSA cert from tmpl and returns the key
// and DER bytes. Kept local so the test needs no fixtures.
func genRSACert(t *testing.T, tmpl *x509.Certificate) (key *rsa.PrivateKey, der []byte) {
	t.Helper()
	k, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	d, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return k, d
}
