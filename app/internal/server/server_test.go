// @spec system-http-server
//
// AC traceability:
// @ac AC-02  (TestServer_TimeoutsLocked)
// @ac AC-03  (TestServer_TLSMinVersion)
// @ac AC-08  (TestServer_CorrelationMiddlewareMounted (verified via AC-9 fixture))
// @ac AC-09  (TestServer_CorrelationHeaderEchoed)
//
// @ac AC-01  ((real bind) and AC-10/AC-11 (graceful shutdown, error propagation))
// require live TLS listener tests and are exercised in main.go integration
// via the Day-4 acceptance scenarios.

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/config"
	"github.com/Hanalyx/openwatch/internal/correlation"
)

// mintSelfSignedCert writes a self-signed ECDSA cert + key pair to dir and
// returns their paths. Cert lives only for the test.
func mintSelfSignedCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "openwatch-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

// pickFreePort returns a port that's free at the moment of the call.
// (Inherently racy, but adequate for test isolation when followed
// immediately by ListenAndServeTLS.)
func pickFreePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return strconvI(port)
}

func strconvI(p int) string {
	// Avoid pulling in strconv just for this single use.
	const digits = "0123456789"
	if p == 0 {
		return "0"
	}
	out := []byte{}
	for p > 0 {
		out = append([]byte{digits[p%10]}, out...)
		p /= 10
	}
	return string(out)
}

// @ac AC-02  (http.Server timeouts match the locked values from the spec.)
func TestServer_TimeoutsLocked(t *testing.T) {
	t.Run("system-http-server/AC-02", func(t *testing.T) {

		cfg := config.Defaults()
		s := New(cfg, nil)

		cases := []struct {
			name string
			got  time.Duration
			want time.Duration
		}{
			{"ReadHeaderTimeout", s.srv.ReadHeaderTimeout, 10 * time.Second},
			{"ReadTimeout", s.srv.ReadTimeout, 30 * time.Second},
			{"WriteTimeout", s.srv.WriteTimeout, 60 * time.Second},
			{"IdleTimeout", s.srv.IdleTimeout, 120 * time.Second},
		}
		for _, c := range cases {
			if c.got != c.want {
				t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
			}
		}
		if s.srv.MaxHeaderBytes != 1<<16 {
			t.Errorf("MaxHeaderBytes = %d, want 65536", s.srv.MaxHeaderBytes)
		}
	})
}

// @ac AC-03  (TLS MinVersion is TLS 1.2 or higher.)
func TestServer_TLSMinVersion(t *testing.T) {
	t.Run("system-http-server/AC-03", func(t *testing.T) {

		cfg := config.Defaults()
		s := New(cfg, nil)
		if s.srv.TLSConfig.MinVersion < tls.VersionTLS12 {
			t.Errorf("MinVersion = 0x%x, want >= 0x%x (TLS 1.2)", s.srv.TLSConfig.MinVersion, tls.VersionTLS12)
		}
		if s.srv.TLSConfig.GetCertificate == nil {
			t.Error("GetCertificate callback is nil; cert hot-reload won't work")
		}
	})
}

// @ac AC-08  (AC-9: chi router has correlation middleware mounted first;)
// every response carries X-Correlation-Id.
func TestServer_CorrelationHeaderEchoed(t *testing.T) {
	t.Run("system-http-server/AC-08", func(t *testing.T) {

		cfg := config.Defaults()
		s := New(cfg, nil)
		s.Routes().Get("/probe", func(w http.ResponseWriter, r *http.Request) {
			// Handler depends on correlation being in ctx — proves middleware ran.
			if _, ok := correlation.From(r.Context()); !ok {
				t.Error("correlation middleware did not run before handler")
			}
			w.WriteHeader(http.StatusNoContent)
		})

		req := httptest.NewRequest(http.MethodGet, "/probe", nil)
		rec := httptest.NewRecorder()
		s.router.ServeHTTP(rec, req)

		got := rec.Header().Get(correlation.HeaderName)
		if got == "" {
			t.Fatal("response missing X-Correlation-Id")
		}
		if !strings.HasPrefix(got, "req-") {
			t.Errorf("response X-Correlation-Id = %q, want req- prefix", got)
		}
	})
}

// @ac AC-01  (Server.Run binds to cfg.Server.Listen and accepts HTTPS
// connections using GetCertificate.) Minted self-signed cert; arbitrary
// port via net.Listen probe before Run.
func TestServer_RunBindsAndAcceptsHTTPS(t *testing.T) {
	t.Run("system-http-server/AC-01", func(t *testing.T) {
		dir := t.TempDir()
		certPath, keyPath := mintSelfSignedCert(t, dir)

		// Probe a free port, then close — Run will rebind to it.
		port := pickFreePort(t)

		cfg := config.Defaults()
		cfg.Server.Listen = "127.0.0.1:" + port
		cfg.Server.TLSCert = certPath
		cfg.Server.TLSKey = keyPath
		s := New(cfg, nil)
		s.Routes().Get("/probe", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})

		ctx, cancel := context.WithCancel(context.Background())
		runDone := make(chan error, 1)
		go func() { runDone <- s.Run(ctx) }()

		// Wait for listener to be live.
		client := &http.Client{
			Timeout: 2 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test-only
			},
		}
		var resp *http.Response
		for i := 0; i < 50; i++ {
			r, err := client.Get("https://127.0.0.1:" + port + "/probe")
			if err == nil {
				resp = r
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if resp == nil {
			cancel()
			<-runDone
			t.Fatal("server did not accept HTTPS within 1s")
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Errorf("status = %d, want 204", resp.StatusCode)
		}
		cancel()
		if err := <-runDone; err != nil {
			t.Errorf("Run returned %v on graceful shutdown; want nil", err)
		}
	})
}

// @ac AC-10  (In-flight request during ctx cancellation is served to)
// completion or rejected cleanly — no panic.
func TestServer_RunHandlesInflightDuringShutdown(t *testing.T) {
	t.Run("system-http-server/AC-10", func(t *testing.T) {
		dir := t.TempDir()
		certPath, keyPath := mintSelfSignedCert(t, dir)
		port := pickFreePort(t)

		cfg := config.Defaults()
		cfg.Server.Listen = "127.0.0.1:" + port
		cfg.Server.TLSCert = certPath
		cfg.Server.TLSKey = keyPath
		s := New(cfg, nil)
		// Slow handler; ctx cancellation must not break it.
		s.Routes().Get("/slow", func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		})

		ctx, cancel := context.WithCancel(context.Background())
		runDone := make(chan error, 1)
		go func() { runDone <- s.Run(ctx) }()

		client := &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test-only
			},
		}
		// Wait for listen.
		for i := 0; i < 50; i++ {
			resp, err := client.Get("https://127.0.0.1:" + port + "/slow")
			if err == nil {
				resp.Body.Close()
				break
			}
			time.Sleep(20 * time.Millisecond)
		}

		// Kick off a request, then cancel mid-flight.
		respCh := make(chan *http.Response, 1)
		errCh := make(chan error, 1)
		go func() {
			r, err := client.Get("https://127.0.0.1:" + port + "/slow")
			if err != nil {
				errCh <- err
				return
			}
			respCh <- r
		}()
		time.Sleep(30 * time.Millisecond) // let the request reach the handler
		cancel()

		select {
		case r := <-respCh:
			// Served to completion under graceful shutdown — acceptable per AC-10.
			r.Body.Close()
			if r.StatusCode != http.StatusOK {
				t.Errorf("inflight status = %d, want 200 (served-to-completion path)", r.StatusCode)
			}
		case err := <-errCh:
			// Connection reset / refused — also acceptable per AC-10 ("rejected cleanly").
			t.Logf("inflight rejected cleanly: %v", err)
		case <-time.After(3 * time.Second):
			t.Error("inflight request neither completed nor errored within 3s")
		}
		_ = <-runDone // ensure goroutine exits — value not asserted here
	})
}

// @ac AC-11  (Run returns the first non-nil error from ListenAndServeTLS)
// that is not http.ErrServerClosed.
func TestServer_RunReturnsListenerError(t *testing.T) {
	t.Run("system-http-server/AC-11", func(t *testing.T) {
		cfg := config.Defaults()
		// Bind to an address that ListenAndServeTLS cannot use.
		cfg.Server.Listen = "127.0.0.1:1" // privileged port; bind will fail
		cfg.Server.TLSCert = "/nonexistent/cert.pem"
		cfg.Server.TLSKey = "/nonexistent/key.pem"
		s := New(cfg, nil)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		err := s.Run(ctx)
		if err == nil {
			t.Error("Run returned nil; expected error from failed bind")
		}
		// Whatever the error class, it must NOT be http.ErrServerClosed.
		if errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Run returned ErrServerClosed; want underlying listener error")
		}
	})
}

// @ac AC-09  ((companion): valid client header is echoed unchanged through chi.)
func TestServer_CorrelationClientEcho(t *testing.T) {
	t.Run("system-http-server/AC-09", func(t *testing.T) {

		cfg := config.Defaults()
		s := New(cfg, nil)
		s.Routes().Get("/probe", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})

		req := httptest.NewRequest(http.MethodGet, "/probe", nil)
		req.Header.Set(correlation.HeaderName, "my-client-001")
		rec := httptest.NewRecorder()
		s.router.ServeHTTP(rec, req)

		if got := rec.Header().Get(correlation.HeaderName); got != "my-client-001" {
			t.Errorf("response X-Correlation-Id = %q, want my-client-001", got)
		}
	})
}
