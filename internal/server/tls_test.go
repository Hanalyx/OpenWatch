// @spec system-http-server
//
// AC traceability:
// @ac AC-04  (TestCertManager_CachesWithinWindow)
// @ac AC-05  (TestCertManager_RefreshesAfterTTL)
// @ac AC-06  (TestCertManager_HotReloadOnFileChange)
// @ac AC-07  (TestCertManager_ErrorsOnMissingFile)

package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeCert generates a self-signed cert+key for a given CN and writes
// them to certPath / keyPath. Used to construct test fixtures inline.
func writeCert(t *testing.T, certPath, keyPath, cn string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

// @ac AC-04  (Two calls within the cache TTL return the same cached cert; no)
// second file read.
func TestCertManager_CachesWithinWindow(t *testing.T) {
	t.Run("system-http-server/AC-04", func(t *testing.T) {

		dir := t.TempDir()
		certPath := filepath.Join(dir, "cert.pem")
		keyPath := filepath.Join(dir, "key.pem")
		writeCert(t, certPath, keyPath, "test-1")

		cm := newCertManager(certPath, keyPath)
		cm.cacheTTL = 5 * time.Second

		first, err := cm.getCertificate(nil)
		if err != nil {
			t.Fatalf("first load: %v", err)
		}
		// Overwrite the file with a different cert — should NOT be picked up
		// while cache is fresh.
		writeCert(t, certPath, keyPath, "test-2")

		second, err := cm.getCertificate(nil)
		if err != nil {
			t.Fatalf("second load: %v", err)
		}
		if first != second {
			t.Error("cache window did not return cached cert; new file was read prematurely")
		}
	})
}

// @ac AC-05  (After the cache TTL expires, the next call re-reads from disk.)
func TestCertManager_RefreshesAfterTTL(t *testing.T) {
	t.Run("system-http-server/AC-05", func(t *testing.T) {

		dir := t.TempDir()
		certPath := filepath.Join(dir, "cert.pem")
		keyPath := filepath.Join(dir, "key.pem")
		writeCert(t, certPath, keyPath, "test-1")

		cm := newCertManager(certPath, keyPath)
		cm.cacheTTL = 50 * time.Millisecond

		first, err := cm.getCertificate(nil)
		if err != nil {
			t.Fatalf("first load: %v", err)
		}
		writeCert(t, certPath, keyPath, "test-2")
		time.Sleep(80 * time.Millisecond)

		second, err := cm.getCertificate(nil)
		if err != nil {
			t.Fatalf("second load: %v", err)
		}
		if first == second {
			t.Error("expected fresh cert after TTL; got cached pointer")
		}
		// Verify the new cert is for test-2 (the rewritten file).
		parsed, err := x509.ParseCertificate(second.Certificate[0])
		if err != nil {
			t.Fatalf("parse second cert: %v", err)
		}
		if parsed.Subject.CommonName != "test-2" {
			t.Errorf("second cert CN = %q, want test-2", parsed.Subject.CommonName)
		}
	})
}

// @ac AC-06  (Replacing the file on disk causes the next post-TTL call to)
// present the new certificate. (Same scenario as AC-5 but framed as the
// operator workflow: rotate cert, wait, new cert served.)
func TestCertManager_HotReloadOnFileChange(t *testing.T) {
	t.Run("system-http-server/AC-06", func(t *testing.T) {

		dir := t.TempDir()
		certPath := filepath.Join(dir, "cert.pem")
		keyPath := filepath.Join(dir, "key.pem")
		writeCert(t, certPath, keyPath, "original")

		cm := newCertManager(certPath, keyPath)
		cm.cacheTTL = 50 * time.Millisecond

		c1, _ := cm.getCertificate(nil)
		parsed1, _ := x509.ParseCertificate(c1.Certificate[0])
		if parsed1.Subject.CommonName != "original" {
			t.Fatalf("first CN = %q, want original", parsed1.Subject.CommonName)
		}

		// Operator rotates the cert.
		writeCert(t, certPath, keyPath, "rotated")
		time.Sleep(80 * time.Millisecond)

		c2, _ := cm.getCertificate(nil)
		parsed2, _ := x509.ParseCertificate(c2.Certificate[0])
		if parsed2.Subject.CommonName != "rotated" {
			t.Errorf("after rotation, CN = %q, want rotated", parsed2.Subject.CommonName)
		}
	})
}

// @ac AC-07  (GetCertificate errors when the file is missing/unreadable; no)
// stale-cache fallback.
func TestCertManager_ErrorsOnMissingFile(t *testing.T) {
	t.Run("system-http-server/AC-07", func(t *testing.T) {

		dir := t.TempDir()
		certPath := filepath.Join(dir, "cert.pem")
		keyPath := filepath.Join(dir, "key.pem")

		cm := newCertManager(certPath, keyPath)
		cm.cacheTTL = 50 * time.Millisecond

		_, err := cm.getCertificate(nil)
		if err == nil {
			t.Fatal("expected error for missing cert file, got nil")
		}
	})
}
