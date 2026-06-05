package server

import (
	"crypto/tls"
	"fmt"
	"sync"
	"time"
)

// certManager loads a TLS cert/key pair from disk and re-reads them
// transparently when called after a cache window. The intent is operator
// cert rotation without process restart: replace cert.pem / key.pem on
// disk and the next handshake (after the cache expiry) presents the new
// certificate.
//
// Spec: app/specs/system/http-server.spec.yaml AC-4, AC-5, AC-6, AC-7.
type certManager struct {
	certPath, keyPath string
	cacheTTL          time.Duration

	mu       sync.RWMutex
	cached   *tls.Certificate
	cachedAt time.Time
}

// newCertManager constructs a manager with a 5-second cache TTL per
// http-server.spec.yaml. Tests can override via the exported helper.
func newCertManager(certPath, keyPath string) *certManager {
	return &certManager{
		certPath: certPath,
		keyPath:  keyPath,
		cacheTTL: 5 * time.Second,
	}
}

// getCertificate is the tls.Config callback. Returns the cached cert
// when fresh; re-reads from disk on cache miss. Errors propagate to the
// TLS handshake (no fallback to stale cert).
func (m *certManager) getCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	if m.cached != nil && time.Since(m.cachedAt) < m.cacheTTL {
		c := m.cached
		m.mu.RUnlock()
		return c, nil
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	// Re-check after acquiring the write lock; a concurrent caller may
	// have refreshed.
	if m.cached != nil && time.Since(m.cachedAt) < m.cacheTTL {
		return m.cached, nil
	}

	cert, err := tls.LoadX509KeyPair(m.certPath, m.keyPath)
	if err != nil {
		return nil, fmt.Errorf("certManager: load %s / %s: %w", m.certPath, m.keyPath, err)
	}
	m.cached = &cert
	m.cachedAt = time.Now()
	return m.cached, nil
}
