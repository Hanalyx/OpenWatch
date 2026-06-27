package httpclient

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"
)

// cgnat is the RFC 6598 carrier-grade NAT shared address space
// (100.64.0.0/10). Go's net.IP.IsPrivate does NOT cover it, but it is
// non-public and a valid SSRF pivot, so the guard blocks it explicitly.
var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0).To4(), Mask: net.CIDRMask(10, 32)}

// BlockedIP reports whether ip is in a range that outbound requests to
// operator- or IdP-supplied URLs must not reach (SSRF). Covers loopback,
// RFC1918 private, RFC6598 CGNAT, link-local (including the 169.254.169.254
// cloud-metadata endpoint), and the unspecified address. IPv4-mapped IPv6
// forms are unwrapped before checking. A nil/unparseable ip is blocked
// (fail closed).
func BlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() ||
		cgnat.Contains(ip)
}

// BlockedHost rejects targets that are non-public by name — literal IPs and
// obvious loopback names — before DNS resolution. The dial-time
// GuardedDialControl re-checks the resolved IP (defeats DNS rebinding).
func BlockedHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return BlockedIP(ip)
	}
	lower := strings.ToLower(host)
	return lower == "localhost" || strings.HasSuffix(lower, ".localhost")
}

// GuardedDialControl runs after DNS resolution with the concrete dial
// address and blocks the connection if the resolved IP is non-public. Wire
// it into a net.Dialer.Control so a hostname that resolves (or rebinds) to
// internal space cannot be reached.
func GuardedDialControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	if ip := net.ParseIP(host); ip != nil && BlockedIP(ip) {
		return fmt.Errorf("httpclient: blocked dial to non-public address %s", host)
	}
	return nil
}

// NewGuardedHTTPClient returns a *http.Client that refuses to dial
// non-public addresses (SSRF guard) and pins TLS >= 1.2. Use for outbound
// calls to operator- or IdP-supplied URLs (webhooks, OIDC discovery/JWKS).
func NewGuardedHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: 10 * time.Second,
				Control: GuardedDialControl,
			}).DialContext,
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2: true,
		},
	}
}

// NewGuardedClient wraps NewGuardedHTTPClient in the correlation-forwarding
// Client. Use for outbound calls to untrusted URLs that should still carry
// the correlation ID (the OIDC flow).
func NewGuardedClient(timeout time.Duration) *Client {
	return WithInner(NewGuardedHTTPClient(timeout))
}
