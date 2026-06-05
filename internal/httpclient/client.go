// Package httpclient is the outbound HTTP wrapper that forwards the
// correlation ID from request context as X-Correlation-Id on every call.
//
// All outbound HTTP MUST go through this package's Client. The forbidigo
// lint rule rejects raw uses of http.DefaultClient and http.NewRequest +
// stdlib http.Client.Do in foundation/business code.
//
// Spec: app/specs/system/correlation.spec.yaml AC-14, AC-15, AC-16.
package httpclient

import (
	"context"
	"net/http"
	"time"

	"github.com/Hanalyx/openwatch/internal/correlation"
)

// Client wraps net/http.Client with correlation forwarding. Use NewClient
// to construct one; the zero value is usable but lacks sensible timeouts.
type Client struct {
	inner *http.Client
}

// NewClient returns a Client with conservative defaults: 30-second total
// timeout, transport pooling enabled. Callers requiring different
// timeouts construct directly via WithInner.
func NewClient() *Client {
	return &Client{
		inner: &http.Client{
			Timeout:   30 * time.Second,
			Transport: http.DefaultTransport,
		},
	}
}

// WithInner wraps a caller-supplied http.Client. Useful for tests, custom
// transports (TLS configs), or short-timeout health checks.
func WithInner(inner *http.Client) *Client {
	return &Client{inner: inner}
}

// Do sends the request, forwarding the correlation ID from req.Context()
// as X-Correlation-Id. If the caller has already set the header (e.g.,
// they explicitly want a different value), Do leaves it alone.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if req.Header.Get(correlation.HeaderName) == "" {
		if id, ok := correlation.From(req.Context()); ok {
			req.Header.Set(correlation.HeaderName, id)
		}
	}
	return c.inner.Do(req)
}

// Get is a convenience matching http.Client.Get's contract. Builds a
// GET request from ctx + url and forwards through Do.
func (c *Client) Get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}
