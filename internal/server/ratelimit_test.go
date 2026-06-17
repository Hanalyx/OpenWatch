// @spec system-http-server
package server

import (
	"bytes"
	"net/http"
	"testing"
	"time"
)

// @ac AC-18
// AC-18: the limiter allows up to its limit and denies the limit+1th for the
// same key; a different key is independent. (The end-to-end login 429 is
// asserted by TestRateLimitAuth_LoginReturns429.)
func TestRateLimiter_AllowsThenDenies(t *testing.T) {
	t.Run("system-http-server/AC-18", func(t *testing.T) {
		rl := newRateLimiter(3, time.Minute)
		for i := 1; i <= 3; i++ {
			if !rl.allow("ip-a") {
				t.Fatalf("attempt %d denied, want allowed (within limit)", i)
			}
		}
		if rl.allow("ip-a") {
			t.Error("limit+1 attempt allowed, want denied")
		}
		if !rl.allow("ip-b") {
			t.Error("a different key was denied; keys must be independent")
		}
	})
}

// AC-18 (end-to-end): the per-IP login budget returns 429 with Retry-After
// once exhausted. Uses an unknown user so each attempt is fast (no Argon2id).
func TestRateLimitAuth_LoginReturns429(t *testing.T) {
	url, _ := freshAPIServer(t)
	body := []byte(`{"username":"nobody-ratelimit","password":"whatever1234"}`)
	got429 := false
	for i := 0; i < authRateLimitPerMinute+1; i++ {
		req, _ := http.NewRequest("POST", url+"/api/v1/auth/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp := doReq(t, req)
		code := resp.StatusCode
		retry := resp.Header.Get("Retry-After")
		resp.Body.Close()
		if code == http.StatusTooManyRequests {
			got429 = true
			if retry == "" {
				t.Error("429 response missing Retry-After header")
			}
			break
		}
	}
	if !got429 {
		t.Errorf("no 429 after %d login attempts from one IP", authRateLimitPerMinute+1)
	}
}
