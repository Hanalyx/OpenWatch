package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/Hanalyx/openwatch/internal/identity"
)

// Double-submit CSRF token names. They match the frontend api-client
// (client.ts CSRF_COOKIE / CSRF_HEADER): the SPA reads the cookie and echoes
// it in the header on unsafe requests.
const (
	csrfCookieName = "XSRF-TOKEN"
	csrfHeaderName = "X-CSRF-Token"
)

// newCSRFToken returns a 256-bit random double-submit token.
func newCSRFToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// setCSRFCookie issues the XSRF-TOKEN cookie. NOT HttpOnly — the SPA must
// read it to echo it in X-CSRF-Token (the whole point of double-submit).
// Secure + SameSite=Lax + Path=/.
func setCSRFCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// csrfProtect enforces double-submit CSRF on unsafe, cookie-authenticated
// requests. CSRF only matters when the browser carries AMBIENT authority —
// the openwatch_session cookie — so the check is gated on its presence:
//   - safe methods (GET/HEAD/OPTIONS): exempt.
//   - Authorization header present: exempt (Bearer/token auth — no ambient
//     cookie the attacker can ride).
//   - /api/v1/auth/* lifecycle endpoints: exempt — protected by their own
//     credentials (password / HttpOnly refresh cookie), and the XSRF cookie
//     does not exist before login.
//   - no session cookie: exempt (nothing to abuse).
//
// Otherwise the request MUST carry X-CSRF-Token equal to the XSRF-TOKEN
// cookie (constant-time compare). Absence/mismatch returns 403. Before this,
// the frontend's double-submit was theater: the server never set the cookie
// nor validated the header, leaving SameSite=Lax as the only defense.
//
// Spec system-http-server C-14 / AC-19.
func csrfProtect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isSafeMethod(r.Method) ||
			r.Header.Get("Authorization") != "" ||
			strings.HasPrefix(r.URL.Path, "/api/v1/auth/") {
			next.ServeHTTP(w, r)
			return
		}
		if _, err := r.Cookie(identity.SessionCookieName); err != nil {
			next.ServeHTTP(w, r) // no ambient session-cookie authority
			return
		}
		cookie, cerr := r.Cookie(csrfCookieName)
		header := r.Header.Get(csrfHeaderName)
		if cerr != nil || cookie.Value == "" || header == "" ||
			subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(header)) != 1 {
			writeError(w, http.StatusForbidden, "authz.csrf_invalid", "client",
				"missing or invalid CSRF token", false)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isSafeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}
