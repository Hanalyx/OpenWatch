// @spec system-auth-identity
//
// Every logout failure message names a remedy the product has (C-46).

package server

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/identity"
)

const logoutRemedy = "An administrator can end it by resetting your password."

// @ac AC-93
// AC-93: when logout cannot revoke, or cannot confirm that it did, its
// message names the administrator reset, which does end the session, and
// never a Settings sessions feature, which does not exist.
func TestLogout_FailureMessagesNameARealRemedy(t *testing.T) {
	t.Run("system-auth-identity/AC-93", func(t *testing.T) {
		url, pool, srv := freshAPIServerWithMaxConns(t, lockTestPoolSize)

		check := func(t *testing.T, got apiResult, status int, code string) {
			t.Helper()
			if got.status != status || got.code != code {
				t.Errorf("response = %d %q, want %d %q", got.status, got.code, status, code)
			}
			if !strings.Contains(got.message, logoutRemedy) {
				t.Errorf("message %q does not name the administrator reset", got.message)
			}
			if strings.Contains(strings.ToLower(got.message), "settings") {
				t.Errorf("message %q sends the user to Settings, which cannot list or end sessions", got.message)
			}
			if !got.clearsCredential() {
				t.Error("logout did not clear the cookies")
			}
		}

		t.Run("revocation failed and rolled back", func(t *testing.T) {
			li := loginFresh(t, url, pool, "ac93failed")
			restore := failOnWrite(t, pool, "refresh_tokens", "UPDATE")
			got := doAPI(t, logoutRequest(url, li.sessionCookie, li.refreshCookie))
			restore()
			check(t, got, http.StatusInternalServerError, "auth.logout_incomplete")
		})

		t.Run("revocation outcome unknown", func(t *testing.T) {
			li := loginFresh(t, url, pool, "ac93unknown")
			srv.handlers.serializer = &indeterminateBeginner{inner: pool}
			got := doAPI(t, logoutRequest(url, li.sessionCookie, li.refreshCookie))
			srv.handlers.serializer = nil
			check(t, got, http.StatusServiceUnavailable, "server.error")
			if !strings.Contains(got.message, "could not be confirmed") {
				t.Errorf("message %q does not say the revocation could not be confirmed", got.message)
			}
		})

		t.Run("account lock not acquired", func(t *testing.T) {
			defer waitPoolIdle(t, pool)
			li := loginFresh(t, url, pool, "ac93lock")
			release := holdUserLock(t, pool, li.u.ID, identity.LockWaitBound+15*time.Second)
			got := doAPI(t, logoutRequest(url, li.sessionCookie, li.refreshCookie))
			release()
			check(t, got, http.StatusServiceUnavailable, "server.error")
		})
	})
}
