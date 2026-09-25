// @spec system-auth-identity
//
// The cookie binder's role lookup (C-45, AC-92): a confirmed "no roles"
// refuses the credential, and a lookup that fails is an infrastructure
// failure.

package server

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// @ac AC-92
// AC-92: a role lookup that fails answers 503, runs no handler and changes
// no cookie; a confirmed "no roles" still answers 401.
func TestCookieBinder_RoleLookupFailureIs503(t *testing.T) {
	t.Run("system-auth-identity/AC-92", func(t *testing.T) {
		url, pool, _ := freshAPIServerWithMaxConns(t, lockTestPoolSize)
		ctx := context.Background()

		t.Run("lookup fails", func(t *testing.T) {
			li := loginFresh(t, url, pool, "ac92failing")
			holder, err := pool.Begin(ctx)
			if err != nil {
				t.Fatalf("begin holder: %v", err)
			}
			defer func() { _ = holder.Rollback(ctx) }()
			// Blocks every read of user_roles, so the binder's role query
			// waits; the test then cancels that query, a real database
			// failure on the lookup.
			if _, err := holder.Exec(ctx, `LOCK TABLE user_roles IN ACCESS EXCLUSIVE MODE`); err != nil {
				t.Fatalf("lock user_roles: %v", err)
			}
			type out struct {
				got apiResult
				cid string
			}
			done := make(chan out, 1)
			go func() {
				got, cid := cookieMe(t, url, li.sessionCookie, false)
				done <- out{got, cid}
			}()
			var pid int32
			deadline := time.Now().Add(10 * time.Second)
			for pid == 0 && time.Now().Before(deadline) {
				_ = pool.QueryRow(ctx, `
					SELECT pid FROM pg_stat_activity
					WHERE wait_event_type = 'Lock' AND query ILIKE '%FROM user_roles%'
					  AND pid <> pg_backend_pid() LIMIT 1`).Scan(&pid)
				if pid == 0 {
					time.Sleep(20 * time.Millisecond)
				}
			}
			if pid == 0 {
				t.Fatal("the role query never waited on user_roles")
			}
			if _, err := pool.Exec(ctx, `SELECT pg_cancel_backend($1)`, pid); err != nil {
				t.Fatalf("cancel the role query: %v", err)
			}
			o := <-done
			_ = holder.Rollback(ctx)

			if o.got.status != http.StatusServiceUnavailable || o.got.code != "server.error" {
				t.Errorf("response = %d %q, want 503 server.error", o.got.status, o.got.code)
			}
			if o.got.handlerRan() {
				t.Error("the protected handler ran")
			}
			if o.got.clearsCredential() || o.got.setsCredential() {
				t.Error("the response changed a credential cookie")
			}
			if reason := loginFailureReasonFor(t, pool, o.cid); reason != "role_lookup_unavailable" {
				t.Errorf("audit reason = %q, want role_lookup_unavailable", reason)
			}
			if code := authMe(t, url, li.sessionCookie); code != http.StatusOK {
				t.Errorf("the session no longer works after the lookup recovered: %d", code)
			}
		})

		t.Run("confirmed no roles", func(t *testing.T) {
			li := loginFresh(t, url, pool, "ac92noroles")
			if _, err := pool.Exec(ctx, `DELETE FROM user_roles WHERE user_id = $1`, li.u.ID); err != nil {
				t.Fatalf("remove roles: %v", err)
			}
			got, cid := cookieMe(t, url, li.sessionCookie, false)
			if got.status != http.StatusUnauthorized || got.handlerRan() {
				t.Errorf("response = %d, want 401 without the handler running", got.status)
			}
			if reason := loginFailureReasonFor(t, pool, cid); reason != "session_user_lookup_failed" {
				t.Errorf("audit reason = %q, want session_user_lookup_failed", reason)
			}
		})
	})
}
