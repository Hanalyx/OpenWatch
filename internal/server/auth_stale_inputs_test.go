// @spec system-auth-identity
//
// Stale authentication inputs (C-39) and the unknown-commit rule (C-40).
//
// Account state was not the only thing a login could read before taking
// the per-user lock and then act on afterwards. The password and MFA
// enrollment were both read early, and both can change in the window.

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/Hanalyx/openwatch/internal/users"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// waitForUserLockWaiter blocks until some other backend is waiting on a
// row lock while running the per-user lock statement. Reading
// pg_stat_activity means the ordering is OBSERVED, not assumed: a sleep
// long enough to be reliable is also long enough to hide the race.
func waitForUserLockWaiter(t *testing.T, pool *pgxpool.Pool) bool {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		var n int
		if err := pool.QueryRow(context.Background(), `
			SELECT count(*) FROM pg_stat_activity
			WHERE wait_event_type = 'Lock'
			  AND query ILIKE '%FOR NO KEY UPDATE%'
			  AND pid <> pg_backend_pid()`).Scan(&n); err != nil {
			t.Fatalf("read pg_stat_activity: %v", err)
		}
		if n > 0 {
			return true
		}
	}
	return false
}

type loginOutcome struct {
	status int
	code   string
}

func loginFor(t *testing.T, url, username, password string, otp *string) loginOutcome {
	t.Helper()
	body := map[string]any{"username": username, "password": password}
	if otp != nil {
		body["otp"] = *otp
	}
	resp := login(t, url, body)
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &env)
	return loginOutcome{status: resp.StatusCode, code: env.Error.Code}
}

func liveCredentials(t *testing.T, pool *pgxpool.Pool, uid uuid.UUID) (sessions, refresh int) {
	t.Helper()
	if err := pool.QueryRow(context.Background(), `
		SELECT (SELECT count(*) FROM sessions WHERE user_id=$1 AND revoked_at IS NULL),
		       (SELECT count(*) FROM refresh_tokens WHERE user_id=$1 AND revoked_at IS NULL)`,
		uid).Scan(&sessions, &refresh); err != nil {
		t.Fatalf("live credentials: %v", err)
	}
	return
}

// @ac AC-46
// AC-46: login refuses when the password changed between verification
// and the per-user lock.
func TestLogin_RefusesAPasswordSupersededDuringTheWindow(t *testing.T) {
	t.Run("system-auth-identity/AC-46", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()
		svc := users.NewService(pool, nil)

		// Control: the identical login succeeds with no reset in flight.
		ctrl := seedAuthUser(t, svc, "ac46control", false)
		_ = svc.AssignRole(ctx, ctrl.ID, "viewer", nil)
		if got := loginFor(t, url, ctrl.Username, ctrl.Password, nil); got.status != http.StatusOK {
			t.Fatalf("control login = %d, want 200", got.status)
		}

		u := seedAuthUser(t, svc, "ac46race", false)
		_ = svc.AssignRole(ctx, u.ID, "viewer", nil)

		// Hold the user row so the login blocks after verifying the
		// password and before revalidating anything.
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		var one int
		if err := tx.QueryRow(ctx,
			`SELECT 1 FROM users WHERE id = $1 FOR NO KEY UPDATE`, u.ID).Scan(&one); err != nil {
			t.Fatalf("hold lock: %v", err)
		}

		done := make(chan loginOutcome, 1)
		go func() { done <- loginFor(t, url, u.Username, u.Password, nil) }()

		if !waitForUserLockWaiter(t, pool) {
			t.Fatal("no backend blocked on the user row; the login never reached the lock")
		}
		// Replace the password from inside the holding transaction, so it
		// becomes visible exactly when the lock is released.
		if _, err := tx.Exec(ctx,
			`UPDATE users SET password_hash = 'superseded-by-reset', last_password_change_at = now() WHERE id = $1`, // pragma: allowlist secret
			u.ID); err != nil {
			t.Fatalf("supersede password: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit reset: %v", err)
		}

		got := <-done
		if got.status == http.StatusOK {
			t.Errorf("login = %d: issued credentials on a password superseded before the lock", got.status)
		}
		if got.code != "auth.invalid_credentials" {
			t.Errorf("code = %q, want auth.invalid_credentials", got.code)
		}
		if s, r := liveCredentials(t, pool, u.ID); s != 0 || r != 0 {
			t.Errorf("the refused login issued credentials: sessions=%d refresh=%d", s, r)
		}
	})
}

// @ac AC-48
// AC-48: login revalidates CONFIRMED MFA enrollment under the lock.
func TestLogin_RefusesWhenEnrollmentConfirmsDuringTheWindow(t *testing.T) {
	t.Run("system-auth-identity/AC-48", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()
		svc := users.NewService(pool, nil)

		// Control: not enrolled, so the login needs no OTP.
		ctrl := seedAuthUser(t, svc, "ac48control", false)
		_ = svc.AssignRole(ctx, ctrl.ID, "viewer", nil)
		if got := loginFor(t, url, ctrl.Username, ctrl.Password, nil); got.status != http.StatusOK {
			t.Fatalf("control login = %d, want 200", got.status)
		}

		u := seedAuthUser(t, svc, "ac48race", false)
		_ = svc.AssignRole(ctx, u.ID, "viewer", nil)
		// A secret exists but is NOT confirmed, so login reads "not
		// enrolled" and asks for no OTP.
		if _, err := identity.EnrollMFA(ctx, pool, u.ID, u.Username); err != nil {
			t.Fatalf("begin enrollment: %v", err)
		}

		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		var one int
		if err := tx.QueryRow(ctx,
			`SELECT 1 FROM users WHERE id = $1 FOR NO KEY UPDATE`, u.ID).Scan(&one); err != nil {
			t.Fatalf("hold lock: %v", err)
		}

		done := make(chan loginOutcome, 1)
		go func() { done <- loginFor(t, url, u.Username, u.Password, nil) }()

		if !waitForUserLockWaiter(t, pool) {
			t.Fatal("no backend blocked on the user row; the login never reached the lock")
		}
		// Confirm enrollment from inside the holding transaction.
		if _, err := tx.Exec(ctx,
			`UPDATE auth_mfa_secrets SET last_verified_at = now() WHERE user_id = $1`, u.ID); err != nil {
			t.Fatalf("confirm enrollment: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit enrollment: %v", err)
		}

		got := <-done
		if got.status == http.StatusOK {
			t.Errorf("login = %d: issued without an OTP for a now-enrolled account", got.status)
		}
		if got.code != "auth.mfa_required" {
			t.Errorf("code = %q, want auth.mfa_required", got.code)
		}
		if s, r := liveCredentials(t, pool, u.ID); s != 0 || r != 0 {
			t.Errorf("the refused login issued credentials: sessions=%d refresh=%d", s, r)
		}
	})
}

// --- AC-50: an unknown commit invites no replay --------------------------

// indeterminateBeginner hands out transactions whose Commit reports an
// error with NO SQLSTATE, which is how a lost acknowledgement looks. When
// commitFirst is true the underlying transaction really commits before
// the lie, which is the durable-commit variant: the write survived and
// the caller cannot know it.
type indeterminateBeginner struct {
	inner       identity.TxBeginner
	commitFirst bool
}

type indeterminateTx struct {
	pgx.Tx
	commitFirst bool
}

func (b *indeterminateBeginner) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := b.inner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &indeterminateTx{Tx: tx, commitFirst: b.commitFirst}, nil
}

func (tx *indeterminateTx) Commit(ctx context.Context) error {
	if tx.commitFirst {
		if err := tx.Tx.Commit(ctx); err != nil {
			return err
		}
	}
	// No *pgconn.PgError: the server never answered, so nothing on this
	// side knows whether the commit applied.
	return fmt.Errorf("write tcp 127.0.0.1:5432: %w", errors.New("connection reset by peer"))
}

// @ac AC-50
// AC-50: an unknown commit outcome is reported NOT retryable, says
// nothing about retrying, and reads identically whether or not the write
// was durable.
func TestUnknownCommit_IsNotRetryableAndInvitesNoReplay(t *testing.T) {
	t.Run("system-auth-identity/AC-50", func(t *testing.T) {
		for _, tc := range []struct {
			name        string
			commitFirst bool
			user        string
		}{
			{"durable commit, lost acknowledgement", true, "ac50durable"},
			{"non-durable", false, "ac50lost"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				url, pool, srv := freshAPIServerWithHandles(t)
				li := loginFresh(t, url, pool, tc.user)

				// Only the refresh below runs with an indeterminate commit.
				srv.handlers.serializer = &indeterminateBeginner{inner: pool, commitFirst: tc.commitFirst}

				req := postJSONReq(t, url+"/api/v1/auth/refresh",
					map[string]string{"refresh_token": li.bodyRefresh})
				resp := doReq(t, req)
				raw, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				if resp.StatusCode != http.StatusServiceUnavailable {
					t.Errorf("status = %d, want 503", resp.StatusCode)
				}
				var env struct {
					Error struct {
						Code      string `json:"code"`
						Retryable bool   `json:"retryable"`
						Human     string `json:"human_message"`
					} `json:"error"`
				}
				if err := json.Unmarshal(raw, &env); err != nil {
					t.Fatalf("decode envelope: %v (%s)", err, raw)
				}
				if env.Error.Code != "server.error" {
					t.Errorf("code = %q, want server.error", env.Error.Code)
				}
				if env.Error.Retryable {
					t.Error("retryable = true on an unknown commit outcome: a replayed refresh is indistinguishable from theft and revokes the family")
				}
				if containsFold(env.Error.Human, "retry") {
					t.Errorf("human_message invites a retry: %q", env.Error.Human)
				}
				// The error response itself must not have revoked the
				// family. Only a SECOND presentation does that, and the
				// server made none.
				var reuse int
				if err := pool.QueryRow(context.Background(),
					`SELECT count(*) FROM refresh_tokens WHERE user_id=$1 AND reuse_detected_at IS NOT NULL`,
					li.u.ID).Scan(&reuse); err != nil {
					t.Fatalf("count reuse rows: %v", err)
				}
				if reuse != 0 {
					t.Errorf("reuse_detected rows = %d: the error path replayed the token", reuse)
				}
			})
		}
	})
}

func containsFold(haystack, needle string) bool {
	h, n := []byte(haystack), []byte(needle)
	lower := func(b byte) byte {
		if b >= 'A' && b <= 'Z' {
			return b + 32
		}
		return b
	}
	if len(n) == 0 || len(n) > len(h) {
		return false
	}
	for i := 0; i+len(n) <= len(h); i++ {
		ok := true
		for j := range n {
			if lower(h[i+j]) != lower(n[j]) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// postJSONReq builds a JSON POST request. Separate from doReq so a test
// can inspect the response envelope rather than only its status.
func postJSONReq(t *testing.T, url string, body any) *http.Request {
	t.Helper()
	bs, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequest("POST", url, bytesReader(bs))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return req
}

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }
