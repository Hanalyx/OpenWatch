// @spec system-auth-identity
//
// Regressions promoted from the first integrated closure run for
// bugs/OW-069 and bugs/doing/OW-073 (bugs/doing/OW-062 section 14.8).
//
// Attribution. A before-and-after count cannot say who wrote a row. These
// tests snapshot the user's credential row IDs before the coordinating
// mutation, again right after it, and once more after the attempt. The
// coordinator's own changes are asserted separately, and any ID that
// appears after the coordinator ran belongs to the attempt.

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/Hanalyx/openwatch/internal/users"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	pgerr "github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// hookedBeginner runs a hook before each transaction begins and, when set,
// replaces Commit. attempt counts from 1 across RunSerialized's retries.
type hookedBeginner struct {
	inner       identity.TxBeginner
	mu          sync.Mutex
	n           int
	beforeBegin func(attempt int)
	atCommit    func(attempt int, tx pgx.Tx) error
}

type hookedTx struct {
	pgx.Tx
	commit func(pgx.Tx) error
}

func (h *hookedTx) Commit(context.Context) error { return h.commit(h.Tx) }

func (b *hookedBeginner) Begin(ctx context.Context) (pgx.Tx, error) {
	b.mu.Lock()
	b.n++
	attempt := b.n
	b.mu.Unlock()
	if b.beforeBegin != nil {
		b.beforeBegin(attempt)
	}
	tx, err := b.inner.Begin(ctx)
	if err != nil || b.atCommit == nil {
		return tx, err
	}
	return &hookedTx{Tx: tx, commit: func(inner pgx.Tx) error { return b.atCommit(attempt, inner) }}, nil
}

func (b *hookedBeginner) attempts() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.n
}

// credentialRows maps each of a user's session and refresh rows, by ID,
// to whether it is revoked.
type credentialRows struct {
	sessions map[uuid.UUID]bool
	refresh  map[uuid.UUID]bool
}

func snapshotCredentials(t *testing.T, pool *pgxpool.Pool, uid uuid.UUID) credentialRows {
	t.Helper()
	read := func(table string) map[uuid.UUID]bool {
		rows, err := pool.Query(context.Background(),
			`SELECT id, revoked_at IS NOT NULL FROM `+table+` WHERE user_id = $1`, uid)
		if err != nil {
			t.Fatalf("snapshot %s: %v", table, err)
		}
		defer rows.Close()
		out := map[uuid.UUID]bool{}
		for rows.Next() {
			var id uuid.UUID
			var revoked bool
			if err := rows.Scan(&id, &revoked); err != nil {
				t.Fatalf("scan %s: %v", table, err)
			}
			out[id] = revoked
		}
		return out
	}
	return credentialRows{sessions: read("sessions"), refresh: read("refresh_tokens")}
}

// added returns the IDs present in c and absent from earlier.
func (c credentialRows) added(earlier credentialRows) (sessions, refresh []uuid.UUID) {
	for id := range c.sessions {
		if _, ok := earlier.sessions[id]; !ok {
			sessions = append(sessions, id)
		}
	}
	for id := range c.refresh {
		if _, ok := earlier.refresh[id]; !ok {
			refresh = append(refresh, id)
		}
	}
	return sessions, refresh
}

func (c credentialRows) live() (sessions, refresh int) {
	for _, revoked := range c.sessions {
		if !revoked {
			sessions++
		}
	}
	for _, revoked := range c.refresh {
		if !revoked {
			refresh++
		}
	}
	return sessions, refresh
}

func (c credentialRows) equal(o credentialRows) bool {
	same := func(a, b map[uuid.UUID]bool) bool {
		if len(a) != len(b) {
			return false
		}
		for k, v := range a {
			if w, ok := b[k]; !ok || w != v {
				return false
			}
		}
		return true
	}
	return same(c.sessions, o.sessions) && same(c.refresh, o.refresh)
}

// apiResult is a response read in full: status, the error envelope's
// code and retryable flag, the JSON body, and every Set-Cookie.
type apiResult struct {
	status    int
	code      string
	retryable bool
	body      map[string]any
	cookies   []*http.Cookie
}

func doAPI(t *testing.T, req *http.Request) apiResult {
	t.Helper()
	resp := doReq(t, req)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	res := apiResult{status: resp.StatusCode, body: body, cookies: resp.Cookies()}
	if e, ok := body["error"].(map[string]any); ok {
		res.code, _ = e["code"].(string)
		res.retryable, _ = e["retryable"].(bool)
	}
	return res
}

// setsCredential reports a non-empty session or refresh cookie.
func (r apiResult) setsCredential() bool {
	for _, c := range r.cookies {
		if (c.Name == identity.SessionCookieName || c.Name == identity.RefreshCookieName) && c.Value != "" {
			return true
		}
	}
	return false
}

// clearsCredential reports a session or refresh cookie being cleared.
func (r apiResult) clearsCredential() bool {
	for _, c := range r.cookies {
		if (c.Name == identity.SessionCookieName || c.Name == identity.RefreshCookieName) && c.Value == "" {
			return true
		}
	}
	return false
}

// carriesToken reports an access or refresh token in the response body.
func (r apiResult) carriesToken() bool {
	for _, k := range []string{"access_token", "refresh_token"} {
		if v, _ := r.body[k].(string); v != "" {
			return true
		}
	}
	return false
}

func loginRequest(url, username, password string, otp *string) *http.Request {
	m := map[string]string{"username": username, "password": password}
	if otp != nil {
		m["otp"] = *otp
	}
	bs, _ := json.Marshal(m)
	req, _ := http.NewRequest("POST", url+"/api/v1/auth/login", bytes.NewReader(bs))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func bodyRefreshRequest(url, token string) *http.Request {
	bs, _ := json.Marshal(map[string]string{"refresh_token": token})
	req, _ := http.NewRequest("POST", url+"/api/v1/auth/refresh", bytes.NewReader(bs))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func cookieRefreshRequest(url string, rc *http.Cookie) *http.Request {
	req, _ := http.NewRequest("POST", url+"/api/v1/auth/refresh-cookie", nil)
	req.AddCookie(rc)
	req.AddCookie(&http.Cookie{Name: "XSRF-TOKEN", Value: "closure-csrf"})
	req.Header.Set("X-CSRF-Token", "closure-csrf")
	return req
}

func logoutRequest(url string, session, refresh *http.Cookie) *http.Request {
	req, _ := http.NewRequest("POST", url+"/api/v1/auth/logout", nil)
	req.AddCookie(session)
	req.AddCookie(refresh)
	req.AddCookie(&http.Cookie{Name: "XSRF-TOKEN", Value: "closure-csrf"})
	req.Header.Set("X-CSRF-Token", "closure-csrf")
	return req
}

// holdUserLock takes the per-user lock on a second connection. The
// returned release is idempotent, and a safety timer releases the lock
// after max so a missing bound fails the test instead of hanging it.
func holdUserLock(t *testing.T, pool *pgxpool.Pool, uid uuid.UUID, max time.Duration) (release func()) {
	t.Helper()
	ctx := context.Background()
	holder, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin holder: %v", err)
	}
	if err := identity.LockUser(ctx, holder, uid); err != nil {
		t.Fatalf("hold the lock: %v", err)
	}
	var once sync.Once
	release = func() { once.Do(func() { _ = holder.Rollback(ctx) }) }
	timer := time.AfterFunc(max, release)
	t.Cleanup(func() { timer.Stop(); release() })
	return release
}

// @ac AC-73
// AC-73: the per-user lock wait is bounded in the production
// configuration. A request that cannot take the lock answers a retryable
// 503 once the bound expires and decides nothing.
func TestLockWait_BoundedInProductionConfiguration(t *testing.T) {
	t.Run("system-auth-identity/AC-73", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		for _, path := range []string{"login", "body refresh", "cookie refresh", "logout", "admin disable"} {
			path := path
			t.Run(path, func(t *testing.T) {
				t.Parallel()
				li := loginFresh(t, url, pool, "ac73"+strings.ReplaceAll(path, " ", ""))
				var req *http.Request
				switch path {
				case "login":
					req = loginRequest(url, li.u.Username, li.u.Password, nil)
				case "body refresh":
					req = bodyRefreshRequest(url, li.bodyRefresh)
				case "cookie refresh":
					req = cookieRefreshRequest(url, li.refreshCookie)
				case "logout":
					req = logoutRequest(url, li.sessionCookie, li.refreshCookie)
				case "admin disable":
					req = asRole(t, "POST", url+"/api/v1/users/"+li.u.ID.String()+":disable", auth.RoleAdmin, nil)
				}
				before := snapshotCredentials(t, pool, li.u.ID)
				release := holdUserLock(t, pool, li.u.ID, identity.LockWaitBound+15*time.Second)
				start := time.Now()
				got := doAPI(t, req)
				elapsed := time.Since(start)
				release()

				if got.status != http.StatusServiceUnavailable || got.code != "server.error" || !got.retryable {
					t.Errorf("response = %d %q retryable=%v, want 503 server.error retryable", got.status, got.code, got.retryable)
				}
				if elapsed < identity.LockWaitBound-250*time.Millisecond || elapsed > identity.LockWaitBound+10*time.Second {
					t.Errorf("answered after %v; the bound is %v", elapsed, identity.LockWaitBound)
				}
				if after := snapshotCredentials(t, pool, li.u.ID); !after.equal(before) {
					t.Error("credential rows changed although the lock was never acquired")
				}
				if got.setsCredential() || got.carriesToken() {
					t.Error("the response issued a credential")
				}
				// Logout clears the cookies on every outcome (C-43); no
				// other path may.
				if cleared := got.clearsCredential(); cleared != (path == "logout") {
					t.Errorf("credential cookies cleared = %v", cleared)
				}
				if path == "admin disable" && isDisabled(t, pool, li.u.ID) {
					t.Error("the account was disabled although the change reported not applied")
				}
				if code := authMe(t, url, li.sessionCookie); code != http.StatusOK {
					t.Errorf("the presented session no longer works: %d", code)
				}
			})
		}
	})
}

// @ac AC-74
// AC-74: a refresh racing Disable leaves nothing usable once Disable
// returns, in both orders and on both refresh paths.
func TestRefreshRacingDisable_LeavesNothingUsable(t *testing.T) {
	t.Run("system-auth-identity/AC-74", func(t *testing.T) {
		url, pool, srv := freshAPIServerWithHandles(t)
		ctx := context.Background()
		svc := users.NewService(pool, nil)
		for _, path := range []string{"body", "cookie"} {
			path := path
			request := func(li loggedInUser) *http.Request {
				if path == "body" {
					return bodyRefreshRequest(url, li.bodyRefresh)
				}
				return cookieRefreshRequest(url, li.refreshCookie)
			}

			t.Run(path+": disable commits before the refresh takes the lock", func(t *testing.T) {
				li := loginFresh(t, url, pool, "ac74first"+path)
				var afterCoordinator credentialRows
				hb := &hookedBeginner{inner: pool, beforeBegin: func(attempt int) {
					if attempt == 1 {
						if err := svc.Disable(ctx, li.u.ID); err != nil {
							t.Errorf("disable: %v", err)
						}
						afterCoordinator = snapshotCredentials(t, pool, li.u.ID)
					}
				}}
				srv.handlers.serializer = hb
				got := doAPI(t, request(li))
				srv.handlers.serializer = nil

				if got.status == http.StatusOK || got.setsCredential() || got.carriesToken() {
					t.Errorf("refresh after a committed disable answered %d and issued a credential", got.status)
				}
				if s, r := snapshotCredentials(t, pool, li.u.ID).added(afterCoordinator); len(s)+len(r) != 0 {
					t.Errorf("the refresh wrote %d sessions and %d refresh rows after the disable", len(s), len(r))
				}
				if s, r := snapshotCredentials(t, pool, li.u.ID).live(); s+r != 0 {
					t.Errorf("live credentials after disable: %d/%d", s, r)
				}
			})

			t.Run(path+": refresh holds the lock while disable waits", func(t *testing.T) {
				li := loginFresh(t, url, pool, "ac74second"+path)
				before := snapshotCredentials(t, pool, li.u.ID)
				disabled := make(chan error, 1)
				hb := &hookedBeginner{inner: pool, atCommit: func(attempt int, inner pgx.Tx) error {
					go func() { disabled <- svc.Disable(ctx, li.u.ID) }()
					if !waitForUserLockWaiter(t, pool) {
						t.Error("disable never queued behind the refresh")
					}
					return inner.Commit(ctx)
				}}
				srv.handlers.serializer = hb
				got := doAPI(t, request(li))
				srv.handlers.serializer = nil
				if err := <-disabled; err != nil {
					t.Fatalf("disable: %v", err)
				}
				if got.status != http.StatusOK {
					t.Fatalf("precondition: the refresh holding the lock should commit, got %d", got.status)
				}
				after := snapshotCredentials(t, pool, li.u.ID)
				// Attributed: the rows the refresh wrote, by ID.
				s, r := after.added(before)
				if len(s)+len(r) == 0 {
					t.Fatal("precondition: the committed refresh wrote no successor")
				}
				for _, id := range s {
					if !after.sessions[id] {
						t.Errorf("the refresh's session %s is live after disable returned", id)
					}
				}
				for _, id := range r {
					if !after.refresh[id] {
						t.Errorf("the refresh's successor token %s is live after disable returned", id)
					}
				}
				if access, _ := got.body["access_token"].(string); access != "" && authMeBearer(t, url, access) != http.StatusUnauthorized {
					t.Error("the successor access token authenticates after disable returned")
				}
				if authMeBearer(t, url, li.accessToken) != http.StatusUnauthorized {
					t.Error("the predecessor access token authenticates after disable returned")
				}
			})
		}
	})
}

// @ac AC-75
// AC-75: credentials revoked by Disable stay dead after Enable, and only a
// fresh sign-in works.
func TestEnable_DoesNotReviveWhatDisableRevoked(t *testing.T) {
	t.Run("system-auth-identity/AC-75", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()
		svc := users.NewService(pool, nil)
		li := loginFresh(t, url, pool, "ac75revived")
		if err := svc.Disable(ctx, li.u.ID); err != nil {
			t.Fatalf("disable: %v", err)
		}
		if err := svc.Enable(ctx, li.u.ID); err != nil {
			t.Fatalf("enable: %v", err)
		}
		if code := authMe(t, url, li.sessionCookie); code != http.StatusUnauthorized {
			t.Errorf("session cookie after disable and enable = %d, want 401", code)
		}
		if code := authMeBearer(t, url, li.accessToken); code != http.StatusUnauthorized {
			t.Errorf("access token after disable and enable = %d, want 401", code)
		}
		if code, _ := refreshBody(t, url, li.bodyRefresh); code == http.StatusOK {
			t.Error("body refresh token rotated after disable and enable")
		}
		if code, sess := refreshCookie(t, url, li.refreshCookie); code == http.StatusOK || sess != nil {
			t.Error("refresh cookie minted a session after disable and enable")
		}
		if !freshLoginWorks(t, url, li.u) {
			t.Error("a fresh sign-in after enable did not work")
		}
	})
}

// waitForLockWaiters waits until n requests are queued on a row lock.
func waitForLockWaiters(t *testing.T, pool *pgxpool.Pool, n int) bool {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		var c int
		if err := pool.QueryRow(context.Background(), `
			SELECT count(*) FROM pg_stat_activity
			WHERE wait_event_type = 'Lock' AND query ILIKE '%FOR NO KEY UPDATE%'
			  AND pid <> pg_backend_pid()`).Scan(&c); err == nil && c >= n {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// @ac AC-76
// AC-76: MFA is decided under the lock. Two logins presenting one code
// issue once; a secret rotated before the lock refuses the old code; an
// enrollment removed before the lock lets the login issue without
// consuming anything (C-39).
func TestMFA_DecidedUnderTheLock(t *testing.T) {
	t.Run("system-auth-identity/AC-76", func(t *testing.T) {
		url, pool, srv := freshAPIServerWithHandles(t)
		ctx := context.Background()

		t.Run("same code, two logins serialized", func(t *testing.T) {
			f := enrolledUser(t, url, pool, "ac76twice")
			code := f.otp(t)
			before := snapshotCredentials(t, pool, f.li.u.ID)
			otpBefore := otpUseCount(t, pool, f.li.u.ID)
			release := holdUserLock(t, pool, f.li.u.ID, 30*time.Second)
			results := make(chan loginOutcome, 2)
			for i := 0; i < 2; i++ {
				go func() { results <- loginFor(t, url, f.li.u.Username, f.li.u.Password, &code) }()
			}
			if !waitForLockWaiters(t, pool, 2) {
				t.Fatal("both logins did not queue on the lock")
			}
			release()
			a, b := <-results, <-results
			ok := 0
			for _, r := range []loginOutcome{a, b} {
				if r.status == http.StatusOK {
					ok++
				} else if r.code != "auth.mfa_invalid" {
					t.Errorf("refused login answered %q, want auth.mfa_invalid", r.code)
				}
			}
			if ok != 1 {
				t.Errorf("successful logins = %d, want 1", ok)
			}
			s, r := snapshotCredentials(t, pool, f.li.u.ID).added(before)
			if len(s) != 1 || len(r) != 1 {
				t.Errorf("rows written = %d sessions, %d refresh; want 1 and 1", len(s), len(r))
			}
			if got := otpUseCount(t, pool, f.li.u.ID) - otpBefore; got != 1 {
				t.Errorf("otp uses recorded = %d, want 1", got)
			}
		})

		t.Run("secret rotated before the lock", func(t *testing.T) {
			f := enrolledUser(t, url, pool, "ac76rotated")
			code := f.otp(t)
			before := snapshotCredentials(t, pool, f.li.u.ID)
			otpBefore := otpUseCount(t, pool, f.li.u.ID)
			srv.handlers.serializer = &hookedBeginner{inner: pool, beforeBegin: func(attempt int) {
				if attempt != 1 {
					return
				}
				if _, err := identity.EnrollMFA(ctx, pool, f.li.u.ID, f.li.u.Username); err != nil {
					t.Errorf("rotate: %v", err)
				}
				if _, err := pool.Exec(ctx, `UPDATE auth_mfa_secrets SET last_verified_at = now() WHERE user_id = $1`, f.li.u.ID); err != nil {
					t.Errorf("confirm rotation: %v", err)
				}
			}}
			got := loginFor(t, url, f.li.u.Username, f.li.u.Password, &code)
			srv.handlers.serializer = nil
			if got.status == http.StatusOK || got.code != "auth.mfa_invalid" {
				t.Errorf("old-secret code after rotation = %d %q, want 401 auth.mfa_invalid", got.status, got.code)
			}
			if s, r := snapshotCredentials(t, pool, f.li.u.ID).added(before); len(s)+len(r) != 0 {
				t.Errorf("rows written = %d sessions, %d refresh; want none", len(s), len(r))
			}
			if got := otpUseCount(t, pool, f.li.u.ID) - otpBefore; got != 0 {
				t.Errorf("otp uses recorded = %d, want 0", got)
			}
		})

		t.Run("enrollment removed before the lock", func(t *testing.T) {
			f := enrolledUser(t, url, pool, "ac76removed")
			code := f.otp(t)
			before := snapshotCredentials(t, pool, f.li.u.ID)
			otpBefore := otpUseCount(t, pool, f.li.u.ID)
			srv.handlers.serializer = &hookedBeginner{inner: pool, beforeBegin: func(attempt int) {
				if attempt == 1 {
					if _, err := pool.Exec(ctx, `DELETE FROM auth_mfa_secrets WHERE user_id = $1`, f.li.u.ID); err != nil {
						t.Errorf("remove enrollment: %v", err)
					}
				}
			}}
			got := loginFor(t, url, f.li.u.Username, f.li.u.Password, &code)
			srv.handlers.serializer = nil
			if got.status != http.StatusOK {
				t.Errorf("login after the enrollment was removed = %d %q, want 200 (C-39)", got.status, got.code)
			}
			if s, r := snapshotCredentials(t, pool, f.li.u.ID).added(before); len(s) != 1 || len(r) != 1 {
				t.Errorf("rows written = %d sessions, %d refresh; want 1 and 1", len(s), len(r))
			}
			if got := otpUseCount(t, pool, f.li.u.ID) - otpBefore; got != 0 {
				t.Errorf("otp uses recorded = %d, want 0: no secret, nothing to consume", got)
			}
		})
	})
}

// @ac AC-77
// AC-77: a retried transaction acts on the state it reads on the retry,
// not on what the lost attempt read.
func TestSerializedRetry_ActsOnTheNewState(t *testing.T) {
	t.Run("system-auth-identity/AC-77", func(t *testing.T) {
		url, pool, srv := freshAPIServerWithHandles(t)
		ctx := context.Background()
		svc := users.NewService(pool, nil)
		for _, state := range []string{"40P01", "40001"} {
			state := state
			t.Run(state, func(t *testing.T) {
				u := seedAuthUser(t, svc, "ac77"+strings.ToLower(state), false)
				_ = svc.AssignRole(ctx, u.ID, "viewer", nil)
				before := snapshotCredentials(t, pool, u.ID)
				hb := &hookedBeginner{inner: pool, atCommit: func(attempt int, inner pgx.Tx) error {
					if attempt == 1 {
						_ = inner.Rollback(ctx)
						if err := svc.Disable(ctx, u.ID); err != nil {
							t.Errorf("disable between attempts: %v", err)
						}
						return &pgerr.PgError{Code: state}
					}
					return inner.Commit(ctx)
				}}
				srv.handlers.serializer = hb
				got := doAPI(t, loginRequest(url, u.Username, u.Password, nil))
				srv.handlers.serializer = nil
				if hb.attempts() != 2 {
					t.Errorf("transactions begun = %d, want 2", hb.attempts())
				}
				if got.status != http.StatusUnauthorized || got.setsCredential() || got.carriesToken() {
					t.Errorf("login retried after the account was disabled = %d, want 401 with nothing issued", got.status)
				}
				if s, r := snapshotCredentials(t, pool, u.ID).added(before); len(s)+len(r) != 0 {
					t.Errorf("rows written = %d sessions, %d refresh; want none", len(s), len(r))
				}
			})
		}
	})
}

// @ac AC-78
// AC-78: every password and refresh issuance path, paused after its
// pre-lock reads and released after an invalidating mutation commits,
// issues nothing.
func TestProtocolOrder_NothingIssuedFromInvalidatedState(t *testing.T) {
	t.Run("system-auth-identity/AC-78", func(t *testing.T) {
		url, pool, srv := freshAPIServerWithHandles(t)
		ctx := context.Background()
		svc := users.NewService(pool, nil)
		coordinators := map[string]func(uuid.UUID) error{
			"disable":        func(id uuid.UUID) error { return svc.Disable(ctx, id) },
			"password reset": func(id uuid.UUID) error { return svc.AdminResetPassword(ctx, id, "ac78-reset-Passphrase-4410") }, // pragma: allowlist secret
		}
		for _, path := range []string{"login", "login with mfa", "body refresh", "cookie refresh"} {
			for _, coordinator := range []string{"disable", "password reset"} {
				path, coordinator := path, coordinator
				t.Run(path+" against "+coordinator, func(t *testing.T) {
					name := "ac78" + strings.NewReplacer(" ", "").Replace(path+coordinator)
					var li loggedInUser
					var otp *string
					if path == "login with mfa" {
						f := enrolledUser(t, url, pool, name)
						li = f.li
						c := f.otp(t)
						otp = &c
					} else {
						li = loginFresh(t, url, pool, name)
					}
					var req *http.Request
					switch path {
					case "login", "login with mfa":
						req = loginRequest(url, li.u.Username, li.u.Password, otp)
					case "body refresh":
						req = bodyRefreshRequest(url, li.bodyRefresh)
					case "cookie refresh":
						req = cookieRefreshRequest(url, li.refreshCookie)
					}
					before := snapshotCredentials(t, pool, li.u.ID)
					otpBefore := otpUseCount(t, pool, li.u.ID)
					var afterCoordinator credentialRows
					var coordErr error
					srv.handlers.serializer = &hookedBeginner{inner: pool, beforeBegin: func(attempt int) {
						if attempt == 1 {
							coordErr = coordinators[coordinator](li.u.ID)
							afterCoordinator = snapshotCredentials(t, pool, li.u.ID)
						}
					}}
					got := doAPI(t, req)
					srv.handlers.serializer = nil
					if coordErr != nil {
						t.Fatalf("%s: %v", coordinator, coordErr)
					}
					// The coordinator's changes, enumerated: it inserts nothing
					// and revokes every row that was live.
					if s, r := afterCoordinator.added(before); len(s)+len(r) != 0 {
						t.Errorf("%s inserted %d sessions and %d refresh rows", coordinator, len(s), len(r))
					}
					if s, r := afterCoordinator.live(); s+r != 0 {
						t.Errorf("%s left %d/%d live", coordinator, s, r)
					}
					// The attempt's own rows: anything after the coordinator.
					if s, r := snapshotCredentials(t, pool, li.u.ID).added(afterCoordinator); len(s)+len(r) != 0 {
						t.Errorf("the %s wrote %d sessions and %d refresh rows", path, len(s), len(r))
					}
					if got.status == http.StatusOK || got.setsCredential() || got.carriesToken() {
						t.Errorf("the %s answered %d and issued a credential", path, got.status)
					}
					if n := otpUseCount(t, pool, li.u.ID) - otpBefore; n != 0 {
						t.Errorf("the attempt consumed %d one-time codes", n)
					}
				})
			}
		}
	})
}

// @ac AC-79
// AC-79: a rotation whose commit fails reports no credential, sets no
// cookie, and leaves the presented token usable.
func TestRefresh_NothingReportedBeforeCommit(t *testing.T) {
	t.Run("system-auth-identity/AC-79", func(t *testing.T) {
		url, pool, srv := freshAPIServerWithHandles(t)
		ctx := context.Background()
		for _, path := range []string{"body", "cookie"} {
			path := path
			t.Run(path, func(t *testing.T) {
				li := loginFresh(t, url, pool, "ac79"+path)
				req := func() *http.Request {
					if path == "body" {
						return bodyRefreshRequest(url, li.bodyRefresh)
					}
					return cookieRefreshRequest(url, li.refreshCookie)
				}
				before := snapshotCredentials(t, pool, li.u.ID)
				srv.handlers.serializer = &hookedBeginner{inner: pool, atCommit: func(_ int, inner pgx.Tx) error {
					_ = inner.Rollback(ctx)
					return &pgerr.PgError{Code: "23505"} // a known rollback
				}}
				got := doAPI(t, req())
				srv.handlers.serializer = nil
				if got.status != http.StatusServiceUnavailable || got.code != "server.error" {
					t.Errorf("response = %d %q, want 503 server.error", got.status, got.code)
				}
				if got.carriesToken() || got.setsCredential() {
					t.Error("a credential was reported although its transaction did not commit")
				}
				if !snapshotCredentials(t, pool, li.u.ID).equal(before) {
					t.Error("credential rows changed although the transaction rolled back")
				}
				if again := doAPI(t, req()); again.status != http.StatusOK {
					t.Errorf("the presented token no longer rotates after the rollback: %d", again.status)
				}
			})
		}
	})
}

// @ac AC-34
// AC-34, end to end: a live, unrevoked session cookie is refused by the
// account-state check, each state recording its own reason on the
// request's own audit row.
func TestCookieBinder_AccountStateEndToEnd(t *testing.T) {
	t.Run("system-auth-identity/AC-34", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()
		for _, tc := range []struct {
			name, stmt, reason string
			status             int
		}{
			{"disabled", `UPDATE users SET disabled_at = now() WHERE id = $1`, "account_disabled", 401},
			{"soft deleted", `UPDATE users SET deleted_at = now() WHERE id = $1`, "account_deleted", 401},
			{"active without roles", `DELETE FROM user_roles WHERE user_id = $1`, "session_user_lookup_failed", 401},
			{"active control", ``, "", 200},
		} {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				li := loginFresh(t, url, pool, "ac34e2e"+strings.ReplaceAll(tc.name, " ", ""))
				if tc.stmt != "" {
					if _, err := pool.Exec(ctx, tc.stmt, li.u.ID); err != nil {
						t.Fatalf("set account state: %v", err)
					}
				}
				code, cid := authMeCookieCorrelated(t, url, li.sessionCookie)
				if code != tc.status {
					t.Errorf("status = %d, want %d", code, tc.status)
				}
				if tc.reason != "" {
					if got := loginFailureReasonFor(t, pool, cid); got != tc.reason {
						t.Errorf("audit reason = %q, want %q", got, tc.reason)
					}
				}
			})
		}
	})
}

// @ac AC-36
// AC-36, Bearer arm: when the binding lookup itself fails, the answer is
// 503, not 401, and the token works again once the lookup recovers.
func TestBearer_LookupFailureIs503(t *testing.T) {
	t.Run("system-auth-identity/AC-36", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()
		li := loginFresh(t, url, pool, "ac36bearer")
		if code := authMeBearer(t, url, li.accessToken); code != http.StatusOK {
			t.Fatalf("precondition: token = %d, want 200", code)
		}
		if _, err := pool.Exec(ctx, `ALTER TABLE sessions RENAME TO sessions_ac36`); err != nil {
			t.Fatalf("break the binding lookup: %v", err)
		}
		restored := false
		restore := func() {
			if !restored {
				if _, err := pool.Exec(ctx, `ALTER TABLE sessions_ac36 RENAME TO sessions`); err != nil {
					t.Fatalf("restore sessions: %v", err)
				}
				restored = true
			}
		}
		t.Cleanup(restore)
		code, cid := authMeBearerCorrelated(t, url, li.accessToken)
		restore()
		if code != http.StatusServiceUnavailable {
			t.Errorf("Bearer request with the lookup failing = %d, want 503", code)
		}
		if got := loginFailureReasonFor(t, pool, cid); got != "session_lookup_failed" {
			t.Errorf("audit reason = %q, want session_lookup_failed", got)
		}
		if code := authMeBearer(t, url, li.accessToken); code != http.StatusOK {
			t.Errorf("token after the lookup recovered = %d, want 200", code)
		}
	})
}
