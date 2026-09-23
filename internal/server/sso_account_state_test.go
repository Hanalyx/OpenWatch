// @spec system-sso
//
// bugs/OW-073: SSO sign-in bypassed disable and soft delete. The shape
// here is the authorized reproduction, kept as regression evidence: the
// same sequence that demonstrated the defect now asserts the fixed
// outcome.
//
// What is real and what is substituted: the HTTP login and callback
// routes, the whole HandleCallback chain (state, discovery, token
// exchange, ID-token validation, identity resolution), issuance, the
// cookie binder, and the real users service all run. Only the SSO
// service's outbound HTTP transport is swapped, so it reaches a
// controlled test provider instead of the internet. The shipped client's
// SSRF guard blocks loopback by design and is left alone.

package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/config"
	"github.com/Hanalyx/openwatch/internal/db/dbtest"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/Hanalyx/openwatch/internal/secretkey"
	"github.com/Hanalyx/openwatch/internal/sso"
	"github.com/Hanalyx/openwatch/internal/users"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ssoTestIDP is a controlled OpenID provider. It signs a real RS256
// ID token for a fixed subject, so every server-side validation runs.
type ssoTestIDP struct {
	*httptest.Server
	key      *rsa.PrivateKey
	kid      string
	clientID string
	nonce    string
	sub      string
	email    string
}

func newSSOTestIDP(t *testing.T) *ssoTestIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	d := &ssoTestIDP{key: key, kid: "sso-test-kid", clientID: "sso-test-client"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 d.URL,
			"authorization_endpoint": d.URL + "/authorize",
			"token_endpoint":         d.URL + "/token",
			"jwks_uri":               d.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		pub := d.key.Public().(*rsa.PublicKey)
		b64 := base64.RawURLEncoding.EncodeToString
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "use": "sig", "kid": d.kid,
			"n": b64(pub.N.Bytes()),
			"e": b64(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": d.URL, "sub": d.sub, "aud": d.clientID,
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
			"nonce": d.nonce, "email": d.email, "email_verified": true,
		})
		tok.Header["kid"] = d.kid
		signed, err := tok.SignedString(d.key)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"id_token": signed, "access_token": "at", "token_type": "Bearer",
		})
	})
	ts := httptest.NewTLSServer(mux)
	d.Server = ts
	t.Cleanup(ts.Close)
	return d
}

// ssoFixture builds a real server whose SSO service reaches the
// controlled provider. Only the transport is substituted.
func ssoFixture(t *testing.T) (string, *pgxpool.Pool, *ssoTestIDP, sso.Provider) {
	t.Helper()
	_ = apiTestDSN(t)
	ctx := context.Background()
	pool := dbtest.Pool(t)

	for _, stmt := range []string{
		"TRUNCATE TABLE audit_events",
		"TRUNCATE TABLE sso_providers CASCADE",
		"TRUNCATE TABLE users CASCADE",
	} {
		_, _ = pool.Exec(ctx, stmt)
	}
	_, _ = pool.Exec(ctx, `INSERT INTO auth_policy (id) VALUES (true)
		ON CONFLICT (id) DO UPDATE SET require_mfa = false,
		  session_idle_timeout_seconds = 900,
		  session_absolute_timeout_seconds = 43200, updated_by = NULL`)

	audit.Init(audit.NewStore(pool), audit.WriterOptions{
		ChannelBuffer: 256, BatchSize: 50, FlushInterval: 20 * time.Millisecond,
	})
	t.Cleanup(func() { audit.Shutdown(2 * time.Second) })
	if err := identity.SetEphemeralJWTKey(); err != nil {
		t.Fatalf("jwt key: %v", err)
	}
	if err := secretkey.SetEphemeral(); err != nil {
		t.Fatalf("secret key: %v", err)
	}

	s := New(config.Defaults(), pool)
	d := newSSOTestIDP(t)
	s.handlers.ssoSvc.WithHTTP(d.Client())

	p, err := s.handlers.ssoSvc.Create(ctx, sso.CreateParams{
		Name: "Controlled IdP", Issuer: d.URL, ClientID: d.clientID,
		ClientSecret: "test-only-not-a-real-secret", DefaultRole: "viewer", Enabled: true,
	})
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	srv := httptest.NewServer(s.router)
	t.Cleanup(srv.Close)
	return srv.URL, pool, d, p
}

type ssoCallbackResult struct {
	status        int
	location      string
	sessionCookie *http.Cookie
	refreshCookie *http.Cookie
}

// ssoSignIn drives the real login redirect and the real callback.
func ssoSignIn(t *testing.T, base string, pool *pgxpool.Pool, d *ssoTestIDP, p sso.Provider) ssoCallbackResult {
	t.Helper()
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	loginResp, err := cl.Get(base + "/api/v1/auth/sso/" + p.ID.String() + "/login")
	if err != nil {
		t.Fatalf("login redirect: %v", err)
	}
	loginResp.Body.Close()
	loc, err := url.Parse(loginResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse authorize url: %v", err)
	}
	state := loc.Query().Get("state")
	if state == "" {
		t.Fatalf("no state in authorize url %q", loginResp.Header.Get("Location"))
	}
	// The controlled provider echoes the nonce the server persisted,
	// exactly as a real provider echoes the one it received.
	if err := pool.QueryRow(context.Background(),
		`SELECT nonce FROM sso_auth_states WHERE state = $1`, state).Scan(&d.nonce); err != nil {
		t.Fatalf("read persisted nonce: %v", err)
	}
	cbResp, err := cl.Get(fmt.Sprintf("%s/api/v1/auth/sso/%s/callback?code=%s&state=%s",
		base, p.ID.String(), "test-code", url.QueryEscape(state)))
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	cbResp.Body.Close()
	res := ssoCallbackResult{status: cbResp.StatusCode, location: cbResp.Header.Get("Location")}
	for _, c := range cbResp.Cookies() {
		switch c.Name {
		case identity.SessionCookieName:
			if c.Value != "" {
				res.sessionCookie = &http.Cookie{Name: c.Name, Value: c.Value}
			}
		case identity.RefreshCookieName:
			if c.Value != "" {
				res.refreshCookie = &http.Cookie{Name: c.Name, Value: c.Value}
			}
		}
	}
	return res
}

func ssoCounts(t *testing.T, pool *pgxpool.Pool, uid uuid.UUID) (sessions, refresh, links int) {
	t.Helper()
	if err := pool.QueryRow(context.Background(), `
		SELECT (SELECT count(*) FROM sessions WHERE user_id = $1),
		       (SELECT count(*) FROM refresh_tokens WHERE user_id = $1),
		       (SELECT count(*) FROM sso_identities WHERE user_id = $1)`,
		uid).Scan(&sessions, &refresh, &links); err != nil {
		t.Fatalf("counts: %v", err)
	}
	return
}

// loginSuccesses counts auth.login.success rows for a user. The audit
// writer batches, so this polls until the reading stops changing.
// Returning on the first result undercounts it.
func loginSuccesses(t *testing.T, pool *pgxpool.Pool, uid uuid.UUID) int {
	t.Helper()
	start := time.Now()
	deadline := start.Add(5 * time.Second)
	last, stable := -1, 0
	for {
		var n int
		if err := pool.QueryRow(context.Background(), `
			SELECT count(*) FROM audit_events
			WHERE action = 'auth.login.success' AND (resource_id = $1 OR actor_id = $1)`,
			uid.String()).Scan(&n); err != nil {
			t.Fatalf("count login successes: %v", err)
		}
		if n == last {
			stable++
			if stable >= 2 && time.Since(start) > 300*time.Millisecond {
				return n
			}
		} else {
			stable, last = 0, n
		}
		if time.Now().After(deadline) {
			return n
		}
	}
}

// @ac AC-09
// AC-09: a federated sign-in for a disabled or soft-deleted account is
// refused. No session row, no refresh row, no cookies, no success audit.
// The link survives, so re-enabling restores sign-in without
// re-provisioning.
func TestSSO_RefusesDisabledAndDeletedAccounts(t *testing.T) {
	t.Run("system-sso/AC-09", func(t *testing.T) {
		for _, tc := range []struct {
			name      string
			subject   string
			email     string
			transform func(t *testing.T, svc *users.Service, uid uuid.UUID)
			wantSign  bool
		}{
			{"active control", "sub-active", "sso-active@example.test", nil, true},
			{"disabled", "sub-disabled", "sso-disabled@example.test",
				func(t *testing.T, svc *users.Service, uid uuid.UUID) {
					if err := svc.Disable(context.Background(), uid); err != nil {
						t.Fatalf("disable: %v", err)
					}
				}, false},
			{"soft-deleted", "sub-deleted", "sso-deleted@example.test",
				func(t *testing.T, svc *users.Service, uid uuid.UUID) {
					if err := svc.SoftDelete(context.Background(), uid); err != nil {
						t.Fatalf("soft delete: %v", err)
					}
				}, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				base, pool, d, p := ssoFixture(t)
				ctx := context.Background()
				d.sub, d.email = tc.subject, tc.email
				svc := users.NewService(pool, nil)

				// First sign-in, account active: provisions and links.
				first := ssoSignIn(t, base, pool, d, p)
				if first.sessionCookie == nil {
					t.Fatalf("precondition: the first sign-in must succeed, got %d -> %q",
						first.status, first.location)
				}
				var uid uuid.UUID
				if err := pool.QueryRow(ctx,
					`SELECT user_id FROM sso_identities WHERE subject = $1`, tc.subject).Scan(&uid); err != nil {
					t.Fatalf("no federation link after the first sign-in: %v", err)
				}
				_ = svc.AssignRole(ctx, uid, auth.RoleID("viewer"), nil)

				sessBefore, refreshBefore, _ := ssoCounts(t, pool, uid)

				if tc.transform != nil {
					tc.transform(t, svc, uid)
				}

				// Second sign-in, through the real callback.
				second := ssoSignIn(t, base, pool, d, p)
				sessAfter, refreshAfter, linksAfter := ssoCounts(t, pool, uid)

				if tc.wantSign {
					if second.sessionCookie == nil || second.refreshCookie == nil {
						t.Fatalf("active control: expected both cookies, got %d -> %q",
							second.status, second.location)
					}
					if code := authMe(t, base, second.sessionCookie); code != http.StatusOK {
						t.Errorf("active control: new session on /auth/me = %d, want 200", code)
					}
					return
				}

				if second.sessionCookie != nil {
					t.Error("a refused account received a session cookie")
				}
				if second.refreshCookie != nil {
					t.Error("a refused account received a refresh cookie")
				}
				// Rows, not just cookies. The reproduction showed the
				// soft-deleted case writing both rows while the cookie
				// happened to fail later at the binder.
				if sessAfter != sessBefore {
					t.Errorf("session rows %d -> %d: a refused sign-in wrote one", sessBefore, sessAfter)
				}
				if refreshAfter != refreshBefore {
					t.Errorf("refresh rows %d -> %d: a refused sign-in wrote one", refreshBefore, refreshAfter)
				}
				if successes := loginSuccesses(t, pool, uid); successes != 1 {
					t.Errorf("auth.login.success rows = %d, want 1 (the legitimate first sign-in only)", successes)
				}
				if linksAfter != 1 {
					t.Errorf("federation links = %d, want exactly 1: a refusal must not provision a second user", linksAfter)
				}
			})
		}
	})
}

// @ac AC-10
// AC-10: SSO issuance revalidates account state under the per-user lock.
// A disable committed while the callback waits on that lock is observed.
//
// The ordering is imposed by the lock, not by sleeping. If the callback
// had not yet reached the lock it still observes the committed disable,
// so the assertion holds either way.
func TestSSO_RevalidatesAccountStateUnderTheLock(t *testing.T) {
	t.Run("system-sso/AC-10", func(t *testing.T) {
		base, pool, d, p := ssoFixture(t)
		ctx := context.Background()
		d.sub, d.email = "sub-race", "sso-race@example.test"
		svc := users.NewService(pool, nil)

		first := ssoSignIn(t, base, pool, d, p)
		if first.sessionCookie == nil {
			t.Fatalf("precondition: the first sign-in must succeed, got %d", first.status)
		}
		var uid uuid.UUID
		if err := pool.QueryRow(ctx,
			`SELECT user_id FROM sso_identities WHERE subject = $1`, d.sub).Scan(&uid); err != nil {
			t.Fatalf("no federation link: %v", err)
		}
		_ = svc.AssignRole(ctx, uid, auth.RoleID("viewer"), nil)
		sessBefore, refreshBefore, _ := ssoCounts(t, pool, uid)

		// Hold the user row so the callback's lock blocks here.
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		var one int
		if err := tx.QueryRow(ctx,
			`SELECT 1 FROM users WHERE id = $1 FOR NO KEY UPDATE`, uid).Scan(&one); err != nil {
			t.Fatalf("hold lock: %v", err)
		}

		done := make(chan ssoCallbackResult, 1)
		go func() { done <- ssoSignIn(t, base, pool, d, p) }()

		// Wait until the callback is provably BLOCKED on the user row.
		// Committing the disable before that point would let identity
		// resolution see it, and the refusal would come from the
		// resolution check rather than from the revalidation this case
		// is about. The two layers mask each other otherwise.
		if !waitForUserLockWaiter(t, pool) {
			t.Fatal("no session ever blocked on the user row; this case did not reach the lock")
		}

		if _, err := tx.Exec(ctx, `UPDATE users SET disabled_at = now() WHERE id = $1`, uid); err != nil {
			t.Fatalf("disable in tx: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit disable: %v", err)
		}

		res := <-done
		if res.sessionCookie != nil || res.refreshCookie != nil {
			t.Error("the callback issued credentials for an account disabled before its lock")
		}
		sessAfter, refreshAfter, _ := ssoCounts(t, pool, uid)
		if sessAfter != sessBefore || refreshAfter != refreshBefore {
			t.Errorf("rows changed (sessions %d->%d, refresh %d->%d): the refused callback wrote something",
				sessBefore, sessAfter, refreshBefore, refreshAfter)
		}
	})
}
