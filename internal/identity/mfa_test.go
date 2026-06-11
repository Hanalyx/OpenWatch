// @spec system-auth-identity
//
// TOTP MFA + identity binder tests (ACs 14, 15, 16, 17, 18).

package identity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/correlation"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// ensureMFAKey installs an ephemeral MFA encryption key for the test.
func ensureMFAKey(t *testing.T) {
	t.Helper()
	if err := SetEphemeralMFAKey(); err != nil {
		t.Fatalf("SetEphemeralMFAKey: %v", err)
	}
}

// @ac AC-14
// AC-14: EnrollMFA persists an encrypted 160-bit secret and returns a
// provisioning URI of the right shape.
func TestMFA_Enroll(t *testing.T) {
	t.Run("system-auth-identity/AC-14", func(t *testing.T) {
		pool := freshPool(t)
		ensureMFAKey(t)
		userID := seedUser(t, pool, "ac14-user")

		uri, err := EnrollMFA(context.Background(), pool, userID, "ac14-user")
		if err != nil {
			t.Fatalf("EnrollMFA: %v", err)
		}
		u, err := url.Parse(uri)
		if err != nil {
			t.Fatalf("parse uri: %v", err)
		}
		if u.Scheme != "otpauth" || u.Host != "totp" {
			t.Errorf("scheme/host = %s://%s, want otpauth://totp", u.Scheme, u.Host)
		}
		q := u.Query()
		if q.Get("issuer") != TOTPIssuer {
			t.Errorf("issuer = %q, want %q", q.Get("issuer"), TOTPIssuer)
		}
		if q.Get("digits") != "6" {
			t.Errorf("digits = %q, want 6", q.Get("digits"))
		}
		if q.Get("period") != "30" {
			t.Errorf("period = %q, want 30", q.Get("period"))
		}
		secret := q.Get("secret")
		if secret == "" {
			t.Fatal("uri missing secret")
		}
		// Encrypted blob present in DB; the plaintext secret is NOT
		// queryable by reading the row.
		var enc []byte
		_ = pool.QueryRow(context.Background(),
			`SELECT encrypted_secret FROM auth_mfa_secrets WHERE user_id = $1`,
			userID).Scan(&enc)
		if len(enc) == 0 {
			t.Fatal("encrypted_secret column empty after enroll")
		}
		if strings.Contains(string(enc), secret) {
			t.Error("plaintext secret appears in DB row — encryption broken")
		}
	})
}

// @ac AC-15
// AC-15: VerifyMFA accepts the current step, the previous step, and the
// next step (±1 window for clock drift); rejects steps outside.
func TestMFA_VerifyDriftWindow(t *testing.T) {
	t.Run("system-auth-identity/AC-15", func(t *testing.T) {
		pool := freshPool(t)
		ensureMFAKey(t)
		userID := seedUser(t, pool, "ac15-user")

		uri, err := EnrollMFA(context.Background(), pool, userID, "ac15-user")
		if err != nil {
			t.Fatalf("EnrollMFA: %v", err)
		}
		secret := extractSecret(t, uri)

		// Generate OTPs for several time steps.
		now := time.Now().UTC()
		for _, offset := range []time.Duration{
			-30 * time.Second, // previous step
			0,                 // current step
			+30 * time.Second, // next step
		} {
			code, err := totp.GenerateCode(secret, now.Add(offset))
			if err != nil {
				t.Fatalf("generate code @%v: %v", offset, err)
			}
			// First-use of each (the replay table is per-OTP, so different
			// time-offset OTPs are different rows).
			if err := VerifyMFA(context.Background(), pool, userID, code); err != nil {
				t.Errorf("VerifyMFA @%v: %v (should accept ±1 step)", offset, err)
			}
		}

		// Truly out-of-window: 5 minutes in the future.
		futureCode, _ := totp.GenerateCode(secret, now.Add(5*time.Minute))
		err = VerifyMFA(context.Background(), pool, userID, futureCode)
		if !errors.Is(err, ErrMFAInvalidOTP) {
			t.Errorf("future OTP err = %v, want ErrMFAInvalidOTP", err)
		}
	})
}

// @ac AC-16
// AC-16: VerifyMFA rejects replay of the same OTP within its window.
func TestMFA_ReplayProtection(t *testing.T) {
	t.Run("system-auth-identity/AC-16", func(t *testing.T) {
		pool := freshPool(t)
		ensureMFAKey(t)
		userID := seedUser(t, pool, "ac16-user")

		uri, err := EnrollMFA(context.Background(), pool, userID, "ac16-user")
		if err != nil {
			t.Fatalf("EnrollMFA: %v", err)
		}
		secret := extractSecret(t, uri)

		code, err := totp.GenerateCode(secret, time.Now().UTC())
		if err != nil {
			t.Fatalf("generate code: %v", err)
		}

		// First use succeeds.
		if err := VerifyMFA(context.Background(), pool, userID, code); err != nil {
			t.Fatalf("first verify: %v", err)
		}
		// Second use within the replay window fails with ErrOTPReplayed.
		err = VerifyMFA(context.Background(), pool, userID, code)
		if !errors.Is(err, ErrOTPReplayed) {
			t.Errorf("replay err = %v, want ErrOTPReplayed", err)
		}
	})
}

// VerifyMFA against a user with no enrolled secret returns ErrMFANotEnrolled.
// Not an AC; defensive.
func TestMFA_VerifyNotEnrolled(t *testing.T) {
	pool := freshPool(t)
	ensureMFAKey(t)
	userID := seedUser(t, pool, "not-enrolled-user")
	err := VerifyMFA(context.Background(), pool, userID, "000000")
	if !errors.Is(err, ErrMFANotEnrolled) {
		t.Errorf("err = %v, want ErrMFANotEnrolled", err)
	}
}

// extractSecret pulls the Base32 TOTP secret out of an otpauth URI.
func extractSecret(t *testing.T, uri string) string {
	t.Helper()
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("parse uri: %v", err)
	}
	s := u.Query().Get("secret")
	if s == "" {
		t.Fatalf("uri missing secret: %s", uri)
	}
	return s
}

// stubLookups is a Lookups implementation used by binder tests so we
// don't depend on the (not-yet-existing) users package.
type stubLookups struct {
	role auth.RoleID
}

func (s stubLookups) RoleForUser(_ context.Context, _ uuid.UUID) (auth.RoleID, error) {
	return s.role, nil
}

// auditPool starts the audit writer against the same pool so binder
// rejection paths can emit auth.login.failure rows. Tests query
// audit_events to assert AC-18.
func auditPool(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	audit.Init(audit.NewStore(pool), audit.WriterOptions{
		ChannelBuffer: 256,
		BatchSize:     50,
		FlushInterval: 20 * time.Millisecond,
	})
	t.Cleanup(func() { audit.Shutdown(2 * time.Second) })
}

// @ac AC-17
// AC-17: Binder reads either Cookie "openwatch_session" or
// Authorization "Bearer <jwt>"; populates auth.Identity. Anonymous when
// neither is present.
func TestBinder_ResolvesFromCookieAndBearer(t *testing.T) {
	t.Run("system-auth-identity/AC-17", func(t *testing.T) {
		pool := freshPool(t)
		auditPool(t, pool)
		ensureKey(t)
		userID := seedUser(t, pool, "ac17-user")
		token, _, err := IssueSession(context.Background(), pool, userID, "1.2.3.4", "test")
		if err != nil {
			t.Fatalf("IssueSession: %v", err)
		}

		// Spec test 1: cookie path resolves to identity.
		captured := make(chan auth.Identity, 1)
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			captured <- auth.FromContext(r.Context())
			w.WriteHeader(http.StatusNoContent)
		})
		mw := Binder(pool, stubLookups{role: auth.RoleViewer})(next)

		req := httptest.NewRequest("GET", "/probe", nil)
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
		mw.ServeHTTP(httptest.NewRecorder(), req)
		id := <-captured
		if id.IsAnonymous {
			t.Errorf("cookie path: identity is anonymous")
		}
		if id.ID != userID.String() {
			t.Errorf("cookie path: ID = %q, want %q", id.ID, userID.String())
		}

		// Spec test 2: bearer JWT path resolves to identity from claims.
		jwtTok, _, err := IssueJWT(userID, "admin")
		if err != nil {
			t.Fatalf("IssueJWT: %v", err)
		}
		req = httptest.NewRequest("GET", "/probe", nil)
		req.Header.Set("Authorization", "Bearer "+jwtTok)
		mw.ServeHTTP(httptest.NewRecorder(), req)
		id = <-captured
		if id.RoleID != auth.RoleID("admin") {
			t.Errorf("bearer path: RoleID = %q, want admin", id.RoleID)
		}

		// Spec test 3: neither present → anonymous, no audit.
		req = httptest.NewRequest("GET", "/probe", nil)
		mw.ServeHTTP(httptest.NewRecorder(), req)
		id = <-captured
		if !id.IsAnonymous {
			t.Errorf("no-credential path: expected anonymous")
		}
	})
}

// @ac AC-18
// AC-18: Binder emits auth.login.failure with detail.reason populated
// on rejected authentication attempts.
func TestBinder_AuditOnRejection(t *testing.T) {
	t.Run("system-auth-identity/AC-18", func(t *testing.T) {
		pool := freshPool(t)
		auditPool(t, pool)
		ensureKey(t)

		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
		mw := Binder(pool, stubLookups{role: auth.RoleViewer})(next)

		// Inject correlation_id so we can find the audit row.
		send := func(corr string, configure func(*http.Request)) {
			req := httptest.NewRequest("GET", "/probe", nil)
			req.Header.Set("X-Correlation-Id", corr)
			req = req.WithContext(correlation.Set(req.Context(), corr))
			configure(req)
			mw.ServeHTTP(httptest.NewRecorder(), req)
		}

		send("rej-bad-jwt", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer not-a-jwt")
		})
		send("rej-no-session", func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "never-issued"})
		})

		// Let the audit writer flush.
		time.Sleep(150 * time.Millisecond)

		// Each rejected attempt must produce one auth.login.failure row
		// with detail.reason populated.
		for _, want := range []struct {
			corr   string
			reason string
		}{
			{"rej-bad-jwt", "invalid_jwt"},
			{"rej-no-session", "invalid_session_token"},
		} {
			var detail string
			err := pool.QueryRow(context.Background(),
				`SELECT COALESCE(detail::text, '') FROM audit_events
				   WHERE action = 'auth.login.failure' AND correlation_id = $1`,
				want.corr,
			).Scan(&detail)
			if err != nil {
				t.Errorf("query audit for %s: %v", want.corr, err)
				continue
			}
			var got map[string]any
			_ = json.Unmarshal([]byte(detail), &got)
			if got["reason"] != want.reason {
				t.Errorf("corr=%s: reason = %v, want %s", want.corr, got["reason"], want.reason)
			}
		}
	})
}

// Silence unused-import warnings under partial builds.
var _ = otp.AlgorithmSHA1
