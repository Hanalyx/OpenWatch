// @spec system-auth-identity
//
// The MFA endpoints must not conflate three different things: an OTP the
// server rejected, an infrastructure failure, and an outcome nobody
// knows.
//
// Calling a database outage an invalid OTP sends the user to their
// authenticator app for a code that was never the problem, and records an
// authentication failure that did not happen. Calling an unknown
// confirmation a failure is worse still: the confirmation may have
// committed, so the user retries a code that is now consumed and is told
// it is invalid.

package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/Hanalyx/openwatch/internal/users"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"
)

type mfaResponse struct {
	status    int
	code      string
	retryable bool
	human     string
}

func postAs(t *testing.T, url string, cookie *http.Cookie, body any) mfaResponse {
	t.Helper()
	req := postJSONReq(t, url, body)
	req.AddCookie(cookie)
	resp := doReq(t, req)
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var env struct {
		Error struct {
			Code      string `json:"code"`
			Retryable bool   `json:"retryable"`
			Human     string `json:"human_message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &env)
	return mfaResponse{
		status:    resp.StatusCode,
		code:      env.Error.Code,
		retryable: env.Error.Retryable,
		human:     env.Error.Human,
	}
}

// mfaFailedEvents counts authentication-failure events for a user. Polls
// until the reading stops changing, because the audit writer batches.
func mfaFailedEvents(t *testing.T, pool *pgxpool.Pool, uid uuid.UUID) int {
	t.Helper()
	start := time.Now()
	deadline := start.Add(3 * time.Second)
	last, stable := -1, 0
	for {
		var n int
		if err := pool.QueryRow(context.Background(), `
			SELECT count(*) FROM audit_events
			WHERE action = 'auth.mfa.failed' AND (resource_id = $1 OR actor_id = $1)`,
			uid.String()).Scan(&n); err != nil {
			t.Fatalf("count mfa failures: %v", err)
		}
		if n == last {
			stable++
			if stable >= 2 && time.Since(start) > 250*time.Millisecond {
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

// @ac AC-51
// AC-51: the MFA endpoints tell a rejected OTP, an infrastructure
// failure and an unknown outcome apart.
func TestMFAEndpoints_DistinguishRejectionFromFailureFromUnknown(t *testing.T) {
	t.Run("system-auth-identity/AC-51", func(t *testing.T) {
		// --- a rejected OTP is a client failure, and is audited ---
		t.Run("confirmation, OTP rejected", func(t *testing.T) {
			url, pool, _ := freshAPIServerWithHandles(t)
			ctx := context.Background()
			li := loginFresh(t, url, pool, "ac51reject")
			if _, err := identity.EnrollMFA(ctx, pool, li.u.ID, li.u.Username); err != nil {
				t.Fatalf("enroll: %v", err)
			}
			got := postAs(t, url+"/api/v1/auth/mfa:verify", li.sessionCookie,
				map[string]string{"otp": "000000"})
			if got.status != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", got.status)
			}
			if got.code != "auth.mfa_invalid" {
				t.Errorf("code = %q, want auth.mfa_invalid", got.code)
			}
			if n := mfaFailedEvents(t, pool, li.u.ID); n != 1 {
				t.Errorf("auth.mfa.failed events = %d, want 1: a rejected OTP IS an authentication failure", n)
			}
		})

		// --- an unknown outcome is neither, on both endpoints ---
		for _, tc := range []struct {
			name        string
			user        string
			commitFirst bool
			enrollFirst bool
			path        string
			body        func(otp string) any
		}{
			{"confirmation, unknown commit, durable", "ac51cd", true, true,
				"/api/v1/auth/mfa:verify", func(otp string) any { return map[string]string{"otp": otp} }},
			{"confirmation, unknown commit, non-durable", "ac51cn", false, true,
				"/api/v1/auth/mfa:verify", func(otp string) any { return map[string]string{"otp": otp} }},
			{"enrollment, unknown commit, durable", "ac51ed", true, false,
				"/api/v1/auth/mfa:enroll", func(string) any { return map[string]string{} }},
			{"enrollment, unknown commit, non-durable", "ac51en", false, false,
				"/api/v1/auth/mfa:enroll", func(string) any { return map[string]string{} }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				url, pool, srv := freshAPIServerWithHandles(t)
				ctx := context.Background()
				li := loginFresh(t, url, pool, tc.user)

				otp := ""
				if tc.enrollFirst {
					uri, err := identity.EnrollMFA(ctx, pool, li.u.ID, li.u.Username)
					if err != nil {
						t.Fatalf("enroll: %v", err)
					}
					code, err := totp.GenerateCode(ssoExtractSecret(t, uri), time.Now().UTC())
					if err != nil {
						t.Fatalf("generate otp: %v", err)
					}
					otp = code
				}

				before := mfaFailedEvents(t, pool, li.u.ID)
				srv.handlers.serializer = &indeterminateBeginner{inner: pool, commitFirst: tc.commitFirst}
				got := postAs(t, url+tc.path, li.sessionCookie, tc.body(otp))

				if got.status != http.StatusServiceUnavailable {
					t.Errorf("status = %d, want 503", got.status)
				}
				if got.code != "server.error" {
					t.Errorf("code = %q, want server.error", got.code)
				}
				if got.retryable {
					t.Error("retryable = true on an unknown outcome")
				}
				if got.code == "auth.mfa_invalid" {
					t.Error("an unknown outcome reported as an invalid OTP")
				}
				// The message must not assert that it failed. The write
				// may have committed.
				for _, claim := range []string{"failed", "invalid"} {
					if containsFold(got.human, claim) {
						t.Errorf("human_message asserts %q on an unknown outcome: %q", claim, got.human)
					}
				}
				if after := mfaFailedEvents(t, pool, li.u.ID); after != before {
					t.Errorf("auth.mfa.failed events %d -> %d: an infrastructure failure was audited as an authentication failure",
						before, after)
				}
			})
		}
	})
}

var _ = users.NewService
var _ = auth.RoleViewer

// mfaFixture enrolls and confirms a user, and returns a generator for
// currently valid OTPs.
type mfaFixture struct {
	li     loggedInUser
	secret string
}

func enrolledUser(t *testing.T, url string, pool *pgxpool.Pool, name string) mfaFixture {
	t.Helper()
	ctx := context.Background()
	li := loginFresh(t, url, pool, name)
	uri, err := identity.EnrollMFA(ctx, pool, li.u.ID, li.u.Username)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE auth_mfa_secrets SET last_verified_at = now() WHERE user_id = $1`, li.u.ID); err != nil {
		t.Fatalf("confirm enrollment: %v", err)
	}
	return mfaFixture{li: li, secret: ssoExtractSecret(t, uri)}
}

func (f mfaFixture) otp(t *testing.T) string {
	t.Helper()
	code, err := totp.GenerateCode(f.secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("generate otp: %v", err)
	}
	return code
}

// corruptSecret makes decryption fail on the crypto path, with no SQL
// error at all, so the failure cannot be mistaken for a poisoned
// transaction.
func corruptSecret(t *testing.T, pool *pgxpool.Pool, uid uuid.UUID) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`UPDATE auth_mfa_secrets SET encrypted_secret = $1 WHERE user_id = $2`,
		[]byte("not-a-valid-ciphertext"), uid); err != nil {
		t.Fatalf("corrupt secret: %v", err)
	}
}

func otpUseCount(t *testing.T, pool *pgxpool.Pool, uid uuid.UUID) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM auth_mfa_otp_uses WHERE user_id = $1`, uid).Scan(&n); err != nil {
		t.Fatalf("count otp uses: %v", err)
	}
	return n
}

// @ac AC-53
// AC-53: a failure INSIDE verification is classified by meaning. Only a
// wrong code, a replayed code and an account with no secret are refusals;
// an unreadable secret or a failed consumption write is an infrastructure
// failure, rolled back, and never audited as an authentication failure.
func TestMFAVerification_ClassifiesFailuresByMeaning(t *testing.T) {
	t.Run("system-auth-identity/AC-53", func(t *testing.T) {
		// --- the genuine rejections are preserved ---
		t.Run("confirmation, wrong OTP", func(t *testing.T) {
			url, pool := freshAPIServer(t)
			f := enrolledUser(t, url, pool, "ac53wrong")
			got := postAs(t, url+"/api/v1/auth/mfa:verify", f.li.sessionCookie,
				map[string]string{"otp": "000000"})
			if got.status != http.StatusUnauthorized || got.code != "auth.mfa_invalid" {
				t.Errorf("status/code = %d/%q, want 401/auth.mfa_invalid", got.status, got.code)
			}
			if n := mfaFailedEvents(t, pool, f.li.u.ID); n != 1 {
				t.Errorf("auth.mfa.failed = %d, want 1: a wrong code IS an authentication failure", n)
			}
		})

		t.Run("confirmation, replayed OTP", func(t *testing.T) {
			url, pool := freshAPIServer(t)
			f := enrolledUser(t, url, pool, "ac53replay")
			code := f.otp(t)
			if first := postAs(t, url+"/api/v1/auth/mfa:verify", f.li.sessionCookie,
				map[string]string{"otp": code}); first.status != http.StatusNoContent {
				t.Fatalf("first use = %d, want 204", first.status)
			}
			got := postAs(t, url+"/api/v1/auth/mfa:verify", f.li.sessionCookie,
				map[string]string{"otp": code})
			if got.status != http.StatusUnauthorized || got.code != "auth.mfa_invalid" {
				t.Errorf("replay status/code = %d/%q, want 401/auth.mfa_invalid", got.status, got.code)
			}
			if n := mfaFailedEvents(t, pool, f.li.u.ID); n != 1 {
				t.Errorf("auth.mfa.failed = %d, want 1", n)
			}
		})

		// --- a rejection must not CONCEAL a transaction failure ---
		// The only case where both happen at once: the OTP is refused AND
		// the commit outcome is unknown. Reporting 401 here would tell the
		// user their code was bad while the server has no idea what it
		// committed. Without this case the ordering of the two checks is
		// unobservable, and reversing them passes every other variant.
		t.Run("rejection with an unknown commit reports the transaction", func(t *testing.T) {
			url, pool, srv := freshAPIServerWithHandles(t)
			f := enrolledUser(t, url, pool, "ac53conceal")
			before := mfaFailedEvents(t, pool, f.li.u.ID)

			srv.handlers.serializer = &indeterminateBeginner{inner: pool, commitFirst: false}
			got := postAs(t, url+"/api/v1/auth/mfa:verify", f.li.sessionCookie,
				map[string]string{"otp": "000000"})

			if got.status != http.StatusServiceUnavailable {
				t.Errorf("status = %d, want 503: the unknown transaction outcome outranks the rejection", got.status)
			}
			if got.code != "server.error" {
				t.Errorf("code = %q, want server.error", got.code)
			}
			if got.retryable {
				t.Error("retryable = true on an unknown outcome")
			}
			if after := mfaFailedEvents(t, pool, f.li.u.ID); after != before {
				t.Errorf("auth.mfa.failed %d -> %d: an authentication failure was recorded while the transaction outcome was unknown",
					before, after)
			}
		})

		// --- infrastructure failures inside verification ---
		for _, tc := range []struct {
			name     string
			user     string
			inject   func(t *testing.T, pool *pgxpool.Pool, uid uuid.UUID) func()
			viaLogin bool
		}{
			{"confirmation, secret unreadable", "ac53cdec",
				func(t *testing.T, pool *pgxpool.Pool, uid uuid.UUID) func() {
					corruptSecret(t, pool, uid)
					return func() {}
				}, false},
			{"confirmation, consumption write fails", "ac53cwrite",
				func(t *testing.T, pool *pgxpool.Pool, _ uuid.UUID) func() {
					return failOnWrite(t, pool, "auth_mfa_otp_uses", "INSERT")
				}, false},
			{"login, secret unreadable", "ac53ldec",
				func(t *testing.T, pool *pgxpool.Pool, uid uuid.UUID) func() {
					corruptSecret(t, pool, uid)
					return func() {}
				}, true},
			{"login, consumption write fails", "ac53lwrite",
				func(t *testing.T, pool *pgxpool.Pool, _ uuid.UUID) func() {
					return failOnWrite(t, pool, "auth_mfa_otp_uses", "INSERT")
				}, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				url, pool := freshAPIServer(t)
				f := enrolledUser(t, url, pool, tc.user)
				code := f.otp(t)
				beforeUses := otpUseCount(t, pool, f.li.u.ID)
				beforeFailures := mfaFailedEvents(t, pool, f.li.u.ID)

				restore := tc.inject(t, pool, f.li.u.ID)

				var status int
				var errCode string
				if tc.viaLogin {
					got := loginFor(t, url, f.li.u.Username, f.li.u.Password, &code)
					status, errCode = got.status, got.code
				} else {
					got := postAs(t, url+"/api/v1/auth/mfa:verify", f.li.sessionCookie,
						map[string]string{"otp": code})
					status, errCode = got.status, got.code
				}
				restore()

				if status != http.StatusServiceUnavailable {
					t.Errorf("status = %d, want 503: a failure to find out is not a bad code", status)
				}
				if errCode != "server.error" {
					t.Errorf("code = %q, want server.error", errCode)
				}
				if errCode == "auth.mfa_invalid" {
					t.Error("an infrastructure failure was reported as an invalid OTP")
				}
				if after := mfaFailedEvents(t, pool, f.li.u.ID); after != beforeFailures {
					t.Errorf("auth.mfa.failed %d -> %d: a failure the user did not cause was audited as authentication failure",
						beforeFailures, after)
				}
				// Nothing durable from a rolled-back attempt.
				if after := otpUseCount(t, pool, f.li.u.ID); after != beforeUses {
					t.Errorf("auth_mfa_otp_uses %d -> %d: a rolled-back attempt left a row", beforeUses, after)
				}
				if tc.viaLogin {
					if s, r := liveCredentials(t, pool, f.li.u.ID); s != 1 || r != 1 {
						t.Errorf("login issued or revoked credentials on a failed attempt: sessions=%d refresh=%d (want the 1/1 from the fixture login)", s, r)
					}
				}
			})
		}
	})
}
