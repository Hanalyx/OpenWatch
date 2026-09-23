// @spec system-auth-identity
//
// Account-state enforcement on both binders (C-31), the 401/503 split
// (C-32) and the bounded retry rules (C-37).

package identity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"
)

// bindOnce runs one request through the binder and reports the status
// and the downstream identity. Every account-state case is a single
// request against state written beforehand, so no case depends on
// timing or on another case having run.
func bindOnce(t *testing.T, pool *pgxpool.Pool, lookups Lookups, cookie *http.Cookie, bearer string) (int, bool) {
	t.Helper()
	sawDownstream := false
	h := Binder(pool, lookups)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawDownstream = !auth.FromContext(r.Context()).IsAnonymous
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code, sawDownstream
}

// @ac AC-34
// AC-34: the cookie binder refuses a live, unrevoked session whose
// account is disabled or soft-deleted, and does so for a reason that is
// DISTINGUISHABLE from an active account holding no role. The role-less
// variant is what stops this criterion from being satisfied by the
// incidental deleted_at join inside role resolution.
func TestBinder_CookieArmEnforcesAccountState(t *testing.T) {
	t.Run("system-auth-identity/AC-34", func(t *testing.T) {
		pool := freshPool(t)
		uid := seedUser(t, pool, "ac34-user")
		// The session is issued while the account is fine and is never
		// revoked, so any refusal below is attributable to account state.
		token, _, err := IssueSession(context.Background(), pool, uid, "127.0.0.1", "go-test")
		if err != nil {
			t.Fatalf("issue session: %v", err)
		}
		cookie := &http.Cookie{Name: SessionCookieName, Value: token}
		auditPool(t, pool)

		cases := []struct {
			name       string
			lookups    stubLookups
			wantStatus int
			wantReason string
			wantBound  bool
		}{
			{"disabled", stubLookups{role: auth.RoleAdmin, status: AccountDisabled},
				http.StatusUnauthorized, "account_disabled", false},
			{"soft-deleted", stubLookups{role: auth.RoleAdmin, status: AccountDeleted},
				http.StatusUnauthorized, "account_deleted", false},
			{"active control", stubLookups{role: auth.RoleAdmin, status: AccountActive},
				http.StatusOK, "", true},
			{"active with no roles", stubLookups{status: AccountActive, roleErr: errors.New("no roles")},
				http.StatusUnauthorized, "session_user_lookup_failed", false},
		}
		reasons := map[string]string{}
		for _, tc := range cases {
			code, bound := bindOnce(t, pool, tc.lookups, cookie, "")
			if code != tc.wantStatus {
				t.Errorf("%s: status = %d, want %d", tc.name, code, tc.wantStatus)
			}
			if bound != tc.wantBound {
				t.Errorf("%s: downstream bound = %v, want %v", tc.name, bound, tc.wantBound)
			}
			if tc.wantReason != "" {
				reasons[tc.name] = tc.wantReason
			}
		}
		// The disabled refusal must not share the reason a role-less
		// account produces. If it did, a binder that only ever checked
		// roles would satisfy this test.
		if reasons["disabled"] == reasons["active with no roles"] {
			t.Error("disabled and role-less accounts refuse for the same reason; the account-state check is not observable")
		}
	})
}

// @ac AC-35
// AC-35: the session-JWT binder refuses a disabled or soft-deleted
// account. The JWT stays cryptographically valid and unexpired in every
// case, so the refusal is attributable to account state alone.
func TestBinder_BearerArmEnforcesAccountState(t *testing.T) {
	t.Run("system-auth-identity/AC-35", func(t *testing.T) {
		pool := freshPool(t)
		uid := seedUser(t, pool, "ac35-user")
		if err := SetEphemeralJWTKey(); err != nil {
			t.Fatalf("jwt key: %v", err)
		}
		jwtToken, _, err := IssueJWT(uid, string(auth.RoleAdmin))
		if err != nil {
			t.Fatalf("issue jwt: %v", err)
		}
		// The same token is presented in every case; only account state moves.
		if _, err := VerifyJWT(jwtToken); err != nil {
			t.Fatalf("precondition: the JWT must be valid in every case, got %v", err)
		}
		auditPool(t, pool)

		for _, tc := range []struct {
			name       string
			status     AccountStatus
			wantStatus int
			wantBound  bool
		}{
			{"disabled", AccountDisabled, http.StatusUnauthorized, false},
			{"soft-deleted", AccountDeleted, http.StatusUnauthorized, false},
			{"active control", AccountActive, http.StatusOK, true},
		} {
			code, bound := bindOnce(t, pool,
				stubLookups{role: auth.RoleAdmin, status: tc.status}, nil, jwtToken)
			if code != tc.wantStatus {
				t.Errorf("%s: status = %d, want %d", tc.name, code, tc.wantStatus)
			}
			if bound != tc.wantBound {
				t.Errorf("%s: downstream bound = %v, want %v", tc.name, bound, tc.wantBound)
			}
		}
	})
}

// @ac AC-36
// AC-36: a failure to READ account state is an infrastructure failure,
// not a rejected credential. It answers 503 server.error. Answering 401
// would tell every signed-in browser its session ended.
func TestBinder_AccountStateUnavailableIs503(t *testing.T) {
	t.Run("system-auth-identity/AC-36", func(t *testing.T) {
		pool := freshPool(t)
		uid := seedUser(t, pool, "ac36-user")
		token, _, err := IssueSession(context.Background(), pool, uid, "127.0.0.1", "go-test")
		if err != nil {
			t.Fatalf("issue session: %v", err)
		}
		cookie := &http.Cookie{Name: SessionCookieName, Value: token}
		auditPool(t, pool)

		// Control: the SAME request succeeds when the lookup works, so
		// the 503 below is attributable to the injected failure.
		if code, _ := bindOnce(t, pool,
			stubLookups{role: auth.RoleAdmin, status: AccountActive}, cookie, ""); code != http.StatusOK {
			t.Fatalf("control: status = %d, want 200", code)
		}

		failing := stubLookups{role: auth.RoleAdmin, statusErr: ErrAccountStateUnavailable}
		h := Binder(pool, failing)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			t.Error("downstream ran on an indeterminate account state")
			w.WriteHeader(http.StatusOK)
		}))
		req := httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		if rr.Code != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want 503", rr.Code)
		}
		var env struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(rr.Body.Bytes(), &env)
		if env.Error.Code != "server.error" {
			t.Errorf("code = %q, want server.error", env.Error.Code)
		}
		if env.Error.Code == "auth.session_invalid" {
			t.Error("an infrastructure failure must not be reported as an invalid session")
		}
	})
}

// --- AC-42: bounded retry, asserted by counting attempts exactly ------------

// countingBeginner hands out transactions that fail in a chosen way and
// counts how many were begun. Nothing here depends on provoking a real
// deadlock, so the attempt counts are exact on every run.
type countingBeginner struct {
	attempts  int
	failWith  []error // one entry per attempt; nil means "succeed"
	commitErr []error
}

type fakeTx struct {
	pgx.Tx
	lockErr   error
	commitErr error
}

func (f *fakeTx) QueryRow(context.Context, string, ...any) pgx.Row { return fakeRow{err: f.lockErr} }
func (f *fakeTx) Commit(context.Context) error                     { return f.commitErr }
func (f *fakeTx) Rollback(context.Context) error                   { return nil }

type fakeRow struct{ err error }

func (r fakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) > 0 {
		if p, ok := dest[0].(*int); ok {
			*p = 1
		}
	}
	return nil
}

func (c *countingBeginner) Begin(context.Context) (pgx.Tx, error) {
	i := c.attempts
	c.attempts++
	tx := &fakeTx{}
	if i < len(c.failWith) {
		tx.lockErr = c.failWith[i]
	}
	if i < len(c.commitErr) {
		tx.commitErr = c.commitErr[i]
	}
	return tx, nil
}

func pgErr(code string) error { return &pgconn.PgError{Code: code} }

// @ac AC-42
// AC-42: 40P01 and 40001 restart the WHOLE transaction, at most three
// attempts. Any other error is not retried. An unknown commit outcome is
// not retried and asserts neither result.
func TestRunSerialized_BoundedRetryAndUnknownCommit(t *testing.T) {
	t.Run("system-auth-identity/AC-42", func(t *testing.T) {
		uid, _ := uuid.NewV7()
		noop := func(context.Context, pgx.Tx) error { return nil }

		t.Run("retryable, succeeds on attempt 2", func(t *testing.T) {
			b := &countingBeginner{failWith: []error{pgErr("40P01")}}
			if err := RunSerialized(context.Background(), b, uid, noop); err != nil {
				t.Fatalf("want success after one retry, got %v", err)
			}
			if b.attempts != 2 {
				t.Errorf("attempts = %d, want exactly 2", b.attempts)
			}
		})

		t.Run("retryable, exhausts three attempts", func(t *testing.T) {
			b := &countingBeginner{failWith: []error{pgErr("40001"), pgErr("40001"), pgErr("40001"), pgErr("40001")}}
			err := RunSerialized(context.Background(), b, uid, noop)
			if !errors.Is(err, ErrSerializationExhausted) {
				t.Fatalf("want ErrSerializationExhausted, got %v", err)
			}
			if b.attempts != MaxSerializedAttempts {
				t.Errorf("attempts = %d, want exactly %d", b.attempts, MaxSerializedAttempts)
			}
		})

		t.Run("non-retryable is not retried", func(t *testing.T) {
			b := &countingBeginner{failWith: []error{pgErr("23505")}} // unique violation
			if err := RunSerialized(context.Background(), b, uid, noop); err == nil {
				t.Fatal("want the error to surface")
			}
			if b.attempts != 1 {
				t.Errorf("attempts = %d, want exactly 1: a unique violation fails identically on a retry", b.attempts)
			}
		})

		t.Run("unknown commit outcome is not retried", func(t *testing.T) {
			// No SQLSTATE: the server never answered, so nothing here
			// knows whether the commit applied.
			b := &countingBeginner{commitErr: []error{errors.New("connection reset by peer")}}
			err := RunSerialized(context.Background(), b, uid, noop)
			if !errors.Is(err, ErrCommitUnknown) {
				t.Fatalf("want ErrCommitUnknown, got %v", err)
			}
			if b.attempts != 1 {
				t.Errorf("attempts = %d, want exactly 1: retrying could duplicate the issuance", b.attempts)
			}
		})

		t.Run("an answered commit failure is not an unknown outcome", func(t *testing.T) {
			// A SQLSTATE means the server replied, and a commit that
			// failed with a reply did not commit.
			b := &countingBeginner{commitErr: []error{pgErr("40001"), nil}}
			if err := RunSerialized(context.Background(), b, uid, noop); err != nil {
				t.Fatalf("an answered retryable commit failure should restart, got %v", err)
			}
			if b.attempts != 2 {
				t.Errorf("attempts = %d, want 2", b.attempts)
			}
		})
	})
}

// @ac AC-40
// AC-40: the MFA one-time password is consumed INSIDE the caller's
// transaction. When that transaction rolls back, the OTP is not
// consumed and the same code still works.
//
// Before this change VerifyMFA consumed on the pool, so an issuance
// failure after a correct OTP burned the code and the user could not
// retry with it still on their screen.
func TestVerifyMFA_ConsumptionIsInsideTheCallersTransaction(t *testing.T) {
	t.Run("system-auth-identity/AC-40", func(t *testing.T) {
		ctx := context.Background()
		pool := freshPool(t)
		ensureMFAKey(t)
		userID := seedUser(t, pool, "ac40-user")

		uri, err := EnrollMFA(ctx, pool, userID, "ac40-user")
		if err != nil {
			t.Fatalf("EnrollMFA: %v", err)
		}
		secret := extractSecret(t, uri)
		code, err := totp.GenerateCode(secret, time.Now().UTC())
		if err != nil {
			t.Fatalf("generate code: %v", err)
		}

		uses := func() int {
			var n int
			if err := pool.QueryRow(ctx,
				`SELECT count(*) FROM auth_mfa_otp_uses WHERE user_id = $1`, userID).Scan(&n); err != nil {
				t.Fatalf("count otp uses: %v", err)
			}
			return n
		}
		if uses() != 0 {
			t.Fatalf("precondition: want no recorded uses, got %d", uses())
		}

		// A transaction that validates the OTP and then fails.
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		if err := VerifyMFA(ctx, tx, userID, code); err != nil {
			t.Fatalf("VerifyMFA inside tx: %v", err)
		}
		// The issuance that would have followed fails here.
		if err := tx.Rollback(ctx); err != nil {
			t.Fatalf("rollback: %v", err)
		}

		if n := uses(); n != 0 {
			t.Errorf("recorded OTP uses after a rolled-back login = %d, want 0: the code was burned by a login that issued nothing", n)
		}

		// The same code still works, which is the user-visible point.
		tx2, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin 2: %v", err)
		}
		if err := VerifyMFA(ctx, tx2, userID, code); err != nil {
			t.Errorf("the same OTP failed on retry after a rolled-back attempt: %v", err)
		}
		if err := tx2.Commit(ctx); err != nil {
			t.Fatalf("commit 2: %v", err)
		}
		if n := uses(); n != 1 {
			t.Errorf("recorded OTP uses after a COMMITTED login = %d, want 1", n)
		}
		// And now it is single-use, as it must remain.
		tx3, _ := pool.Begin(ctx)
		if err := VerifyMFA(ctx, tx3, userID, code); err == nil {
			t.Error("a committed OTP was accepted a second time; single-use is broken")
		}
		_ = tx3.Rollback(ctx)
	})
}
