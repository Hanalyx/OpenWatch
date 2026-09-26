// @spec system-api-tokens
//
// A service-account token is refused while its owner may not authenticate
// (C-02, C-04; bugs/OW-071).

package server

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/Hanalyx/openwatch/internal/apitoken"
	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/users"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// tokenRow is the part of an api_tokens row the gate must never write.
type tokenRow struct {
	revoked, used bool
}

func readTokenRow(t *testing.T, pool *pgxpool.Pool, id uuid.UUID) tokenRow {
	t.Helper()
	var r tokenRow
	if err := pool.QueryRow(context.Background(),
		`SELECT revoked_at IS NOT NULL, last_used_at IS NOT NULL FROM api_tokens WHERE id = $1`, id).
		Scan(&r.revoked, &r.used); err != nil {
		t.Fatalf("read token row: %v", err)
	}
	return r
}

// presentToken sends the token as a Bearer credential to a route the
// token's role may read, with its own correlation id.
func presentToken(t *testing.T, url, raw string) (int, string) {
	t.Helper()
	cid := "tok-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	req, _ := http.NewRequest("GET", url+"/api/v1/hosts", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	req.Header.Set("X-Correlation-Id", cid)
	resp := doReq(t, req)
	resp.Body.Close()
	return resp.StatusCode, cid
}

// @ac AC-06
// AC-06: an otherwise-valid token does not authenticate while its owner is
// disabled or deleted, nor at all without an owner; the refusal writes
// nothing to the token; re-enabling the owner restores it, and a revoked
// token stays revoked.
func TestAPIToken_RefusedWhileOwnerMayNotAuthenticate(t *testing.T) {
	t.Run("system-api-tokens/AC-06", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()
		svc := users.NewService(pool, nil)
		tokens := apitoken.NewService(pool)

		newOwnerToken := func(t *testing.T, name string) (uuid.UUID, uuid.UUID, string) {
			t.Helper()
			u := seedAuthUser(t, svc, name, false)
			_ = svc.AssignRole(ctx, u.ID, "admin", nil)
			raw, tok, err := tokens.Create(ctx, apitoken.CreateParams{Name: name, RoleID: auth.RoleID("viewer"), CreatedBy: &u.ID})
			if err != nil {
				t.Fatalf("create token: %v", err)
			}
			return u.ID, tok.ID, raw
		}

		for _, tc := range []struct {
			name, stmt, reason string
		}{
			{"owner disabled", `UPDATE users SET disabled_at = now() WHERE id = $1`, "api_token_owner_disabled"},
			{"owner soft-deleted", `UPDATE users SET deleted_at = now() WHERE id = $1`, "api_token_owner_deleted"},
		} {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				owner, tokID, raw := newOwnerToken(t, "ac06"+strings.ReplaceAll(tc.name, " ", ""))
				if _, err := pool.Exec(ctx, tc.stmt, owner); err != nil {
					t.Fatalf("set owner state: %v", err)
				}
				code, cid := presentToken(t, url, raw)
				if code != http.StatusUnauthorized {
					t.Errorf("status = %d, want 401", code)
				}
				if got := loginFailureReasonFor(t, pool, cid); got != tc.reason {
					t.Errorf("audit reason = %q, want %q", got, tc.reason)
				}
				if row := readTokenRow(t, pool, tokID); row.revoked || row.used {
					t.Errorf("the refusal wrote to the token: revoked=%v last_used=%v", row.revoked, row.used)
				}
			})
		}

		t.Run("ownerless", func(t *testing.T) {
			_, tokID, raw := newOwnerToken(t, "ac06ownerless")
			if _, err := pool.Exec(ctx, `UPDATE api_tokens SET created_by = NULL WHERE id = $1`, tokID); err != nil {
				t.Fatalf("clear owner: %v", err)
			}
			code, cid := presentToken(t, url, raw)
			if code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401: an ownerless token fails closed", code)
			}
			if got := loginFailureReasonFor(t, pool, cid); got != "api_token_ownerless" {
				t.Errorf("audit reason = %q, want api_token_ownerless", got)
			}
			if row := readTokenRow(t, pool, tokID); row.revoked || row.used {
				t.Errorf("the refusal wrote to the token: revoked=%v last_used=%v", row.revoked, row.used)
			}
		})

		t.Run("active control", func(t *testing.T) {
			_, tokID, raw := newOwnerToken(t, "ac06active")
			if code, _ := presentToken(t, url, raw); code != http.StatusOK {
				t.Errorf("status = %d, want 200 for an active owner", code)
			}
			if row := readTokenRow(t, pool, tokID); !row.used {
				t.Error("a successful authentication did not record last_used_at")
			}
		})

		t.Run("re-enable restores, revoked stays revoked", func(t *testing.T) {
			owner, _, raw := newOwnerToken(t, "ac06reenable")
			revokedRaw, revoked, err := tokens.Create(ctx, apitoken.CreateParams{Name: "ac06revoked", RoleID: auth.RoleID("viewer"), CreatedBy: &owner})
			if err != nil {
				t.Fatalf("create second token: %v", err)
			}
			if err := tokens.Revoke(ctx, revoked.ID); err != nil {
				t.Fatalf("revoke: %v", err)
			}
			if err := svc.Disable(ctx, owner); err != nil {
				t.Fatalf("disable: %v", err)
			}
			if code, _ := presentToken(t, url, raw); code != http.StatusUnauthorized {
				t.Fatalf("precondition: token while owner disabled = %d, want 401", code)
			}
			if _, err := svc.Enable(ctx, owner); err != nil {
				t.Fatalf("enable: %v", err)
			}
			if code, _ := presentToken(t, url, raw); code != http.StatusOK {
				t.Errorf("token after re-enable = %d, want 200: the gate is a check, not a revocation", code)
			}
			if code, _ := presentToken(t, url, revokedRaw); code != http.StatusUnauthorized {
				t.Errorf("revoked token after re-enable = %d, want 401", code)
			}
		})
	})
}
