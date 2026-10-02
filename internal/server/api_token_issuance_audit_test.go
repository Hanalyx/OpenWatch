// @spec system-api-tokens
//
// AC traceability (DSN-gated like every api_*_test in this package):
//
//	AC-14  TestAPITokenIssueRevoke_AuditedWithCallerAsActor
//	AC-15  TestAPITokenIssue_AuditRowCarriesNoSecret
//
// bugs/OW-101: creating or revoking an API token wrote no audit row.
package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/server/api"
)

// tokCall sends one request as a session role or as an owk_ bearer, with
// its own correlation id, and returns status, body and the correlation id.
func tokCall(t *testing.T, url, bearer string, role auth.RoleID, method, path string, body any) (int, []byte, string) {
	t.Helper()
	corr := "tok-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:24]
	var req *http.Request
	if bearer != "" {
		var rdr io.Reader
		if body != nil {
			bs, _ := json.Marshal(body)
			rdr = bytes.NewReader(bs)
		}
		req, _ = http.NewRequest(method, url+path, rdr)
		req.Header.Set("Authorization", "Bearer "+bearer)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
	} else {
		req = asRole(t, method, url+path, role, body)
	}
	req.Header.Set("X-Correlation-Id", corr)
	req.Header.Set("Idempotency-Key", "k-"+uuid.NewString())
	resp := doReq(t, req)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, corr
}

type tokAuditRow struct {
	Action, ActorType, ActorID, ResourceType, ResourceID string
	Detail                                               map[string]any
	Raw                                                  string
}

// tokAuditRowsFor polls until the batched writer's rows for corr hold steady.
func tokAuditRowsFor(t *testing.T, pool *pgxpool.Pool, corr string) []tokAuditRow {
	t.Helper()
	var out []tokAuditRow
	last, steady := -1, 0
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		rows, err := pool.Query(context.Background(), `
			SELECT action, actor_type, COALESCE(actor_id,''), COALESCE(resource_type,''),
			       COALESCE(resource_id,''), COALESCE(detail::text,'{}'), row_to_json(a)::text
			FROM audit_events a WHERE correlation_id = $1 ORDER BY occurred_at`, corr)
		if err != nil {
			t.Fatalf("query audit: %v", err)
		}
		out = out[:0]
		for rows.Next() {
			var r tokAuditRow
			var d string
			if err := rows.Scan(&r.Action, &r.ActorType, &r.ActorID, &r.ResourceType, &r.ResourceID, &d, &r.Raw); err != nil {
				t.Fatalf("scan audit: %v", err)
			}
			_ = json.Unmarshal([]byte(d), &r.Detail)
			out = append(out, r)
		}
		rows.Close()
		if len(out) == last {
			steady++
			if steady >= 3 {
				break
			}
		} else {
			steady = 0
		}
		last = len(out)
		time.Sleep(60 * time.Millisecond)
	}
	return append([]tokAuditRow(nil), out...)
}

func tokOnlyAction(t *testing.T, rows []tokAuditRow, action string) []tokAuditRow {
	t.Helper()
	var out []tokAuditRow
	for _, r := range rows {
		if r.Action == action {
			out = append(out, r)
		}
	}
	return out
}

func tokDetailKeys(d map[string]any) string {
	var ks []string
	for k := range d {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return strings.Join(ks, ",")
}

// @ac AC-14
func TestAPITokenIssueRevoke_AuditedWithCallerAsActor(t *testing.T) {
	t.Run("system-api-tokens/AC-14", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		admin := roleUserIDs[auth.RoleAdmin]
		callerRaw, callerID := mintTokenAs(t, url, auth.RoleAdmin, auth.RoleAdmin)

		for _, mode := range []string{"session", "token"} {
			bearer, wantType, wantActor := "", "user", admin.String()
			if mode == "token" {
				bearer, wantType, wantActor = callerRaw, "api_key", callerID.String()
			}
			// Issue.
			st, body, corr := tokCall(t, url, bearer, auth.RoleAdmin, "POST", "/api/v1/tokens",
				map[string]any{"name": "aud-" + mode, "role_id": "viewer"})
			if st != http.StatusCreated {
				t.Fatalf("%s: create token = %d %s", mode, st, body)
			}
			var created api.ApiTokenCreated
			_ = json.Unmarshal(body, &created)
			newID := uuid.UUID(created.ApiToken.Id).String()
			iss := tokOnlyAction(t, tokAuditRowsFor(t, pool, corr), "auth.api_token.issued")
			if len(iss) != 1 {
				t.Fatalf("%s: auth.api_token.issued rows = %d, want 1", mode, len(iss))
			}
			e := iss[0]
			if e.ActorType != wantType || e.ActorID != wantActor {
				t.Errorf("%s issue: actor = %s/%s, want %s/%s", mode, e.ActorType, e.ActorID, wantType, wantActor)
			}
			if mode == "token" && e.ActorID == admin.String() {
				t.Errorf("token issue: actor is the owner, want the calling token")
			}
			if e.ResourceType != "api_token" || e.ResourceID != newID {
				t.Errorf("%s issue: resource = %s/%s, want api_token/%s", mode, e.ResourceType, e.ResourceID, newID)
			}
			if k := tokDetailKeys(e.Detail); k != "expires_at,name,prefix,role_id" {
				t.Errorf("%s issue: detail keys = %s, want expires_at,name,prefix,role_id", mode, k)
			}
			if e.Detail["role_id"] != "viewer" || e.Detail["name"] != "aud-"+mode || e.Detail["prefix"] != created.ApiToken.Prefix {
				t.Errorf("%s issue: detail = %v", mode, e.Detail)
			}

			// Revoke.
			st, body, corr = tokCall(t, url, bearer, auth.RoleAdmin, "DELETE", "/api/v1/tokens/"+newID, nil)
			if st != http.StatusNoContent {
				t.Fatalf("%s: revoke = %d %s", mode, st, body)
			}
			rev := tokOnlyAction(t, tokAuditRowsFor(t, pool, corr), "auth.api_token.revoked")
			if len(rev) != 1 {
				t.Fatalf("%s: auth.api_token.revoked rows = %d, want 1", mode, len(rev))
			}
			if rev[0].ActorType != wantType || rev[0].ActorID != wantActor || rev[0].ResourceID != newID {
				t.Errorf("%s revoke: actor %s/%s resource %s, want %s/%s and %s",
					mode, rev[0].ActorType, rev[0].ActorID, rev[0].ResourceID, wantType, wantActor, newID)
			}

			// Nothing changes on a second revoke or an unknown id: still 204,
			// and no event.
			for _, id := range []string{newID, uuid.NewString()} {
				st, _, corr = tokCall(t, url, bearer, auth.RoleAdmin, "DELETE", "/api/v1/tokens/"+id, nil)
				if st != http.StatusNoContent {
					t.Errorf("%s: idempotent revoke of %s = %d, want 204", mode, id, st)
				}
				if n := len(tokOnlyAction(t, tokAuditRowsFor(t, pool, corr), "auth.api_token.revoked")); n != 0 {
					t.Errorf("%s: revoke that changed nothing emitted %d events, want 0", mode, n)
				}
			}
		}
	})
}

// @ac AC-15
func TestAPITokenIssue_AuditRowCarriesNoSecret(t *testing.T) {
	t.Run("system-api-tokens/AC-15", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		callerRaw, _ := mintTokenAs(t, url, auth.RoleAdmin, auth.RoleAdmin)
		for _, bearer := range []string{"", callerRaw} {
			st, body, corr := tokCall(t, url, bearer, auth.RoleAdmin, "POST", "/api/v1/tokens",
				map[string]any{"name": "secret-scan", "role_id": "viewer"})
			if st != http.StatusCreated {
				t.Fatalf("create = %d %s", st, body)
			}
			var created api.ApiTokenCreated
			_ = json.Unmarshal(body, &created)
			raw := created.Token
			if !strings.HasPrefix(raw, auth.APITokenPrefix) || len(raw) <= len(created.ApiToken.Prefix) {
				t.Fatalf("unexpected token shape")
			}
			sum := sha256.Sum256([]byte(raw))
			forbidden := map[string]string{
				"raw token":              raw,
				"secret beyond prefix":   raw[len(created.ApiToken.Prefix):],
				"sha256 hex":             hex.EncodeToString(sum[:]),
				"sha256 base64":          base64.StdEncoding.EncodeToString(sum[:]),
				"sha256 base64url":       base64.RawURLEncoding.EncodeToString(sum[:]),
				"postgres bytea of hash": `\\x` + hex.EncodeToString(sum[:]),
			}
			rows := tokAuditRowsFor(t, pool, corr)
			if len(tokOnlyAction(t, rows, "auth.api_token.issued")) != 1 {
				t.Fatalf("no issued event to scan")
			}
			for _, r := range rows {
				for what, v := range forbidden {
					if strings.Contains(r.Raw, v) {
						t.Errorf("audit row %s contains the %s", r.Action, what)
					}
				}
			}
		}
	})
}
