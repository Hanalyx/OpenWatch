// @spec system-api-tokens
//
// AC traceability (DSN-gated like every api_*_test in this package):
//
//	AC-08  TestTokenWrites_RecordOwner_NotToken
//	AC-09  TestTokenSeparationOfDuties_OwnerSessionAndOwnedTokens
//	AC-10  TestTokenSelfDisable_GuardHolds
//	AC-11  TestTokenSelfService_Refused403
//	AC-12  TestTokenPermissions_NeverInheritOwner
//
// bugs/OW-098: handlers wrote auth.Identity.ID into users-referencing
// columns and compared it in "acting on yourself" rules. On an API token ID
// is the token's own id, so writes failed and self guards were bypassed.
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/alertrouter"
	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/license"
	"github.com/Hanalyx/openwatch/internal/notifyfeed"
	"github.com/Hanalyx/openwatch/internal/server/api"
)

// mintTokenAs issues a real owk_ token through the API, created by the
// fixture user holding creator, carrying tokenRole.
func mintTokenAs(t *testing.T, url string, creator, tokenRole auth.RoleID) (string, uuid.UUID) {
	t.Helper()
	resp := doReq(t, asRole(t, "POST", url+"/api/v1/tokens", creator,
		map[string]any{"name": "t-" + uuid.NewString()[:8], "role_id": string(tokenRole)}))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("mint %s token as %s = %d %s", tokenRole, creator, resp.StatusCode, b)
	}
	var created api.ApiTokenCreated
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode token: %v", err)
	}
	return created.Token, uuid.UUID(created.ApiToken.Id)
}

// bearerDo sends one request with an owk_ bearer and returns status, the
// error code (if any) and the decoded body.
func bearerDo(t *testing.T, url, raw, method, path string, body any) (int, string, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		bs, _ := json.Marshal(body)
		rdr = bytes.NewReader(bs)
	}
	req, err := http.NewRequest(method, url+path, rdr)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+raw)
	req.Header.Set("Idempotency-Key", "k-"+uuid.NewString())
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp := doReq(t, req)
	defer resp.Body.Close()
	return decodeStatus(t, resp)
}

func sessionDo(t *testing.T, url string, role auth.RoleID, method, path string, body any) (int, string, map[string]any) {
	t.Helper()
	req := asRole(t, method, url+path, role, body)
	req.Header.Set("Idempotency-Key", "k-"+uuid.NewString())
	resp := doReq(t, req)
	defer resp.Body.Close()
	return decodeStatus(t, resp)
}

func decodeStatus(t *testing.T, resp *http.Response) (int, string, map[string]any) {
	t.Helper()
	b, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	code := ""
	if e, ok := m["error"].(map[string]any); ok {
		code, _ = e["code"].(string)
	}
	return resp.StatusCode, code, m
}

func queryUUID(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) *uuid.UUID {
	t.Helper()
	var v *uuid.UUID
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&v); err != nil {
		t.Fatalf("query %q: %v", sql, err)
	}
	return v
}

func queryString(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) string {
	t.Helper()
	var v string
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&v); err != nil {
		t.Fatalf("query %q: %v", sql, err)
	}
	return v
}

func wantOwner(t *testing.T, what string, got *uuid.UUID, owner, token uuid.UUID) {
	t.Helper()
	switch {
	case got == nil:
		t.Errorf("%s = NULL, want the token's owner %s", what, owner)
	case *got == token:
		t.Errorf("%s is the token's own id; it must be the owner %s", what, owner)
	case *got != owner:
		t.Errorf("%s = %s, want the token's owner %s", what, *got, owner)
	}
}

// @ac AC-08
func TestTokenWrites_RecordOwner_NotToken(t *testing.T) {
	t.Run("system-api-tokens/AC-08", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		defer license.EnableFeatureForTesting(license.ComplianceAttestation)()
		ctx := context.Background()
		owner := roleUserIDs[auth.RoleAdmin]
		raw, tokenID := mintTokenAs(t, url, auth.RoleAdmin, auth.RoleAdmin)
		hostID := seedHostForIntel(t, pool)

		expect := func(what string, st int, code string, want int) {
			t.Helper()
			if st != want {
				t.Fatalf("%s: status %d (%s), want %d (OW-098 answered 400/500)", what, st, code, want)
			}
		}

		st, code, _ := bearerDo(t, url, raw, "POST", "/api/v1/hosts", map[string]any{"hostname": "tok-host", "ip_address": "192.0.2.61", "environment": "production"})
		expect("POST /hosts", st, code, http.StatusCreated)
		wantOwner(t, "hosts.created_by", queryUUID(t, pool, `SELECT created_by FROM hosts WHERE hostname = 'tok-host'`), owner, tokenID)

		st, code, cred := bearerDo(t, url, raw, "POST", "/api/v1/credentials", map[string]any{"scope": "system", "name": "tok-cred", "username": "u", "auth_method": "password", "password": "pw-1"})
		expect("POST /credentials", st, code, http.StatusCreated)
		wantOwner(t, "credentials.created_by", queryUUID(t, pool, `SELECT created_by FROM credentials WHERE name = 'tok-cred'`), owner, tokenID)
		credID, _ := cred["id"].(string)

		st, code, _ = bearerDo(t, url, raw, "POST", "/api/v1/credentials/"+credID+":clone", map[string]any{"scope": "host", "scope_id": hostID.String(), "name": "tok-clone"})
		expect("POST /credentials/{id}:clone", st, code, http.StatusCreated)
		wantOwner(t, "clone created_by", queryUUID(t, pool, `SELECT created_by FROM credentials WHERE name = 'tok-clone'`), owner, tokenID)

		viewer := roleUserIDs[auth.RoleViewer]
		st, code, _ = bearerDo(t, url, raw, "POST", "/api/v1/users/"+viewer.String()+"/roles:assign", map[string]any{"role_id": "ops_lead"})
		expect("POST /users/{id}/roles:assign", st, code, http.StatusNoContent)
		wantOwner(t, "user_roles.granted_by", queryUUID(t, pool, `SELECT granted_by FROM user_roles WHERE user_id = $1 AND role_id = 'ops_lead'`, viewer), owner, tokenID)

		st, code, _ = bearerDo(t, url, raw, "PUT", "/api/v1/auth-policy", map[string]any{"require_mfa": false, "session_idle_timeout_seconds": 1700, "session_absolute_timeout_seconds": 86400})
		expect("PUT /auth-policy", st, code, http.StatusOK)
		wantOwner(t, "auth_policy.updated_by", queryUUID(t, pool, `SELECT updated_by FROM auth_policy LIMIT 1`), owner, tokenID)

		st, code, _ = bearerDo(t, url, raw, "POST", "/api/v1/sso/providers", map[string]any{"name": "tok-idp", "issuer": "https://idp.example.com", "client_id": "abc", "client_secret": "shh-t", "default_role": "viewer"})
		expect("POST /sso/providers", st, code, http.StatusCreated)
		wantOwner(t, "sso_providers.created_by", queryUUID(t, pool, `SELECT created_by FROM sso_providers WHERE name = 'tok-idp'`), owner, tokenID)

		st, code, _ = bearerDo(t, url, raw, "POST", "/api/v1/tokens", map[string]any{"name": "tok-child", "role_id": "viewer"})
		expect("POST /tokens", st, code, http.StatusCreated)
		wantOwner(t, "api_tokens.created_by", queryUUID(t, pool, `SELECT created_by FROM api_tokens WHERE name = 'tok-child'`), owner, tokenID)

		st, code, exc := bearerDo(t, url, raw, "POST", "/api/v1/hosts/"+hostID.String()+"/exceptions", map[string]any{"rule_id": "tok-rule", "reason": "accepted"})
		expect("POST /hosts/{id}/exceptions", st, code, http.StatusCreated)
		excID, _ := exc["id"].(string)
		wantOwner(t, "compliance_exceptions.requested_by", queryUUID(t, pool, `SELECT requested_by FROM compliance_exceptions WHERE id = $1`, excID), owner, tokenID)

		// Review a request someone else opened, so separation of duties allows it.
		_, _, other := sessionDo(t, url, auth.RoleOpsLead, "POST", "/api/v1/hosts/"+hostID.String()+"/exceptions", map[string]any{"rule_id": "tok-rule-2", "reason": "x"})
		otherID, _ := other["id"].(string)
		st, code, _ = bearerDo(t, url, raw, "POST", "/api/v1/exceptions/"+otherID+":approve", map[string]any{})
		expect("POST /exceptions/{id}:approve", st, code, http.StatusOK)
		wantOwner(t, "compliance_exceptions.reviewed_by", queryUUID(t, pool, `SELECT reviewed_by FROM compliance_exceptions WHERE id = $1`, otherID), owner, tokenID)

		_, _, other2 := sessionDo(t, url, auth.RoleOpsLead, "POST", "/api/v1/hosts/"+hostID.String()+"/exceptions", map[string]any{"rule_id": "tok-rule-3", "reason": "x"})
		other2ID, _ := other2["id"].(string)
		st, code, _ = bearerDo(t, url, raw, "POST", "/api/v1/exceptions/"+other2ID+":reject", map[string]any{"note": "no"})
		expect("POST /exceptions/{id}:reject", st, code, http.StatusOK)
		wantOwner(t, "reject reviewed_by", queryUUID(t, pool, `SELECT reviewed_by FROM compliance_exceptions WHERE id = $1`, other2ID), owner, tokenID)

		st, code, rem := bearerDo(t, url, raw, "POST", "/api/v1/remediation/requests", map[string]any{"host_id": hostID.String(), "rule_id": "tok-rem"})
		expect("POST /remediation/requests", st, code, http.StatusCreated)
		remID, _ := rem["id"].(string)
		wantOwner(t, "remediation_requests.requested_by", queryUUID(t, pool, `SELECT requested_by FROM remediation_requests WHERE id = $1`, remID), owner, tokenID)

		// A pending request opened by another user, reviewed by the token.
		_, _, prem := sessionDo(t, url, auth.RoleOpsLead, "POST", "/api/v1/remediation/requests", map[string]any{"host_id": hostID.String(), "rule_id": "tok-rem-2"})
		premID, _ := prem["id"].(string)
		if _, err := pool.Exec(ctx, `UPDATE remediation_requests SET status = 'pending_approval', reviewed_by = NULL, reviewed_at = NULL, review_note = NULL WHERE id = $1`, premID); err != nil {
			t.Fatalf("seed pending: %v", err)
		}
		st, code, _ = bearerDo(t, url, raw, "POST", "/api/v1/remediation/requests/"+premID+":approve", map[string]any{})
		expect("POST /remediation/requests/{rid}:approve", st, code, http.StatusOK)
		wantOwner(t, "remediation reviewed_by", queryUUID(t, pool, `SELECT reviewed_by FROM remediation_requests WHERE id = $1`, premID), owner, tokenID)

		aid := seedAlertRow(t, pool, alertrouter.AlertTypeHostUnreachable, alertrouter.SeverityHigh, uuid.Nil, time.Now().UTC())
		st, code, _ = bearerDo(t, url, raw, "POST", "/api/v1/alerts/"+aid.String()+":acknowledge", map[string]any{"reason": "seen"})
		expect("POST /alerts/{id}:acknowledge", st, code, http.StatusOK)
		wantOwner(t, "alerts.acknowledged_by", queryUUID(t, pool, `SELECT acknowledged_by FROM alerts WHERE id = $1`, aid), owner, tokenID)

		aid2 := seedAlertRow(t, pool, alertrouter.AlertTypeHostUnreachable, alertrouter.SeverityHigh, uuid.Nil, time.Now().UTC())
		st, code, _ = bearerDo(t, url, raw, "POST", "/api/v1/alerts/"+aid2.String()+":resolve", map[string]any{"reason": "fixed"})
		expect("POST /alerts/{id}:resolve", st, code, http.StatusOK)
		wantOwner(t, "alerts.resolved_by", queryUUID(t, pool, `SELECT resolved_by FROM alerts WHERE id = $1`, aid2), owner, tokenID)

		chID := uuid.New()
		if _, err := pool.Exec(ctx, `INSERT INTO notification_channels (id, type, name, enabled, config_ciphertext) VALUES ($1, 'email', 'tok-ch', true, $2)`, chID, []byte("x")); err != nil {
			t.Fatalf("seed channel: %v", err)
		}
		st, code, _ = bearerDo(t, url, raw, "POST", "/api/v1/reports/schedules", map[string]any{"name": "tok-sched", "kind": "attestation", "framework": "cis_rhel9", "frequency": "daily", "channel_id": chID.String()})
		expect("POST /reports/schedules", st, code, http.StatusCreated)
		wantOwner(t, "report_schedules.created_by", queryUUID(t, pool, `SELECT created_by FROM report_schedules WHERE name = 'tok-sched'`), owner, tokenID)
	})
}

// @ac AC-09
func TestTokenSeparationOfDuties_OwnerSessionAndOwnedTokens(t *testing.T) {
	t.Run("system-api-tokens/AC-09", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()
		hostID := seedHostForIntel(t, pool)
		// security_admin holds both request and approve for exceptions and
		// remediation, so every refusal below is separation of duties, not
		// a missing permission.
		owner := roleUserIDs[auth.RoleSecurityAdmin]
		tokA, _ := mintTokenAs(t, url, auth.RoleSecurityAdmin, auth.RoleSecurityAdmin)
		tokB, _ := mintTokenAs(t, url, auth.RoleSecurityAdmin, auth.RoleSecurityAdmin)
		independent := roleUserIDs[auth.RoleAdmin]

		status := func(table, id string) string {
			return queryString(t, pool, `SELECT status FROM `+table+` WHERE id = $1`, id)
		}

		// --- exceptions ---
		mkExcByToken := func(rule string) string {
			st, code, b := bearerDo(t, url, tokA, "POST", "/api/v1/hosts/"+hostID.String()+"/exceptions", map[string]any{"rule_id": rule, "reason": "r"})
			if st != http.StatusCreated {
				t.Fatalf("token A request exception = %d %s", st, code)
			}
			id, _ := b["id"].(string)
			return id
		}
		e1 := mkExcByToken("sod-1")
		if got := queryUUID(t, pool, `SELECT requested_by FROM compliance_exceptions WHERE id = $1`, e1); got == nil || *got != owner {
			t.Fatalf("requested_by = %v, want owner %s", got, owner)
		}
		if st, code, _ := bearerDo(t, url, tokB, "POST", "/api/v1/exceptions/"+e1+":approve", map[string]any{}); st != http.StatusConflict || code != "exceptions.self_review" {
			t.Errorf("another token of the same owner approving = %d %s, want 409 exceptions.self_review", st, code)
		}
		if st, code, _ := bearerDo(t, url, tokA, "POST", "/api/v1/exceptions/"+e1+":approve", map[string]any{}); st != http.StatusConflict || code != "exceptions.self_review" {
			t.Errorf("the requesting token approving = %d %s, want 409", st, code)
		}
		if st, code, _ := sessionDo(t, url, auth.RoleSecurityAdmin, "POST", "/api/v1/exceptions/"+e1+":approve", map[string]any{}); st != http.StatusConflict || code != "exceptions.self_review" {
			t.Errorf("the owner's session approving a request its token opened = %d %s, want 409", st, code)
		}
		if s := status("compliance_exceptions", e1); s != "requested" {
			t.Errorf("after refused self-reviews status = %s, want requested", s)
		}
		// The owner's session opens one; the owner's token may not review it.
		_, _, sb := sessionDo(t, url, auth.RoleSecurityAdmin, "POST", "/api/v1/hosts/"+hostID.String()+"/exceptions", map[string]any{"rule_id": "sod-2", "reason": "r"})
		e2, _ := sb["id"].(string)
		if st, code, _ := bearerDo(t, url, tokA, "POST", "/api/v1/exceptions/"+e2+":reject", map[string]any{"note": "n"}); st != http.StatusConflict || code != "exceptions.self_review" {
			t.Errorf("owner's token rejecting the owner's session request = %d %s, want 409", st, code)
		}
		// An independent authorized user approves.
		if st, code, _ := sessionDo(t, url, auth.RoleAdmin, "POST", "/api/v1/exceptions/"+e1+":approve", map[string]any{}); st != http.StatusOK {
			t.Fatalf("independent approval = %d %s, want 200", st, code)
		}
		if s := status("compliance_exceptions", e1); s != "approved" {
			t.Errorf("after independent approval status = %s, want approved", s)
		}
		if got := queryUUID(t, pool, `SELECT reviewed_by FROM compliance_exceptions WHERE id = $1`, e1); got == nil || *got != independent {
			t.Errorf("reviewed_by = %v, want the independent reviewer %s", got, independent)
		}

		// --- remediation (pending_approval is the licensed track; seeded) ---
		st, code, rb := bearerDo(t, url, tokA, "POST", "/api/v1/remediation/requests", map[string]any{"host_id": hostID.String(), "rule_id": "sod-rem"})
		if st != http.StatusCreated {
			t.Fatalf("token A remediation request = %d %s", st, code)
		}
		r1, _ := rb["id"].(string)
		if _, err := pool.Exec(ctx, `UPDATE remediation_requests SET status = 'pending_approval', reviewed_by = NULL, reviewed_at = NULL, review_note = NULL WHERE id = $1`, r1); err != nil {
			t.Fatalf("seed pending: %v", err)
		}
		if st, code, _ := bearerDo(t, url, tokB, "POST", "/api/v1/remediation/requests/"+r1+":approve", map[string]any{}); st != http.StatusConflict || code != "remediation.self_review" {
			t.Errorf("another token of the same owner approving remediation = %d %s, want 409 remediation.self_review", st, code)
		}
		if st, code, _ := sessionDo(t, url, auth.RoleSecurityAdmin, "POST", "/api/v1/remediation/requests/"+r1+":reject", map[string]any{}); st != http.StatusConflict || code != "remediation.self_review" {
			t.Errorf("the owner's session rejecting = %d %s, want 409", st, code)
		}
		if s := status("remediation_requests", r1); s != "pending_approval" {
			t.Errorf("after refused self-reviews remediation status = %s, want pending_approval", s)
		}
		if st, code, _ := sessionDo(t, url, auth.RoleAdmin, "POST", "/api/v1/remediation/requests/"+r1+":approve", map[string]any{}); st != http.StatusOK {
			t.Fatalf("independent remediation approval = %d %s, want 200", st, code)
		}
		if got := queryUUID(t, pool, `SELECT reviewed_by FROM remediation_requests WHERE id = $1`, r1); got == nil || *got != independent {
			t.Errorf("remediation reviewed_by = %v, want %s", got, independent)
		}
	})
}

// @ac AC-10
func TestTokenSelfDisable_GuardHolds(t *testing.T) {
	t.Run("system-api-tokens/AC-10", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		owner := roleUserIDs[auth.RoleAdmin]
		raw, tokenID := mintTokenAs(t, url, auth.RoleAdmin, auth.RoleAdmin)

		st, code, _ := bearerDo(t, url, raw, "POST", "/api/v1/users/"+owner.String()+":disable", nil)
		if st != http.StatusConflict || code != "users.cannot_disable_self" {
			t.Errorf("token disabling its own owner = %d %s, want 409 users.cannot_disable_self (OW-098 answered 200)", st, code)
		}
		var disabled bool
		if err := pool.QueryRow(context.Background(), `SELECT disabled_at IS NOT NULL FROM users WHERE id = $1`, owner).Scan(&disabled); err != nil {
			t.Fatalf("read owner: %v", err)
		}
		if disabled {
			t.Error("the owner was disabled by their own token")
		}
		if st, _, _ := bearerDo(t, url, raw, "GET", "/api/v1/hosts", nil); st != http.StatusOK {
			t.Errorf("the token afterwards = %d, want 200 (owner still enabled)", st)
		}

		// A password reset of the owner by the owner's token is recorded as
		// self. The actor stays the token.
		corr := "selfreset-" + uuid.NewString()[:12]
		req, _ := http.NewRequest("POST", url+"/api/v1/users/"+owner.String()+":reset-password", bytes.NewReader([]byte(`{"new_password":"Owner-Reset-Pass-2026!"}`)))
		req.Header.Set("Authorization", "Bearer "+raw)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Correlation-Id", corr)
		req.Header.Set("Idempotency-Key", "k-"+uuid.NewString())
		resp := doReq(t, req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("token reset of owner's password = %d, want 204", resp.StatusCode)
		}
		deadline := time.Now().Add(3 * time.Second)
		var self, actor string
		for {
			err := pool.QueryRow(context.Background(), `SELECT detail->>'self', COALESCE(actor_id,'') FROM audit_events
				WHERE action = 'admin.user.password_reset' AND correlation_id = $1`, corr).Scan(&self, &actor)
			if err == nil || time.Now().After(deadline) {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if self != "true" {
			t.Errorf("password_reset detail.self = %q, want true for the owner's own token", self)
		}
		if actor != tokenID.String() {
			t.Errorf("password_reset actor = %q, want the token %s (the actor is the principal)", actor, tokenID)
		}
	})
}

// @ac AC-11
func TestTokenSelfService_Refused403(t *testing.T) {
	t.Run("system-api-tokens/AC-11", func(t *testing.T) {
		url, pool, srv := freshAPIServerWithHandles(t)
		srv.WithNotifyFeed(notifyfeed.NewStore(pool))
		ctx := context.Background()
		owner := roleUserIDs[auth.RoleAdmin]
		raw, _ := mintTokenAs(t, url, auth.RoleAdmin, auth.RoleAdmin)

		if err := notifyfeed.NewStore(pool).Record(ctx, notifyfeed.Notification{UserID: owner, Kind: "t", Severity: "info", Title: "owner item", GroupKey: "ac11"}); err != nil {
			t.Fatalf("seed feed: %v", err)
		}
		var nid uuid.UUID
		if err := pool.QueryRow(ctx, `SELECT id FROM notifications WHERE user_id = $1 AND group_key = 'ac11'`, owner).Scan(&nid); err != nil {
			t.Fatalf("read feed item: %v", err)
		}
		before := queryString(t, pool, `SELECT COALESCE(display_name,'') || '|' || preferences::text FROM users WHERE id = $1`, owner)

		cases := []struct {
			method, path string
			body         any
		}{
			{"GET", "/api/v1/auth/me", nil},
			{"PATCH", "/api/v1/auth/me", map[string]any{"display_name": "changed-by-token"}},
			{"POST", "/api/v1/auth/mfa:enroll", nil},
			{"POST", "/api/v1/auth/mfa:verify", map[string]any{"otp": "123456"}},
			{"POST", "/api/v1/auth/password:change", map[string]any{"current_password": "x", "new_password": "Token-Should-Not-2026!"}},
			{"GET", "/api/v1/users/me/preferences", nil},
			{"PATCH", "/api/v1/users/me/preferences", map[string]any{"hosts_view_default": "table"}},
			{"GET", "/api/v1/notifications/feed", nil},
			{"POST", "/api/v1/notifications/feed:read-all", nil},
			{"POST", "/api/v1/notifications/feed/" + nid.String() + ":read", nil},
		}
		for _, c := range cases {
			st, code, body := bearerDo(t, url, raw, c.method, c.path, c.body)
			if st != http.StatusForbidden || code != "auth.api_token_not_allowed" {
				t.Errorf("%s %s with a token = %d %s, want 403 auth.api_token_not_allowed", c.method, c.path, st, code)
			}
			if items, ok := body["items"]; ok {
				t.Errorf("%s %s returned feed items to a token: %v", c.method, c.path, items)
			}
		}

		if after := queryString(t, pool, `SELECT COALESCE(display_name,'') || '|' || preferences::text FROM users WHERE id = $1`, owner); after != before {
			t.Errorf("owner profile/preferences changed: %q -> %q", before, after)
		}
		var mfaRows, readRows int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM auth_mfa_secrets WHERE user_id = $1`, owner).Scan(&mfaRows)
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE id = $1 AND read_at IS NOT NULL`, nid).Scan(&readRows)
		if mfaRows != 0 || readRows != 0 {
			t.Errorf("owner state changed: mfa rows %d, feed item read %d; want 0/0", mfaRows, readRows)
		}

		// Sessions are unaffected.
		if st, _, _ := sessionDo(t, url, auth.RoleAdmin, "GET", "/api/v1/auth/me", nil); st != http.StatusOK {
			t.Errorf("owner's session GET /auth/me = %d, want 200", st)
		}
		if st, _, b := sessionDo(t, url, auth.RoleAdmin, "GET", "/api/v1/notifications/feed", nil); st != http.StatusOK {
			t.Errorf("owner's session GET feed = %d, want 200", st)
		} else if items, _ := b["items"].([]any); len(items) != 1 {
			t.Errorf("owner's session sees %d feed items, want 1", len(items))
		}
	})
}

// @ac AC-12
func TestTokenPermissions_NeverInheritOwner(t *testing.T) {
	t.Run("system-api-tokens/AC-12", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)
		// An admin owns an ops_lead token. The admin holds every permission
		// below; the token's role holds none of them.
		raw, _ := mintTokenAs(t, url, auth.RoleAdmin, auth.RoleOpsLead)
		_, _, ex := sessionDo(t, url, auth.RoleOpsLead, "POST", "/api/v1/hosts/"+hostID.String()+"/exceptions", map[string]any{"rule_id": "perm-1", "reason": "r"})
		excID, _ := ex["id"].(string)
		viewer := roleUserIDs[auth.RoleViewer]

		denied := []struct {
			method, path string
			body         any
		}{
			{"PUT", "/api/v1/auth-policy", map[string]any{"require_mfa": true, "session_idle_timeout_seconds": 600, "session_absolute_timeout_seconds": 86400}},
			{"POST", "/api/v1/credentials", map[string]any{"scope": "system", "name": "perm-cred", "username": "u", "auth_method": "password", "password": "pw"}},
			{"POST", "/api/v1/exceptions/" + excID + ":approve", map[string]any{}},
			{"POST", "/api/v1/users/" + viewer.String() + "/roles:assign", map[string]any{"role_id": "admin"}},
			{"POST", "/api/v1/users/" + viewer.String() + ":disable", nil},
			{"POST", "/api/v1/tokens", map[string]any{"name": "perm-child", "role_id": "admin"}},
		}
		for _, d := range denied {
			if st, code, _ := bearerDo(t, url, raw, d.method, d.path, d.body); st != http.StatusForbidden {
				t.Errorf("ops_lead token owned by admin: %s %s = %d %s, want 403", d.method, d.path, st, code)
			}
		}
		// Nothing those requests would have changed did change.
		var n int
		_ = pool.QueryRow(context.Background(), `SELECT count(*) FROM credentials WHERE name = 'perm-cred'`).Scan(&n)
		if n != 0 {
			t.Errorf("credential created by an under-privileged token")
		}
		if s := queryString(t, pool, `SELECT status FROM compliance_exceptions WHERE id = $1`, excID); s != "requested" {
			t.Errorf("exception status = %s, want requested", s)
		}
		// Within its own role the token works, and records its owner.
		if st, code, _ := bearerDo(t, url, raw, "POST", "/api/v1/hosts", map[string]any{"hostname": "perm-host", "ip_address": "192.0.2.62", "environment": "production"}); st != http.StatusCreated {
			t.Errorf("ops_lead token POST /hosts = %d %s, want 201", st, code)
		}
	})
}
