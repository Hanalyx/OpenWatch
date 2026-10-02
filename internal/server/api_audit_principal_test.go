// @spec system-audit-emission
//
// AC traceability (DSN-gated like every api_*_test in this package):
//
//	AC-21  TestAuditPrincipal_EveryEventNamesTheCaller
//	AC-22  TestAuditPrincipal_PermissionDeniedNamesTheCaller
//	AC-23  TestAuditPrincipal_FilterAndExportFindTokenActions
//
// bugs/OW-100: events emitted by services recorded a token's action as its
// owner (the accountable user they also store as requester or reviewer),
// and events emitted with a hardcoded "user" type filed every token action
// under actor_type=user, so filtering on api_key returned nothing.
package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/alertrouter"
	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/license"
)

// principalCase is one request and the audit actions it must produce. Every
// row for those actions under the request's correlation id must name the
// caller as the actor.
type principalCase struct {
	name    string
	actions []string
	run     func(t *testing.T, env principalEnv, c auditCaller) (corr string, status int)
	want    int
}

type principalEnv struct {
	url   string
	pool  *pgxpool.Pool
	admin auditCaller
	host  string
}

func idOf(m map[string]any) string { s, _ := m["id"].(string); return s }

func principalCases() []principalCase {
	// An exception opened by another user, so the admin's session or token
	// may review it under separation of duties.
	excByOther := func(t *testing.T, env principalEnv, rule string) string {
		t.Helper()
		r := doReq(t, asRole(t, "POST", env.url+"/api/v1/hosts/"+env.host+"/exceptions", auth.RoleOpsLead, map[string]any{"rule_id": rule, "reason": "r"}))
		defer r.Body.Close()
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		return idOf(b)
	}
	pendingByOther := func(t *testing.T, env principalEnv, rule string) string {
		t.Helper()
		r := doReq(t, asRole(t, "POST", env.url+"/api/v1/remediation/requests", auth.RoleOpsLead, map[string]any{"host_id": env.host, "rule_id": rule}))
		defer r.Body.Close()
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		id := idOf(b)
		if _, err := env.pool.Exec(context.Background(), `UPDATE remediation_requests SET status = 'pending_approval', reviewed_by = NULL, reviewed_at = NULL, review_note = NULL WHERE id = $1`, id); err != nil {
			t.Fatalf("seed pending: %v", err)
		}
		return id
	}
	alert := func(t *testing.T, env principalEnv) string {
		t.Helper()
		return seedAlertRow(t, env.pool, alertrouter.AlertTypeHostUnreachable, alertrouter.SeverityHigh, uuid.Nil, time.Now().UTC()).String()
	}
	tag := func(c auditCaller, s string) string { return s + "-" + c.mode }
	return []principalCase{
		{"system config (compliance)", []string{"system.config.changed"}, func(t *testing.T, env principalEnv, c auditCaller) (string, int) {
			st, _, corr := c.call(t, env.url, "PUT", "/api/v1/system/compliance/config", map[string]any{"default_framework": "cis_rhel9"})
			return corr, st
		}, 200},
		{"system config (scan)", []string{"system.config.changed"}, func(t *testing.T, env principalEnv, c auditCaller) (string, int) {
			_, cur, _ := env.admin.call(t, env.url, "GET", "/api/v1/system/scan/config", nil)
			st, _, corr := c.call(t, env.url, "PUT", "/api/v1/system/scan/config", cur)
			return corr, st
		}, 200},
		{"scan queued", []string{"scan.queued"}, func(t *testing.T, env principalEnv, c auditCaller) (string, int) {
			h := seedHostForIntel(t, env.pool)
			st, _, corr := c.call(t, env.url, "POST", "/api/v1/hosts/"+h.String()+"/scans", nil)
			return corr, st
		}, 202},
		{"report generated", []string{"report.generated"}, func(t *testing.T, env principalEnv, c auditCaller) (string, int) {
			st, _, corr := c.call(t, env.url, "POST", "/api/v1/reports:generate", map[string]any{})
			return corr, st
		}, 201},
		{"report schedule created", []string{"report.schedule.created"}, func(t *testing.T, env principalEnv, c auditCaller) (string, int) {
			st, _, corr := c.call(t, env.url, "POST", "/api/v1/reports/schedules", scheduleBody(t, env, tag(c, "sch-c")))
			return corr, st
		}, 201},
		{"report schedule toggled", []string{"report.schedule.toggled"}, func(t *testing.T, env principalEnv, c auditCaller) (string, int) {
			_, b, _ := env.admin.call(t, env.url, "POST", "/api/v1/reports/schedules", scheduleBody(t, env, tag(c, "sch-t")))
			st, _, corr := c.call(t, env.url, "PATCH", "/api/v1/reports/schedules/"+idOf(b), map[string]any{"enabled": false})
			return corr, st
		}, 200},
		{"report schedule deleted", []string{"report.schedule.deleted"}, func(t *testing.T, env principalEnv, c auditCaller) (string, int) {
			_, b, _ := env.admin.call(t, env.url, "POST", "/api/v1/reports/schedules", scheduleBody(t, env, tag(c, "sch-d")))
			st, _, corr := c.call(t, env.url, "DELETE", "/api/v1/reports/schedules/"+idOf(b), nil)
			return corr, st
		}, 204},
		{"remediation execute intent", []string{"remediation.executed"}, func(t *testing.T, env principalEnv, c auditCaller) (string, int) {
			_, b, _ := env.admin.call(t, env.url, "POST", "/api/v1/remediation/requests", map[string]any{"host_id": env.host, "rule_id": tag(c, "rem-x")})
			st, _, corr := c.call(t, env.url, "POST", "/api/v1/remediation/requests/"+idOf(b)+":execute", map[string]any{})
			return corr, st
		}, 202},
		{"diagnostics echo", []string{"integration.plugin.executed"}, func(t *testing.T, env principalEnv, c auditCaller) (string, int) {
			st, _, corr := c.call(t, env.url, "POST", "/api/v1/diagnostics:echo", map[string]any{"message": "m"})
			return corr, st
		}, 200},
		{"exception requested", []string{"compliance.exception.requested"}, func(t *testing.T, env principalEnv, c auditCaller) (string, int) {
			st, _, corr := c.call(t, env.url, "POST", "/api/v1/hosts/"+env.host+"/exceptions", map[string]any{"rule_id": tag(c, "x-req"), "reason": "r"})
			return corr, st
		}, 201},
		{"exception approved", []string{"compliance.exception.approved"}, func(t *testing.T, env principalEnv, c auditCaller) (string, int) {
			st, _, corr := c.call(t, env.url, "POST", "/api/v1/exceptions/"+excByOther(t, env, tag(c, "x-app"))+":approve", map[string]any{})
			return corr, st
		}, 200},
		{"exception rejected", []string{"compliance.exception.rejected"}, func(t *testing.T, env principalEnv, c auditCaller) (string, int) {
			st, _, corr := c.call(t, env.url, "POST", "/api/v1/exceptions/"+excByOther(t, env, tag(c, "x-rej"))+":reject", map[string]any{"note": "n"})
			return corr, st
		}, 200},
		{"exception revoked", []string{"compliance.exception.revoked"}, func(t *testing.T, env principalEnv, c auditCaller) (string, int) {
			id := excByOther(t, env, tag(c, "x-rev"))
			_, _, _ = env.admin.call(t, env.url, "POST", "/api/v1/exceptions/"+id+":approve", map[string]any{})
			st, _, corr := c.call(t, env.url, "POST", "/api/v1/exceptions/"+id+":revoke", map[string]any{"note": "n"})
			return corr, st
		}, 200},
		{"remediation requested and auto-approved", []string{"remediation.requested", "remediation.approved"}, func(t *testing.T, env principalEnv, c auditCaller) (string, int) {
			st, _, corr := c.call(t, env.url, "POST", "/api/v1/remediation/requests", map[string]any{"host_id": env.host, "rule_id": tag(c, "rem-req")})
			return corr, st
		}, 201},
		{"remediation approved", []string{"remediation.approved"}, func(t *testing.T, env principalEnv, c auditCaller) (string, int) {
			st, _, corr := c.call(t, env.url, "POST", "/api/v1/remediation/requests/"+pendingByOther(t, env, tag(c, "rem-app"))+":approve", map[string]any{})
			return corr, st
		}, 200},
		{"remediation rejected", []string{"remediation.approved"}, func(t *testing.T, env principalEnv, c auditCaller) (string, int) {
			st, _, corr := c.call(t, env.url, "POST", "/api/v1/remediation/requests/"+pendingByOther(t, env, tag(c, "rem-rej"))+":reject", map[string]any{})
			return corr, st
		}, 200},
		{"alert acknowledged", []string{"alert.acknowledged"}, func(t *testing.T, env principalEnv, c auditCaller) (string, int) {
			st, _, corr := c.call(t, env.url, "POST", "/api/v1/alerts/"+alert(t, env)+":acknowledge", map[string]any{"reason": "r"})
			return corr, st
		}, 200},
		{"alert silenced", []string{"alert.silenced"}, func(t *testing.T, env principalEnv, c auditCaller) (string, int) {
			until := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
			st, _, corr := c.call(t, env.url, "POST", "/api/v1/alerts/"+alert(t, env)+":silence", map[string]any{"reason": "r", "until": until})
			return corr, st
		}, 200},
		{"alert resolved", []string{"alert.resolved"}, func(t *testing.T, env principalEnv, c auditCaller) (string, int) {
			st, _, corr := c.call(t, env.url, "POST", "/api/v1/alerts/"+alert(t, env)+":resolve", map[string]any{"reason": "r"})
			return corr, st
		}, 200},
		{"alert dismissed", []string{"alert.dismissed"}, func(t *testing.T, env principalEnv, c auditCaller) (string, int) {
			st, _, corr := c.call(t, env.url, "POST", "/api/v1/alerts/"+alert(t, env)+":dismiss", map[string]any{"reason": "r"})
			return corr, st
		}, 200},
	}
}

func scheduleBody(t *testing.T, env principalEnv, name string) map[string]any {
	t.Helper()
	ch := uuid.New()
	if _, err := env.pool.Exec(context.Background(), `INSERT INTO notification_channels (id, type, name, enabled, config_ciphertext) VALUES ($1, 'email', $3, true, $2)`, ch, []byte("x"), "ch-"+name); err != nil {
		t.Fatalf("seed channel: %v", err)
	}
	return map[string]any{"name": name, "kind": "attestation", "framework": "cis_rhel9", "frequency": "daily", "channel_id": ch.String()}
}

func runPrincipalCase(t *testing.T, env principalEnv, tc principalCase, c auditCaller, owner string) {
	t.Helper()
	corr, st := tc.run(t, env, c)
	if st != tc.want {
		t.Fatalf("%s as %s: status %d, want %d", tc.name, c.mode, st, tc.want)
	}
	for _, action := range tc.actions {
		rows := auditRowsFor(t, env.pool, corr, action)
		if len(rows) == 0 {
			t.Errorf("%s as %s: no %s row for the request", tc.name, c.mode, action)
			continue
		}
		for _, r := range rows {
			if r.ActorType != c.actorTyp || r.ActorID != c.actorID {
				t.Errorf("%s as %s: %s actor = %s/%s, want %s/%s", tc.name, c.mode, action, r.ActorType, r.ActorID, c.actorTyp, c.actorID)
			}
			if c.mode == "token" && r.ActorID == owner {
				t.Errorf("%s as token: %s names the token's owner as the actor (OW-100)", tc.name, action)
			}
		}
	}
}

// @ac AC-21
func TestAuditPrincipal_EveryEventNamesTheCaller(t *testing.T) {
	t.Run("system-audit-emission/AC-21", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		defer license.EnableFeatureForTesting(license.ComplianceAttestation)()
		owner := roleUserIDs[auth.RoleAdmin].String()
		admin := auditCaller{mode: "session", actorTyp: "user", actorID: owner}
		raw, tokenID := mintTokenAs(t, url, auth.RoleAdmin, auth.RoleAdmin)
		tok := auditCaller{mode: "token", bearer: raw, actorTyp: "api_key", actorID: tokenID.String()}
		env := principalEnv{url: url, pool: pool, admin: admin, host: seedHostForIntel(t, pool).String()}
		cases := principalCases()
		if len(cases) != 20 {
			t.Fatalf("cases = %d, want 20", len(cases))
		}
		for _, c := range []auditCaller{admin, tok} {
			for _, tc := range cases {
				t.Run(c.mode+"/"+tc.name, func(t *testing.T) { runPrincipalCase(t, env, tc, c, owner) })
			}
		}
	})
}

// @ac AC-22
func TestAuditPrincipal_PermissionDeniedNamesTheCaller(t *testing.T) {
	t.Run("system-audit-emission/AC-22", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		raw, lowID := mintTokenAs(t, url, auth.RoleAdmin, auth.RoleOpsLead)
		body := map[string]any{"require_mfa": true, "session_idle_timeout_seconds": 600, "session_absolute_timeout_seconds": 86400}
		for _, c := range []auditCaller{
			{mode: "token", bearer: raw, actorTyp: "api_key", actorID: lowID.String()},
		} {
			st, _, corr := c.call(t, url, "PUT", "/api/v1/auth-policy", body)
			if st != http.StatusForbidden {
				t.Fatalf("ops_lead token PUT /auth-policy = %d, want 403", st)
			}
			rows := auditRowsFor(t, pool, corr, "authz.permission.denied")
			if len(rows) != 1 || rows[0].ActorType != c.actorTyp || rows[0].ActorID != c.actorID {
				t.Errorf("token denial rows = %+v, want one %s/%s", rows, c.actorTyp, c.actorID)
			}
		}
		// A viewer session, denied the same way, is a user.
		corr := "ow100-deny-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
		req := asRole(t, "PUT", url+"/api/v1/auth-policy", auth.RoleViewer, body)
		req.Header.Set("X-Correlation-Id", corr)
		resp := doReq(t, req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("viewer PUT /auth-policy = %d, want 403", resp.StatusCode)
		}
		rows := auditRowsFor(t, pool, corr, "authz.permission.denied")
		if len(rows) != 1 || rows[0].ActorType != "user" || rows[0].ActorID != roleUserIDs[auth.RoleViewer].String() {
			t.Errorf("session denial rows = %+v, want one user/%s", rows, roleUserIDs[auth.RoleViewer])
		}
	})
}

// @ac AC-23
func TestAuditPrincipal_FilterAndExportFindTokenActions(t *testing.T) {
	t.Run("system-audit-emission/AC-23", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		defer license.EnableFeatureForTesting(license.ComplianceAttestation)()
		owner := roleUserIDs[auth.RoleAdmin].String()
		admin := auditCaller{mode: "session", actorTyp: "user", actorID: owner}
		raw, tokenID := mintTokenAs(t, url, auth.RoleAdmin, auth.RoleAdmin)
		tok := auditCaller{mode: "token", bearer: raw, actorTyp: "api_key", actorID: tokenID.String()}
		env := principalEnv{url: url, pool: pool, admin: admin, host: seedHostForIntel(t, pool).String()}
		for _, tc := range principalCases() {
			corr, st := tc.run(t, env, tok)
			if st != tc.want {
				t.Fatalf("%s: status %d, want %d", tc.name, st, tc.want)
			}
			_ = auditRowsFor(t, pool, corr, tc.actions[0]) // let the batched writer flush
		}
		time.Sleep(300 * time.Millisecond)

		var truth int
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE actor_id = $1`, tokenID.String()).Scan(&truth); err != nil {
			t.Fatalf("count: %v", err)
		}
		if truth < 20 {
			t.Fatalf("only %d rows name the token; the cases did not run", truth)
		}
		var mistyped int
		_ = pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE actor_id = $1 AND actor_type <> 'api_key'`, tokenID.String()).Scan(&mistyped)
		if mistyped != 0 {
			t.Errorf("%d rows name the token with an actor_type other than api_key", mistyped)
		}

		listCount := func(actorType string) int {
			n, cursor := 0, ""
			for page := 0; page < 100; page++ {
				p := "/api/v1/audit/events?limit=200&actor_type=" + actorType
				if cursor != "" {
					p += "&cursor=" + cursor
				}
				resp := doReq(t, asRole(t, "GET", url+p, auth.RoleAdmin, nil))
				var body struct {
					Items      []map[string]any `json:"items"`
					NextCursor *string          `json:"next_cursor"`
				}
				_ = json.NewDecoder(resp.Body).Decode(&body)
				resp.Body.Close()
				for _, it := range body.Items {
					if id, _ := it["actor_id"].(string); id == tokenID.String() {
						n++
					}
				}
				if body.NextCursor == nil || *body.NextCursor == "" {
					break
				}
				cursor = *body.NextCursor
			}
			return n
		}
		if got := listCount("api_key"); got != truth {
			t.Errorf("GET /audit/events?actor_type=api_key returned %d of the token's %d rows (OW-100 returned 0)", got, truth)
		}
		if got := listCount("user"); got != 0 {
			t.Errorf("GET /audit/events?actor_type=user returned %d of the token's rows; they must not be filed as user", got)
		}

		exportCount := func(actorType string) int {
			resp := doReq(t, asRole(t, "GET", url+"/api/v1/audit/events/export?format=json&actor_type="+actorType, auth.RoleAdmin, nil))
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			var rows []map[string]any
			if err := json.Unmarshal(b, &rows); err != nil {
				var wrapped struct {
					Items []map[string]any `json:"items"`
				}
				if err2 := json.Unmarshal(b, &wrapped); err2 != nil {
					t.Fatalf("export body is neither a list nor {items}: %v / %v", err, err2)
				}
				rows = wrapped.Items
			}
			n := 0
			for _, r := range rows {
				if id, _ := r["actor_id"].(string); id == tokenID.String() {
					n++
				}
			}
			return n
		}
		if got := exportCount("api_key"); got != truth {
			t.Errorf("export actor_type=api_key has %d of the token's %d rows", got, truth)
		}
		if got := exportCount("user"); got != 0 {
			t.Errorf("export actor_type=user has %d of the token's rows", got)
		}
	})
}
