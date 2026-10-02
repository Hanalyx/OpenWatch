// @spec system-audit-emission
//
// AC traceability (DSN-gated like every api_*_test in this package):
//
//	AC-18  TestAuditActor_SessionCallerIsActorAndObjectIsTarget
//	AC-19  TestAuditActor_TokenCallerIsActorAsAPIKey
//	AC-20  TestAuditActor_FailedSignInIsAnonymous
//
// bugs/OW-099: fourteen handler events recorded the affected object as the
// actor, so the trail named a host or a user account and never the person.
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/auth"
)

// auditRow is the attribution part of one audit_events row.
type auditRow struct {
	ActorType, ActorID, ResourceType, ResourceID string
}

type auditCaller struct {
	mode     string // "session" or "token"
	bearer   string // set for the token caller
	actorTyp string
	actorID  string
}

// callAs sends one request as the caller, with its own correlation id.
func (c auditCaller) call(t *testing.T, url, method, path string, body any) (int, map[string]any, string) {
	t.Helper()
	corr := "ow099-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:24]
	var req *http.Request
	if c.bearer != "" {
		var rdr io.Reader
		if body != nil {
			bs, _ := json.Marshal(body)
			rdr = bytes.NewReader(bs)
		}
		req, _ = http.NewRequest(method, url+path, rdr)
		req.Header.Set("Authorization", "Bearer "+c.bearer)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
	} else {
		req = asRole(t, method, url+path, auth.RoleAdmin, body)
	}
	req.Header.Set("X-Correlation-Id", corr)
	req.Header.Set("Idempotency-Key", "ow099-"+uuid.NewString())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return resp.StatusCode, m, corr
}

// auditRowsFor reads the rows for one correlation id and action. The writer
// is batched, so it polls until the count holds steady across consecutive
// readings rather than stopping at the first non-empty one.
func auditRowsFor(t *testing.T, pool *pgxpool.Pool, corr, action string) []auditRow {
	t.Helper()
	read := func() []auditRow {
		rows, err := pool.Query(context.Background(), `
			SELECT actor_type, COALESCE(actor_id, ''), COALESCE(resource_type, ''), COALESCE(resource_id, '')
			FROM audit_events WHERE correlation_id = $1 AND action = $2`, corr, action)
		if err != nil {
			t.Fatalf("read audit: %v", err)
		}
		defer rows.Close()
		var out []auditRow
		for rows.Next() {
			var r auditRow
			if err := rows.Scan(&r.ActorType, &r.ActorID, &r.ResourceType, &r.ResourceID); err != nil {
				t.Fatalf("scan audit: %v", err)
			}
			out = append(out, r)
		}
		return out
	}
	deadline := time.Now().Add(3 * time.Second)
	last, steady := -1, 0
	var got []auditRow
	for time.Now().Before(deadline) {
		got = read()
		if len(got) == last && len(got) > 0 {
			if steady++; steady >= 3 {
				return got
			}
		} else {
			steady = 0
		}
		last = len(got)
		time.Sleep(50 * time.Millisecond)
	}
	return got
}

// auditCase is one of the fourteen events. run performs the request as the
// caller (fixtures are created through the admin session) and returns the
// correlation id, the HTTP status, and the target the row must name.
type auditCase struct {
	name, action string
	wantStatus   int
	run          func(t *testing.T, url string, pool *pgxpool.Pool, c auditCaller, admin auditCaller) (corr string, status int, target auditRow)
}

func auditCases() []auditCase {
	newHost := func(t *testing.T, url string, admin auditCaller) string {
		t.Helper()
		st, b, _ := admin.call(t, url, "POST", "/api/v1/hosts", map[string]any{
			"hostname": "ow099-" + uuid.NewString()[:8], "ip_address": "192.0.2." + strconv.Itoa(int(uuid.New()[0])%200+20),
		})
		if st != http.StatusCreated {
			t.Fatalf("fixture host: %d %v", st, b)
		}
		return b["id"].(string)
	}
	newCred := func(t *testing.T, url string, admin auditCaller) string {
		t.Helper()
		st, b, _ := admin.call(t, url, "POST", "/api/v1/credentials", map[string]any{
			"scope": "system", "name": "ow099-" + uuid.NewString()[:8], "username": "u", "auth_method": "password", "password": "pw-ow099",
		})
		if st != http.StatusCreated {
			t.Fatalf("fixture credential: %d %v", st, b)
		}
		return b["id"].(string)
	}
	newUser := func(t *testing.T, url string, admin auditCaller) string {
		t.Helper()
		n := "ow099" + strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
		st, b, _ := admin.call(t, url, "POST", "/api/v1/users", map[string]any{
			"username": n, "email": n + "@example.test", "password": "Ow099-Fixture-Pass-1!",
		})
		if st != http.StatusCreated {
			t.Fatalf("fixture user: %d %v", st, b)
		}
		return b["id"].(string)
	}
	host := func(id string) auditRow { return auditRow{ResourceType: "host", ResourceID: id} }
	cred := func(id string) auditRow { return auditRow{ResourceType: "credential", ResourceID: id} }
	user := func(id string) auditRow { return auditRow{ResourceType: "user", ResourceID: id} }
	return []auditCase{
		{name: "host created", action: "host.created", wantStatus: 201,
			run: func(t *testing.T, url string, _ *pgxpool.Pool, c, _ auditCaller) (string, int, auditRow) {
				st, b, corr := c.call(t, url, "POST", "/api/v1/hosts", map[string]any{"hostname": "ow099-c-" + uuid.NewString()[:8], "ip_address": "198.51.100." + strconv.Itoa(int(uuid.New()[0])%200+20)})
				id, _ := b["id"].(string)
				return corr, st, host(id)
			}},
		{name: "host updated (patch)", action: "host.updated", wantStatus: 200,
			run: func(t *testing.T, url string, _ *pgxpool.Pool, c, admin auditCaller) (string, int, auditRow) {
				id := newHost(t, url, admin)
				st, _, corr := c.call(t, url, "PATCH", "/api/v1/hosts/"+id, map[string]any{"description": "ow099"})
				return corr, st, host(id)
			}},
		{name: "host updated (target framework)", action: "host.updated", wantStatus: 200,
			run: func(t *testing.T, url string, _ *pgxpool.Pool, c, admin auditCaller) (string, int, auditRow) {
				id := newHost(t, url, admin)
				st, _, corr := c.call(t, url, "POST", "/api/v1/hosts/"+id+":target", map[string]any{"target_framework": "stig"})
				return corr, st, host(id)
			}},
		{name: "host updated (maintenance)", action: "host.updated", wantStatus: 200,
			run: func(t *testing.T, url string, _ *pgxpool.Pool, c, admin auditCaller) (string, int, auditRow) {
				id := newHost(t, url, admin)
				st, _, corr := c.call(t, url, "PUT", "/api/v1/hosts/"+id+"/maintenance", map[string]any{"enabled": true})
				return corr, st, host(id)
			}},
		{name: "host deleted", action: "host.deleted", wantStatus: 204,
			run: func(t *testing.T, url string, _ *pgxpool.Pool, c, admin auditCaller) (string, int, auditRow) {
				id := newHost(t, url, admin)
				st, _, corr := c.call(t, url, "DELETE", "/api/v1/hosts/"+id, nil)
				return corr, st, host(id)
			}},
		{name: "credential created", action: "credential.created", wantStatus: 201,
			run: func(t *testing.T, url string, _ *pgxpool.Pool, c, _ auditCaller) (string, int, auditRow) {
				st, b, corr := c.call(t, url, "POST", "/api/v1/credentials", map[string]any{"scope": "system", "name": "ow099-c-" + uuid.NewString()[:8], "username": "u", "auth_method": "password", "password": "pw-ow099"})
				id, _ := b["id"].(string)
				return corr, st, cred(id)
			}},
		{name: "credential updated", action: "credential.updated", wantStatus: 200,
			run: func(t *testing.T, url string, _ *pgxpool.Pool, c, admin auditCaller) (string, int, auditRow) {
				id := newCred(t, url, admin)
				st, _, corr := c.call(t, url, "PATCH", "/api/v1/credentials/"+id, map[string]any{"description": "ow099"})
				return corr, st, cred(id)
			}},
		{name: "credential created (clone)", action: "credential.created", wantStatus: 201,
			run: func(t *testing.T, url string, _ *pgxpool.Pool, c, admin auditCaller) (string, int, auditRow) {
				src := newCred(t, url, admin)
				hid := newHost(t, url, admin)
				st, b, corr := c.call(t, url, "POST", "/api/v1/credentials/"+src+":clone", map[string]any{"scope": "host", "scope_id": hid, "name": "ow099-clone-" + uuid.NewString()[:8]})
				id, _ := b["id"].(string)
				return corr, st, cred(id)
			}},
		{name: "credential deleted", action: "credential.deleted", wantStatus: 204,
			run: func(t *testing.T, url string, _ *pgxpool.Pool, c, admin auditCaller) (string, int, auditRow) {
				id := newCred(t, url, admin)
				st, _, corr := c.call(t, url, "DELETE", "/api/v1/credentials/"+id, nil)
				return corr, st, cred(id)
			}},
		{name: "user created", action: "admin.user.created", wantStatus: 201,
			run: func(t *testing.T, url string, _ *pgxpool.Pool, c, _ auditCaller) (string, int, auditRow) {
				n := "ow099c" + strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
				st, b, corr := c.call(t, url, "POST", "/api/v1/users", map[string]any{"username": n, "email": n + "@example.test", "password": "Ow099-Fixture-Pass-1!"})
				id, _ := b["id"].(string)
				return corr, st, user(id)
			}},
		{name: "user deleted", action: "admin.user.deleted", wantStatus: 204,
			run: func(t *testing.T, url string, _ *pgxpool.Pool, c, admin auditCaller) (string, int, auditRow) {
				id := newUser(t, url, admin)
				st, _, corr := c.call(t, url, "DELETE", "/api/v1/users/"+id, nil)
				return corr, st, user(id)
			}},
		{name: "role assigned", action: "authz.role.assigned", wantStatus: 204,
			run: func(t *testing.T, url string, _ *pgxpool.Pool, c, admin auditCaller) (string, int, auditRow) {
				id := newUser(t, url, admin)
				st, _, corr := c.call(t, url, "POST", "/api/v1/users/"+id+"/roles:assign", map[string]any{"role_id": "auditor"})
				return corr, st, user(id)
			}},
		{name: "role removed", action: "authz.role.removed", wantStatus: 204,
			run: func(t *testing.T, url string, _ *pgxpool.Pool, c, admin auditCaller) (string, int, auditRow) {
				id := newUser(t, url, admin)
				if st, b, _ := admin.call(t, url, "POST", "/api/v1/users/"+id+"/roles:assign", map[string]any{"role_id": "auditor"}); st != http.StatusNoContent {
					t.Fatalf("fixture assign: %d %v", st, b)
				}
				st, _, corr := c.call(t, url, "POST", "/api/v1/users/"+id+"/roles:unassign", map[string]any{"role_id": "auditor"})
				return corr, st, user(id)
			}},
		{name: "role created", action: "authz.role.created", wantStatus: 201,
			run: func(t *testing.T, url string, _ *pgxpool.Pool, c, _ auditCaller) (string, int, auditRow) {
				rid := "ow099_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
				st, _, corr := c.call(t, url, "POST", "/api/v1/roles:create", map[string]any{"id": rid, "description": "ow099", "permissions": []string{"host:read"}})
				return corr, st, auditRow{ResourceType: "role", ResourceID: rid}
			}},
	}
}

// runAuditCase checks the one row an event must produce: the caller as the
// actor, with the right actor type, and the object as the resource.
func runAuditCase(t *testing.T, url string, pool *pgxpool.Pool, tc auditCase, c, admin auditCaller) {
	t.Helper()
	corr, st, target := tc.run(t, url, pool, c, admin)
	if st != tc.wantStatus {
		t.Fatalf("%s as %s: status %d, want %d", tc.name, c.mode, st, tc.wantStatus)
	}
	rows := auditRowsFor(t, pool, corr, tc.action)
	if len(rows) != 1 {
		t.Fatalf("%s as %s: %d %s rows for the request, want 1", tc.name, c.mode, len(rows), tc.action)
	}
	got := rows[0]
	want := auditRow{ActorType: c.actorTyp, ActorID: c.actorID, ResourceType: target.ResourceType, ResourceID: target.ResourceID}
	if target.ResourceID == "" {
		t.Fatalf("%s as %s: the request returned no object id to compare", tc.name, c.mode)
	}
	if got != want {
		t.Errorf("%s as %s: audit attribution\n  got  %+v\n  want %+v", tc.name, c.mode, got, want)
	}
	if got.ActorID == target.ResourceID {
		t.Errorf("%s as %s: actor_id is the affected object's id (OW-099)", tc.name, c.mode)
	}
}

// @ac AC-18
func TestAuditActor_SessionCallerIsActorAndObjectIsTarget(t *testing.T) {
	t.Run("system-audit-emission/AC-18", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		admin := auditCaller{mode: "session", actorTyp: "user", actorID: roleUserIDs[auth.RoleAdmin].String()}
		cases := auditCases()
		if len(cases) != 14 {
			t.Fatalf("cases = %d, want the 14 events of OW-099", len(cases))
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) { runAuditCase(t, url, pool, tc, admin, admin) })
		}
	})
}

// @ac AC-19
func TestAuditActor_TokenCallerIsActorAsAPIKey(t *testing.T) {
	t.Run("system-audit-emission/AC-19", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		admin := auditCaller{mode: "session", actorTyp: "user", actorID: roleUserIDs[auth.RoleAdmin].String()}
		raw, tokenID := mintScanToken(t, url, auth.RoleAdmin)
		tok := auditCaller{mode: "token", bearer: raw, actorTyp: "api_key", actorID: tokenID.String()}
		cases := auditCases()
		if len(cases) != 14 {
			t.Fatalf("cases = %d, want the 14 events of OW-099", len(cases))
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) { runAuditCase(t, url, pool, tc, tok, admin) })
		}
	})
}

// @ac AC-20
func TestAuditActor_FailedSignInIsAnonymous(t *testing.T) {
	t.Run("system-audit-emission/AC-20", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		corr := "ow099-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:24]
		bs, _ := json.Marshal(map[string]any{"username": "ow099-nobody", "password": "wrong-password-ow099"})
		req, _ := http.NewRequest("POST", url+"/api/v1/auth/login", bytes.NewReader(bs))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Correlation-Id", corr)
		resp := doReq(t, req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("login status = %d, want 401", resp.StatusCode)
		}
		rows := auditRowsFor(t, pool, corr, "auth.login.failure")
		if len(rows) != 1 {
			t.Fatalf("auth.login.failure rows = %d, want 1", len(rows))
		}
		if rows[0].ActorType != "anonymous" || rows[0].ActorID != "" {
			t.Errorf("failed sign-in actor = (%q, %q), want (anonymous, empty): no identity is established",
				rows[0].ActorType, rows[0].ActorID)
		}
	})
}
