// @spec api-reports
//
// Report attribution. generated_by is part of the signed artifact, so it
// is either the real principal or the artifact does not exist.
package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/reportschedule"
	"github.com/Hanalyx/openwatch/internal/specfixture"
)

// @ac AC-26
// AC-26: attribution is real or absent, never invented.
func TestReportActor_RealOrAbsentNeverInvented(t *testing.T) {
	t.Run("api-reports/AC-26", func(t *testing.T) {
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/api/reports.spec.yaml", "api-reports"), "AC-26")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		forbidden := in.Str("forbidden_actor")
		seen := map[string]bool{}
		for _, c := range in.MapList("cases") {
			seen[c.Str("caller")] = true
			c.Str("principal")
			c.AllConsumed()
		}
		for _, want := range []string{"authenticated", "anonymous", "authorized", "scheduler"} {
			if !seen[want] {
				t.Errorf("fixture does not cover the %q caller", want)
			}
		}

		url, pool := freshAPIServer(t)

		// An authenticated caller is recorded as itself.
		if !exp.Bool("authenticated_records_principal") {
			t.Fatal("fixture must require the principal to be recorded")
		}
		req := asRole(t, "POST", url+"/api/v1/reports:generate", auth.RoleOpsLead, map[string]any{})
		resp := doReq(t, req)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
			t.Fatalf("authenticated generate = %d: %s", resp.StatusCode, body)
		}
		var made struct {
			GeneratedBy string `json:"generated_by"`
		}
		if err := json.Unmarshal(body, &made); err != nil {
			t.Fatalf("decode generated report: %v", err)
		}
		if made.GeneratedBy == "" || made.GeneratedBy == forbidden {
			t.Errorf("generated_by = %q; an authenticated request records its own principal, "+
				"and %q is the placeholder this criterion forbids", made.GeneratedBy, forbidden)
		}

		// An anonymous caller never reaches generation.
		if !exp.Bool("anonymous_rejected_before_generation") {
			t.Fatal("fixture must require anonymous rejection")
		}
		beforeCount := reportRowCount(t, pool)
		anon, err := http.NewRequest("POST", url+"/api/v1/reports:generate", http.NoBody)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		anonResp := doReq(t, anon)
		anonResp.Body.Close()
		if anonResp.StatusCode != http.StatusUnauthorized && anonResp.StatusCode != http.StatusForbidden {
			t.Errorf("anonymous generate = %d, want 401 or 403", anonResp.StatusCode)
		}
		if got := reportRowCount(t, pool); got != beforeCount {
			t.Errorf("an anonymous request created %d artifact(s); rejection must happen "+
				"before anything is written", got-beforeCount)
		}

		// Authorization passed, but no principal reached the handler. The
		// artifact must not exist. This is the branch that used to record a
		// placeholder into content about to be signed.
		if !exp.Bool("missing_principal_generates_nothing") {
			t.Fatal("fixture must require a missing principal to generate nothing")
		}
		for _, id := range []auth.Identity{
			{ID: "", RoleID: auth.RoleOpsLead},
			{ID: "someone", IsAnonymous: true},
		} {
			probe := httptest.NewRequest("POST", "/api/v1/reports:generate", http.NoBody)
			probe = probe.WithContext(auth.SetIdentity(context.Background(), id))
			actor, ok := reportActor(probe)
			if ok {
				t.Errorf("reportActor accepted identity %+v and returned %q; an authorized "+
					"request with no principal must fail closed", id, actor)
			}
			if actor == forbidden {
				t.Errorf("reportActor returned %q, which fabricates audit provenance into a "+
					"signed artifact", forbidden)
			}
		}
		// And the positive case, so the check above is discrimination rather
		// than a function that refuses everything.
		good := httptest.NewRequest("POST", "/api/v1/reports:generate", http.NoBody)
		good = good.WithContext(auth.SetIdentity(context.Background(),
			auth.Identity{ID: "user-42", RoleID: auth.RoleOpsLead}))
		if actor, ok := reportActor(good); !ok || actor != "user-42" {
			t.Errorf("reportActor(valid principal) = %q, %v; want user-42, true", actor, ok)
		}

		// No artifact anywhere is attributed to the placeholder.
		var forbiddenRows int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*)::int FROM report_snapshots WHERE generated_by = $1`,
			forbidden).Scan(&forbiddenRows); err != nil {
			t.Fatalf("count placeholder rows: %v", err)
		}
		if forbiddenRows != exp.Int("artifacts_attributed_to_forbidden_actor") {
			t.Errorf("%d artifact(s) attributed to %q, want %d",
				forbiddenRows, forbidden, exp.Int("artifacts_attributed_to_forbidden_actor"))
		}

		// The scheduled path is untouched and keeps its explicit actor.
		if want := exp.Str("scheduler_records"); want != reportschedule.Actor {
			t.Errorf("the dispatcher records %q, want %q; scheduled generation is a separate "+
				"authenticated path and this change must not have altered it",
				reportschedule.Actor, want)
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

func reportRowCount(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*)::int FROM report_snapshots`).Scan(&n); err != nil {
		t.Fatalf("count reports: %v", err)
	}
	return n
}
