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

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/report"
	"github.com/Hanalyx/openwatch/internal/reportschedule"
	"github.com/Hanalyx/openwatch/internal/specfixture"
)

// capturingGenerator records the actor the dispatcher hands to Generate.
//
// The dispatcher's Generator seam is what makes the scheduled call site
// observable. Comparing the fixture against reportschedule.Actor would only
// prove the constant equals itself, and would still pass if the call site
// were changed to pass a literal.
type capturingGenerator struct {
	gotActor string
	calls    int
}

func (g *capturingGenerator) Generate(_ context.Context, generatedBy string,
	_ report.GenerateRequest) (report.Report, error) {
	g.calls++
	g.gotActor = generatedBy
	return report.Report{ID: uuid.New(), Kind: report.KindExecutive}, nil
}

func (g *capturingGenerator) Export(context.Context, uuid.UUID, string) ([]byte, string, error) {
	return []byte("%PDF-1.7\n"), "application/pdf", nil
}

// silentDeliverer accepts the email so Tick reaches its end.
type silentDeliverer struct{}

func (silentDeliverer) SendReportEmail(context.Context, uuid.UUID,
	string, string, string, []byte) error {
	return nil
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

// @ac AC-26
// AC-26: attribution is real or absent, never invented, observed at each
// production call site.
func TestReportActor_RealOrAbsentNeverInvented(t *testing.T) {
	t.Run("api-reports/AC-26", func(t *testing.T) {
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/api/reports.spec.yaml", "api-reports"), "AC-26")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		url, pool := freshAPIServer(t)
		forbidden := in.Str("forbidden_actor")
		if !exp.Bool("observed_at_call_site") {
			t.Fatal("fixture must require observation at the production call site")
		}
		rejectedCreated := 0

		// Every case comes from the table: the identity presented, the entry
		// point it goes through, and what it must produce.
		for _, c := range in.MapList("cases") {
			caller := c.Str("caller")
			identity := c.Str("identity")
			through := c.Str("through")
			wantStatus := c.Int("expect_status")
			wantActor := c.Str("expect_actor")
			c.AllConsumed()

			switch through {
			case "PostReportGenerate":
				before := reportRowCount(t, pool)
				status, actor := generateAs(t, url, pool, identity)
				if status != wantStatus {
					t.Errorf("%s: status = %d, want %d", caller, status, wantStatus)
				}
				switch wantActor {
				case "caller_principal_id":
					// The caller's OWN id, compared exactly. "any non-empty
					// value" would accept a placeholder that merely differs
					// from the forbidden one.
					want := roleUserIDs[auth.RoleOpsLead].String()
					if actor != want {
						t.Errorf("%s: generated_by = %q, want the caller's principal %q",
							caller, actor, want)
					}
				case "none":
					if actor != "" {
						t.Errorf("%s: an artifact was attributed to %q; this case must "+
							"produce none", caller, actor)
					}
					if got := reportRowCount(t, pool) - before; got != 0 {
						rejectedCreated += got
						t.Errorf("%s: created %d artifact(s); a request with no usable "+
							"principal must generate nothing", caller, got)
					}
				default:
					t.Fatalf("%s: unknown expected actor %q", caller, wantActor)
				}

			case "Dispatcher.Tick":
				got := tickActor(t, pool)
				if got != wantActor {
					t.Errorf("%s: the dispatcher handed Generate the actor %q, want %q; "+
						"scheduled generation is a separate authenticated path",
						caller, got, wantActor)
				}
				if got == forbidden {
					t.Errorf("%s: the scheduled path records the placeholder %q",
						caller, forbidden)
				}

			default:
				t.Fatalf("%s: fixture names entry point %q, which this test does not drive",
					caller, through)
			}
		}

		if rejectedCreated != exp.Int("artifacts_created_by_rejected_cases") {
			t.Errorf("rejected cases created %d artifact(s), want %d",
				rejectedCreated, exp.Int("artifacts_created_by_rejected_cases"))
		}
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

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// generateAs drives PostReportGenerate with one identity shape and returns
// the status and the actor recorded on any artifact it produced.
//
// The empty-principal case cannot be reached through the router, because the
// auth middleware rebuilds the identity from the session. It is driven
// against the real handler with the identity injected, so the assertion
// still covers the handler rather than the helper it calls.
func generateAs(t *testing.T, url string, pool *pgxpool.Pool, identity string) (int, string) {
	t.Helper()
	switch identity {
	case "role_principal":
		req := asRole(t, "POST", url+"/api/v1/reports:generate", auth.RoleOpsLead,
			map[string]any{})
		resp := doReq(t, req)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
			return resp.StatusCode, ""
		}
		var made struct {
			GeneratedBy string `json:"generated_by"`
		}
		if err := json.Unmarshal(body, &made); err != nil {
			t.Fatalf("decode generated report: %v", err)
		}
		return resp.StatusCode, made.GeneratedBy

	case "none":
		req, err := http.NewRequest("POST", url+"/api/v1/reports:generate", http.NoBody)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		resp := doReq(t, req)
		resp.Body.Close()
		return resp.StatusCode, ""

	case "empty_id_with_role":
		h := &handlers{pool: pool, reportSvc: report.NewService(pool)}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/v1/reports:generate", http.NoBody)
		req = req.WithContext(auth.SetIdentity(req.Context(),
			auth.Identity{ID: "", RoleID: auth.RoleOpsLead}))
		h.PostReportGenerate(rec, req)
		return rec.Code, ""
	}
	t.Fatalf("unknown identity shape %q", identity)
	return 0, ""
}

// tickActor runs one real dispatcher tick over a due schedule and returns
// the actor the dispatcher passed to Generate.
func tickActor(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	ctx := context.Background()
	svc := reportschedule.NewService(pool)

	channel := uuid.New()
	if _, err := pool.Exec(ctx,
		`INSERT INTO notification_channels (id, type, name, enabled, config_ciphertext)
		 VALUES ($1, 'email', 'ac26-auditors', true, $2)`, channel, []byte("x")); err != nil {
		t.Fatalf("seed channel: %v", err)
	}
	sch, err := svc.Create(ctx, reportschedule.CreateParams{
		Name: "ac26-daily", Kind: "executive", Frequency: reportschedule.Daily,
		Hour: 6, ChannelID: channel,
	})
	if err != nil {
		t.Fatalf("create schedule: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE report_schedules SET next_run_at = now() - interval '1 minute' WHERE id = $1`,
		sch.ID); err != nil {
		t.Fatalf("backdate schedule: %v", err)
	}

	gen := &capturingGenerator{}
	d := reportschedule.NewDispatcher(svc, gen, silentDeliverer{})
	if err := d.Tick(ctx); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if gen.calls == 0 {
		t.Fatal("the dispatcher never generated; the scheduled call site was not exercised")
	}
	return gen.gotActor
}
