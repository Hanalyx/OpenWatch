// @spec system-report-schedule
//
// AC traceability:
//   AC-01  ComputeNextRun honours daily/weekly/monthly cadence at the hour
//   AC-02  Create computes a future next_run; Due returns past-due enabled
//          schedules; the dispatcher generates + renders + delivers + advances

package reportschedule

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/db/dbtest"
	"github.com/Hanalyx/openwatch/internal/report"
)

func intp(i int) *int { return &i }

// @ac AC-01
func TestComputeNextRun(t *testing.T) {
	t.Run("system-report-schedule/AC-01", testComputeNextRun)
}

func testComputeNextRun(t *testing.T) {
	// Daily: 06:00 the next day when after today's 06:00.
	from := time.Date(2026, 6, 22, 9, 0, 0, 0, time.UTC) // 09:00, past 06:00
	next := ComputeNextRun(Daily, 6, nil, nil, from)
	if next.Hour() != 6 || next.Day() != 23 {
		t.Errorf("daily next = %v, want 2026-06-23 06:00", next)
	}
	// Daily: today's 06:00 when still before it.
	from2 := time.Date(2026, 6, 22, 3, 0, 0, 0, time.UTC)
	if n := ComputeNextRun(Daily, 6, nil, nil, from2); n.Day() != 22 || n.Hour() != 6 {
		t.Errorf("daily (before hour) next = %v, want same-day 06:00", n)
	}
	// Weekly: next Monday (weekday 1). 2026-06-22 is a Monday; from 09:00
	// it should advance to the following Monday (06-29).
	wk := ComputeNextRun(Weekly, 6, intp(1), nil, from)
	if wk.Weekday() != time.Monday || wk.Day() != 29 {
		t.Errorf("weekly next = %v, want Monday 2026-06-29", wk)
	}
	// Monthly: day 1 next month (today is the 22nd).
	mo := ComputeNextRun(Monthly, 6, nil, intp(1), from)
	if mo.Day() != 1 || mo.Month() != time.July {
		t.Errorf("monthly next = %v, want 2026-07-01", mo)
	}
}

// fakeGen returns a fixed report + PDF bytes without touching the DB.
type fakeGen struct{ exported bool }

func (f *fakeGen) Generate(ctx context.Context, by string, req report.GenerateRequest) (report.Report, error) {
	return report.Report{
		ID:         uuid.New(),
		Title:      "Framework Attestation",
		Kind:       report.KindAttestation,
		ScopeLabel: "All hosts",
		DataAsOf:   time.Now().UTC(),
	}, nil
}

func (f *fakeGen) Export(ctx context.Context, id uuid.UUID, face string) ([]byte, string, error) {
	f.exported = true
	return []byte("%PDF-1.4 fake"), "application/pdf", nil
}

// fakeDeliver records the delivery call.
type fakeDeliver struct {
	called    bool
	channelID uuid.UUID
	filename  string
	attach    []byte
}

func (d *fakeDeliver) SendReportEmail(ctx context.Context, channelID uuid.UUID, subject, body, filename string, attachment []byte) error {
	d.called = true
	d.channelID = channelID
	d.filename = filename
	d.attach = attachment
	return nil
}

func freshPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := dbtest.Pool(t)
	ctx := context.Background()
	for _, stmt := range []string{
		"TRUNCATE TABLE report_schedules CASCADE",
		"TRUNCATE TABLE notification_channels CASCADE",
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Logf("truncate (ok if benign): %v", err)
		}
	}
	return pool
}

// seedChannel inserts a minimal email channel (the dispatcher's delivery is
// faked, so the encrypted config is never read; only the FK must resolve).
func seedChannel(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO notification_channels (id, type, name, enabled, config_ciphertext)
		 VALUES ($1, 'email', 'auditors', true, $2)`, id, []byte("x"))
	if err != nil {
		t.Fatalf("seed channel: %v", err)
	}
	return id
}

// @ac AC-02
func TestDispatcher_RunsDueSchedule(t *testing.T) {
	t.Run("system-report-schedule/AC-02", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		svc := NewService(pool)
		ch := seedChannel(t, pool)

		sch, err := svc.Create(ctx, CreateParams{
			Name:      "weekly cis attestation",
			Kind:      "attestation",
			Scope:     Scope{Framework: "cis_rhel9"},
			Frequency: Daily,
			Hour:      6,
			ChannelID: ch,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		// Create computes a FUTURE next_run; it should not be due yet.
		if due, _ := svc.Due(ctx, time.Now().UTC()); len(due) != 0 {
			t.Fatalf("a fresh schedule should not be due, got %d", len(due))
		}
		// Backdate next_run_at so it is now due.
		if _, err := pool.Exec(ctx,
			`UPDATE report_schedules SET next_run_at = now() - interval '1 minute' WHERE id = $1`, sch.ID); err != nil {
			t.Fatalf("backdate: %v", err)
		}

		gen := &fakeGen{}
		del := &fakeDeliver{}
		disp := NewDispatcher(svc, gen, del)
		if err := disp.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}

		if !gen.exported || !del.called {
			t.Errorf("dispatcher did not generate+deliver (exported=%v called=%v)", gen.exported, del.called)
		}
		if del.channelID != ch {
			t.Errorf("delivered to channel %s, want %s", del.channelID, ch)
		}
		if string(del.attach) != "%PDF-1.4 fake" {
			t.Errorf("attachment = %q", del.attach)
		}

		// next_run advanced into the future, last_status ok.
		after, err := svc.Get(ctx, sch.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if !after.NextRunAt.After(time.Now().UTC()) {
			t.Errorf("next_run_at = %v, want future", after.NextRunAt)
		}
		if after.LastStatus != "ok" {
			t.Errorf("last_status = %q, want ok", after.LastStatus)
		}
		// No longer due.
		if due, _ := svc.Due(ctx, time.Now().UTC()); len(due) != 0 {
			t.Errorf("schedule still due after run, got %d", len(due))
		}
	})
}
