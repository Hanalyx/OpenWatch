package reportschedule

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/report"
)

// Generator generates a report and renders a face. Satisfied by
// *report.Service; an interface so the dispatcher is testable without a
// real report service.
type Generator interface {
	Generate(ctx context.Context, generatedBy string, req report.GenerateRequest) (report.Report, error)
	Export(ctx context.Context, id uuid.UUID, face string) ([]byte, string, error)
}

// Deliverer sends a report PDF as an email attachment through a channel.
// Satisfied by *notification.Service (SendReportEmail).
type Deliverer interface {
	SendReportEmail(ctx context.Context, channelID uuid.UUID, subject, body, filename string, attachment []byte) error
}

// Dispatcher runs due schedules: generate -> render PDF -> email -> advance.
type Dispatcher struct {
	svc     *Service
	gen     Generator
	deliver Deliverer
}

// NewDispatcher wires the dispatcher over the schedule service, a report
// generator, and an email deliverer.
func NewDispatcher(svc *Service, gen Generator, deliver Deliverer) *Dispatcher {
	return &Dispatcher{svc: svc, gen: gen, deliver: deliver}
}

// Tick claims + processes every due schedule once. It is the cron TickFunc.
// ClaimDue atomically reserves the due schedules (FOR UPDATE SKIP LOCKED +
// advance), so concurrent dispatchers never double-send. An error from one
// schedule is recorded on that schedule (last_status) and does not abort the
// others. The return error is non-nil only on a claim failure.
func (d *Dispatcher) Tick(ctx context.Context) error {
	now := time.Now().UTC()
	claimed, err := d.svc.ClaimDue(ctx, now)
	if err != nil {
		return err
	}
	for _, sch := range claimed {
		status := "ok"
		if rerr := d.run(ctx, sch); rerr != nil {
			status = "failed: " + rerr.Error()
			slog.WarnContext(ctx, "report schedule run failed",
				slog.String("schedule_id", sch.ID.String()), slog.String("error", rerr.Error()))
		}
		if merr := d.svc.MarkResult(ctx, sch.ID, status); merr != nil {
			slog.WarnContext(ctx, "report schedule mark-result failed",
				slog.String("schedule_id", sch.ID.String()), slog.String("error", merr.Error()))
		}
	}
	return nil
}

// run generates the scheduled report, renders its PDF face, and emails it.
func (d *Dispatcher) run(ctx context.Context, sch Schedule) error {
	req := report.GenerateRequest{
		Kind:       report.Kind(sch.Kind),
		GroupID:    sch.Scope.GroupID,
		Framework:  sch.Scope.Framework,
		PeriodDays: sch.Scope.PeriodDays,
	}
	rep, err := d.gen.Generate(ctx, "scheduler", req)
	if err != nil {
		return fmt.Errorf("generate: %w", err)
	}
	pdf, _, err := d.gen.Export(ctx, rep.ID, report.FacePDF)
	if err != nil {
		return fmt.Errorf("render pdf: %w", err)
	}
	filename := report.ExportFilename(rep, report.FacePDF)
	subject := fmt.Sprintf("%s - %s", rep.Title, rep.DataAsOf.Format("2006-01-02"))
	body := fmt.Sprintf("Your scheduled OpenWatch report is attached.\n\n%s\nScope: %s\nData as of: %s\n",
		rep.Title, rep.ScopeLabel, rep.DataAsOf.Format("2006-01-02 15:04 MST"))
	if err := d.deliver.SendReportEmail(ctx, sch.ChannelID, subject, body, filename, pdf); err != nil {
		return fmt.Errorf("deliver: %w", err)
	}
	return nil
}
