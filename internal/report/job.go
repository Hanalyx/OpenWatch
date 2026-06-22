package report

// Async report rendering: the bulk attestation faces (CSV / OSCAL SAR /
// PDF) can be expensive to assemble for a large fleet, so generating an
// attestation enqueues a render job instead of blocking the request. A
// worker claims the job, renders each face (warming the report_faces cache
// and flipping each face's row from 'pending' to 'ready'), then publishes
// a ReportReady event on the bus - the first producer of the in-app
// notification bell.
//
// Export stays the lazy fallback: a download that arrives before the job
// runs still renders the face inline (a cache miss), so async rendering is
// a warm-the-cache-and-notify optimization, never a correctness gate.
//
// Spec: api-reports.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/eventbus"
	"github.com/Hanalyx/openwatch/internal/queue"
)

// RenderJobType is the job_type for an async report-face render.
const RenderJobType = "report.render"

// RenderPayload is the job payload: which snapshot to render faces for.
type RenderPayload struct {
	SnapshotID uuid.UUID `json:"snapshot_id"`
}

// attestationFaces are the bulk faces rendered asynchronously for an
// attestation report, in render order.
var attestationFaces = []string{FaceCSV, FaceOSCALSAR, FacePDF}

// markFacesPending inserts a 'pending' report_faces row for each face that
// does not already exist, so the lifecycle status is genuine (the render
// worker flips them to 'ready'). ON CONFLICT DO NOTHING leaves an already
// rendered ('ready') face untouched.
func (s *Service) markFacesPending(ctx context.Context, snapshotID uuid.UUID, faces []string) error {
	for _, face := range faces {
		mediaType := "application/octet-stream"
		switch face {
		case FaceCSV:
			mediaType = "text/csv"
		case FaceOSCALSAR, FaceJSON:
			mediaType = "application/json"
		case FacePDF:
			mediaType = "application/pdf"
		}
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO report_faces (snapshot_id, face, media_type, size_bytes, status)
			VALUES ($1, $2, $3, 0, 'pending')
			ON CONFLICT (snapshot_id, face) DO NOTHING`,
			snapshotID, face, mediaType); err != nil {
			return fmt.Errorf("report: mark face pending: %w", err)
		}
	}
	return nil
}

// enqueueRender marks the attestation's bulk faces pending and enqueues a
// render job. Best-effort: a failure to enqueue is logged but does not fail
// Generate, because Export still renders each face lazily on first
// download (the async path is an optimization, not a correctness gate).
func (s *Service) enqueueRender(ctx context.Context, snapshotID uuid.UUID) {
	if err := s.markFacesPending(ctx, snapshotID, attestationFaces); err != nil {
		slog.WarnContext(ctx, "report: mark faces pending failed",
			slog.String("snapshot_id", snapshotID.String()), slog.String("error", err.Error()))
		return
	}
	if _, err := queue.Enqueue(ctx, s.pool, RenderJobType, RenderPayload{SnapshotID: snapshotID}); err != nil {
		slog.WarnContext(ctx, "report: enqueue render job failed",
			slog.String("snapshot_id", snapshotID.String()), slog.String("error", err.Error()))
	}
}

// RenderProcessor renders a report's faces for a claimed report.render job
// and publishes ReportReady. It is registered on the in-process worker via
// WithReportProcessor; its ProcessJob signature matches the worker's other
// processors.
type RenderProcessor struct {
	svc *Service
	bus *eventbus.Bus
}

// NewRenderProcessor builds the processor over a report Service (for
// Export) and an event bus (to publish ReportReady). A nil bus renders the
// faces but publishes nothing.
func NewRenderProcessor(svc *Service, bus *eventbus.Bus) *RenderProcessor {
	return &RenderProcessor{svc: svc, bus: bus}
}

// ProcessJob renders every face that applies to the report's kind (warming
// the cache and flipping each 'pending' row to 'ready' via Export's upsert)
// and publishes a ReportReady event. A render error fails the job so it can
// be retried; faces already rendered are idempotent (deterministic bytes).
func (p *RenderProcessor) ProcessJob(ctx context.Context, j *queue.Job) {
	var payload RenderPayload
	if err := json.Unmarshal(j.Payload, &payload); err != nil {
		_ = queue.Fail(ctx, p.svc.pool, j.ID, fmt.Sprintf("report.render: payload decode: %v", err))
		return
	}
	if payload.SnapshotID == uuid.Nil {
		_ = queue.Fail(ctx, p.svc.pool, j.ID, "report.render: payload snapshot_id missing")
		return
	}

	rep, err := p.svc.Get(ctx, payload.SnapshotID)
	if err != nil {
		// An unknown snapshot (e.g. deleted before the job ran) is terminal,
		// not retryable.
		_ = queue.Fail(ctx, p.svc.pool, j.ID, fmt.Sprintf("report.render: load snapshot: %v", err))
		return
	}

	faces := facesForKind(rep.Kind)
	rendered := make([]string, 0, len(faces))
	for _, face := range faces {
		if _, _, err := p.svc.Export(ctx, payload.SnapshotID, face); err != nil {
			// Mark the face failed so the lifecycle reflects reality, then
			// fail the job for retry.
			_, _ = p.svc.pool.Exec(ctx,
				`UPDATE report_faces SET status = 'failed' WHERE snapshot_id = $1 AND face = $2 AND status = 'pending'`,
				payload.SnapshotID, face)
			_ = queue.Fail(ctx, p.svc.pool, j.ID, fmt.Sprintf("report.render: face %s: %v", face, err))
			return
		}
		rendered = append(rendered, face)
	}

	if p.bus != nil {
		p.bus.Publish(ctx, eventbus.ReportReady{
			SnapshotID:  rep.ID,
			ReportKind:  string(rep.Kind),
			Faces:       rendered,
			GeneratedBy: rep.GeneratedBy,
			OccurredAt:  time.Now().UTC(),
		})
	}

	if err := queue.Complete(ctx, p.svc.pool, j.ID); err != nil {
		slog.WarnContext(ctx, "report.render: complete failed",
			slog.String("job_id", j.ID.String()), slog.String("error", err.Error()))
	}
}

// facesForKind lists the faces an async render produces for a report kind:
// the bulk faces for an attestation; just the (cheap) PDF for an executive
// so the executive path can also notify if ever enqueued. The JSON face is
// always available lazily and is not pre-rendered.
func facesForKind(kind Kind) []string {
	switch kind {
	case KindAttestation:
		return attestationFaces
	case KindExecutive:
		return []string{FacePDF}
	default:
		return nil
	}
}
