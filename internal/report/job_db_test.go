// @spec api-reports
//
// AC traceability:
//   AC-22  async attestation render: Generate(asyncRender) marks the bulk
//          faces 'pending' + enqueues a report.render job; the
//          RenderProcessor renders them 'ready', completes the job, and
//          publishes a ReportReady event carrying the snapshot + faces.

package report

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/correlation"
	"github.com/Hanalyx/openwatch/internal/eventbus"
	"github.com/Hanalyx/openwatch/internal/queue"
)

// faceStatuses returns the status of every report_faces row for a snapshot,
// keyed by face.
func faceStatuses(t *testing.T, pool *pgxpool.Pool, snapshotID uuid.UUID) map[string]string {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT face, status FROM report_faces WHERE snapshot_id = $1`, snapshotID)
	if err != nil {
		t.Fatalf("query face statuses: %v", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var face, status string
		if err := rows.Scan(&face, &status); err != nil {
			t.Fatalf("scan face status: %v", err)
		}
		out[face] = status
	}
	return out
}

// @ac AC-22
func TestRenderProcessor_AsyncAttestation(t *testing.T) {
	t.Run("api-reports/AC-22", func(t *testing.T) {
		pool := freshPool(t)
		// queue.Enqueue requires a correlation id on the context (the HTTP
		// middleware sets one in production); set one for the test.
		ctx := correlation.Set(context.Background(), correlation.Generate(correlation.PrefixRequest))
		// job_queue is not part of freshPool's truncation set; clear it so a
		// stale job from another test isn't dequeued first.
		if _, err := pool.Exec(ctx, "TRUNCATE TABLE job_queue"); err != nil {
			t.Fatalf("truncate job_queue: %v", err)
		}

		signer, _ := NewSigner("")
		svc := NewService(pool).WithSigner(signer).WithAsyncRender()
		owner := seedUser(t, pool)
		h := seedHost(t, pool, owner, false)
		scan := seedScanRun(t, pool, h)
		seedScanResult(t, pool, scan, h, "r1", "pass", `{"cis_rhel9_v2.0.0": ["1.1"]}`)
		seedScanResult(t, pool, scan, h, "r2", "fail", `{"cis_rhel9_v2.0.0": ["1.2"]}`)

		// Generate marks the bulk faces 'pending' and enqueues a render job.
		rep, err := svc.Generate(ctx, "alice@example.com", GenerateRequest{Kind: KindAttestation})
		if err != nil {
			t.Fatalf("Generate attestation: %v", err)
		}
		pending := faceStatuses(t, pool, rep.ID)
		for _, face := range []string{FaceCSV, FaceOSCALSAR, FacePDF} {
			if pending[face] != "pending" {
				t.Errorf("face %s status = %q, want pending", face, pending[face])
			}
		}

		// A report.render job is queued for this snapshot.
		var jobType string
		if err := pool.QueryRow(ctx,
			`SELECT job_type FROM job_queue WHERE status = 'pending' ORDER BY created_at DESC LIMIT 1`).
			Scan(&jobType); err != nil {
			t.Fatalf("query queued job: %v", err)
		}
		if jobType != RenderJobType {
			t.Fatalf("queued job_type = %q, want %q", jobType, RenderJobType)
		}

		// Subscribe before processing so the ReportReady event is captured.
		bus := eventbus.NewBus()
		sub := bus.Subscribe(eventbus.SubscribeOptions{Kinds: []eventbus.EventKind{eventbus.EventKindReportReady}})
		defer sub.Unsubscribe()

		// Claim and process the job through the RenderProcessor.
		job, _, err := queue.Dequeue(ctx, pool)
		if err != nil {
			t.Fatalf("Dequeue: %v", err)
		}
		if job.JobType != RenderJobType {
			t.Fatalf("dequeued job_type = %q, want %q", job.JobType, RenderJobType)
		}
		proc := NewRenderProcessor(svc, bus)
		proc.ProcessJob(ctx, job)

		// Every bulk face flipped to 'ready'.
		ready := faceStatuses(t, pool, rep.ID)
		for _, face := range []string{FaceCSV, FaceOSCALSAR, FacePDF} {
			if ready[face] != "ready" {
				t.Errorf("after render, face %s status = %q, want ready", face, ready[face])
			}
		}

		// The job is completed.
		var jobStatus string
		if err := pool.QueryRow(ctx,
			`SELECT status FROM job_queue WHERE id = $1`, job.ID).Scan(&jobStatus); err != nil {
			t.Fatalf("query job status: %v", err)
		}
		if jobStatus != "completed" {
			t.Errorf("job status = %q, want completed", jobStatus)
		}

		// A ReportReady event was published for this snapshot, naming the faces.
		select {
		case ev := <-sub.Events():
			rr, ok := ev.(eventbus.ReportReady)
			if !ok {
				t.Fatalf("event type = %T, want ReportReady", ev)
			}
			if rr.SnapshotID != rep.ID {
				t.Errorf("event snapshot = %s, want %s", rr.SnapshotID, rep.ID)
			}
			if rr.ReportKind != string(KindAttestation) {
				t.Errorf("event kind = %q, want attestation", rr.ReportKind)
			}
			if len(rr.Faces) != 3 {
				t.Errorf("event faces = %v, want 3", rr.Faces)
			}
			if rr.GeneratedBy != "alice@example.com" {
				t.Errorf("event generated_by = %q", rr.GeneratedBy)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("no ReportReady event published")
		}
	})
}
