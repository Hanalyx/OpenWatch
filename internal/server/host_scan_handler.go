// On-demand compliance scan — POST /hosts/{id}/scans.
//
// Creates the scan_runs logbook row and enqueues the HMAC-signed scan
// job the worker executes via Kensa. The response is 202 + scan_id;
// the scan is asynchronous (completion lands in
// host_rule_state/transactions and on the event bus).
//
// Spec: specs/api/host-scan.spec.yaml.
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	openapitypes "github.com/oapi-codegen/runtime/types"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/correlation"
	"github.com/Hanalyx/openwatch/internal/host"
	"github.com/Hanalyx/openwatch/internal/queue"
	"github.com/Hanalyx/openwatch/internal/scanruns"
	"github.com/Hanalyx/openwatch/internal/scheduler"
	"github.com/Hanalyx/openwatch/internal/server/api"
)

// PostHostScan implements api.ServerInterface. Spec api-host-scan
// AC-01..AC-07.
func (h *handlers) PostHostScan(
	w http.ResponseWriter,
	r *http.Request,
	id openapitypes.UUID,
	_ api.PostHostScanParams,
) {
	if denied := auth.EnforcePermission(w, r, auth.HostWrite); denied {
		return
	}
	if h.scanQueueKey == nil {
		writeError(w, http.StatusServiceUnavailable, "server.unavailable", "server",
			"scan queue not wired", true)
		return
	}

	ctx := r.Context()
	hostID := uuid.UUID(id)

	// 404 before any side effect.
	if _, err := h.hosts.GetByID(ctx, hostID); err != nil {
		if errors.Is(err, host.ErrHostNotFound) {
			writeError(w, http.StatusNotFound, "hosts.not_found", "client",
				"host not found", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"lookup failed", true)
		return
	}

	// One active run per host: 409 with the existing scan id.
	if active, err := scanruns.ActiveForHost(ctx, h.pool, hostID); err == nil {
		writeError(w, http.StatusConflict, "conflict.scan_active", "client",
			fmt.Sprintf("a scan for this host is already %s (scan_id %s)", active.Status, active.ID), true)
		return
	} else if !errors.Is(err, scanruns.ErrNotFound) {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"active-run lookup failed", true)
		return
	}

	// Enqueue the HMAC-signed job — the exact payload shape the worker
	// verifies (scheduler.Verify); same encoding as scheduler.Dispatch.
	now := time.Now().UTC()
	payload := scheduler.JobPayload{
		HostID:        hostID,
		PolicyVersion: "", // on-demand runs are unversioned (no schedules policy snapshot)
		EnqueuedAt:    now,
	}
	tag := scheduler.Sign(h.scanQueueKey, payload)
	body := map[string]any{
		"host_id":        payload.HostID.String(),
		"policy_version": payload.PolicyVersion,
		"enqueued_at":    payload.EnqueuedAt.Format(time.RFC3339Nano),
		"hmac":           fmt.Sprintf("%x", tag[:]),
	}
	jobID, err := queue.Enqueue(ctx, h.pool, "scan", body)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"enqueue failed", true)
		return
	}

	// Logbook row: scan_runs.id == job id (system-scan-runs C-01).
	run := scanruns.Run{
		ID:            jobID,
		HostID:        hostID,
		TriggerSource: scanruns.TriggerOnDemand,
	}
	if corrID, ok := correlation.From(ctx); ok {
		run.CorrelationID = corrID
	}
	ident := auth.FromContext(ctx)
	if userID, perr := uuid.Parse(ident.ID); perr == nil {
		run.RequestedBy = &userID
	}
	if err := scanruns.Insert(ctx, h.pool, run); err != nil {
		// The job is already queued; the worker's MarkRunning UPSERT
		// will still create a row (attributed 'scheduled'). Log-only.
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"scan run record failed", true)
		return
	}

	// Audit: who asked for the scan, from where. scan.started/
	// completed/failed follow from the executor with the same scan id.
	detail, _ := json.Marshal(map[string]string{
		"scan_id": jobID.String(),
		"host_id": hostID.String(),
		"trigger": string(scanruns.TriggerOnDemand),
	})
	audit.Emit(ctx, audit.ScanQueued, audit.Event{
		ActorType: "user",
		ActorID:   ident.ID,
		Detail:    detail,
	})

	writeJSON(w, http.StatusAccepted, api.ScanRunQueued{
		ScanId:   jobID,
		Status:   api.Queued,
		QueuedAt: now,
	})
}
