// Per-host maintenance toggle + monitoring-history tail (v1.3.0).
// Spec: app/specs/api/hosts/host-monitoring.spec.yaml.
//
// Maintenance: PUT /hosts/{id}/maintenance flips the hosts.maintenance_mode
// boolean. listProbeTargets skips maintenance hosts on every subsequent
// tick — no probes, no audits, no history rows. The host_liveness row
// is left intact so resuming maintenance picks up from the last
// observed band.
//
// History: GET /hosts/{id}/monitoring/history tails the
// host_monitoring_history append-only table (newest first). Surface
// for the operator dashboard's "why is this host degraded?" drill-down.

package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	openapitypes "github.com/oapi-codegen/runtime/types"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/host"
	"github.com/Hanalyx/openwatch/internal/server/api"
)

// PutHostMaintenance flips hosts.maintenance_mode and emits an audit.
// Spec api-hosts v1.4.0 AC-20.
func (h *handlers) PutHostMaintenance(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.HostWrite); denied {
		return
	}
	var req api.HostMaintenanceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"enabled is required", false)
		return
	}
	hostID := uuid.UUID(id)

	tag, err := h.pool.Exec(r.Context(),
		`UPDATE hosts
		    SET maintenance_mode = $1, updated_at = now()
		  WHERE id = $2 AND deleted_at IS NULL`,
		req.Enabled, hostID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"maintenance update failed", true)
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "hosts.not_found", "client",
			"host not found", false)
		return
	}

	updated, err := h.hosts.GetByID(r.Context(), hostID)
	if err != nil {
		if errors.Is(err, host.ErrHostNotFound) {
			writeError(w, http.StatusNotFound, "hosts.not_found", "client",
				"host not found", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"lookup failed", true)
		return
	}
	emitAudit(r, audit.HostUpdated, hostID.String(), map[string]any{
		"maintenance_mode": req.Enabled,
	})
	writeJSON(w, http.StatusOK, hostResponse(updated))
}

// GetHostMonitoringHistory tails up to `limit` rows newest-first.
// Spec api-hosts v1.4.0 AC-21.
func (h *handlers) GetHostMonitoringHistory(w http.ResponseWriter, r *http.Request, id openapitypes.UUID, params api.GetHostMonitoringHistoryParams) {
	if denied := auth.EnforcePermission(w, r, auth.HostRead); denied {
		return
	}
	hostID := uuid.UUID(id)

	// Existence check so the 404 path is consistent with the rest of
	// the host CRUD surface.
	if _, err := h.hosts.GetByID(r.Context(), hostID); err != nil {
		if errors.Is(err, host.ErrHostNotFound) {
			writeError(w, http.StatusNotFound, "hosts.not_found", "client",
				"host not found", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"lookup failed", true)
		return
	}

	limit := 50
	if params.Limit != nil {
		limit = *params.Limit
	}
	if limit < 1 || limit > 500 {
		limit = 50
	}

	rows, err := h.pool.Query(r.Context(), `
		SELECT id, host_id, check_time, monitoring_state, previous_state,
		       response_time_ms, ping_ok, ssh_ok, privilege_ok,
		       failed_layer, error_message, error_type
		  FROM host_monitoring_history
		 WHERE host_id = $1
		 ORDER BY check_time DESC
		 LIMIT $2`, hostID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"history query failed", true)
		return
	}
	defer rows.Close()

	entries := make([]api.HostMonitoringHistoryEntry, 0, limit)
	for rows.Next() {
		var (
			rowID         int64
			hID           uuid.UUID
			checkTime     time.Time
			monitoring    string
			previous      *string
			responseMS    *int
			pingOK        *bool
			sshOK         *bool
			privOK        *bool
			failedLayer   *string
			errMsg        *string
			errType       *string
		)
		if err := rows.Scan(&rowID, &hID, &checkTime, &monitoring, &previous,
			&responseMS, &pingOK, &sshOK, &privOK,
			&failedLayer, &errMsg, &errType); err != nil {
			writeError(w, http.StatusInternalServerError, "server.error", "server",
				"history scan failed", true)
			return
		}
		entry := api.HostMonitoringHistoryEntry{
			Id:              rowID,
			HostId:          openapitypes.UUID(hID),
			CheckTime:       checkTime,
			MonitoringState: api.HostMonitoringHistoryEntryMonitoringState(monitoring),
			ResponseTimeMs:  responseMS,
			PingOk:          pingOK,
			SshOk:           sshOK,
			PrivilegeOk:     privOK,
			ErrorMessage:    errMsg,
			ErrorType:       errType,
		}
		if previous != nil {
			ps := api.HostMonitoringHistoryEntryPreviousState(*previous)
			entry.PreviousState = &ps
		}
		if failedLayer != nil {
			fl := api.HostMonitoringHistoryEntryFailedLayer(*failedLayer)
			entry.FailedLayer = &fl
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"history iter failed", true)
		return
	}

	writeJSON(w, http.StatusOK, api.HostMonitoringHistoryResponse{
		HostId:  openapitypes.UUID(hostID),
		Entries: entries,
	})
}
