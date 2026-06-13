// Compliance trend HTTP surface: per-host and fleet daily posture
// trends from the posture_snapshots rollup.
//
// Spec: specs/api/compliance-trend.spec.yaml
//
// Thin handlers: RBAC + 404 + the days clamp here; the queries live in
// internal/posture (the snapshot table's owning package).

package server

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	openapitypes "github.com/oapi-codegen/runtime/types"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/host"
	"github.com/Hanalyx/openwatch/internal/posture"
	"github.com/Hanalyx/openwatch/internal/scheduler"
	"github.com/Hanalyx/openwatch/internal/server/api"
	"github.com/Hanalyx/openwatch/internal/systemconfig"
)

// trendDays clamps the ?days window into [1, 90], defaulting to 30.
func trendDays(raw *int) int {
	if raw == nil {
		return 30
	}
	d := *raw
	if d < 1 {
		return 1
	}
	if d > 90 {
		return 90
	}
	return d
}

// GetHostComplianceTrend implements api.ServerInterface.
// Spec api-compliance-trend AC-01 / AC-02 / AC-04.
func (h *handlers) GetHostComplianceTrend(
	w http.ResponseWriter,
	r *http.Request,
	id openapitypes.UUID,
	params api.GetHostComplianceTrendParams,
) {
	if denied := auth.EnforcePermission(w, r, auth.HostRead); denied {
		return
	}
	ctx := r.Context()
	hostID := uuid.UUID(id)

	// 404 pre-read: same lookup as the compliance lens (C-03 there).
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

	points, err := posture.HostTrend(ctx, h.pool, hostID, trendDays(params.Days))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"trend query failed", true)
		return
	}

	resp := api.HostComplianceTrend{Days: []struct {
		Date     openapitypes.Date `json:"date"`
		Failing  int               `json:"failing"`
		Passing  int               `json:"passing"`
		ScorePct float32           `json:"score_pct"`
		Total    int               `json:"total"`
	}{}}
	for _, p := range points {
		resp.Days = append(resp.Days, struct {
			Date     openapitypes.Date `json:"date"`
			Failing  int               `json:"failing"`
			Passing  int               `json:"passing"`
			ScorePct float32           `json:"score_pct"`
			Total    int               `json:"total"`
		}{
			Date:     openapitypes.Date{Time: p.Date},
			Failing:  p.Failing,
			Passing:  p.Passing,
			ScorePct: float32(p.ScorePct),
			Total:    p.Total,
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

// GetFleetComplianceTrend implements api.ServerInterface.
// Spec api-compliance-trend AC-03 / AC-04.
func (h *handlers) GetFleetComplianceTrend(
	w http.ResponseWriter,
	r *http.Request,
	params api.GetFleetComplianceTrendParams,
) {
	if denied := auth.EnforcePermission(w, r, auth.HostRead); denied {
		return
	}

	points, err := posture.FleetTrend(r.Context(), h.pool, trendDays(params.Days))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"fleet trend query failed", true)
		return
	}

	resp := api.FleetComplianceTrend{Days: []struct {
		AvgScorePct   float32           `json:"avg_score_pct"`
		CriticalHosts int               `json:"critical_hosts"`
		Date          openapitypes.Date `json:"date"`
		Failing       int               `json:"failing"`
		Hosts         int               `json:"hosts"`
	}{}}
	for _, p := range points {
		resp.Days = append(resp.Days, struct {
			AvgScorePct   float32           `json:"avg_score_pct"`
			CriticalHosts int               `json:"critical_hosts"`
			Date          openapitypes.Date `json:"date"`
			Failing       int               `json:"failing"`
			Hosts         int               `json:"hosts"`
		}{
			AvgScorePct:   float32(p.AvgScorePct),
			CriticalHosts: p.CriticalHosts,
			Date:          openapitypes.Date{Time: p.Date},
			Failing:       p.Failing,
			Hosts:         p.Hosts,
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

// GetHostComplianceSchedule implements api.ServerInterface.
// Backs the host detail Auto-scan tile: the host's schedule row plus
// the scheduler-wide pause flags. Read view lives in internal/scheduler
// (table owner). Spec api-system-scan-config AC-10.
func (h *handlers) GetHostComplianceSchedule(
	w http.ResponseWriter,
	r *http.Request,
	id openapitypes.UUID,
) {
	if denied := auth.EnforcePermission(w, r, auth.HostRead); denied {
		return
	}
	ctx := r.Context()
	hostID := uuid.UUID(id)

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

	info, err := scheduler.HostSchedule(ctx, h.pool, hostID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"schedule query failed", true)
		return
	}

	cfg := systemconfig.DefaultScan()
	if h.sysCfg != nil {
		if loaded, cfgErr := h.sysCfg.LoadScan(ctx); cfgErr == nil {
			cfg = loaded
		}
	}

	writeJSON(w, http.StatusOK, api.HostComplianceSchedule{
		SchedulerEnabled: cfg.Enabled,
		SchedulerPaused:  !cfg.Enabled || cfg.MaintenanceGlobal,
		ComplianceState:  api.HostComplianceScheduleComplianceState(info.State),
		NextScanAt:       info.NextScanAt,
		IntervalMinutes:  info.IntervalMinutes,
		HostMaintenance:  info.Maintenance,
	})
}
