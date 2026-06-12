// Adaptive compliance scan scheduler HTTP surface: config GET/PUT,
// fleet per-state counts, and the 24h schedule projection.
//
// Spec: specs/api/system-scan-config.spec.yaml
//
// Mirrors discovery_config_handlers.go: same {config, defaults}
// envelope, same RBAC split (system:read to read, system:config:write
// to write), same SystemConfigChanged audit emission inside the store.
// The one divergence is PUT semantics: ladder minutes and rate_limit
// are CLAMPED (ScanConfig.Normalize), never rejected, and the response
// echoes the clamped values (scan plan Phase 4 ratification).

package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/scheduler"
	"github.com/Hanalyx/openwatch/internal/server/api"
	"github.com/Hanalyx/openwatch/internal/systemconfig"
)

// GetSystemScanConfig implements api.ServerInterface.
// Spec api-system-scan-config AC-01 / AC-02.
func (h *handlers) GetSystemScanConfig(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.SystemRead); denied {
		return
	}
	if h.sysCfg == nil {
		writeJSON(w, http.StatusOK, scanConfigResponse(systemconfig.DefaultScan()))
		return
	}
	cfg, err := h.sysCfg.LoadScan(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"failed to load scan config", true)
		return
	}
	writeJSON(w, http.StatusOK, scanConfigResponse(cfg))
}

// PutSystemScanConfig implements api.ServerInterface.
// Spec api-system-scan-config AC-03 / AC-04 / AC-05.
func (h *handlers) PutSystemScanConfig(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.SystemConfigWrite); denied {
		return
	}
	var req api.ScanConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"malformed request body", false)
		return
	}

	cfg := systemconfig.ScanConfig{
		Enabled:             req.Enabled,
		UnknownMins:         req.UnknownMins,
		CriticalMins:        req.CriticalMins,
		NonCompliantMins:    req.NonCompliantMins,
		PartialMins:         req.PartialMins,
		MostlyCompliantMins: req.MostlyCompliantMins,
		CompliantMins:       req.CompliantMins,
		RateLimit:           req.RateLimit,
		MaintenanceGlobal:   req.MaintenanceGlobal,
	}

	changedBy := auth.FromContext(r.Context()).ID
	if changedBy == "" {
		changedBy = "anonymous"
	}
	if h.sysCfg == nil {
		writeError(w, http.StatusServiceUnavailable, "server.unavailable", "server",
			"systemconfig store not wired", true)
		return
	}
	// SetScan normalizes (clamps) before persisting and returns what
	// was actually stored; the response echoes the clamped values so
	// the UI re-renders the effective config.
	saved, err := h.sysCfg.SetScan(r.Context(), cfg, changedBy)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"failed to save scan config", true)
		return
	}
	writeJSON(w, http.StatusOK, toAPIScanConfig(saved))
}

// GetFleetComplianceStates implements api.ServerInterface.
// The projection lives in internal/scheduler (the table owner —
// system-scheduler AC-07 bans this package from referencing it).
// Spec api-system-scan-config AC-06.
func (h *handlers) GetFleetComplianceStates(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.HostRead); denied {
		return
	}
	counts, err := scheduler.FleetStateCounts(r.Context(), h.pool)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"failed to query compliance states", true)
		return
	}
	resp := api.FleetComplianceStates{}
	for _, c := range counts {
		resp.States = append(resp.States, struct {
			HostCount int                                  `json:"host_count"`
			State     api.FleetComplianceStatesStatesState `json:"state"`
		}{
			HostCount: c.HostCount,
			State:     api.FleetComplianceStatesStatesState(c.State),
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

// GetSystemScanSchedulePreview implements api.ServerInterface.
// Projection logic lives in internal/scheduler (table owner); this
// handler adds RBAC, the scan_runs queue depth, and the wire shape.
// Spec api-system-scan-config AC-07.
func (h *handlers) GetSystemScanSchedulePreview(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.SystemRead); denied {
		return
	}
	ctx := r.Context()

	prev, err := scheduler.PreviewSchedule(ctx, h.pool, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"failed to project schedule", true)
		return
	}

	resp := api.ScanSchedulePreview{
		NextScanAt: prev.NextScanAt,
		DueNow:     prev.DueNow,
	}

	// Live queue depth from the scan logbook (same source as the
	// fleet scan-queue KPI).
	if err := h.pool.QueryRow(ctx, `
		SELECT COUNT(*) FILTER (WHERE status = 'queued'),
		       COUNT(*) FILTER (WHERE status = 'running')
		  FROM scan_runs WHERE status IN ('queued', 'running')`,
	).Scan(&resp.QueuedJobs, &resp.RunningJobs); err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"failed to read scan queue depth", true)
		return
	}

	for i, n := range prev.Buckets {
		resp.Buckets = append(resp.Buckets, struct {
			DueCount int `json:"due_count"`

			// HourOffset Hours from now (0 = the coming hour)
			HourOffset int `json:"hour_offset"`
		}{DueCount: n, HourOffset: i})
	}

	writeJSON(w, http.StatusOK, resp)
}

// scanConfigResponse wraps active + defaults. Spec C-01.
func scanConfigResponse(active systemconfig.ScanConfig) api.ScanConfigResponse {
	return api.ScanConfigResponse{
		Config:   toAPIScanConfig(active),
		Defaults: toAPIScanConfig(systemconfig.DefaultScan()),
	}
}

func toAPIScanConfig(c systemconfig.ScanConfig) api.ScanConfig {
	return api.ScanConfig{
		Enabled:             c.Enabled,
		UnknownMins:         c.UnknownMins,
		CriticalMins:        c.CriticalMins,
		NonCompliantMins:    c.NonCompliantMins,
		PartialMins:         c.PartialMins,
		MostlyCompliantMins: c.MostlyCompliantMins,
		CompliantMins:       c.CompliantMins,
		RateLimit:           c.RateLimit,
		MaintenanceGlobal:   c.MaintenanceGlobal,
	}
}

// GetSystemScanVariables implements api.ServerInterface.
// Spec api-system-scan-config v1.1.0 AC-08.
func (h *handlers) GetSystemScanVariables(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.SystemRead); denied {
		return
	}
	overrides := systemconfig.ScanVariables{}
	if h.sysCfg != nil {
		loaded, err := h.sysCfg.LoadScanVars(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server.error", "server",
				"failed to load scan variables", true)
			return
		}
		overrides = loaded
	}

	resp := api.ScanVariablesResponse{Variables: []struct {
		AffectsRules int      `json:"affects_rules"`
		ConfigureMe  bool     `json:"configure_me"`
		Default      string   `json:"default"`
		Name         string   `json:"name"`
		Overridden   bool     `json:"overridden"`
		RuleIds      []string `json:"rule_ids"`
		Value        string   `json:"value"`
	}{}}
	for _, v := range h.varCatalog.List() {
		value, overridden := overrides[v.Name]
		if !overridden {
			value = v.Default
		}
		resp.Variables = append(resp.Variables, struct {
			AffectsRules int      `json:"affects_rules"`
			ConfigureMe  bool     `json:"configure_me"`
			Default      string   `json:"default"`
			Name         string   `json:"name"`
			Overridden   bool     `json:"overridden"`
			RuleIds      []string `json:"rule_ids"`
			Value        string   `json:"value"`
		}{
			AffectsRules: len(v.Rules),
			ConfigureMe:  v.ConfigureMe,
			Default:      v.Default,
			Name:         v.Name,
			Overridden:   overridden,
			RuleIds:      v.Rules,
			Value:        value,
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

// PutSystemScanVariables implements api.ServerInterface.
// Spec api-system-scan-config v1.1.0 AC-09.
func (h *handlers) PutSystemScanVariables(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.SystemConfigWrite); denied {
		return
	}
	var req api.ScanVariableOverrides
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"malformed request body", false)
		return
	}

	// Validate names against the corpus-used catalog and drop
	// overrides equal to the built-in default (storing them would
	// just mask future default changes for no operator intent).
	vars := systemconfig.ScanVariables{}
	for _, v := range h.varCatalog.List() {
		val, ok := req.Overrides[v.Name]
		if !ok {
			continue
		}
		if val != v.Default {
			vars[v.Name] = val
		}
	}
	for name := range req.Overrides {
		if !h.varCatalog.Has(name) {
			writeErrorDetail(w, http.StatusBadRequest, "validation.field_invalid", "client",
				"unknown scan variable: "+name, false, map[string]any{"field": name})
			return
		}
	}

	changedBy := auth.FromContext(r.Context()).ID
	if changedBy == "" {
		changedBy = "anonymous"
	}
	if h.sysCfg == nil {
		writeError(w, http.StatusServiceUnavailable, "server.unavailable", "server",
			"systemconfig store not wired", true)
		return
	}
	if err := h.sysCfg.SetScanVars(r.Context(), vars, changedBy); err != nil {
		if errors.Is(err, systemconfig.ErrInvalidConfig) {
			writeError(w, http.StatusBadRequest, "validation.range_exceeded", "client",
				err.Error(), false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"failed to save scan variables", true)
		return
	}

	out := map[string]string(vars)
	writeJSON(w, http.StatusOK, api.ScanVariableOverrides{Overrides: out})
}
