// Connectivity-monitor HTTP surface.
//
// Specs:
//   - app/specs/api/system-connectivity.spec.yaml
//   - app/specs/api/fleet-connectivity-breakdown.spec.yaml
//
// All handlers delegate to internal/systemconfig (persistence) and
// internal/liveness (in-process probe loop). No SQL lives here.

package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/server/api"
	"github.com/Hanalyx/openwatch/internal/systemconfig"
)

// ---------------------------------------------------------------------
// GET /api/v1/system/connectivity/config
// ---------------------------------------------------------------------

// GetSystemConnectivityConfig implements api.ServerInterface.
// Spec api-system-connectivity AC-01.
func (h *handlers) GetSystemConnectivityConfig(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.SystemRead); denied {
		return
	}
	if h.sysCfg == nil {
		// Config store not wired (tests). Fall back to defaults so the
		// endpoint still satisfies its contract.
		writeJSON(w, http.StatusOK, configResponse(systemconfig.DefaultConnectivity()))
		return
	}
	cfg, err := h.sysCfg.LoadConnectivity(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"failed to load connectivity config", true)
		return
	}
	writeJSON(w, http.StatusOK, configResponse(cfg))
}

// ---------------------------------------------------------------------
// PUT /api/v1/system/connectivity/config
// ---------------------------------------------------------------------

// PutSystemConnectivityConfig implements api.ServerInterface.
// Spec api-system-connectivity AC-02 / AC-03 / AC-06 / AC-11.
func (h *handlers) PutSystemConnectivityConfig(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.SystemConfigWrite); denied {
		return
	}
	var req api.ConnectivityConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"malformed request body", false)
		return
	}

	cfg := systemconfig.ConnectivityConfig{
		IntervalSec:          req.IntervalSec,
		TimeoutSec:           req.TimeoutSec,
		UnreachableThreshold: req.UnreachableThreshold,
		RateLimit:            req.RateLimit,
		MaintenanceGlobal:    req.MaintenanceGlobal,
	}
	if err := cfg.Validate(); err != nil {
		field := firstInvalidField(cfg)
		writeErrorDetail(w, http.StatusBadRequest, "validation.range_exceeded", "client",
			err.Error(), false, map[string]any{"field": field})
		return
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
	if err := h.sysCfg.SetConnectivity(r.Context(), cfg, changedBy); err != nil {
		if errors.Is(err, systemconfig.ErrInvalidConfig) {
			field := firstInvalidField(cfg)
			writeErrorDetail(w, http.StatusBadRequest, "validation.range_exceeded", "client",
				err.Error(), false, map[string]any{"field": field})
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"failed to save connectivity config", true)
		return
	}

	// Signal the in-process liveness service to pick up the new values
	// on the next tick. Best-effort: a nil service (test paths) or a
	// reload failure does not invalidate the PUT — the persisted state
	// is what matters. Spec C-04.
	if h.liveSvc != nil {
		if err := h.liveSvc.Reload(r.Context()); err != nil {
			slog.WarnContext(r.Context(), "liveness reload after config PUT failed",
				slog.String("err", err.Error()))
		}
	}

	writeJSON(w, http.StatusOK, toAPIConfig(cfg))
}

// ---------------------------------------------------------------------
// GET /api/v1/system/connectivity/status
// ---------------------------------------------------------------------

// GetSystemConnectivityStatus implements api.ServerInterface.
// Spec api-system-connectivity AC-08.
func (h *handlers) GetSystemConnectivityStatus(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.SystemRead); denied {
		return
	}

	resp := api.ConnectivityStatus{
		MaintenanceActive: false,
	}
	if h.liveSvc != nil {
		snap := h.liveSvc.Metrics().Snapshot()
		resp.ProbeCount = snap.ProbeCount
		resp.ProbeSuccessCount = snap.ProbeSuccessCount
		resp.ProbeFailureCount = snap.ProbeFailureCount
		resp.StateTransitionCount = snap.StateTransitionCount
		if !snap.LastProbeAt.IsZero() {
			t := snap.LastProbeAt
			resp.LastProbeAt = &t
		}
	}
	if h.sysCfg != nil {
		if cfg, err := h.sysCfg.LoadConnectivity(r.Context()); err == nil {
			resp.MaintenanceActive = cfg.MaintenanceGlobal
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

// configResponse builds the wrapped response containing both the
// active config and the baked-in defaults — UI uses the defaults
// sub-object to render a "reset to defaults" affordance without a
// round-trip. Spec C-01.
func configResponse(active systemconfig.ConnectivityConfig) api.ConnectivityConfigResponse {
	return api.ConnectivityConfigResponse{
		Config:   toAPIConfig(active),
		Defaults: toAPIConfig(systemconfig.DefaultConnectivity()),
	}
}

func toAPIConfig(c systemconfig.ConnectivityConfig) api.ConnectivityConfig {
	return api.ConnectivityConfig{
		IntervalSec:          c.IntervalSec,
		TimeoutSec:           c.TimeoutSec,
		UnreachableThreshold: c.UnreachableThreshold,
		RateLimit:            c.RateLimit,
		MaintenanceGlobal:    c.MaintenanceGlobal,
	}
}

// firstInvalidField returns the name of the first out-of-bounds field
// — used to populate the validation error envelope's detail.field.
// Order matches systemconfig.Validate so the surfaced field is the
// one the user actually broke first.
func firstInvalidField(c systemconfig.ConnectivityConfig) string {
	switch {
	case c.IntervalSec < 60 || c.IntervalSec > 86400:
		return "interval_sec"
	case c.TimeoutSec < 1 || c.TimeoutSec > 30:
		return "timeout_sec"
	case c.UnreachableThreshold < 1 || c.UnreachableThreshold > 10:
		return "unreachable_threshold"
	case c.RateLimit < 1 || c.RateLimit > 200:
		return "rate_limit"
	}
	return ""
}

// writeErrorDetail mirrors writeError but accepts a free-form detail
// map so handlers can surface field-level diagnostics.
func writeErrorDetail(w http.ResponseWriter, status int, code, fault, msg string, retryable bool, detail map[string]any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	env := map[string]any{
		"error": map[string]any{
			"code":          code,
			"fault":         fault,
			"human_message": msg,
			"retryable":     retryable,
		},
	}
	if len(detail) > 0 {
		errObj := env["error"].(map[string]any)
		errObj["detail"] = detail
	}
	_ = json.NewEncoder(w).Encode(env)
}

// unused-import guard so audit stays referenced even when only the
// systemconfig package emits via its EmitFunc.
var _ = audit.SystemConfigChanged
var _ context.Context
