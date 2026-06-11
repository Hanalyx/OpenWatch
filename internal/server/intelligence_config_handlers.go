// OS Intelligence scheduler HTTP config surface.
//
// Spec: app/specs/api/system-intelligence-config.spec.yaml
//
// Mirrors systemconfig_handlers.go (connectivity) verbatim — same shape,
// same validation/audit pattern. The two could share helpers in a
// follow-up but the bodies are small enough that the duplication is
// load-bearing readability rather than dead weight.

package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/server/api"
	"github.com/Hanalyx/openwatch/internal/systemconfig"
)

// GetSystemIntelligenceConfig implements api.ServerInterface.
// Spec api-system-intelligence-config AC-01 / AC-02.
func (h *handlers) GetSystemIntelligenceConfig(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.SystemRead); denied {
		return
	}
	if h.sysCfg == nil {
		// Config store not wired (tests). Fall back to defaults so the
		// endpoint still satisfies its contract.
		writeJSON(w, http.StatusOK, intelligenceConfigResponse(systemconfig.DefaultIntelligence()))
		return
	}
	cfg, err := h.sysCfg.LoadIntelligence(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"failed to load intelligence config", true)
		return
	}
	writeJSON(w, http.StatusOK, intelligenceConfigResponse(cfg))
}

// PutSystemIntelligenceConfig implements api.ServerInterface.
// Spec api-system-intelligence-config AC-03 / AC-04 / AC-05 / AC-06 / AC-07 / AC-08.
func (h *handlers) PutSystemIntelligenceConfig(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.SystemConfigWrite); denied {
		return
	}
	var req api.IntelligenceConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"malformed request body", false)
		return
	}

	cfg := systemconfig.IntelligenceConfig{
		IntervalSec:       req.IntervalSec,
		RateLimit:         req.RateLimit,
		MaintenanceGlobal: req.MaintenanceGlobal,
	}
	if err := cfg.Validate(); err != nil {
		field := firstInvalidIntelligenceField(cfg)
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
	if err := h.sysCfg.SetIntelligence(r.Context(), cfg, changedBy); err != nil {
		if errors.Is(err, systemconfig.ErrInvalidConfig) {
			field := firstInvalidIntelligenceField(cfg)
			writeErrorDetail(w, http.StatusBadRequest, "validation.range_exceeded", "client",
				err.Error(), false, map[string]any{"field": field})
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"failed to save intelligence config", true)
		return
	}

	writeJSON(w, http.StatusOK, toAPIIntelligenceConfig(cfg))
}

// intelligenceConfigResponse wraps active + defaults. Spec C-01.
func intelligenceConfigResponse(active systemconfig.IntelligenceConfig) api.IntelligenceConfigResponse {
	return api.IntelligenceConfigResponse{
		Config:   toAPIIntelligenceConfig(active),
		Defaults: toAPIIntelligenceConfig(systemconfig.DefaultIntelligence()),
	}
}

func toAPIIntelligenceConfig(c systemconfig.IntelligenceConfig) api.IntelligenceConfig {
	return api.IntelligenceConfig{
		IntervalSec:       c.IntervalSec,
		RateLimit:         c.RateLimit,
		MaintenanceGlobal: c.MaintenanceGlobal,
	}
}

// firstInvalidIntelligenceField returns the name of the first
// out-of-bounds field so the 400 envelope's detail.field points at
// the value the user broke first. Order matches
// systemconfig.IntelligenceConfig.Validate.
func firstInvalidIntelligenceField(c systemconfig.IntelligenceConfig) string {
	switch {
	case c.IntervalSec < 300 || c.IntervalSec > 86400:
		return "interval_sec"
	case c.RateLimit < 1 || c.RateLimit > 200:
		return "rate_limit"
	}
	return ""
}
