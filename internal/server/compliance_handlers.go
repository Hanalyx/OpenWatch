package server

// Compliance-display endpoints: the org-wide DEFAULT LENS setting and the
// list of framework families present in the scanned corpus (for the picker).
// The lens is a read-time projection — it changes what scores are shown, not
// what was scanned (scans always run the full Kensa corpus).

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/framework"
	"github.com/Hanalyx/openwatch/internal/server/api"
	"github.com/Hanalyx/openwatch/internal/systemconfig"
)

// GetComplianceFrameworks lists the framework families derived from the
// corpus (host_rule_state.framework_refs). Read-gated on host:read. By
// default the list is narrowed to the enabled-frameworks allowlist (Phase 2);
// pass all=true to return every corpus family (for the allowlist editor).
func (h *handlers) GetComplianceFrameworks(w http.ResponseWriter, r *http.Request, params api.GetComplianceFrameworksParams) {
	if denied := auth.EnforcePermission(w, r, auth.HostRead); denied {
		return
	}
	fams, err := framework.NewService(h.pool).Families(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"list compliance frameworks failed", true)
		return
	}
	// Narrow to the enabled-frameworks allowlist unless the caller asked for
	// all (the editor) or no allowlist is set. This is a display filter, not a
	// security boundary: a config-load error degrades to showing all families.
	all := params.All != nil && *params.All
	if !all {
		if cfg, cerr := h.sysCfg.LoadCompliance(r.Context()); cerr == nil && len(cfg.EnabledFrameworks) > 0 {
			enabled := make(map[string]bool, len(cfg.EnabledFrameworks))
			for _, f := range cfg.EnabledFrameworks {
				enabled[f] = true
			}
			filtered := make([]framework.Family, 0, len(fams))
			for _, f := range fams {
				if enabled[f.ID] {
					filtered = append(filtered, f)
				}
			}
			fams = filtered
		}
	}
	out := api.ComplianceFrameworksResponse{Frameworks: make([]api.ComplianceFramework, 0, len(fams))}
	for _, f := range fams {
		out.Frameworks = append(out.Frameworks, api.ComplianceFramework{
			Id: f.ID, Label: f.Label, Keys: f.Keys,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// GetSystemComplianceConfig returns the org-wide compliance-display config
// (the default lens). system:read.
func (h *handlers) GetSystemComplianceConfig(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.SystemRead); denied {
		return
	}
	cfg, err := h.sysCfg.LoadCompliance(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"load compliance config failed", true)
		return
	}
	writeJSON(w, http.StatusOK, toAPIComplianceConfig(cfg))
}

// toAPIComplianceConfig maps the stored config to the API shape. An empty
// allowlist is emitted as an absent enabled_frameworks (omitempty), matching
// "empty means all families available".
func toAPIComplianceConfig(cfg systemconfig.ComplianceConfig) api.ComplianceConfig {
	out := api.ComplianceConfig{DefaultFramework: cfg.DefaultFramework}
	if len(cfg.EnabledFrameworks) > 0 {
		ef := cfg.EnabledFrameworks
		out.EnabledFrameworks = &ef
	}
	return out
}

// PutSystemComplianceConfig sets the default compliance lens. system:config:write.
func (h *handlers) PutSystemComplianceConfig(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.SystemConfigWrite); denied {
		return
	}
	var req api.ComplianceConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.malformed", "client",
			"malformed request body", false)
		return
	}
	var enabled []string
	if req.EnabledFrameworks != nil {
		enabled = *req.EnabledFrameworks
	}
	actor := auth.FromContext(r.Context()).ID
	cfg, err := h.sysCfg.SetCompliance(r.Context(),
		systemconfig.ComplianceConfig{DefaultFramework: req.DefaultFramework, EnabledFrameworks: enabled}, actor)
	if err != nil {
		if errors.Is(err, systemconfig.ErrInvalidConfig) {
			writeError(w, http.StatusBadRequest, "validation.field_invalid", "client",
				"invalid compliance config", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"save compliance config failed", true)
		return
	}
	writeJSON(w, http.StatusOK, toAPIComplianceConfig(cfg))
}
