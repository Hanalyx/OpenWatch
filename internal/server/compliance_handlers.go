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
// corpus (host_rule_state.framework_refs). Read-gated on host:read.
func (h *handlers) GetComplianceFrameworks(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.HostRead); denied {
		return
	}
	fams, err := framework.NewService(h.pool).Families(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"list compliance frameworks failed", true)
		return
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
	writeJSON(w, http.StatusOK, api.ComplianceConfig{DefaultFramework: cfg.DefaultFramework})
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
	actor := auth.FromContext(r.Context()).ID
	cfg, err := h.sysCfg.SetCompliance(r.Context(),
		systemconfig.ComplianceConfig{DefaultFramework: req.DefaultFramework}, actor)
	if err != nil {
		if errors.Is(err, systemconfig.ErrInvalidConfig) {
			writeError(w, http.StatusBadRequest, "validation.field_invalid", "client",
				"invalid default_framework", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"save compliance config failed", true)
		return
	}
	writeJSON(w, http.StatusOK, api.ComplianceConfig{DefaultFramework: cfg.DefaultFramework})
}
