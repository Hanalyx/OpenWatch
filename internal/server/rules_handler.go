// Rule library HTTP surface: the full Kensa rule catalog (reference data)
// for the rule-library browser on /scans. Read-only; the corpus is static
// and normalized once at boot in internal/kensa.RuleLibrary. The browser
// filters client-side, so this returns the whole list.
//
// Spec: api-rules.

package server

import (
	"net/http"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/kensa"
	"github.com/Hanalyx/openwatch/internal/server/api"
)

// GetRules returns the Kensa rule library. Spec api-rules.
func (h *handlers) GetRules(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.ScanRead); denied {
		return
	}
	if h.ruleLibrary == nil {
		writeError(w, http.StatusServiceUnavailable, "server.unavailable", "server",
			"rule library not wired", true)
		return
	}
	rules := h.ruleLibrary.List()
	resp := api.RuleList{Rules: make([]api.RuleListItem, 0, len(rules)), Total: len(rules)}
	for _, ru := range rules {
		resp.Rules = append(resp.Rules, toAPIRuleListItem(ru))
	}
	writeJSON(w, http.StatusOK, resp)
}

// toAPIRuleListItem maps a normalized library rule to the wire shape.
func toAPIRuleListItem(ru kensa.RuleListItem) api.RuleListItem {
	tags := ru.Tags
	if tags == nil {
		tags = []string{}
	}
	refs := ru.FrameworkRefs
	if refs == nil {
		refs = map[string][]string{}
	}
	mechs := ru.Remediation.Mechanisms
	if mechs == nil {
		mechs = []string{}
	}
	restarts := ru.Remediation.RestartsServices
	if restarts == nil {
		restarts = []string{}
	}
	return api.RuleListItem{
		Id:            ru.ID,
		Title:         ru.Title,
		Description:   ru.Description,
		Severity:      ru.Severity,
		Category:      ru.Category,
		Tags:          tags,
		FrameworkRefs: refs,
		Transactional: ru.Transactional,
		Remediation: api.RuleRemediation{
			Available:        ru.Remediation.Available,
			Mechanisms:       mechs,
			RestartsServices: restarts,
			RebootBehavior:   ru.Remediation.RebootBehavior,
		},
	}
}
