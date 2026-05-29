package server

import (
	"net/http"

	"github.com/Hanalyx/openwatch/internal/auth"
	openapitypes "github.com/oapi-codegen/runtime/types"

	"github.com/Hanalyx/openwatch/internal/server/api"
)

// Fleet observability endpoints.
//
// Spec: app/specs/api/fleet-observability.spec.yaml.
//
// Every handler is a thin wrapper: RBAC gate, parse/validate, delegate
// to internal/fleetrollup.Service, JSON-encode. No SQL, no aggregation
// logic — those live in the fleetrollup package. AC-13 enforces the
// SQL-free invariant via source inspection.

// GetFleetScore implements api.ServerInterface.GetFleetScore.
// Spec api-fleet-observability AC-01, AC-02, AC-11, AC-12.
func (h *handlers) GetFleetScore(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.SystemRead); denied {
		return
	}
	score, err := h.fleet.FleetComplianceScore(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"failed to compute fleet compliance score", true)
		return
	}
	writeJSON(w, http.StatusOK, api.FleetScore{
		PassingFraction:  score.PassingFraction,
		TotalEvaluations: score.TotalEvaluations,
	})
}

// GetFleetLiveness implements api.ServerInterface.GetFleetLiveness.
// Spec api-fleet-observability AC-03, AC-11, AC-12.
func (h *handlers) GetFleetLiveness(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.SystemRead); denied {
		return
	}
	roll, err := h.fleet.FleetLiveness(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"failed to compute fleet liveness", true)
		return
	}
	writeJSON(w, http.StatusOK, api.FleetLiveness{
		Reachable:   roll.Reachable,
		Unreachable: roll.Unreachable,
		Unknown:     roll.Unknown,
		NeverProbed: roll.NeverProbed,
	})
}

// GetFleetTopFailingRules implements api.ServerInterface.GetFleetTopFailingRules.
// Spec api-fleet-observability AC-04, AC-09, AC-10, AC-11, AC-12.
func (h *handlers) GetFleetTopFailingRules(w http.ResponseWriter, r *http.Request, params api.GetFleetTopFailingRulesParams) {
	if denied := auth.EnforcePermission(w, r, auth.SystemRead); denied {
		return
	}
	limit, ok := validatePaginatedLimit(w, params.Limit)
	if !ok {
		return
	}
	rows, err := h.fleet.TopFailingRules(r.Context(), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"failed to query top failing rules", true)
		return
	}
	out := make([]api.FleetRuleFailure, len(rows))
	for i, row := range rows {
		out[i] = api.FleetRuleFailure{
			RuleId:           row.RuleID,
			FailingHostCount: row.FailingHostCount,
		}
	}
	writeJSON(w, http.StatusOK, api.FleetTopFailingRules{Items: out})
}

// GetFleetTopFailingHosts implements api.ServerInterface.GetFleetTopFailingHosts.
// Spec api-fleet-observability AC-05, AC-09, AC-10, AC-11, AC-12.
func (h *handlers) GetFleetTopFailingHosts(w http.ResponseWriter, r *http.Request, params api.GetFleetTopFailingHostsParams) {
	if denied := auth.EnforcePermission(w, r, auth.SystemRead); denied {
		return
	}
	limit, ok := validatePaginatedLimit(w, params.Limit)
	if !ok {
		return
	}
	rows, err := h.fleet.TopFailingHosts(r.Context(), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"failed to query top failing hosts", true)
		return
	}
	out := make([]api.FleetHostFailure, len(rows))
	for i, row := range rows {
		out[i] = api.FleetHostFailure{
			HostId:           openapitypes.UUID(row.HostID),
			FailingRuleCount: row.FailingRuleCount,
		}
	}
	writeJSON(w, http.StatusOK, api.FleetTopFailingHosts{Items: out})
}

// GetFleetRecentChanges implements api.ServerInterface.GetFleetRecentChanges.
// Spec api-fleet-observability AC-06, AC-07, AC-09, AC-10, AC-11, AC-12.
func (h *handlers) GetFleetRecentChanges(w http.ResponseWriter, r *http.Request, params api.GetFleetRecentChangesParams) {
	if denied := auth.EnforcePermission(w, r, auth.SystemRead); denied {
		return
	}
	limit, ok := validatePaginatedLimit(w, params.Limit)
	if !ok {
		return
	}
	// since is already typed *time.Time by oapi-codegen — malformed
	// values are rejected upstream by the codegen wrapper with 400.
	var since = nilOrTime(params.Since)
	rows, err := h.fleet.RecentChanges(r.Context(), since, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"failed to query recent changes", true)
		return
	}
	out := make([]api.FleetTransaction, len(rows))
	for i, row := range rows {
		t := api.FleetTransaction{
			Id:         openapitypes.UUID(row.ID),
			HostId:     openapitypes.UUID(row.HostID),
			RuleId:     row.RuleID,
			Status:     api.FleetTransactionStatus(row.Status),
			ChangeKind: api.FleetTransactionChangeKind(row.ChangeKind),
			OccurredAt: row.OccurredAt,
		}
		if row.Severity != "" {
			s := row.Severity
			t.Severity = &s
		}
		out[i] = t
	}
	writeJSON(w, http.StatusOK, api.FleetRecentChanges{Items: out})
}
