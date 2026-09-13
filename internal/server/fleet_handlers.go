package server

import (
	"net/http"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/compliance"
	"github.com/Hanalyx/openwatch/internal/fleetrollup"
	openapitypes "github.com/oapi-codegen/runtime/types"

	"github.com/Hanalyx/openwatch/internal/scanruns"
	"github.com/Hanalyx/openwatch/internal/server/api"
)

// Fleet observability endpoints.
//
// Spec: specs/api/fleet-observability.spec.yaml.
//
// Every handler is a thin wrapper: RBAC gate, parse/validate, delegate
// to internal/fleetrollup.Service, JSON-encode. No SQL, no aggregation
// logic — those live in the fleetrollup package. AC-13 enforces the
// SQL-free invariant via source inspection.

// GetFleetScore implements api.ServerInterface.GetFleetScore.
// Spec api-fleet-observability AC-01, AC-02, AC-11, AC-12, AC-14, AC-17.
func (h *handlers) GetFleetScore(w http.ResponseWriter, r *http.Request, params api.GetFleetScoreParams) {
	if denied := auth.EnforcePermission(w, r, auth.SystemRead); denied {
		return
	}
	// v1.2.0 (compliance-targets): with no explicit ?framework=, the fleet KPI
	// defaults to the ORG default lens (ComplianceConfig.DefaultFramework) so
	// the tile reflects the selected standard instead of All rules. Per-host
	// targets are not aggregated into one fleet number here — mixed-fleet
	// cohorts are Phase 3b; the org default is the single-lens fleet view.
	lens := params.Framework
	if (lens == nil || *lens == "") && h.sysCfg != nil {
		if cfg, cerr := h.sysCfg.LoadCompliance(r.Context()); cerr == nil && cfg.DefaultFramework != "" {
			d := cfg.DefaultFramework
			lens = &d
		}
	}
	score, err := h.fleet.FleetComplianceScore(r.Context(), frameworkOpts(lens)...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"failed to compute fleet compliance score", true)
		return
	}
	// The envelope, so the number says how it was produced.
	env, err := aggregateEnvelope(lens, score.Engines, score.HostsWithoutEngine, score.HostsScored)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"failed to build the score envelope", true)
		return
	}
	writeJSON(w, http.StatusOK, aggregateScoreWire(score, env))
}

// aggregateScoreWire is the ONE mapping from a fleet or group score onto the
// contract.
//
// The Groups page and GET /fleet/score share it for the same reason
// group.Summary shares the calculation: two mappers of one shape agree until
// someone edits one. Every field the contract requires is filled here, so a new
// caller cannot ship a number without the metadata that says what it measures.
func aggregateScoreWire(score fleetrollup.Score, env compliance.Envelope) api.AggregateScore {
	return api.AggregateScore{
		ScorePct:          scorePct64(score.Score),
		Passing:           int64(score.Counts.Pass),
		Failing:           int64(score.Counts.Fail),
		Skipped:           int64(score.Counts.Skipped),
		Error:             int64(score.Counts.Error),
		CoverageStatus:    api.AggregateScoreCoverageStatus(score.Coverage.Status),
		CoveragePct:       scorePct64(score.Coverage.Pct),
		HostsScored:       score.HostsScored,
		HostsWithoutScore: score.HostsWithoutScore,
		HostsTotal:        score.HostsTotal,
		Envelope:          envelopeWire(env),
	}
}

// aggregateEnvelope builds the envelope for a fleet or group average.
//
// No contributors are passed. Until the scan engine can report which corpus it
// used (Kensa features/KN-KN-030) no host can name one, so every SCORED host is
// counted in hosts_without_corpus_identity. The constructor derives the status
// and that count from what it is given; an empty list is the truth, not a
// shortcut.
func aggregateEnvelope(
	lens *string,
	engines []compliance.EngineContributor,
	hostsWithoutEngine, hostsScored int,
) (compliance.Envelope, error) {
	return compliance.ScoreBearingEnvelope(
		lensName(lens),
		compliance.AggregationEqualHostMean,
		engines,
		hostsWithoutEngine,
		nil,
		hostsScored,
		hostsScored,
	)
}

// lensName is what the envelope reports as the lens.
//
// An empty framework is not an absent lens: it means every rule in the host's
// current corpus, which is a nameable scope. C-15 requires every score-bearing
// response to say what it was measured against, and "all_rules" says it.
func lensName(lens *string) string {
	if lens == nil || *lens == "" {
		return "all_rules"
	}
	return *lens
}

// envelopeWire renders the envelope onto the contract.
//
// Every field is sent even when the score is null. A response that cannot say
// which lens and formula produced its number is not interpretable later, and
// that is as true of an absent number as of a present one.
func envelopeWire(e compliance.Envelope) api.ScoreEnvelope {
	out := api.ScoreEnvelope{
		Engines: []struct {
			ContributorsScored int    `json:"contributors_scored"`
			EngineVersion      string `json:"engine_version"`
		}{},
		EngineIdentityStatus: api.ScoreEnvelopeEngineIdentityStatus(e.EngineIdentityStatus),
		CorpusIdentityStatus: api.ScoreEnvelopeCorpusIdentityStatus(e.Status),
		Corpora: []struct {
			ContributorsScored int     `json:"contributors_scored"`
			CorpusDigest       string  `json:"corpus_digest"`
			CorpusVersion      *string `json:"corpus_version"`
		}{},
		CorpusVersion: e.CorpusVersion,
		CorpusDigest:  e.CorpusDigest,
	}
	if e.Lens != nil {
		out.Lens = *e.Lens
	}
	if e.AggregationMethod != nil {
		out.AggregationMethod = api.ScoreEnvelopeAggregationMethod(*e.AggregationMethod)
	}
	// The singular field carries a value in exactly one state, the same rule
	// the corpus pair follows. Null under "several" is the point: naming one of
	// them would be picking a value and calling it the artifact's.
	out.EngineVersion = e.EngineVersion
	for _, en := range e.Engines {
		out.Engines = append(out.Engines, struct {
			ContributorsScored int    `json:"contributors_scored"`
			EngineVersion      string `json:"engine_version"`
		}{ContributorsScored: en.ContributorsScored, EngineVersion: en.EngineVersion})
	}
	if e.HostsWithoutEngineIdentity != nil {
		out.HostsWithoutEngineIdentity = *e.HostsWithoutEngineIdentity
	}
	out.FormulaVersion = e.FormulaVersion
	if e.HostsWithoutCorpusIdentity != nil {
		out.HostsWithoutCorpusIdentity = *e.HostsWithoutCorpusIdentity
	}
	for _, c := range e.Corpora {
		out.Corpora = append(out.Corpora, struct {
			ContributorsScored int     `json:"contributors_scored"`
			CorpusDigest       string  `json:"corpus_digest"`
			CorpusVersion      *string `json:"corpus_version"`
		}{
			ContributorsScored: c.ContributorsScored,
			CorpusDigest:       c.Digest,
			CorpusVersion:      c.Version,
		})
	}
	return out
}

// GetFleetConnectivityBreakdown implements
// api.ServerInterface.GetFleetConnectivityBreakdown.
// Spec api-fleet-connectivity-breakdown AC-01..AC-08.
func (h *handlers) GetFleetConnectivityBreakdown(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.SystemRead); denied {
		return
	}
	bd, err := h.fleet.ConnectivityBreakdown(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"failed to compute connectivity breakdown", true)
		return
	}
	writeJSON(w, http.StatusOK, api.ConnectivityBreakdown{
		Online:      bd.Online,
		Degraded:    bd.Degraded,
		Critical:    bd.Critical,
		Down:        bd.Down,
		NeverProbed: bd.NeverProbed,
	})
}

// GetFleetScanQueue implements api.ServerInterface.GetFleetScanQueue.
// Queued/running scan_runs counts — the scan-queue depth KPI. Delegates
// to scanruns.ActiveBreakdown (no SQL here, AC-13 of fleet-observability
// style). Spec api-host-compliance AC-07.
func (h *handlers) GetFleetScanQueue(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.HostRead); denied {
		return
	}
	queued, running, err := scanruns.ActiveBreakdown(r.Context(), h.pool)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"failed to count active scan runs", true)
		return
	}
	writeJSON(w, http.StatusOK, api.FleetScanQueue{
		Queued:  int64(queued),
		Running: int64(running),
	})
}

// GetFleetLiveness implements api.ServerInterface.GetFleetLiveness.
// Spec api-fleet-observability AC-03, AC-11, AC-12.
// (?framework= has no effect on liveness — host_liveness is OS-agnostic.)
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
// Spec api-fleet-observability AC-04, AC-09, AC-10, AC-11, AC-12, AC-15.
func (h *handlers) GetFleetTopFailingRules(w http.ResponseWriter, r *http.Request, params api.GetFleetTopFailingRulesParams) {
	if denied := auth.EnforcePermission(w, r, auth.SystemRead); denied {
		return
	}
	limit, ok := validatePaginatedLimit(w, params.Limit)
	if !ok {
		return
	}
	rows, err := h.fleet.TopFailingRules(r.Context(), limit, frameworkOpts(params.Framework)...)
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
// Spec api-fleet-observability AC-05, AC-09, AC-10, AC-11, AC-12 (+v1.1.0 framework filter).
func (h *handlers) GetFleetTopFailingHosts(w http.ResponseWriter, r *http.Request, params api.GetFleetTopFailingHostsParams) {
	if denied := auth.EnforcePermission(w, r, auth.SystemRead); denied {
		return
	}
	limit, ok := validatePaginatedLimit(w, params.Limit)
	if !ok {
		return
	}
	rows, err := h.fleet.TopFailingHosts(r.Context(), limit, frameworkOpts(params.Framework)...)
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
// Spec api-fleet-observability AC-06, AC-07, AC-09, AC-10, AC-11, AC-12, AC-16.
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
	rows, err := h.fleet.RecentChanges(r.Context(), since, limit, frameworkOpts(params.Framework)...)
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
