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
	"github.com/Hanalyx/openwatch/internal/compliance"
	"github.com/Hanalyx/openwatch/internal/framework"
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

	// Lens: the trend follows the same effective lens as the host-detail hero
	// tile (per-host / group target, else the org default), OS-resolved at
	// rollup time. So the trend line and the tile agree instead of the trend
	// showing all-rules. Empty (no target, no org default) reads the all-rules
	// series. compliance-lens Phase 3c.
	lens := ""
	if h.sysCfg != nil {
		if cfg, cerr := h.sysCfg.LoadCompliance(ctx); cerr == nil {
			if eff, eerr := framework.NewService(h.pool).EffectiveTarget(ctx, hostID, cfg.DefaultFramework); eerr == nil {
				lens = eff
			}
		}
	}
	points, err := posture.HostTrend(ctx, h.pool, hostID, trendDays(params.Days), lens)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"trend query failed", true)
		return
	}

	type hostDay = struct {
		Date           openapitypes.Date                        `json:"date"`
		Envelope       api.ScoreEnvelope                        `json:"envelope"`
		Failing        int                                      `json:"failing"`
		FormulaStatus  api.HostComplianceTrendDaysFormulaStatus `json:"formula_status"`
		FormulaVersion *int                                     `json:"formula_version"`
		Passing        int                                      `json:"passing"`
		ScorePct       *float32                                 `json:"score_pct"`
		Total          int                                      `json:"total"`
	}
	resp := api.HostComplianceTrend{Days: []hostDay{}}
	for _, p := range points {
		// A day whose rules produced no verdict APPEARS, with a null score and
		// its counts. It used to be omitted, because the field could not say
		// "no score" and sending 0.0 would have invented a verdict. Omission
		// was honest but silent: the day looked the same as one with no
		// snapshot at all. Now it says which formula produced it and, when
		// there is no number, the reader can see why.
		// One snapshot, so at most one contributor of each kind, and only when
		// it produced a score.
		scored := boolToInt(p.Score.Present())
		var corpora []compliance.CorpusContributor
		if scored == 1 && p.CorpusStatus == compliance.CorpusIdentified && p.CorpusDigest != nil {
			corpora = []compliance.CorpusContributor{{
				Version: p.CorpusVersion, Digest: *p.CorpusDigest, ContributorsScored: 1,
			}}
		}
		env, eerr := trendEnvelope(lens, compliance.AggregationNone,
			formulaVersionWire(p.FormulaStatus), p.Engines, scored-len(p.Engines),
			corpora, scored-len(corpora), scored)
		if eerr != nil {
			writeError(w, http.StatusInternalServerError, "server.error", "server",
				"failed to build the score envelope", true)
			return
		}
		resp.Days = append(resp.Days, hostDay{
			Date:           openapitypes.Date{Time: p.Date},
			Envelope:       env,
			Failing:        p.Failing,
			FormulaStatus:  api.HostComplianceTrendDaysFormulaStatus(p.FormulaStatus),
			FormulaVersion: formulaVersionWire(p.FormulaStatus),
			Passing:        p.Passing,
			ScorePct:       scorePct32(p.Score),
			Total:          p.Total,
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

	// Fleet trend follows the ORG default lens (each host OS-resolved at
	// rollup time), so the dashboard trend agrees with the fleet KPI. Empty
	// org default reads the all-rules series. compliance-lens Phase 3c.
	lens := ""
	if h.sysCfg != nil {
		if cfg, cerr := h.sysCfg.LoadCompliance(r.Context()); cerr == nil {
			lens = cfg.DefaultFramework
		}
	}
	points, err := posture.FleetTrend(r.Context(), h.pool, trendDays(params.Days), lens)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"fleet trend query failed", true)
		return
	}

	type fleetDay = struct {
		AvgScorePct       *float32                                  `json:"avg_score_pct"`
		CriticalHosts     int                                       `json:"critical_hosts"`
		Date              openapitypes.Date                         `json:"date"`
		Envelope          api.ScoreEnvelope                         `json:"envelope"`
		Failing           int                                       `json:"failing"`
		FormulaStatus     api.FleetComplianceTrendDaysFormulaStatus `json:"formula_status"`
		FormulaVersion    *int                                      `json:"formula_version"`
		Hosts             int                                       `json:"hosts"`
		HostsScored       int                                       `json:"hosts_scored"`
		HostsWithoutScore int                                       `json:"hosts_without_score"`
	}
	resp := api.FleetComplianceTrend{Days: []fleetDay{}}
	for _, p := range points {
		// Same rule as the host trend: a day with no score appears and says why.
		// A mixed day is the case that most needs saying: it has snapshots, it
		// has hosts, and there is deliberately no number because the formulas
		// behind them measure different things.
		// The counts describe contributors to a SCORE, so the total is
		// HostsScored, not the number of snapshots lacking a corpus identity.
		// Passing the latter made a day with one scored and one unscored
		// snapshot report hosts_scored 1 beside an envelope claiming two
		// contributors. Both contributor sets come from the day's SCORED
		// snapshots, so a day where some named a corpus and some did not
		// reports partially_identified rather than a blanket unavailable.
		env, eerr := trendEnvelope(lens, compliance.AggregationEqualHostMean,
			formulaVersionWire(p.FormulaStatus), p.Engines, p.HostsWithoutEngineIdentity,
			p.Corpora, p.HostsWithoutCorpusIdentity, p.HostsScored)
		if eerr != nil {
			writeError(w, http.StatusInternalServerError, "server.error", "server",
				"failed to build the score envelope", true)
			return
		}
		resp.Days = append(resp.Days, fleetDay{
			AvgScorePct:       scorePct32(p.Score),
			Envelope:          env,
			FormulaStatus:     api.FleetComplianceTrendDaysFormulaStatus(p.FormulaStatus),
			FormulaVersion:    formulaVersionWire(p.FormulaStatus),
			HostsScored:       p.HostsScored,
			HostsWithoutScore: p.HostsWithoutScore,
			CriticalHosts:     p.CriticalHosts,
			Date:              openapitypes.Date{Time: p.Date},
			Failing:           p.Failing,
			Hosts:             p.Hosts,
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

// formulaVersionWire pins formula_version to the status: 2 for identified,
// null otherwise.
//
// The two travel together on the wire because a version without its status
// cannot say whether a null means "predates the formula" or "the contributors
// disagreed", and those are different facts about the same missing number.
func formulaVersionWire(s compliance.FormulaStatus) *int {
	if s != compliance.FormulaIdentified {
		return nil
	}
	v := 2
	return &v
}

// trendEnvelope builds a trend point's envelope from what the SNAPSHOT recorded.
//
// A legacy point carries no formula version and no engine, because the release
// that wrote it recorded neither. That absence is the honest historical shape:
// substituting the current formula, or the serving process's engine, would
// describe the point with provenance that does not belong to it.
//
// Corpus contributors come from the snapshot's own identity. Until Kensa
// features/KN-KN-030 ships, no snapshot names a corpus, so the list is empty and
// every scored contributor is counted as lacking one.
func trendEnvelope(
	lens, aggregation string,
	formulaVersion *int,
	engines []compliance.EngineContributor,
	withoutEngine int,
	corpora []compliance.CorpusContributor,
	withoutCorpus int,
	scored int,
) (api.ScoreEnvelope, error) {
	env, err := compliance.HistoricalEnvelope(
		lensName(&lens), aggregation, formulaVersion, engines, withoutEngine,
		corpora, withoutCorpus, scored)
	if err != nil {
		return api.ScoreEnvelope{}, err
	}
	return envelopeWire(env), nil
}

// boolToInt is one when a point produced a score, zero otherwise. The envelope
// counts CONTRIBUTORS TO A SCORE, so a point with none contributes none.
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
