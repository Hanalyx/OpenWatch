// Per-host compliance lens — GET /hosts/{id}/compliance and
// GET /hosts/{id}/compliance/frameworks.
//
// The lens is the "one scan, many framework views" projection: the
// host's CURRENT corpus (internal/corpus: the host_rule_state rows the
// host's most recent completed scan evaluated, bounded at ~539 rows) is
// read in ONE unpaginated query, optionally filtered to a framework, and
// summarized three ways — summary counts, per-category breakdown
// (computed in Go from the kensa RuleCatalog), and the full rules
// list. The frameworks endpoint lists the lens options.
//
// SECURITY: both queries project explicit column lists — the stored
// per-rule check output (which may contain sensitive host
// configuration) is never selected; spec AC-13 enforces that
// invariant by source inspection of this file.
//
// Spec: specs/api/host-compliance.spec.yaml v1.1.0.
package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	openapitypes "github.com/oapi-codegen/runtime/types"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/compliance"
	"github.com/Hanalyx/openwatch/internal/framework"
	"github.com/Hanalyx/openwatch/internal/host"
	"github.com/Hanalyx/openwatch/internal/scanruns"
	"github.com/Hanalyx/openwatch/internal/server/api"
)

// lensFallbackCategory buckets rules the catalog does not know.
const lensFallbackCategory = "uncategorized"

// GetHostCompliance implements api.ServerInterface.
// Spec api-host-compliance AC-08, AC-09, AC-10, AC-12, AC-13.
func (h *handlers) GetHostCompliance(
	w http.ResponseWriter,
	r *http.Request,
	id openapitypes.UUID,
	params api.GetHostComplianceParams,
) {
	if denied := auth.EnforcePermission(w, r, auth.HostRead); denied {
		return
	}

	ctx := r.Context()
	hostID := uuid.UUID(id)

	// 404 pre-side-effect: same lookup as failed-rules (spec C-03).
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

	// scan_context: latest COMPLETED run only — queued/running/failed
	// never qualify (spec AC-10). Never-scanned hosts keep the nulls.
	scanCtx := api.HostScanContext{}
	// The engine comes from the RULE ROWS below, not from a separate lookup, so
	// it always describes the same scan the counts do.
	hostEngine := ""
	run, err := scanruns.LatestCompletedForHost(ctx, h.pool, hostID)
	switch {
	case err == nil:
		scanID := openapitypes.UUID(run.ID)
		scanCtx.ScanId = &scanID
		scanCtx.LastScanAt = run.FinishedAt
		scanCtx.PolicyVersion = run.PolicyVersion
		// Duration powers the prototype's SCAN panel ("Duration 47s").
		if run.StartedAt != nil && run.FinishedAt != nil {
			d := int(run.FinishedAt.Sub(*run.StartedAt).Round(time.Second).Seconds())
			scanCtx.DurationSeconds = &d
		}
	case errors.Is(err, scanruns.ErrNotFound):
		// never scanned — nulls/empty stand
	default:
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"scan context lookup failed", true)
		return
	}

	// scan_state: the in-flight (queued/running) run, independent of the
	// latest COMPLETED run above — null when no scan is in flight. Drives
	// the host-detail hero "Running"/"Queued" badge. Spec
	// api-host-compliance AC-17.
	if active, err := scanruns.ActiveForHost(ctx, h.pool, hostID); err == nil {
		s := api.HostScanContextScanState(active.Status)
		scanCtx.ScanState = &s
	} else if !errors.Is(err, scanruns.ErrNotFound) {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"scan state lookup failed", true)
		return
	}

	// nil framework disables both the filter and the control-id
	// projection ($2::text IS NULL short-circuits — same idiom as the
	// failed-rules handler). One query, no pagination: the per-host
	// corpus is bounded (spec C-05 constraint note).
	var framework any
	if params.Framework != nil && *params.Framework != "" {
		framework = *params.Framework
	}
	const q = `
		SELECT hrs.rule_id,
		       COALESCE(hrs.severity, ''),
		       hrs.current_status,
		       hrs.last_checked_at,
		       CASE WHEN $2::text IS NULL THEN '[]'::jsonb
		            ELSE COALESCE(hrs.framework_refs -> $2, '[]'::jsonb)
		       END AS control_ids,
		       -- The engine bound to THESE rows, through the scan id they carry.
		       -- Reading the latest completed run separately could name a scan
		       -- that finished after these rows were read, pairing one scan's
		       -- score with another scan's engine.
		       COALESCE(sr.engine_version, '') AS engine_version
		  FROM host_rule_state_current hrs
		  LEFT JOIN scan_runs sr ON sr.id = hrs.last_scan_id
		 WHERE hrs.host_id = $1
		   AND ($2::text IS NULL OR hrs.framework_refs ? $2)
		 ORDER BY CASE lower(COALESCE(severity, ''))
		            WHEN 'critical' THEN 0
		            WHEN 'high'     THEN 1
		            WHEN 'medium'   THEN 2
		            WHEN 'low'      THEN 3
		            ELSE 4
		          END,
		          rule_id ASC`
	rows, err := h.pool.Query(ctx, q, hostID, framework)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"compliance lens query failed", true)
		return
	}
	defer rows.Close()

	resp := api.HostComplianceLensResponse{
		ScanContext: scanCtx,
		Categories:  []api.HostComplianceCategory{},
		Rules:       []api.HostComplianceRule{},
	}
	for rows.Next() {
		var (
			item       api.HostComplianceRule
			checkedAt  time.Time
			controlIDs []byte
			rowEngine  string
		)
		if err := rows.Scan(&item.RuleId, &item.Severity, &item.Status,
			&checkedAt, &controlIDs, &rowEngine); err != nil {
			writeError(w, http.StatusInternalServerError, "server.error", "server",
				"compliance lens scan failed", true)
			return
		}
		// Every row in the current corpus belongs to the same scan, so they all
		// carry the same value. Taking it from a row rather than from a second
		// query is what binds it to these counts.
		if rowEngine != "" {
			hostEngine = rowEngine
		}
		item.LastCheckedAt = checkedAt
		item.ControlIds = []string{}
		if len(controlIDs) > 0 {
			// framework_refs values are JSON arrays of control ids; a
			// malformed value degrades to an empty list, never a 500.
			_ = json.Unmarshal(controlIDs, &item.ControlIds)
			if item.ControlIds == nil {
				item.ControlIds = []string{}
			}
		}
		// Catalog fallback: without a catalog (or for an uncataloged
		// rule) the rule id doubles as the title and the category
		// degrades to the shared "uncategorized" bucket.
		item.Title = item.RuleId
		item.Category = lensFallbackCategory
		if meta, ok := h.ruleCatalog.Get(item.RuleId); ok {
			item.Title = meta.Title
			if meta.Category != "" {
				item.Category = meta.Category
			}
			// One-line description under the title (prototype rule rows).
			// Catalog text, never stored check output (C-02 stands).
			item.Description = firstSentence(meta.Description)
		}
		resp.Rules = append(resp.Rules, item)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"compliance lens iterate failed", true)
		return
	}

	// summary + categories aggregate the SAME fetched rows, so the
	// reconciliation invariant (spec C-05) holds by construction.
	// The lens this summary was computed under. Empty means all rules, which
	// lensName reports as "all_rules": a named scope, not an absence.
	lens := ""
	if params.Framework != nil {
		lens = *params.Framework
	}
	summary, err := lensSummaryFromRules(resp.Rules, lens, hostEngine)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"failed to build the score envelope", true)
		return
	}
	resp.Summary = summary
	resp.Categories = lensCategoriesFromRules(resp.Rules)

	writeJSON(w, http.StatusOK, resp)
}

// lensSummaryFromRules counts the per-status totals over the lens rules and
// takes the score from internal/compliance.
//
// The arithmetic used to live here: passing over TOTAL, rounded inline. Two
// things were wrong with that. The formula counted a rule nothing could evaluate
// as a failure, and a compliance percentage computed in an HTTP handler is one
// the rest of the product cannot agree with by construction
// (system-compliance-scoring C-14). Spec api-host-compliance AC-08 / C-05.
func lensSummaryFromRules(rules []api.HostComplianceRule, lens, engine string) (api.HostComplianceLensSummary, error) {
	var s api.HostComplianceLensSummary
	for _, r := range rules {
		switch r.Status {
		case "pass":
			s.Passing++
		case "fail":
			s.Failing++
		case "skipped":
			s.Skipped++
		case "error":
			s.Error++
		}
		s.Total++
	}
	counts := compliance.Counts{
		Pass: int(s.Passing), Fail: int(s.Failing),
		Skipped: int(s.Skipped), Error: int(s.Error),
	}
	score := compliance.HostScore(counts)
	s.ScorePct = scorePct64(score)
	// skipReasonsTyped is false until KN-OW-021 ships.
	cov := compliance.AssessmentCoverage(counts, false)
	s.CoverageStatus = api.HostComplianceLensSummaryCoverageStatus(cov.Status)
	s.CoveragePct = scorePct64(cov.Pct)
	env, err := hostEnvelope(lens, score.Present(), engine)
	if err != nil {
		return api.HostComplianceLensSummary{}, err
	}
	s.Envelope = env
	return s, nil
}

// hostEnvelope builds the envelope for a SINGLE host's score.
//
// aggregation_method is none: one host aggregates nothing, and saying
// equal_host_mean here would claim it averaged something. Corpus identity is
// unavailable until the scan engine can report it, so no contributor is named
// and a scored host is counted as lacking one.
//
// scored says whether the host actually produced a score. A host whose rules all
// skipped has none, and reporting one scored contributor for it would claim a
// measurement that did not happen: the envelope's counts describe contributors
// to a SCORE, not hosts that were looked at.
//
// It returns an error rather than a degraded envelope. An envelope the
// constructor refuses is provenance that cannot be stated honestly, and the
// caller's only correct move is to fail: publishing the score with a read-model
// envelope would relabel a score-bearing response as a different artifact class
// and emit empty strings where a lens and an engine version belong.
func hostEnvelope(lens string, scored bool, engine string) (api.ScoreEnvelope, error) {
	n := 0
	if scored {
		n = 1
	}
	// One host contributes at most one engine. It contributes NONE when it has
	// no score, and none when its run predates migration 0063 and recorded no
	// version. Those two cases are what hosts_without_engine_identity counts.
	var engines []compliance.EngineContributor
	withoutEngine := n
	if n == 1 && engine != "" {
		engines = []compliance.EngineContributor{{EngineVersion: engine, ContributorsScored: 1}}
		withoutEngine = 0
	}
	env, err := compliance.ScoreBearingEnvelope(
		lensName(&lens), compliance.AggregationNone, engines, withoutEngine, nil, n, n)
	if err != nil {
		return api.ScoreEnvelope{}, err
	}
	return envelopeWire(env), nil
}

// scorePct64 and scorePct32 render a score into a nullable wire field.
//
// A host whose rules produced no verdict has NO score, and the field says so.
// Until this release it was required and non-nullable, so absence read as 0 and
// was indistinguishable from every evaluated rule failing.
func scorePct64(score compliance.Score) *float64 {
	pct, ok := score.Rounded()
	if !ok {
		return nil
	}
	return &pct
}

func scorePct32(score compliance.Score) *float32 {
	pct, ok := score.Rounded()
	if !ok {
		return nil
	}
	v := float32(pct)
	return &v
}

// lensCategoriesFromRules groups the lens rules by their (already
// catalog-resolved) category and sorts failing DESC then category
// ASC. Pure aggregation over the same rows the response returns, so
// the category totals reconcile with the rules array (spec C-05).
func lensCategoriesFromRules(rules []api.HostComplianceRule) []api.HostComplianceCategory {
	byName := map[string]*api.HostComplianceCategory{}
	for _, r := range rules {
		c, ok := byName[r.Category]
		if !ok {
			c = &api.HostComplianceCategory{Category: r.Category}
			byName[r.Category] = c
		}
		switch r.Status {
		case "pass":
			c.Passing++
		case "fail":
			c.Failing++
		}
		c.Total++
	}
	out := make([]api.HostComplianceCategory, 0, len(byName))
	for _, c := range byName {
		// Scored here, not in the browser. The category bar derived this
		// itself, which is compliance arithmetic in a frontend component
		// (system-compliance-scoring C-14) even though its formula was right.
		c.ScorePct = scorePct64(compliance.HostScore(compliance.Counts{
			Pass: int(c.Passing), Fail: int(c.Failing),
		}))
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Failing != out[j].Failing {
			return out[i].Failing > out[j].Failing
		}
		return out[i].Category < out[j].Category
	})
	return out
}

// GetHostComplianceFrameworks implements api.ServerInterface.
// Spec api-host-compliance AC-11, AC-12, AC-13.
func (h *handlers) GetHostComplianceFrameworks(
	w http.ResponseWriter,
	r *http.Request,
	id openapitypes.UUID,
) {
	if denied := auth.EnforcePermission(w, r, auth.HostRead); denied {
		return
	}

	ctx := r.Context()
	hostID := uuid.UUID(id)

	hostRow, err := h.hosts.GetByID(ctx, hostID)
	if err != nil {
		if errors.Is(err, host.ErrHostNotFound) {
			writeError(w, http.StatusNotFound, "hosts.not_found", "client",
				"host not found", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"lookup failed", true)
		return
	}
	osFamily, osVersion := "", ""
	if hostRow.OSFamily != nil {
		osFamily = *hostRow.OSFamily
	}
	if hostRow.OSVersion != nil {
		osVersion = *hostRow.OSVersion
	}

	// Distinct framework keys with mapped-rule counts AND per-lens
	// pass/fail tallies so the lens bar can show each framework's score
	// without N follow-up queries (prototype: "CIS ... 36%").
	// Never-scanned hosts get the empty list (spec AC-11).
	const q = `
		SELECT key,
		       COUNT(*)::bigint,
		       COUNT(*) FILTER (WHERE hrs.current_status = 'pass')::bigint,
		       COUNT(*) FILTER (WHERE hrs.current_status = 'fail')::bigint,
		       -- Bound to these rows, in this snapshot, for the same reason as
		       -- the lens summary above.
		       COALESCE(MIN(sr.engine_version), '')
		  FROM host_rule_state_current hrs
		  LEFT JOIN scan_runs sr ON sr.id = hrs.last_scan_id,
		       LATERAL jsonb_object_keys(hrs.framework_refs) AS key
		 WHERE hrs.host_id = $1
		 GROUP BY key
		 ORDER BY key`
	rows, err := h.pool.Query(ctx, q, hostID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"frameworks query failed", true)
		return
	}
	defer rows.Close()

	// Enabled-frameworks allowlist (system-compliance-lens C-04): the lens
	// bar offers only the framework FAMILIES the org enabled. Empty allowlist =
	// every family (unchanged). A config-load error degrades to showing all —
	// this is a display filter, not a security boundary, exactly like the
	// org-level GET /compliance/frameworks. The ?framework= deep link and the
	// overall aggregate stay unfiltered (a disabled family is still viewable by
	// direct link; only the offered chips are narrowed).
	var enabledFamilies map[string]bool
	if cfg, cerr := h.sysCfg.LoadCompliance(ctx); cerr == nil && len(cfg.EnabledFrameworks) > 0 {
		enabledFamilies = make(map[string]bool, len(cfg.EnabledFrameworks))
		for _, f := range cfg.EnabledFrameworks {
			enabledFamilies[f] = true
		}
	}

	resp := api.HostComplianceFrameworksResponse{Frameworks: []api.HostComplianceFramework{}}
	for rows.Next() {
		var item api.HostComplianceFramework
		var passing, failing int64
		var chipEngine string
		if err := rows.Scan(&item.FrameworkId, &item.RuleCount, &passing, &failing,
			&chipEngine); err != nil {
			writeError(w, http.StatusInternalServerError, "server.error", "server",
				"frameworks scan failed", true)
			return
		}
		// OS-aware lens filtering (spec C-06): a version-pinned
		// framework only lists when it matches the host's detected OS;
		// OS-neutral frameworks (NIST, PCI, SRG) always list. The keys
		// exist because shared rules carry refs for several framework
		// versions; offering a RHEL 9 lens on a RHEL 8 host is noise.
		if !frameworkCompatibleWithOS(item.FrameworkId, osFamily, osVersion) {
			continue
		}
		// Allowlist narrowing: drop a family the org disabled as a lens.
		if enabledFamilies != nil && !enabledFamilies[framework.FamilyOf(item.FrameworkId)] {
			continue
		}
		item.Passing = int(passing)
		item.Failing = int(failing)
		// Scored over the verdicts, not over rule_count. rule_count includes
		// rules that were skipped or errored, and dividing by it made every
		// unevaluated rule count against the host.
		item.ScorePct = scorePct32(compliance.HostScore(compliance.Counts{
			Pass: int(passing), Fail: int(failing),
		}))
		// The chip's lens IS its framework id, so the envelope names it.
		chipEnv, err := hostEnvelope(item.FrameworkId, item.ScorePct != nil, chipEngine)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server.error", "server",
				"failed to build the score envelope", true)
			return
		}
		item.Envelope = chipEnv
		resp.Frameworks = append(resp.Frameworks, item)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"frameworks iterate failed", true)
		return
	}

	// All-rules aggregate for the All chip's score (framework_id "all").
	resp.Overall = api.HostComplianceFramework{FrameworkId: "all"}
	var oPassing, oFailing int64
	var overallEngine string
	if err := h.pool.QueryRow(ctx, `
		SELECT COUNT(*)::bigint,
		       COUNT(*) FILTER (WHERE hrs.current_status = 'pass')::bigint,
		       COUNT(*) FILTER (WHERE hrs.current_status = 'fail')::bigint,
		       -- Bound to the same rows, in the same snapshot.
		       COALESCE(MIN(sr.engine_version), '')
		  FROM host_rule_state_current hrs
		  LEFT JOIN scan_runs sr ON sr.id = hrs.last_scan_id
		 WHERE hrs.host_id = $1`, hostID).
		Scan(&resp.Overall.RuleCount, &oPassing, &oFailing, &overallEngine); err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"overall aggregate failed", true)
		return
	}
	resp.Overall.Passing = int(oPassing)
	resp.Overall.Failing = int(oFailing)
	resp.Overall.ScorePct = scorePct32(compliance.HostScore(compliance.Counts{
		Pass: int(oPassing), Fail: int(oFailing),
	}))
	overallEnv, err := hostEnvelope("", resp.Overall.ScorePct != nil, overallEngine)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"failed to build the score envelope", true)
		return
	}
	resp.Overall.Envelope = overallEnv

	writeJSON(w, http.StatusOK, resp)
}

// firstSentence trims a catalog description to its first sentence (or
// 160 chars, whichever is shorter) for the rule-row sub-line. Catalog
// prose only — stored check output never flows here (C-02).
func firstSentence(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if i := strings.Index(s, ". "); i > 0 && i < 160 {
		return s[:i+1]
	}
	if len(s) > 160 {
		return s[:159] + "."
	}
	return s
}

// osFamilyTokens are the OS family names a framework id may embed as a
// version-pinned segment (e.g. "rhel8" inside cis_rhel8). Segments not
// matching any of these (nist, 800, dss, plain numbers) never mark a
// framework OS-specific.
var osFamilyTokens = map[string]bool{
	"rhel": true, "centos": true, "rocky": true, "alma": true,
	"ol": true, "ubuntu": true, "debian": true, "sles": true,
	"amzn": true, "windows": true,
}

// osPinnedSegment matches one underscore-separated segment that pins a
// framework to an OS release: a known family name immediately followed
// by digits ("rhel8", "ubuntu2404").
var osPinnedSegment = regexp.MustCompile(`^([a-z]+)(\d+)$`)

// frameworkCompatibleWithOS reports whether a framework lens should be
// offered for a host with the given detected OS (spec C-06):
//
//   - ids with no OS-pinned segment are OS-neutral -> always true
//   - an undiscovered host (empty family) cannot be judged -> true
//   - otherwise the pinned family must equal the host's BENCHMARK family, and
//     the pinned digits must equal the host's major version (or the
//     major+minor concatenation, covering ubuntu2404 vs "24.04")
//
// The host family is normalized through framework.BenchmarkFamily so an EL
// rebuild is judged against its upstream. Comparing the raw distro id rejected
// stig_rhel9 for an almalinux host, and because this function decides which
// lenses are OFFERED, the effect was not an empty STIG score but no STIG option
// at all -- a page that looks complete while withholding two thirds of the
// host's compliance signal.
func frameworkCompatibleWithOS(frameworkID, osFamily, osVersion string) bool {
	pinFamily, pinVersion := "", ""
	for _, seg := range strings.Split(strings.ToLower(frameworkID), "_") {
		m := osPinnedSegment.FindStringSubmatch(seg)
		if m != nil && osFamilyTokens[m[1]] {
			pinFamily, pinVersion = m[1], m[2]
			break
		}
	}
	if pinFamily == "" {
		return true // OS-neutral framework
	}
	if osFamily == "" {
		return true // host OS unknown; cannot judge, do not hide
	}
	if pinFamily != framework.BenchmarkFamily(osFamily) {
		return false
	}
	if osVersion == "" {
		return true // family matches; no version to compare
	}
	parts := strings.SplitN(osVersion, ".", 3)
	major := parts[0]
	if pinVersion == major {
		return true
	}
	if len(parts) > 1 && pinVersion == major+parts[1] {
		return true // ubuntu2404 vs "24.04"
	}
	return false
}
