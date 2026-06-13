// Per-host compliance lens — GET /hosts/{id}/compliance and
// GET /hosts/{id}/compliance/frameworks.
//
// The lens is the "one scan, many framework views" projection: the
// host's full host_rule_state corpus (bounded, ~539 rows) is read in
// ONE unpaginated query, optionally filtered to a framework, and
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
	"math"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	openapitypes "github.com/oapi-codegen/runtime/types"

	"github.com/Hanalyx/openwatch/internal/auth"
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

	// nil framework disables both the filter and the control-id
	// projection ($2::text IS NULL short-circuits — same idiom as the
	// failed-rules handler). One query, no pagination: the per-host
	// corpus is bounded (spec C-05 constraint note).
	var framework any
	if params.Framework != nil && *params.Framework != "" {
		framework = *params.Framework
	}
	const q = `
		SELECT rule_id,
		       COALESCE(severity, ''),
		       current_status,
		       last_checked_at,
		       CASE WHEN $2::text IS NULL THEN '[]'::jsonb
		            ELSE COALESCE(framework_refs -> $2, '[]'::jsonb)
		       END AS control_ids
		  FROM host_rule_state
		 WHERE host_id = $1
		   AND ($2::text IS NULL OR framework_refs ? $2)
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
		)
		if err := rows.Scan(&item.RuleId, &item.Severity, &item.Status,
			&checkedAt, &controlIDs); err != nil {
			writeError(w, http.StatusInternalServerError, "server.error", "server",
				"compliance lens scan failed", true)
			return
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
	resp.Summary = lensSummaryFromRules(resp.Rules)
	resp.Categories = lensCategoriesFromRules(resp.Rules)

	writeJSON(w, http.StatusOK, resp)
}

// lensSummaryFromRules counts the per-status totals over the lens
// rules and derives score_pct = round(passing/total*1000)/10 (one
// decimal; 0 when total is 0). Spec api-host-compliance AC-08 / C-05.
func lensSummaryFromRules(rules []api.HostComplianceRule) api.HostComplianceLensSummary {
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
	if s.Total > 0 {
		s.ScorePct = math.Round(float64(s.Passing)/float64(s.Total)*1000) / 10
	}
	return s
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
		       COUNT(*) FILTER (WHERE current_status = 'pass')::bigint,
		       COUNT(*) FILTER (WHERE current_status = 'fail')::bigint
		  FROM host_rule_state,
		       LATERAL jsonb_object_keys(framework_refs) AS key
		 WHERE host_id = $1
		 GROUP BY key
		 ORDER BY key`
	rows, err := h.pool.Query(ctx, q, hostID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"frameworks query failed", true)
		return
	}
	defer rows.Close()

	resp := api.HostComplianceFrameworksResponse{Frameworks: []api.HostComplianceFramework{}}
	for rows.Next() {
		var item api.HostComplianceFramework
		var passing, failing int64
		if err := rows.Scan(&item.FrameworkId, &item.RuleCount, &passing, &failing); err != nil {
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
		item.Passing = int(passing)
		item.Failing = int(failing)
		if item.RuleCount > 0 {
			item.ScorePct = float32(math.Round(float64(passing)/float64(item.RuleCount)*1000) / 10)
		}
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
	if err := h.pool.QueryRow(ctx, `
		SELECT COUNT(*)::bigint,
		       COUNT(*) FILTER (WHERE current_status = 'pass')::bigint,
		       COUNT(*) FILTER (WHERE current_status = 'fail')::bigint
		  FROM host_rule_state WHERE host_id = $1`, hostID).
		Scan(&resp.Overall.RuleCount, &oPassing, &oFailing); err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"overall aggregate failed", true)
		return
	}
	resp.Overall.Passing = int(oPassing)
	resp.Overall.Failing = int(oFailing)
	if resp.Overall.RuleCount > 0 {
		resp.Overall.ScorePct = float32(math.Round(float64(oPassing)/float64(resp.Overall.RuleCount)*1000) / 10)
	}

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
//   - otherwise the pinned family must equal the host family, and the
//     pinned digits must equal the host's major version (or the
//     major+minor concatenation, covering ubuntu2404 vs "24.04")
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
	if pinFamily != strings.ToLower(osFamily) {
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
