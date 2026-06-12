// Per-host failing-rule listing — GET /hosts/{id}/compliance/failed-rules.
//
// Reads host_rule_state rows with current_status='fail' for the host,
// severity-ordered (critical > high > medium > low > unset, then
// last_checked_at DESC), with titles/categories resolved from the
// in-memory kensa RuleCatalog. SECURITY: the query projects an explicit
// column list — the stored per-rule check output (which may contain
// sensitive host configuration) is never selected; spec AC-06 enforces
// that invariant by source inspection of this file.
//
// Spec: specs/api/host-compliance.spec.yaml.
package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	openapitypes "github.com/oapi-codegen/runtime/types"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/host"
	"github.com/Hanalyx/openwatch/internal/server/api"
)

// failedRulesDefaultLimit / failedRulesMaxLimit bound the page size.
// Out-of-range values are clamped, not rejected (spec C-01).
const (
	failedRulesDefaultLimit = 10
	failedRulesMaxLimit     = 100
)

// GetHostFailedRules implements api.ServerInterface.
// Spec api-host-compliance AC-01..AC-06.
func (h *handlers) GetHostFailedRules(
	w http.ResponseWriter,
	r *http.Request,
	id openapitypes.UUID,
	params api.GetHostFailedRulesParams,
) {
	if denied := auth.EnforcePermission(w, r, auth.HostRead); denied {
		return
	}

	ctx := r.Context()
	hostID := uuid.UUID(id)

	// Same lookup as PostHostScan: 404 for unknown/deleted hosts.
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

	limit := failedRulesDefaultLimit
	if params.Limit != nil {
		limit = *params.Limit
		if limit < 1 {
			limit = 1
		}
		if limit > failedRulesMaxLimit {
			limit = failedRulesMaxLimit
		}
	}

	// nil framework disables both the filter and the control-id
	// projection ($2::text IS NULL short-circuits, same idiom as
	// fleetrollup). The window COUNT(*) is computed before LIMIT, so
	// it carries the post-filter, pre-limit total (spec C-01/C-04).
	var framework any
	if params.Framework != nil && *params.Framework != "" {
		framework = *params.Framework
	}
	const q = `
		SELECT rule_id,
		       COALESCE(severity, ''),
		       last_checked_at,
		       check_count,
		       CASE WHEN $2::text IS NULL THEN '[]'::jsonb
		            ELSE COALESCE(framework_refs -> $2, '[]'::jsonb)
		       END AS control_ids,
		       COUNT(*) OVER ()::bigint AS total_failing
		  FROM host_rule_state
		 WHERE host_id = $1
		   AND current_status = 'fail'
		   AND ($2::text IS NULL OR framework_refs ? $2)
		 ORDER BY CASE lower(COALESCE(severity, ''))
		            WHEN 'critical' THEN 0
		            WHEN 'high'     THEN 1
		            WHEN 'medium'   THEN 2
		            WHEN 'low'      THEN 3
		            ELSE 4
		          END,
		          last_checked_at DESC
		 LIMIT $3`
	rows, err := h.pool.Query(ctx, q, hostID, framework, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"failed-rules query failed", true)
		return
	}
	defer rows.Close()

	resp := api.HostFailedRulesResponse{Rules: []api.HostFailedRule{}}
	for rows.Next() {
		var (
			item       api.HostFailedRule
			checkedAt  time.Time
			controlIDs []byte
			total      int64
		)
		if err := rows.Scan(&item.RuleId, &item.Severity, &checkedAt,
			&item.CheckCount, &controlIDs, &total); err != nil {
			writeError(w, http.StatusInternalServerError, "server.error", "server",
				"failed-rules scan failed", true)
			return
		}
		resp.TotalFailing = total
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
		// Catalog fallback (spec AC-03): without a catalog (or for an
		// uncataloged rule) the rule id doubles as the title.
		item.Title = item.RuleId
		if meta, ok := h.ruleCatalog.Get(item.RuleId); ok {
			item.Title = meta.Title
			item.Category = meta.Category
		}
		resp.Rules = append(resp.Rules, item)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"failed-rules iterate failed", true)
		return
	}

	writeJSON(w, http.StatusOK, resp)
}
