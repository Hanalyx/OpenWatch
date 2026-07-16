// OS Intelligence read API — GET /intelligence/events + /intelligence/state.
//
// Spec: app/specs/api/os-intelligence.spec.yaml.

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	openapitypes "github.com/oapi-codegen/runtime/types"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/host"
	"github.com/Hanalyx/openwatch/internal/server/api"
)

// GetIntelligenceEvents implements api.ServerInterface.
// Spec api-os-intelligence AC-01, AC-02, AC-03, AC-04, AC-05, AC-09, AC-10.
func (h *handlers) GetIntelligenceEvents(
	w http.ResponseWriter,
	r *http.Request,
	params api.GetIntelligenceEventsParams,
) {
	if denied := auth.EnforcePermission(w, r, auth.HostRead); denied {
		return
	}

	limit := int32(50)
	if params.Limit != nil {
		v := *params.Limit
		if v < 1 || v > 200 {
			writeError(w, http.StatusBadRequest, "pagination.limit_exceeded", "client",
				"limit must be between 1 and 200", false)
			return
		}
		limit = int32(v)
	}
	if params.Severity != nil {
		if !params.Severity.Valid() {
			writeError(w, http.StatusBadRequest, "validation.field_range", "client",
				"severity must be one of info/low/medium/high/critical", false)
			return
		}
	}

	rows, err := h.queryIntelligenceEvents(r.Context(), params, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.internal", "server",
			"failed to query intelligence events", true)
		return
	}

	resp := api.IntelligenceEventsPage{Items: rows}
	if len(rows) == int(limit) {
		last := rows[len(rows)-1].DetectedAt.Format(time.RFC3339Nano)
		resp.NextCursor = &last
	}
	writeJSON(w, http.StatusOK, resp)
}

// queryIntelligenceEvents reads host_intelligence_events with the given
// filters, newest-first.
func (h *handlers) queryIntelligenceEvents(
	ctx context.Context,
	p api.GetIntelligenceEventsParams,
	limit int32,
) ([]api.IntelligenceEvent, error) {
	q := `
SELECT id, host_id, event_code, severity, detail,
       occurred_at, detected_at, correlation_id
  FROM host_intelligence_events
 WHERE 1=1
`
	args := []any{}
	idx := 1
	addArg := func(condition string, val any) {
		q += " AND " + strings.Replace(condition, "$N", "$"+itoa(idx), 1)
		args = append(args, val)
		idx++
	}

	if p.HostId != nil {
		addArg("host_id = $N", uuid.UUID(*p.HostId))
	}
	if p.EventCode != nil && *p.EventCode != "" {
		addArg("event_code = $N", *p.EventCode)
	}
	if p.Severity != nil {
		addArg("severity = $N", string(*p.Severity))
	}
	if p.Since != nil {
		addArg("detected_at >= $N", *p.Since)
	}
	if p.Until != nil {
		addArg("detected_at < $N", *p.Until)
	}
	if p.Cursor != nil && *p.Cursor != "" {
		if t, err := time.Parse(time.RFC3339Nano, *p.Cursor); err == nil {
			addArg("detected_at < $N", t)
		}
	}

	q += " ORDER BY detected_at DESC, id DESC LIMIT $" + itoa(idx)
	args = append(args, limit)

	rows, err := h.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []api.IntelligenceEvent{}
	for rows.Next() {
		var (
			ev          api.IntelligenceEvent
			id, hostID  uuid.UUID
			detailBytes []byte
		)
		if err := rows.Scan(
			&id, &hostID, &ev.EventCode, &ev.Severity, &detailBytes,
			&ev.OccurredAt, &ev.DetectedAt, &ev.CorrelationId,
		); err != nil {
			return nil, err
		}
		ev.Id = openapitypes.UUID(id)
		ev.HostId = openapitypes.UUID(hostID)
		if len(detailBytes) > 0 {
			var d map[string]any
			if json.Unmarshal(detailBytes, &d) == nil {
				ev.Detail = &d
			}
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// GetIntelligenceState implements api.ServerInterface.
// Spec api-os-intelligence AC-06, AC-07, AC-08.
func (h *handlers) GetIntelligenceState(
	w http.ResponseWriter,
	r *http.Request,
	hostID openapitypes.UUID,
) {
	if denied := auth.EnforcePermission(w, r, auth.HostRead); denied {
		return
	}

	hid := uuid.UUID(hostID)

	// Spec C-04: probe for the host first. If the host is missing /
	// soft-deleted, return 404. We deliberately collapse the
	// "host-missing" and "no-snapshot-yet" cases under the same envelope
	// so callers cannot probe host existence here.
	if _, err := h.hosts.GetByID(r.Context(), hid); err != nil {
		if errors.Is(err, host.ErrHostNotFound) {
			writeError(w, http.StatusNotFound, "hosts.not_found", "client",
				"host not found", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"host lookup failed", true)
		return
	}

	var (
		snapshotBytes []byte
		collectedAt   time.Time
		freshRaw      []byte
	)
	err := h.pool.QueryRow(r.Context(),
		`SELECT snapshot, collected_at, category_freshness FROM host_intelligence_state WHERE host_id = $1`,
		hid,
	).Scan(&snapshotBytes, &collectedAt, &freshRaw)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Spec C-04: same envelope as "host unknown".
			writeError(w, http.StatusNotFound, "hosts.not_found", "client",
				"host not found", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"state lookup failed", true)
		return
	}

	var snap map[string]any
	if len(snapshotBytes) > 0 {
		_ = json.Unmarshal(snapshotBytes, &snap)
	}
	resp := api.IntelligenceState{
		HostId:      openapitypes.UUID(hid),
		Snapshot:    snap,
		CollectedAt: collectedAt,
	}
	// category_freshness is JSONB; NULL for rows written before migration
	// 0052. Decode failures are non-fatal — the snapshot is still valid.
	if len(freshRaw) > 0 {
		var cf api.CategoryFreshness
		if json.Unmarshal(freshRaw, &cf) == nil && len(cf) > 0 {
			resp.CategoryFreshness = &cf
		}
	}
	writeJSON(w, http.StatusOK, resp)
}
