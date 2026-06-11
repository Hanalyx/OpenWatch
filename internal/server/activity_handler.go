// Activity feed handler — GET /api/v1/activity. Spec api-activity.

package server

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	openapitypes "github.com/oapi-codegen/runtime/types"

	"github.com/Hanalyx/openwatch/internal/activity"
	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/server/api"
)

// GetActivity implements api.ServerInterface. Spec api-activity AC-01..AC-10.
func (h *handlers) GetActivity(w http.ResponseWriter, r *http.Request, params api.GetActivityParams) {
	// Spec C-01: anonymous callers get 403; the endpoint itself does
	// not require a specific permission — the per-source RBAC happens
	// inside the service.
	id := auth.FromContext(r.Context())
	if id.IsAnonymous {
		writeError(w, http.StatusForbidden, "authz.permission_denied", "client",
			"authenticated session required", false)
		return
	}
	if h.activitySvc == nil {
		writeError(w, http.StatusServiceUnavailable, "server.unavailable", "server",
			"activity service not wired", true)
		return
	}

	limit := 50
	if params.Limit != nil {
		limit = int(*params.Limit)
	}
	if limit < 1 || limit > 200 {
		writeError(w, http.StatusBadRequest, "pagination.limit_exceeded", "client",
			"limit must be between 1 and 200", false)
		return
	}

	filter := activity.Filter{Limit: limit}
	if params.Source != nil {
		filter.Source = string(*params.Source)
		if !activity.IsKnownSource(filter.Source) {
			writeError(w, http.StatusBadRequest, "validation.field_range", "client",
				"unknown source", false)
			return
		}
	}
	if params.Severity != nil {
		filter.Severity = string(*params.Severity)
		if !activity.IsKnownSeverity(filter.Severity) {
			writeError(w, http.StatusBadRequest, "validation.field_range", "client",
				"unknown severity", false)
			return
		}
	}
	if params.HostId != nil {
		u := uuid.UUID(*params.HostId)
		filter.HostID = &u
	}
	if params.Since != nil {
		t := *params.Since
		filter.Since = &t
	}
	if params.Until != nil {
		t := *params.Until
		filter.Until = &t
	}
	if params.Cursor != nil {
		filter.Cursor = *params.Cursor
	}

	caller := activity.Caller{
		CanReadAlerts: id.HasPermission(auth.AlertRead),
		CanReadHosts:  id.HasPermission(auth.HostRead),
		CanReadAudit:  id.HasPermission(auth.AuditRead),
	}

	rows, hidden, cursor, err := h.activitySvc.List(r.Context(), filter, caller)
	if err != nil {
		switch {
		case errors.Is(err, activity.ErrInvalidLimit):
			writeError(w, http.StatusBadRequest, "pagination.limit_exceeded", "client",
				"limit must be between 1 and 200", false)
		case errors.Is(err, activity.ErrInvalidSource):
			writeError(w, http.StatusBadRequest, "validation.field_range", "client",
				"unknown source", false)
		case errors.Is(err, activity.ErrInvalidSeverity):
			writeError(w, http.StatusBadRequest, "validation.field_range", "client",
				"unknown severity", false)
		default:
			writeError(w, http.StatusInternalServerError, "server.internal", "server",
				"activity query failed", true)
		}
		return
	}

	page := api.ActivityPage{
		Items:       activityRowsToAPI(rows),
		HiddenCount: hidden,
	}
	if cursor != "" {
		page.NextCursor = &cursor
	}
	writeJSON(w, http.StatusOK, page)
}

func activityRowsToAPI(rows []activity.Row) []api.Activity {
	out := make([]api.Activity, len(rows))
	for i, r := range rows {
		a := api.Activity{
			Id:         openapitypes.UUID(r.ID),
			Source:     api.ActivitySource(r.Source),
			Severity:   api.ActivitySeverity(r.Severity),
			Title:      r.Title,
			Summary:    &r.Summary,
			OccurredAt: r.OccurredAt,
		}
		if r.HostID != nil {
			u := openapitypes.UUID(*r.HostID)
			a.HostId = &u
		}
		out[i] = a
	}
	return out
}
