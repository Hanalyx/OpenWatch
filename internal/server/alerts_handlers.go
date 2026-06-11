// Alerts read + lifecycle API — spec api-alerts.

package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	openapitypes "github.com/oapi-codegen/runtime/types"

	"github.com/Hanalyx/openwatch/internal/alerts"
	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/server/api"
)

// GetAlerts implements api.ServerInterface.
// Spec api-alerts AC-01..AC-05, AC-14, AC-15.
func (h *handlers) GetAlerts(w http.ResponseWriter, r *http.Request, params api.GetAlertsParams) {
	if denied := auth.EnforcePermission(w, r, auth.AlertRead); denied {
		return
	}
	if h.alertsSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "server.unavailable", "server",
			"alerts service not wired", true)
		return
	}

	limit := 50
	if params.Limit != nil {
		v := int(*params.Limit)
		if v < 1 || v > 200 {
			writeError(w, http.StatusBadRequest, "pagination.limit_exceeded", "client",
				"limit must be between 1 and 200", false)
			return
		}
		limit = v
	}
	if params.Severity != nil && !alerts.IsKnownSeverity(string(*params.Severity)) {
		writeError(w, http.StatusBadRequest, "validation.field_range", "client",
			"severity must be one of info/low/medium/high/critical", false)
		return
	}
	if params.State != nil && !alerts.IsKnownState(string(*params.State)) {
		writeError(w, http.StatusBadRequest, "validation.field_range", "client",
			"state must be one of active/acknowledged/silenced/resolved/dismissed", false)
		return
	}

	filter := alerts.ListFilter{Limit: limit}
	if params.State != nil {
		s := string(*params.State)
		filter.State = &s
	}
	if params.HostId != nil {
		u := uuid.UUID(*params.HostId)
		filter.HostID = &u
	}
	if params.Severity != nil {
		s := string(*params.Severity)
		filter.Severity = &s
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

	rows, nextCursor, err := h.alertsSvc.List(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.internal", "server",
			"alerts list failed", true)
		return
	}
	page := api.AlertsPage{Items: alertsToAPI(rows)}
	if nextCursor != "" {
		page.NextCursor = &nextCursor
	}
	writeJSON(w, http.StatusOK, page)
}

// GetAlertByID implements api.ServerInterface.
func (h *handlers) GetAlertByID(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.AlertRead); denied {
		return
	}
	if h.alertsSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "server.unavailable", "server",
			"alerts service not wired", true)
		return
	}
	a, err := h.alertsSvc.Get(r.Context(), uuid.UUID(id))
	if err != nil {
		if errors.Is(err, alerts.ErrAlertNotFound) {
			writeError(w, http.StatusNotFound, "alerts.not_found", "client",
				"alert not found", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"alert lookup failed", true)
		return
	}
	writeJSON(w, http.StatusOK, alertToAPI(a))
}

// lifecycleVerb dispatches POST /{id}:verb endpoints. body parsing is
// shared; the verb specifies which Service method to call.
type lifecycleVerb int

const (
	verbAcknowledge lifecycleVerb = iota
	verbSilence
	verbResolve
	verbDismiss
)

func (h *handlers) lifecycle(w http.ResponseWriter, r *http.Request, id openapitypes.UUID, verb lifecycleVerb) {
	if denied := auth.EnforcePermission(w, r, auth.AlertWrite); denied {
		return
	}
	if h.alertsSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "server.unavailable", "server",
			"alerts service not wired", true)
		return
	}

	var req struct {
		Reason string     `json:"reason"`
		Until  *time.Time `json:"until"`
	}
	body, _ := io.ReadAll(r.Body)
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, "validation.field_range", "client",
				"invalid JSON body", false)
			return
		}
	}
	if len(req.Reason) > 256 {
		writeError(w, http.StatusBadRequest, "validation.field_range", "client",
			"reason exceeds 256 chars", false)
		return
	}

	actor := h.identityUUIDOrNil(r)
	alertID := uuid.UUID(id)

	var err error
	switch verb {
	case verbAcknowledge:
		err = h.alertsSvc.Acknowledge(r.Context(), alertID, actor, req.Reason)
	case verbSilence:
		err = h.alertsSvc.Silence(r.Context(), alertID, actor, req.Until, req.Reason)
	case verbResolve:
		err = h.alertsSvc.Resolve(r.Context(), alertID, actor, req.Reason)
	case verbDismiss:
		err = h.alertsSvc.Dismiss(r.Context(), alertID, actor, req.Reason)
	}
	if err != nil {
		switch {
		case errors.Is(err, alerts.ErrAlertNotFound):
			writeError(w, http.StatusNotFound, "alerts.not_found", "client",
				"alert not found", false)
		case errors.Is(err, alerts.ErrInvalidTransition):
			writeError(w, http.StatusConflict, "alerts.invalid_transition", "client",
				err.Error(), false)
		case errors.Is(err, alerts.ErrInvalidSilenceWindow):
			writeError(w, http.StatusBadRequest, "validation.field_range", "client",
				"silenced_until must be in the future", false)
		default:
			writeError(w, http.StatusInternalServerError, "server.error", "server",
				"lifecycle failed", true)
		}
		return
	}
	updated, err := h.alertsSvc.Get(r.Context(), alertID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"updated lookup failed", true)
		return
	}
	writeJSON(w, http.StatusOK, alertToAPI(updated))
}

// PostAlertAcknowledge implements api.ServerInterface.
func (h *handlers) PostAlertAcknowledge(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	h.lifecycle(w, r, id, verbAcknowledge)
}

// PostAlertSilence implements api.ServerInterface.
func (h *handlers) PostAlertSilence(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	h.lifecycle(w, r, id, verbSilence)
}

// PostAlertResolve implements api.ServerInterface.
func (h *handlers) PostAlertResolve(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	h.lifecycle(w, r, id, verbResolve)
}

// PostAlertDismiss implements api.ServerInterface.
func (h *handlers) PostAlertDismiss(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	h.lifecycle(w, r, id, verbDismiss)
}

// identityUUIDOrNil returns the calling identity's UUID, or uuid.Nil
// when the identity is anonymous (e.g. tests).
func (h *handlers) identityUUIDOrNil(r *http.Request) uuid.UUID {
	if u := h.identityUUID(r); u != nil {
		return *u
	}
	return uuid.Nil
}

// alertsToAPI converts service-layer slices to API response types.
func alertsToAPI(in []alerts.Alert) []api.Alert {
	out := make([]api.Alert, len(in))
	for i, a := range in {
		out[i] = alertToAPI(a)
	}
	return out
}

func alertToAPI(a alerts.Alert) api.Alert {
	out := api.Alert{
		Id:         openapitypes.UUID(a.ID),
		DedupKey:   a.DedupKey,
		AlertType:  a.Type,
		Severity:   api.AlertSeverity(a.Severity),
		RuleId:     &a.RuleID,
		Title:      a.Title,
		Body:       &a.Body,
		State:      api.AlertState(a.State),
		OccurredAt: a.OccurredAt,
		CreatedAt:  &a.CreatedAt,
		UpdatedAt:  &a.UpdatedAt,
	}
	if a.HostID != uuid.Nil {
		h := openapitypes.UUID(a.HostID)
		out.HostId = &h
	}
	if len(a.Tags) > 0 {
		t := a.Tags
		out.Tags = &t
	}
	if a.AcknowledgedBy != nil {
		u := openapitypes.UUID(*a.AcknowledgedBy)
		out.AcknowledgedBy = &u
	}
	out.AcknowledgedAt = a.AcknowledgedAt
	if a.SilencedBy != nil {
		u := openapitypes.UUID(*a.SilencedBy)
		out.SilencedBy = &u
	}
	out.SilencedUntil = a.SilencedUntil
	if a.ResolvedBy != nil {
		u := openapitypes.UUID(*a.ResolvedBy)
		out.ResolvedBy = &u
	}
	out.ResolvedAt = a.ResolvedAt
	if a.DismissedBy != nil {
		u := openapitypes.UUID(*a.DismissedBy)
		out.DismissedBy = &u
	}
	out.DismissedAt = a.DismissedAt
	return out
}
