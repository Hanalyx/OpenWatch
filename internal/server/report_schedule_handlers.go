// Report schedule HTTP surface: CRUD over report_schedules (list, create,
// toggle, delete). Thin handlers over internal/reportschedule with RBAC
// (host:read for list, host:write for mutations) and wire-shaping. Spec:
// system-report-schedule.

package server

import (
	"encoding/json"
	"errors"
	"net/http"

	openapitypes "github.com/oapi-codegen/runtime/types"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/notification"
	"github.com/Hanalyx/openwatch/internal/reportschedule"
	"github.com/Hanalyx/openwatch/internal/server/api"
)

// toAPISchedule maps a service schedule to the wire shape.
func toAPISchedule(s reportschedule.Schedule) api.ReportSchedule {
	out := api.ReportSchedule{
		Id:         openapitypes.UUID(s.ID),
		Name:       s.Name,
		Kind:       api.ReportScheduleKind(s.Kind),
		Frequency:  api.ReportScheduleFrequency(s.Frequency),
		Hour:       s.Hour,
		Weekday:    s.Weekday,
		DayOfMonth: s.DayOfMonth,
		ChannelId:  openapitypes.UUID(s.ChannelID),
		Enabled:    s.Enabled,
		NextRunAt:  s.NextRunAt,
		LastRunAt:  s.LastRunAt,
		CreatedAt:  s.CreatedAt,
	}
	if s.Scope.GroupID != nil {
		gid := openapitypes.UUID(*s.Scope.GroupID)
		out.GroupId = &gid
	}
	if s.Scope.Framework != "" {
		out.Framework = &s.Scope.Framework
	}
	if s.Scope.PeriodDays != 0 {
		pd := s.Scope.PeriodDays
		out.PeriodDays = &pd
	}
	if s.LastStatus != "" {
		ls := s.LastStatus
		out.LastStatus = &ls
	}
	return out
}

func (h *handlers) reportScheduleReady(w http.ResponseWriter) bool {
	if h.reportScheduleSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "server.unavailable", "server",
			"report schedule service not wired", true)
		return false
	}
	return true
}

// GetReportSchedules implements api.ServerInterface.
// Spec system-report-schedule.
func (h *handlers) GetReportSchedules(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.HostRead); denied {
		return
	}
	if !h.reportScheduleReady(w) {
		return
	}
	list, err := h.reportScheduleSvc.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server", "schedule list failed", true)
		return
	}
	resp := api.ReportScheduleList{Schedules: []api.ReportSchedule{}}
	for _, s := range list {
		resp.Schedules = append(resp.Schedules, toAPISchedule(s))
	}
	writeJSON(w, http.StatusOK, resp)
}

// CreateReportSchedule implements api.ServerInterface.
// Spec system-report-schedule.
func (h *handlers) CreateReportSchedule(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.HostWrite); denied {
		return
	}
	if !h.reportScheduleReady(w) {
		return
	}
	var body api.CreateReportScheduleRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "schedule.invalid_request", "client", "malformed request body", false)
		return
	}
	if body.Name == "" {
		writeError(w, http.StatusBadRequest, "schedule.invalid_request", "client", "name is required", false)
		return
	}
	freq := reportschedule.Frequency(body.Frequency)
	if !freq.IsValid() {
		writeError(w, http.StatusBadRequest, "schedule.invalid_request", "client", "frequency must be daily, weekly, or monthly", false)
		return
	}
	if freq == reportschedule.Weekly && body.Weekday == nil {
		writeError(w, http.StatusBadRequest, "schedule.invalid_request", "client", "weekly schedule requires weekday", false)
		return
	}
	if freq == reportschedule.Monthly && body.DayOfMonth == nil {
		writeError(w, http.StatusBadRequest, "schedule.invalid_request", "client", "monthly schedule requires day_of_month", false)
		return
	}

	p := reportschedule.CreateParams{
		Name:       body.Name,
		Kind:       string(body.Kind),
		Frequency:  freq,
		Hour:       6,
		Weekday:    body.Weekday,
		DayOfMonth: body.DayOfMonth,
		ChannelID:  uuid.UUID(body.ChannelId),
	}
	if body.Hour != nil {
		p.Hour = *body.Hour
	}
	if body.GroupId != nil {
		gid := uuid.UUID(*body.GroupId)
		p.Scope.GroupID = &gid
	}
	if body.Framework != nil {
		p.Scope.Framework = *body.Framework
	}
	if body.PeriodDays != nil {
		p.Scope.PeriodDays = *body.PeriodDays
	}
	if id := auth.FromContext(r.Context()); !id.IsAnonymous && id.ID != "" {
		if u, err := uuid.Parse(id.ID); err == nil {
			p.CreatedBy = &u
		}
	}

	// The delivery channel must be an EMAIL channel (only email carries the
	// PDF attachment). Validate up front so a misconfigured schedule fails at
	// create rather than silently at every dispatch.
	if h.notificationSvc != nil {
		ch, cerr := h.notificationSvc.Get(r.Context(), p.ChannelID)
		if errors.Is(cerr, notification.ErrChannelNotFound) {
			writeError(w, http.StatusBadRequest, "schedule.invalid_request", "client", "channel not found", false)
			return
		}
		if cerr == nil && ch.Type != notification.TypeEmail {
			writeError(w, http.StatusBadRequest, "schedule.invalid_request", "client",
				"channel must be an email channel", false)
			return
		}
	}

	sch, err := h.reportScheduleSvc.Create(r.Context(), p)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server", "schedule create failed", true)
		return
	}

	ident := auth.FromContext(r.Context())
	detail, _ := json.Marshal(map[string]string{
		"schedule_id": sch.ID.String(), "name": sch.Name, "kind": sch.Kind,
		"frequency": string(sch.Frequency), "channel_id": sch.ChannelID.String(),
	})
	audit.Emit(r.Context(), audit.ReportScheduleCreated, audit.Event{
		ActorType: "user", ActorID: ident.ID,
		ResourceType: "report_schedule", ResourceID: sch.ID.String(), Detail: detail,
	})

	writeJSON(w, http.StatusCreated, toAPISchedule(sch))
}

// UpdateReportSchedule implements api.ServerInterface (enable/disable).
// Spec system-report-schedule.
func (h *handlers) UpdateReportSchedule(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.HostWrite); denied {
		return
	}
	if !h.reportScheduleReady(w) {
		return
	}
	var body api.UpdateReportScheduleRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "schedule.invalid_request", "client", "malformed request body", false)
		return
	}
	sch, err := h.reportScheduleSvc.SetEnabled(r.Context(), uuid.UUID(id), body.Enabled)
	if errors.Is(err, reportschedule.ErrNotFound) {
		writeError(w, http.StatusNotFound, "schedule.not_found", "client", "schedule not found", false)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server", "schedule update failed", true)
		return
	}

	ident := auth.FromContext(r.Context())
	detail, _ := json.Marshal(map[string]any{"schedule_id": sch.ID.String(), "enabled": sch.Enabled})
	audit.Emit(r.Context(), audit.ReportScheduleToggled, audit.Event{
		ActorType: "user", ActorID: ident.ID,
		ResourceType: "report_schedule", ResourceID: sch.ID.String(), Detail: detail,
	})

	writeJSON(w, http.StatusOK, toAPISchedule(sch))
}

// DeleteReportSchedule implements api.ServerInterface.
// Spec system-report-schedule.
func (h *handlers) DeleteReportSchedule(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.HostWrite); denied {
		return
	}
	if !h.reportScheduleReady(w) {
		return
	}
	err := h.reportScheduleSvc.Delete(r.Context(), uuid.UUID(id))
	if errors.Is(err, reportschedule.ErrNotFound) {
		writeError(w, http.StatusNotFound, "schedule.not_found", "client", "schedule not found", false)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server", "schedule delete failed", true)
		return
	}

	ident := auth.FromContext(r.Context())
	detail, _ := json.Marshal(map[string]string{"schedule_id": uuid.UUID(id).String()})
	audit.Emit(r.Context(), audit.ReportScheduleDeleted, audit.Event{
		ActorType: "user", ActorID: ident.ID,
		ResourceType: "report_schedule", ResourceID: uuid.UUID(id).String(), Detail: detail,
	})

	w.WriteHeader(http.StatusNoContent)
}
