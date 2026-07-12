package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/notification"
	"github.com/Hanalyx/openwatch/internal/server/api"
	openapitypes "github.com/oapi-codegen/runtime/types"

	"github.com/google/uuid"
)

// notificationsReady writes 503 when the notification service is not
// wired (tests / early boot) and reports false. Mirrors the other
// optional-service guards.
func (h *handlers) notificationsReady(w http.ResponseWriter) bool {
	if h.notificationSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "service.unavailable", "server",
			"notification service not configured", true)
		return false
	}
	return true
}

// GetNotificationChannels lists channels with secrets redacted.
// Spec api-notifications AC-01.
func (h *handlers) GetNotificationChannels(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.NotificationRead); denied {
		return
	}
	if !h.notificationsReady(w) {
		return
	}
	list, err := h.notificationSvc.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"list notification channels failed", true)
		return
	}
	out := make([]api.NotificationChannel, len(list))
	for i, c := range list {
		out[i] = toAPINotificationChannel(c)
	}
	writeJSON(w, http.StatusOK, api.NotificationChannelList{Channels: out})
}

// PostNotificationChannel creates a channel. Spec api-notifications AC-02.
func (h *handlers) PostNotificationChannel(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.NotificationWrite); denied {
		return
	}
	if !h.notificationsReady(w) {
		return
	}
	var req api.NotificationChannelCreate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"type, name, url required", false)
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	p := notification.CreateParams{
		Type:    notification.ChannelType(req.Type),
		Name:    req.Name,
		Enabled: enabled,
		Config: notificationConfig(req.Url, req.Token, req.SmtpHost, req.SmtpPort,
			createEnc(req.SmtpEncryption), req.Username, req.Password, req.From, req.To),
		TagFilter: derefTagFilter(req.TagFilter),
	}
	c, err := h.notificationSvc.Create(r.Context(), p)
	if err != nil {
		writeNotificationErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toAPINotificationChannel(c))
}

// GetNotificationChannel fetches one channel (secret redacted).
// Spec api-notifications AC-01.
func (h *handlers) GetNotificationChannel(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.NotificationRead); denied {
		return
	}
	if !h.notificationsReady(w) {
		return
	}
	c, err := h.notificationSvc.Get(r.Context(), uuid.UUID(id))
	if err != nil {
		writeNotificationErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toAPINotificationChannel(c))
}

// PatchNotificationChannel updates a channel. Spec api-notifications AC-03.
func (h *handlers) PatchNotificationChannel(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.NotificationWrite); denied {
		return
	}
	if !h.notificationsReady(w) {
		return
	}
	var req api.NotificationChannelUpdate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"name, enabled required", false)
		return
	}
	p := notification.UpdateParams{
		Name:      req.Name,
		Enabled:   req.Enabled,
		TagFilter: derefTagFilter(req.TagFilter),
	}
	// A secret field supplied in the patch (url for slack/webhook,
	// smtp_host for email) replaces the encrypted config; omitting it
	// leaves the existing secret untouched.
	if req.Url != nil || req.SmtpHost != nil {
		p.ReplaceConfig = true
		p.Config = notificationConfig(req.Url, req.Token, req.SmtpHost, req.SmtpPort,
			updateEnc(req.SmtpEncryption), req.Username, req.Password, req.From, req.To)
	}
	c, err := h.notificationSvc.Update(r.Context(), uuid.UUID(id), p)
	if err != nil {
		writeNotificationErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toAPINotificationChannel(c))
}

// DeleteNotificationChannel removes a channel. Spec api-notifications AC-04.
func (h *handlers) DeleteNotificationChannel(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.NotificationDelete); denied {
		return
	}
	if !h.notificationsReady(w) {
		return
	}
	if err := h.notificationSvc.Delete(r.Context(), uuid.UUID(id)); err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"delete notification channel failed", true)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// TestNotificationChannel sends a synthetic alert through the channel.
// Spec api-notifications AC-05.
func (h *handlers) TestNotificationChannel(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.NotificationTest); denied {
		return
	}
	if !h.notificationsReady(w) {
		return
	}
	if err := h.notificationSvc.Test(r.Context(), uuid.UUID(id)); err != nil {
		if errors.Is(err, notification.ErrChannelNotFound) {
			writeError(w, http.StatusNotFound, "notifications.not_found", "client",
				"channel not found", false)
			return
		}
		// Delivery failed (unreachable relay, auth rejected, STARTTLS not
		// offered, non-2xx webhook, blocked host). Client-fault 400 so the
		// operator fixes the channel config. Surface the reason (the delivery
		// layer already scrubs the secret webhook URL from HTTP errors) and log
		// it server-side — previously it was swallowed, leaving no way to
		// diagnose why a test failed.
		slog.WarnContext(r.Context(), "notification test delivery failed",
			"channel_id", uuid.UUID(id).String(), "error", err.Error())
		writeError(w, http.StatusBadRequest, "notifications.delivery_failed", "client",
			"test delivery failed: "+testErrDetail(err), false)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func toAPINotificationChannel(c notification.Channel) api.NotificationChannel {
	tags := c.TagFilter
	if tags == nil {
		tags = map[string]string{}
	}
	out := api.NotificationChannel{
		Id:         openapitypes.UUID(c.ID),
		Type:       api.NotificationChannelType(c.Type),
		Name:       c.Name,
		Enabled:    c.Enabled,
		TargetHint: c.TargetHint,
		TagFilter:  tags,
		CreatedAt:  c.CreatedAt,
		UpdatedAt:  c.UpdatedAt,
	}
	// Email channels surface their NON-secret config so the edit form can
	// pre-fill. The store already redacted the password; the slack/webhook
	// URL + token stay hidden (their Config is zeroed on read).
	if c.Type == notification.TypeEmail {
		if c.Config.SMTPPort != 0 {
			p := c.Config.SMTPPort
			out.SmtpPort = &p
		}
		if c.Config.SMTPEncryption != "" {
			e := c.Config.SMTPEncryption
			out.SmtpEncryption = &e
		}
		if c.Config.From != "" {
			f := c.Config.From
			out.From = &f
		}
		if len(c.Config.To) > 0 {
			to := c.Config.To
			out.To = &to
		}
		if c.Config.Username != "" {
			u := c.Config.Username
			out.Username = &u
		}
	}
	return out
}

// testErrDetail bounds a delivery error for the human-facing test response.
// The delivery layer already scrubs the secret webhook URL from HTTP errors,
// so what remains (SMTP/dial/auth causes) is safe to show the operator; this
// only trims the internal wrapper prefix and caps the length.
func testErrDetail(err error) string {
	s := strings.TrimPrefix(err.Error(), "notification: ")
	const max = 300
	if len(s) > max {
		s = s[:max] + "..."
	}
	return s
}

func derefTagFilter(m *map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return *m
}

// createEnc / updateEnc flatten the generated per-request SMTP-encryption
// enum pointers to a plain string ("" when absent → the store treats empty
// as the STARTTLS default).
func createEnc(e *api.NotificationChannelCreateSmtpEncryption) string {
	if e == nil {
		return ""
	}
	return string(*e)
}

func updateEnc(e *api.NotificationChannelUpdateSmtpEncryption) string {
	if e == nil {
		return ""
	}
	return string(*e)
}

// notificationConfig assembles the decrypted Config from the optional
// request fields. HTTP channels use url/token; email uses the smtp* +
// from/to fields. Unset pointers stay zero (validated per-type downstream).
func notificationConfig(url, token, smtpHost *string, smtpPort *int, smtpEncryption string, username, password, from *string, to *[]string) notification.Config {
	cfg := notification.Config{}
	if url != nil {
		cfg.URL = *url
	}
	if token != nil {
		cfg.Token = *token
	}
	if smtpHost != nil {
		cfg.SMTPHost = *smtpHost
	}
	if smtpPort != nil {
		cfg.SMTPPort = *smtpPort
	}
	cfg.SMTPEncryption = smtpEncryption
	if username != nil {
		cfg.Username = *username
	}
	if password != nil {
		cfg.Password = *password
	}
	if from != nil {
		cfg.From = *from
	}
	if to != nil {
		cfg.To = *to
	}
	return cfg
}

// writeNotificationErr maps service errors to HTTP status.
func writeNotificationErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, notification.ErrChannelNotFound):
		writeError(w, http.StatusNotFound, "notifications.not_found", "client",
			"channel not found", false)
	case errors.Is(err, notification.ErrInvalidConfig):
		writeError(w, http.StatusBadRequest, "notifications.invalid", "client",
			err.Error(), false)
	default:
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"notification channel operation failed", true)
	}
}
