package server

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	openapitypes "github.com/oapi-codegen/runtime/types"

	"github.com/Hanalyx/openwatch/internal/notifyfeed"
	"github.com/Hanalyx/openwatch/internal/server/api"
)

// GetNotificationFeed returns the calling user's in-app notifications (the
// bell) newest-first plus the unread count for the badge. Self-scoped — a user
// only ever sees their own rows. Spec system-notifications.
func (h *handlers) GetNotificationFeed(w http.ResponseWriter, r *http.Request, params api.GetNotificationFeedParams) {
	if h.notifyFeed == nil {
		writeError(w, http.StatusServiceUnavailable, "server.unavailable", "server", "notifications unavailable", true)
		return
	}
	uid := callerUUID(r)
	if uid == nil {
		writeError(w, http.StatusUnauthorized, "auth.required", "client", "authentication required", false)
		return
	}
	unread := params.Unread != nil && *params.Unread
	limit := 0
	if params.Limit != nil {
		limit = *params.Limit
	}
	list, err := h.notifyFeed.List(r.Context(), *uid, unread, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server", "list notifications failed", true)
		return
	}
	count, err := h.notifyFeed.UnreadCount(r.Context(), *uid)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server", "unread count failed", true)
		return
	}
	items := make([]api.NotificationFeedItem, 0, len(list))
	for _, n := range list {
		items = append(items, toAPINotification(n))
	}
	writeJSON(w, http.StatusOK, api.NotificationFeed{Items: items, UnreadCount: count})
}

// PostNotificationFeedRead marks one notification read. The store scopes the
// update to the caller, so a user can never read another user's row (404).
func (h *handlers) PostNotificationFeedRead(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	if h.notifyFeed == nil {
		writeError(w, http.StatusServiceUnavailable, "server.unavailable", "server", "notifications unavailable", true)
		return
	}
	uid := callerUUID(r)
	if uid == nil {
		writeError(w, http.StatusUnauthorized, "auth.required", "client", "authentication required", false)
		return
	}
	err := h.notifyFeed.MarkRead(r.Context(), *uid, uuid.UUID(id))
	switch {
	case errors.Is(err, notifyfeed.ErrNotFound):
		writeError(w, http.StatusNotFound, "notification.not_found", "client", "notification not found", false)
	case err != nil:
		writeError(w, http.StatusInternalServerError, "server.error", "server", "mark read failed", true)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// PostNotificationFeedReadAll marks every unread notification for the caller read.
func (h *handlers) PostNotificationFeedReadAll(w http.ResponseWriter, r *http.Request) {
	if h.notifyFeed == nil {
		writeError(w, http.StatusServiceUnavailable, "server.unavailable", "server", "notifications unavailable", true)
		return
	}
	uid := callerUUID(r)
	if uid == nil {
		writeError(w, http.StatusUnauthorized, "auth.required", "client", "authentication required", false)
		return
	}
	n, err := h.notifyFeed.MarkAllRead(r.Context(), *uid)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server", "mark all read failed", true)
		return
	}
	writeJSON(w, http.StatusOK, api.NotificationReadResult{MarkedRead: n})
}

func toAPINotification(n notifyfeed.Notification) api.NotificationFeedItem {
	item := api.NotificationFeedItem{
		Id:         openapitypes.UUID(n.ID),
		Kind:       n.Kind,
		Severity:   api.NotificationFeedItemSeverity(n.Severity),
		Title:      n.Title,
		OccurredAt: n.OccurredAt,
		Read:       n.ReadAt != nil,
	}
	if n.Body != "" {
		item.Body = &n.Body
	}
	if n.Link != "" {
		item.Link = &n.Link
	}
	if n.HostID != nil {
		hid := openapitypes.UUID(*n.HostID)
		item.HostId = &hid
	}
	return item
}
