// Per-user UI preferences HTTP surface. Self-scoped: every authenticated
// identity reads and updates ONLY its own preferences (the user id comes
// from the session/bearer identity, never from a path param), so there is
// no RBAC permission to check beyond "is authenticated". Spec:
// system-user-preferences.

package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/server/api"
	"github.com/Hanalyx/openwatch/internal/userpref"
)

// meUserID resolves the calling identity to an active user UUID, writing a
// 401 and returning ok=false when the caller is anonymous or carries a
// malformed id. Mirrors GetAuthMe's guard.
func (h *handlers) meUserID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id := auth.FromContext(r.Context())
	if id.IsAnonymous {
		writeError(w, http.StatusUnauthorized, "auth.required", "client",
			"authentication required", false)
		return uuid.Nil, false
	}
	userID, err := uuid.Parse(id.ID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "auth.required", "client",
			"identity id is not a UUID", false)
		return uuid.Nil, false
	}
	return userID, true
}

// GetUsersMePreferences returns the caller's stored UI preferences.
// Spec system-user-preferences AC-01.
func (h *handlers) GetUsersMePreferences(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.meUserID(w, r)
	if !ok {
		return
	}
	if h.userPrefSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "server.unavailable", "server",
			"preferences service not configured", true)
		return
	}
	raw, err := h.userPrefSvc.Get(r.Context(), userID)
	if err != nil {
		if errors.Is(err, userpref.ErrUserNotFound) {
			writeError(w, http.StatusUnauthorized, "auth.required", "client",
				"identity user not found", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"read preferences failed", true)
		return
	}
	// Project the stored blob through the typed contract so only known keys
	// surface (additionalProperties:false), dropping any legacy junk.
	var prefs api.UserPreferences
	if err := json.Unmarshal(raw, &prefs); err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"stored preferences are malformed", true)
		return
	}
	writeJSON(w, http.StatusOK, prefs)
}

// PatchUsersMePreferences shallow-merges the provided keys into the
// caller's preferences and returns the merged result. Only known,
// well-typed keys are merged — unknown keys are dropped at decode, invalid
// enum values are rejected 400. Spec system-user-preferences AC-02, AC-03, AC-04.
func (h *handlers) PatchUsersMePreferences(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.meUserID(w, r)
	if !ok {
		return
	}
	if h.userPrefSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "server.unavailable", "server",
			"preferences service not configured", true)
		return
	}
	var body api.UserPreferences
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "validation.invalid_body", "client",
			"preferences body is not valid JSON", false)
		return
	}
	if msg, valid := validateUserPrefs(body); !valid {
		writeError(w, http.StatusBadRequest, "validation.invalid_value", "client", msg, false)
		return
	}
	// Re-marshal the typed struct: every field is a pointer with omitempty,
	// so the patch carries exactly the keys the caller supplied — never a
	// full overwrite of unset keys.
	patch, err := json.Marshal(body)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"encode patch failed", true)
		return
	}
	merged, err := h.userPrefSvc.Merge(r.Context(), userID, patch)
	if err != nil {
		if errors.Is(err, userpref.ErrUserNotFound) {
			writeError(w, http.StatusUnauthorized, "auth.required", "client",
				"identity user not found", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"merge preferences failed", true)
		return
	}
	var prefs api.UserPreferences
	if err := json.Unmarshal(merged, &prefs); err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"stored preferences are malformed", true)
		return
	}
	writeJSON(w, http.StatusOK, prefs)
}

// validateUserPrefs checks each present field against its allowed enum
// set. The generated typed string fields do not self-validate at decode,
// so an out-of-range value (e.g. hosts_view_default:"weird") would
// otherwise persist. Returns (message, false) on the first invalid field.
func validateUserPrefs(p api.UserPreferences) (string, bool) {
	if v := p.HostsViewDefault; v != nil && *v != api.Table && *v != api.Cards {
		return "hosts_view_default must be 'table' or 'cards'", false
	}
	if v := p.Density; v != nil && *v != api.Comfortable && *v != api.Compact {
		return "density must be 'comfortable' or 'compact'", false
	}
	if v := p.AccentColor; v != nil && *v != api.UserPreferencesAccentColorInfo &&
		*v != api.UserPreferencesAccentColorOk && *v != api.UserPreferencesAccentColorBrand2 {
		return "accent_color must be 'info', 'ok', or 'brand2'", false
	}
	if v := p.LandingPage; v != nil && *v != api.Hosts && *v != api.Dashboard && *v != api.Reports {
		return "landing_page must be 'hosts', 'dashboard', or 'reports'", false
	}
	if v := p.DateFormat; v != nil && *v != api.Us12 && *v != api.Iso24 && *v != api.Long24 {
		return "date_format must be 'us12', 'iso24', or 'long24'", false
	}
	return "", true
}
