package auth

import (
	"encoding/json"
	"net/http"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/correlation"
	"github.com/Hanalyx/openwatch/internal/license"
)

// EnforcePermission performs the same RBAC + license-gate check as
// RequirePermission but as a function callable inside an oapi-codegen-
// generated handler. Returns true if the response is already written
// (the handler should return immediately).
func EnforcePermission(w http.ResponseWriter, r *http.Request, p Permission) (denied bool) {
	id := FromContext(r.Context())
	if !id.HasPermission(p) {
		denyPermission(w, r, p, id)
		return true
	}
	if feature := LicenseGate(p); feature != "" {
		if !license.IsEnabled(license.Feature(feature)) {
			denyLicense(w, r, license.Feature(feature))
			return true
		}
	}
	return false
}

// RequirePermission returns a chi middleware that enforces both RBAC and
// the license gate for the given permission in one pass. The check order is:
//
//  1. Identity has p? If not → 403 authz.permission_denied. RBAC always
//     fails first; never leak the license gate to a caller who lacks the
//     permission anyway.
//  2. p is license-gated and the feature is not enabled? → 402
//     license.feature_unavailable.
//  3. Otherwise the inner handler runs.
//
// Spec system-rbac AC-08, AC-09, AC-10, AC-11.
func RequirePermission(p Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := FromContext(r.Context())
			if !id.HasPermission(p) {
				denyPermission(w, r, p, id)
				return
			}
			// License gate (if applicable). The feature id comes from the
			// registry; runtime lookup is O(1).
			if feature := LicenseGate(p); feature != "" {
				if !license.IsEnabled(license.Feature(feature)) {
					denyLicense(w, r, license.Feature(feature))
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// denyPermission writes the canonical 403 envelope and emits the
// authz.permission_denied audit event with detail.required_permission
// set to the permission id. Per system-rbac AC-09 + AC-11 + C-04.
func denyPermission(w http.ResponseWriter, r *http.Request, p Permission, id Identity) {
	errBody := map[string]any{
		"code":          "authz.permission_denied",
		"fault":         "policy",
		"retryable":     false,
		"human_message": "this operation requires a permission your role does not grant",
		"detail": map[string]any{
			"required_permission": string(p),
		},
	}
	if cid, ok := correlation.From(r.Context()); ok {
		errBody["correlation_id"] = cid
	}
	envelope := map[string]any{"error": errBody}
	body, _ := json.Marshal(envelope)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(body)

	actorID := id.ID
	if actorID == "" {
		actorID = "anonymous"
	}
	detail, _ := json.Marshal(map[string]any{
		"required_permission": string(p),
		"actor_role":          string(id.RoleID),
	})
	audit.Emit(r.Context(), audit.AuthzPermissionDenied, audit.Event{
		ActorType: "user",
		ActorID:   actorID,
		Detail:    detail,
	})
}

// denyLicense reuses the license package's deny path so the envelope is
// produced once. Audit emission is handled inside the license package.
//
// Per system-rbac AC-10 + C-05: the audit code is license.feature_check_denied,
// NOT authz.permission_denied — RBAC passed; this is a separate denial class.
func denyLicense(w http.ResponseWriter, r *http.Request, f license.Feature) {
	license.DenyFeature(w, r, f)
}
