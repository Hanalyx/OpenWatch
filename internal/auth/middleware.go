package auth

import (
	"encoding/json"
	"net/http"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/correlation"
)

// EnforcePermission performs the same RBAC check as RequirePermission but
// as a function callable inside an oapi-codegen-generated handler. Returns
// true if the response is already written (the handler should return
// immediately).
//
// This checks RBAC only. Entitlement is a separate, later check: a handler
// that also needs a paid feature calls license.EnforceFeature after this
// returns false. Keeping the two apart is what lets one permission cover
// both a free per-host route and a paid fleet-scale route.
func EnforcePermission(w http.ResponseWriter, r *http.Request, p Permission) (denied bool) {
	id := FromContext(r.Context())
	if !id.HasPermission(p) {
		denyPermission(w, r, p, id)
		return true
	}
	return false
}

// RequirePermission returns a chi middleware that enforces RBAC for the
// given permission. The check order is:
//
//  1. Identity has p? If not → 401 auth.required for an anonymous caller,
//     403 authz.permission_denied for an authenticated one.
//  2. Otherwise the inner handler runs.
//
// There is no license stage here. A route that needs an entitlement declares
// x-required-feature in api/openapi.yaml and its handler calls
// license.EnforceFeature, which produces the 402. RBAC still fails first,
// because the handler cannot run until this middleware passes. Never leak
// the entitlement state to a caller who lacks the permission anyway.
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
			next.ServeHTTP(w, r)
		})
	}
}

// denyPermission writes the RBAC denial envelope and emits the
// authz.permission_denied audit event with detail.required_permission
// set to the permission id. Per system-rbac AC-09 + AC-11 + C-04.
//
// The HTTP status distinguishes the two denial classes so the SPA can react
// correctly: an ANONYMOUS caller (no or expired credentials — the request
// arrived without a usable session) gets 401 auth.required so the client
// redirects to login; an AUTHENTICATED caller whose role lacks the permission
// gets 403 authz.permission_denied. The audit record is identical either way —
// a denial is a denial.
func denyPermission(w http.ResponseWriter, r *http.Request, p Permission, id Identity) {
	status, code, fault, msg := http.StatusForbidden, "authz.permission_denied", "policy",
		"this operation requires a permission your role does not grant"
	if id.IsAnonymous {
		status, code, fault, msg = http.StatusUnauthorized, "auth.required", "client",
			"authentication required; sign in to continue"
	}
	errBody := map[string]any{
		"code":          code,
		"fault":         fault,
		"retryable":     false,
		"human_message": msg,
		"detail": map[string]any{
			"required_permission": string(p),
		},
	}
	if cid, ok := correlation.From(r.Context()); ok {
		errBody["correlation_id"] = cid
	}
	envelope := map[string]any{"error": errBody}
	body, _ := json.Marshal(envelope)
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
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
