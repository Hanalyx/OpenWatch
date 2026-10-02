// Audit attribution for handler-emitted events: who acted, and on what.
//
// Every handler event goes through one of three typed helpers, so the actor
// cannot be passed as an arbitrary string. Before this, a single
// emitAudit(r, code, actorID, detail) took the actor as a string, and
// fourteen call sites passed the id of the object they acted on, so the
// trail named a host or a user account as the actor and never the person
// (bugs/OW-099).
//
// Spec system-audit-emission C-10, C-11.
package server

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/auth"
)

// Audit actor types for request callers, from the audit taxonomy's actor
// set. A token is recorded as itself (api_key, the token's id), never as its
// owner: the owner is the accountable user, not the actor.
const (
	auditActorUser   = "user"
	auditActorAPIKey = "api_key"
)

// Audit resource types for the objects these handlers act on.
const (
	auditResourceHost       = "host"
	auditResourceCredential = "credential"
	auditResourceUser       = "user"
	auditResourceRole       = "role"
	auditResourceAuthPolicy = "auth_policy"
	auditResourceSSO        = "sso_provider"
)

// auditTarget is the object an event acted on. The zero value means the
// event has no single target.
type auditTarget struct {
	Type string
	ID   string
}

// callerAuditActor returns the request caller as an audit actor: the user
// for a session, the token itself for an API token. ok is false for an
// anonymous identity, which no caller-attributed event should have.
func callerAuditActor(id auth.Identity) (actorType, actorID string, ok bool) {
	if id.IsAnonymous || id.ID == "" {
		return "", "", false
	}
	if id.IsAPIToken {
		return auditActorAPIKey, id.ID, true
	}
	return auditActorUser, id.ID, true
}

// emitCallerAudit records an event performed by the authenticated caller on
// target. The actor comes from the request identity, never from an argument.
// An anonymous caller is recorded as anonymous rather than as a user.
func emitCallerAudit(r *http.Request, code audit.Code, target auditTarget, detail map[string]any) {
	actorType, actorID, ok := callerAuditActor(auth.FromContext(r.Context()))
	if !ok {
		actorType, actorID = "anonymous", ""
	}
	writeHandlerAudit(r, code, actorType, actorID, target, detail)
}

// emitUserAudit records an event whose actor is a known user account before
// or outside request identity binding: sign-in, sign-out and their MFA step,
// where the handler has just established who the user is.
func emitUserAudit(r *http.Request, code audit.Code, userID uuid.UUID, detail map[string]any) {
	writeHandlerAudit(r, code, auditActorUser, userID.String(),
		auditTarget{Type: auditResourceUser, ID: userID.String()}, detail)
}

// selfAuditTarget is the caller's own account, for self-service events.
func selfAuditTarget(id auth.Identity) auditTarget {
	if u, ok := id.AccountableUser(); ok {
		return auditTarget{Type: auditResourceUser, ID: u.String()}
	}
	return auditTarget{}
}

func writeHandlerAudit(r *http.Request, code audit.Code, actorType, actorID string, target auditTarget, detail map[string]any) {
	var detailBytes []byte
	if detail != nil {
		detailBytes, _ = json.Marshal(detail)
	}
	audit.Emit(r.Context(), code, audit.Event{
		ActorType:    actorType,
		ActorID:      actorID,
		ResourceType: target.Type,
		ResourceID:   target.ID,
		Detail:       detailBytes,
	})
}
