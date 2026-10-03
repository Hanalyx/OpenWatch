package audit

// Actor types a request can be attributed to, from the audit taxonomy's
// actor set. A token is recorded as itself (ActorAPIKey and the token's
// id), never as its owner: the owner is the accountable user, not the
// actor. Spec system-audit-emission C-12; bugs/OW-100.
const (
	ActorUser      = "user"
	ActorAPIKey    = "api_key"
	ActorSystem    = "system"
	ActorAnonymous = "anonymous"
)

// Actor is who performed an audited action: a type from the set above and
// the principal's id. It travels separately from any accountable user a
// service records in its own columns, so a service can store a token's
// owner as requester or reviewer while the audit trail still names the
// token. The zero value is not a valid actor; use one of the constructors.
type Actor struct {
	Type string
	ID   string
}

// SystemActor is work the system performs on its own (expiry, scheduled
// jobs), with no request principal.
func SystemActor() Actor { return Actor{Type: ActorSystem} }

// AnonymousActor is an unauthenticated caller.
func AnonymousActor() Actor { return Actor{Type: ActorAnonymous} }

// Set writes the actor onto ev. An empty Type falls back to anonymous, so
// an unset actor is never recorded as a user.
func (a Actor) Set(ev *Event) {
	if a.Type == "" {
		a = AnonymousActor()
	}
	ev.ActorType = a.Type
	ev.ActorID = a.ID
}
