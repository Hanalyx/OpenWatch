package sso

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// ProvisionFunc creates a local user for a first-time federated sign-in and
// returns its id. Injected by the server layer so this package never
// depends on the users service. role is the provider's default_role.
type ProvisionFunc func(ctx context.Context, username, email, role string) (uuid.UUID, error)

// CallbackResult is what the handler needs to finish login: the local user
// to issue a session for and where to send them.
type CallbackResult struct {
	UserID      uuid.UUID
	RedirectTo  string
	Provisioned bool
}

// HandleCallback runs the whole callback: consume the one-time state,
// exchange + validate the ID token, then map the federated identity to a
// local user (linking an existing one or provisioning a new one). It never
// issues the session itself — that stays in the handler, which owns the
// HTTP response.
//
// Spec system-sso AC-05, AC-06, AC-08.
func (s *Service) HandleCallback(ctx context.Context, state, redirectURI, code string, provision ProvisionFunc) (CallbackResult, error) {
	st, err := s.consumeAuthState(ctx, state)
	if err != nil {
		return CallbackResult{}, err
	}
	cfg, err := s.getConfig(ctx, st.ProviderID)
	if err != nil {
		return CallbackResult{}, err
	}
	claims, err := s.Exchange(ctx, st, redirectURI, code)
	if err != nil {
		return CallbackResult{}, err
	}

	// Existing federation link → reuse the user, but only if that user
	// may still sign in. Without this an account an administrator
	// disabled signs straight back in through SSO and receives a working
	// session: the link outlives the disable, and a soft delete never
	// fires the ON DELETE CASCADE because it is an UPDATE.
	// Reproduced 2026-09-23 as bugs/OW-073.
	//
	// Refusing here rather than filtering the row out of the query is
	// deliberate: a filtered query reports "no link" and the code below
	// would provision a SECOND user for a subject that already has one.
	if uid, found, state, err := s.linkedUserState(ctx, st.ProviderID, claims.Subject); err != nil {
		return CallbackResult{}, err
	} else if found && !state.MaySignIn() {
		return CallbackResult{}, &AccountNotActiveError{State: state}
	} else if found {
		return CallbackResult{UserID: uid, RedirectTo: st.RedirectTo}, nil
	}

	// First sign-in → provision a local user and record the link.
	uid, err := provision(ctx, deriveUsername(claims), claims.Email, cfg.DefaultRole)
	if err != nil {
		return CallbackResult{}, err
	}
	if err := s.link(ctx, st.ProviderID, claims.Subject, uid); err != nil {
		return CallbackResult{}, err
	}
	return CallbackResult{UserID: uid, RedirectTo: st.RedirectTo, Provisioned: true}, nil
}

// deriveUsername picks a stable, human-recognizable username for a newly
// provisioned user: email, else preferred_username, else a sub-derived
// fallback. Uniqueness is enforced by the DB; a collision surfaces as a
// provisioning error.
func deriveUsername(c Claims) string {
	if e := strings.TrimSpace(c.Email); e != "" {
		return e
	}
	if u := strings.TrimSpace(c.PreferredUsername); u != "" {
		return u
	}
	sub := c.Subject
	if len(sub) > 12 {
		sub = sub[:12]
	}
	return fmt.Sprintf("sso-%s", sub)
}
