// Package auth provides RBAC: a codegen-typed permission registry,
// built-in roles, and the RequirePermission middleware that combines RBAC
// and license-gate checks in one pass.
//
// Identity binding is performed by the internal/identity package's
// production binder (session cookie + Bearer JWT). This package owns
// only the Identity shape and the permission-enforcement logic.
package auth

import (
	"context"
)

// Identity is the calling user's identity carried on the request context.
// Bound by the production identity binder (session cookie or Bearer JWT)
// — see internal/identity/binder.go.
type Identity struct {
	// ID is a stable string identifier for the calling principal. Stage 0
	// uses the role name itself; Stage 2 uses the user/account UUID.
	ID string

	// RoleID is the built-in role granting the effective permissions. Stage 2
	// replaces this with a union of roles, but the spec only requires a
	// single role concept for Day 8.
	RoleID RoleID

	// IsAnonymous is true when no role was bound. The middleware uses this
	// to short-circuit the permission lookup; an anonymous identity has
	// no permissions.
	IsAnonymous bool

	// Grants is the stored permission set of a CUSTOM role (one that
	// BuiltInRoles does not resolve), attached by the identity binder at
	// bind time from the roles table. It is consulted only when RoleID is
	// not built in; a built-in role's permissions come from the registry
	// and Grants is ignored. nil means "nothing resolved": a custom role
	// that is absent or whose lookup failed binds with no permissions.
	//
	// Spec system-rbac C-11.
	Grants []Permission
}

// grants returns the permission list this identity's role confers: the
// registry entry for a built-in role, the bound Grants for a custom one,
// nil for anonymous. Spec system-rbac AC-05, C-11.
func (i Identity) grants() []Permission {
	if i.IsAnonymous {
		return nil
	}
	if role, ok := BuiltInRoles[i.RoleID]; ok {
		return role.Permissions
	}
	return i.Grants
}

// HasPermission returns true iff this identity's role grants p.
// Anonymous identities have no permissions.
//
// Spec system-rbac AC-05.
func (i Identity) HasPermission(p Permission) bool {
	for _, granted := range i.grants() {
		if granted == p {
			return true
		}
	}
	return false
}

// Permissions returns the effective permission list for this identity in
// registry order. Empty slice for anonymous.
//
// Spec system-rbac AC-13.
func (i Identity) Permissions() []Permission {
	src := i.grants()
	if src == nil {
		return nil
	}
	out := make([]Permission, len(src))
	copy(out, src)
	return out
}

type ctxKey struct{}

// SetIdentity returns a derived context with the identity attached.
func SetIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// FromContext returns the Identity bound on the context, or an anonymous
// Identity if none is set.
func FromContext(ctx context.Context) Identity {
	if v, ok := ctx.Value(ctxKey{}).(Identity); ok {
		return v
	}
	return Identity{IsAnonymous: true}
}
