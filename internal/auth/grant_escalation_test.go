// @spec system-rbac
//
// Anti-escalation guard, custom-role behaviour.
//
//	AC-19  TestRoleGrantsWithin_FailsClosedOnUnresolvableRole
package auth

import (
	"errors"
	"testing"
)

// admin identity for the caller side of the guard.
func adminCaller() Identity  { return Identity{RoleID: RoleAdmin} }
func viewerCaller() Identity { return Identity{RoleID: RoleViewer} }

// @ac AC-19
// AC-19 (NEGATIVE PATH): the guard denies any role it cannot resolve, and
// evaluates a resolvable custom role on its real permissions.
//
// The bug this pins: RoleGrantsWithin returned true for every role missing from
// BuiltInRoles. The comment justified it as "an unknown role confers no
// permissions, so it is trivially within". That is true for a typo and false
// for a custom role, which exists and whose downstream existence check passes.
// The guard therefore waved through every custom role on both the role-assign
// and the token-mint paths. It was inert only because custom-role permissions
// are not yet enforced, which made it a latent escalation rather than a live
// one: wiring enforcement would have made every waved-through grant real.
func TestRoleGrantsWithin_FailsClosedOnUnresolvableRole(t *testing.T) {
	t.Run("system-rbac/AC-19", func(t *testing.T) {
		const custom = RoleID("delegated-role-manager")

		// No resolver: the guard cannot prove the grant is within the caller's
		// authority, so it must deny even for an admin caller.
		if RoleGrantsWithin(adminCaller(), custom) {
			t.Error("guard must DENY an unresolvable role; returning true here is the escalation")
		}
		if RoleGrantsWithinResolved(adminCaller(), custom, nil) {
			t.Error("a nil resolver must deny, not allow")
		}

		// INDETERMINATE (query failed): must deny. Failing open on a database
		// problem would be the same defect via a different route.
		broken := func(RoleID) ([]Permission, bool, error) {
			return nil, false, errors.New("connection refused")
		}
		if RoleGrantsWithinResolved(adminCaller(), custom, broken) {
			t.Error("an indeterminate resolver result must deny, not allow")
		}

		// PROVABLY ABSENT: pass through. The role confers nothing and the
		// downstream existence check returns 400 for an unknown role id.
		// Denying here would turn a client typo into an authorization error,
		// which is what the first cut of this fix did (caught by CI).
		absent := func(RoleID) ([]Permission, bool, error) { return nil, false, nil }
		if !RoleGrantsWithinResolved(adminCaller(), custom, absent) {
			t.Error("a provably absent role must pass the guard so the downstream check can 400 it")
		}

		// Resolvable custom role, permissions WITHIN the caller's own set:
		// allowed. Fail-closed must not mean "custom roles never work".
		within := func(RoleID) ([]Permission, bool, error) {
			return []Permission{HostRead}, true, nil
		}
		if !RoleGrantsWithinResolved(adminCaller(), custom, within) {
			t.Error("admin must be able to grant a custom role whose permissions admin holds")
		}

		// Resolvable custom role granting MORE than the caller holds: denied.
		// This is the case the old guard allowed.
		beyond := func(RoleID) ([]Permission, bool, error) {
			return []Permission{CredentialWrite, RemediationExecute}, true, nil
		}
		if RoleGrantsWithinResolved(viewerCaller(), custom, beyond) {
			t.Error("a viewer must not be able to grant credential:write + remediation:execute via a custom role")
		}

		// Built-in roles keep working, resolver or not.
		if !RoleGrantsWithinResolved(adminCaller(), RoleViewer, nil) {
			t.Error("admin must still be able to grant a built-in role that is a subset of admin")
		}
		if RoleGrantsWithinResolved(viewerCaller(), RoleAdmin, nil) {
			t.Error("a viewer must never be able to grant admin")
		}
	})
}

// @ac AC-20
// AC-20: PermissionsWithin names exactly the permissions the caller lacks. It
// backs the custom-role AUTHORING check, which is the other half of the fix:
// blocking the assign step alone still lets a caller author an over-broad role
// and wait for someone else to assign it.
func TestPermissionsWithin_NamesWhatTheCallerLacks(t *testing.T) {
	t.Run("system-rbac/AC-20", func(t *testing.T) {
		if missing := PermissionsWithin(adminCaller(), []Permission{HostRead}); len(missing) != 0 {
			t.Errorf("admin holds host:read; got missing=%v", missing)
		}
		missing := PermissionsWithin(viewerCaller(), []Permission{HostRead, CredentialWrite})
		if len(missing) != 1 || missing[0] != CredentialWrite {
			t.Errorf("viewer lacks exactly credential:write; got %v", missing)
		}
		// Anonymous holds nothing.
		anon := Identity{IsAnonymous: true}
		if got := PermissionsWithin(anon, []Permission{HostRead}); len(got) != 1 {
			t.Errorf("anonymous must lack every permission; got %v", got)
		}
	})
}
