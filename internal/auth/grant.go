package auth

// RoleResolver answers what a non-built-in role confers. It exists so the
// anti-escalation guard can evaluate a CUSTOM role (whose permission set lives
// in the roles table) without internal/auth importing a database layer.
//
// The three states are distinct and the distinction is load-bearing:
//
//	found=true,  err=nil  the role exists; perms is its permission set
//	found=false, err=nil  the role PROVABLY does not exist
//	err != nil            cannot determine (query failed, service missing)
//
// "Provably absent" and "cannot determine" must never be collapsed. An absent
// role confers nothing and is rejected downstream as bad input, so the guard
// lets it through to produce the correct 400. An indeterminate answer is a
// denial, because the guard cannot show the grant is within the caller's
// authority.
type RoleResolver func(RoleID) (perms []Permission, found bool, err error)

// RoleGrantsWithin reports whether every permission conferred by the
// requested role is also held by the caller. It is the anti-privilege-
// escalation primitive: a caller may never grant, via an API token, a
// role assignment, or a custom role, a permission they do not themselves
// hold.
//
// It resolves BUILT-IN roles only, and DENIES anything else.
//
// This function previously returned true (allow) for any role missing from
// BuiltInRoles, on the reasoning that an unknown role confers nothing and a
// downstream existence check would reject it. That reasoning does not hold for
// custom roles: they exist, they are not in BuiltInRoles, and the downstream
// check accepts them. The guard therefore passed for every custom role, which
// is fail-open on the one code path whose entire job is to fail closed.
//
// Prefer [RoleGrantsWithinResolved] wherever custom roles are legitimate, so a
// real custom role is checked on its actual permissions rather than refused.
func RoleGrantsWithin(caller Identity, requested RoleID) bool {
	return RoleGrantsWithinResolved(caller, requested, nil)
}

// RoleGrantsWithinResolved is RoleGrantsWithin with custom-role support.
// resolve supplies the permission set for a role that is not built in; a nil
// resolver, or a resolver reporting the role unknown, DENIES.
//
// Fail-closed is deliberate and load-bearing here. The alternative, treating
// an unresolvable role as harmless because nothing currently enforces its
// permissions, is what made this a latent escalation: the day custom-role
// enforcement is wired, every previously-waved-through grant becomes real.
func RoleGrantsWithinResolved(caller Identity, requested RoleID, resolve RoleResolver) bool {
	if def, ok := BuiltInRoles[requested]; ok {
		return holdsAll(caller, def.Permissions)
	}
	if resolve == nil {
		// No way to evaluate a non-built-in role. Deny.
		return false
	}
	perms, found, err := resolve(requested)
	switch {
	case err != nil:
		// Cannot determine. Deny rather than guess; failing open on a
		// database fault would be the same defect by another route.
		return false
	case !found:
		// Provably absent. It confers nothing and the downstream existence
		// check rejects it as bad input, which is the correct response for a
		// role id that does not exist. Denying here instead would turn a
		// client typo into an authorization error.
		return true
	default:
		return holdsAll(caller, perms)
	}
}

func holdsAll(caller Identity, perms []Permission) bool {
	for _, p := range perms {
		if !caller.HasPermission(p) {
			return false
		}
	}
	return true
}

// PermissionsWithin reports whether every permission in requested is held by
// the caller. It is the same subset rule as RoleGrantsWithin applied to a raw
// permission list, for the custom-role CREATION path: a caller must not be
// able to author a role granting more than they themselves hold, since
// authoring it and then assigning it is a two-step escalation that neither
// step alone would catch.
//
// Returns the permissions the caller lacks, so the API can name them.
func PermissionsWithin(caller Identity, requested []Permission) []Permission {
	var missing []Permission
	for _, p := range requested {
		if !caller.HasPermission(p) {
			missing = append(missing, p)
		}
	}
	return missing
}

// RolesWithPermission returns the built-in role IDs whose definition grants p,
// in declaration order. It is the recipient-resolution primitive for
// permission-scoped fan-out (e.g. "every role that can approve an exception"):
// callers translate a permission into the set of roles, then query user_roles
// for the holders. An unknown/empty permission yields no roles.
func RolesWithPermission(p Permission) []RoleID {
	var out []RoleID
	for _, id := range BuiltInRoleIDs() {
		def := BuiltInRoles[id]
		for _, granted := range def.Permissions {
			if granted == p {
				out = append(out, id)
				break
			}
		}
	}
	return out
}
