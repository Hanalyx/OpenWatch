package auth

// RoleGrantsWithin reports whether every permission conferred by the
// requested role is also held by the caller. It is the anti-privilege-
// escalation primitive: a caller may never grant — via an API token, a
// role assignment, or a custom role — a permission they do not themselves
// hold.
//
// An unknown requested role confers no permissions (BuiltInRoles miss), so
// it is trivially "within"; the caller's downstream existence check rejects
// it on its own. Returns false as soon as one required permission is not
// held by the caller.
func RoleGrantsWithin(caller Identity, requested RoleID) bool {
	def, ok := BuiltInRoles[requested]
	if !ok {
		return true
	}
	for _, p := range def.Permissions {
		if !caller.HasPermission(p) {
			return false
		}
	}
	return true
}
