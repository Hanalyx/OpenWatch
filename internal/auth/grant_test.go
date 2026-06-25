package auth

import (
	"sort"
	"testing"
)

func roleSet(ids []RoleID) map[RoleID]bool {
	m := make(map[RoleID]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	return m
}

func TestRolesWithPermission(t *testing.T) {
	cases := []struct {
		perm Permission
		want []RoleID
	}{
		// exception:approve is held by the auditor (review role) and the two
		// security roles — but NOT ops_lead (who can only request).
		{ExceptionApprove, []RoleID{RoleAuditor, RoleSecurityAdmin, RoleAdmin}},
		// remediation:execute is held by the operator tier and up.
		{RemediationExecute, []RoleID{RoleOpsLead, RoleSecurityAdmin, RoleAdmin}},
		// host:read is universal across the five built-in roles.
		{HostRead, []RoleID{RoleViewer, RoleAuditor, RoleOpsLead, RoleSecurityAdmin, RoleAdmin}},
		// admin-only verb.
		{SystemConfigWrite, []RoleID{RoleAdmin}},
	}
	for _, c := range cases {
		got := roleSet(RolesWithPermission(c.perm))
		want := roleSet(c.want)
		if len(got) != len(want) {
			t.Errorf("RolesWithPermission(%s): got %v, want %v", c.perm, sortedRoles(got), c.want)
			continue
		}
		for r := range want {
			if !got[r] {
				t.Errorf("RolesWithPermission(%s): missing %s (got %v)", c.perm, r, sortedRoles(got))
			}
		}
	}

	// An unknown permission yields no roles.
	if got := RolesWithPermission(Permission("does:not_exist")); len(got) != 0 {
		t.Errorf("unknown permission must yield no roles, got %v", got)
	}
}

func sortedRoles(m map[RoleID]bool) []RoleID {
	out := make([]RoleID, 0, len(m))
	for r := range m {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
