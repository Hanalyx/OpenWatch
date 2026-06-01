package collector

// Code is a single OS Intelligence event code in the closed taxonomy.
// Three-segment dotted: category.subcategory.action.
//
// Spec: app/specs/system/os-intelligence.spec.yaml C-05.
//
// Adding a new code requires:
//
//  1. Add the const here AND append to taxonomyCodes.
//  2. Add the matching entry to app/audit/events.yaml + regenerate
//     internal/audit/events.gen.go.
//  3. Add the literal to the CHECK constraint in
//     internal/db/migrations/0018_host_intelligence.sql via a follow-up
//     migration.
//  4. Wire the detection in the Diff engine.
//
// This list is the SSOT for runtime validation; the audit codegen +
// the DB CHECK enforce structural alignment at PR review time.
type Code string

// Account / identity codes.
const (
	CodeAccountUserLocked             Code = "account.user.locked"
	CodeAccountUserUnlocked           Code = "account.user.unlocked"
	CodeAccountUserCreated            Code = "account.user.created"
	CodeAccountUserDeleted            Code = "account.user.deleted"
	CodeAccountUserPrivilegedGroupAdd Code = "account.user.privileged_group_added"
	CodeAccountPasswordExpired        Code = "account.password.expired"
	CodeAccountPasswordExpiring       Code = "account.password.expiring"
	CodeAccountSSHKeyAdded            Code = "account.ssh_key.added"
	CodeAccountSSHKeyRemoved          Code = "account.ssh_key.removed"
	CodeAccountSudoFailureThreshold   Code = "account.sudo.failure_threshold"
)

// Security codes.
const (
	CodeSecurityLoginNewSourceIP     Code = "security.login.new_source_ip"
	CodeSecurityLoginFailedThreshold Code = "security.login.failed_threshold"
	CodeSecuritySELinuxDenied        Code = "security.selinux.denied"
	CodeSecurityAppArmorDenied       Code = "security.apparmor.denied"
	CodeSecurityFirewallRuleChanged  Code = "security.firewall.rule_changed"
	CodeSecurityPortOpened           Code = "security.port.opened"
)

// System codes.
const (
	CodeSystemPackageInstalled    Code = "system.package.installed"
	CodeSystemPackageUpdated      Code = "system.package.updated"
	CodeSystemPackageRemoved      Code = "system.package.removed"
	CodeSystemKernelUpdated       Code = "system.kernel.updated"
	CodeSystemRebootRequired      Code = "system.reboot.required"
	CodeSystemRebootCompleted     Code = "system.reboot.completed"
	CodeSystemConfigChanged       Code = "system.config.file_changed"
	CodeSystemServiceStarted      Code = "system.service.started"
	CodeSystemServiceStopped      Code = "system.service.stopped"
	CodeSystemServiceFailed       Code = "system.service.failed"
	CodeSystemFilesystemMounted   Code = "system.filesystem.mounted"
	CodeSystemFilesystemUnmounted Code = "system.filesystem.unmounted"
)

// taxonomyCodes is the registration-order list. Code-correctness checks
// derive their input from this slice.
var taxonomyCodes = []Code{
	CodeAccountUserLocked,
	CodeAccountUserUnlocked,
	CodeAccountUserCreated,
	CodeAccountUserDeleted,
	CodeAccountUserPrivilegedGroupAdd,
	CodeAccountPasswordExpired,
	CodeAccountPasswordExpiring,
	CodeAccountSSHKeyAdded,
	CodeAccountSSHKeyRemoved,
	CodeAccountSudoFailureThreshold,

	CodeSecurityLoginNewSourceIP,
	CodeSecurityLoginFailedThreshold,
	CodeSecuritySELinuxDenied,
	CodeSecurityAppArmorDenied,
	CodeSecurityFirewallRuleChanged,
	CodeSecurityPortOpened,

	CodeSystemPackageInstalled,
	CodeSystemPackageUpdated,
	CodeSystemPackageRemoved,
	CodeSystemKernelUpdated,
	CodeSystemRebootRequired,
	CodeSystemRebootCompleted,
	CodeSystemConfigChanged,
	CodeSystemServiceStarted,
	CodeSystemServiceStopped,
	CodeSystemServiceFailed,
	CodeSystemFilesystemMounted,
	CodeSystemFilesystemUnmounted,
}

// Codes returns a defensive copy of every code in the closed taxonomy.
// Used by tests (AC-01, AC-02) and by future scheduler / API code that
// needs to iterate the closed set.
func Codes() []Code {
	out := make([]Code, len(taxonomyCodes))
	copy(out, taxonomyCodes)
	return out
}

// IsKnown reports whether the given string is a valid taxonomy code.
// Use at boundaries that receive a code value from untrusted sources.
func IsKnown(s string) bool {
	for _, c := range taxonomyCodes {
		if string(c) == s {
			return true
		}
	}
	return false
}
