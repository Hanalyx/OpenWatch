package activity

import (
	"encoding/json"
	"strings"
)

// Human-readable rendering for the three feed legs that otherwise emit raw
// machine codes as their title (compliance/transactions, intelligence, and
// audit). The alert and monitoring legs already build sentences in SQL and
// are left untouched. Spec system-activity v1.2.0 (C-09).
//
// Every formatter degrades gracefully: an unmapped code is humanized
// structurally (dots/underscores -> spaces, capitalized) so a new event
// code can never leak to the UI as a raw dotted enum.

// RuleTitleFunc resolves a Kensa rule id to its catalog title. Injected by
// the server from the rule catalog so this package takes no kensa
// dependency. Nil-safe: a nil func (or a miss) falls back to the rule id.
type RuleTitleFunc func(ruleID string) (title string, ok bool)

// formatTransaction renders a compliance state-change row. The transactions
// table records the NEW status + the change_kind (it does not retain the
// prior status), so the summary says "now <Status>", never "X -> Y".
func formatTransaction(ruleID, status, changeKind string, titler RuleTitleFunc) (title, summary string) {
	title = ruleID
	if titler != nil {
		if t, ok := titler(ruleID); ok && t != "" {
			title = t
		}
	}
	st := statusWord(status)
	switch changeKind {
	case "first_seen":
		summary = "First seen: " + st
	case "severity_changed":
		summary = "Severity changed (now " + st + ")"
	case "state_changed":
		summary = "Changed: now " + st
	default:
		summary = st
	}
	return title, summary
}

// formatIntelligence renders an OS-intelligence diff row. The title comes
// from the event-code registry (or the humanized code); the summary is
// extracted generically from the detail JSONB (subject + optional from->to).
func formatIntelligence(eventCode string, detail []byte) (title, summary string) {
	title = intelTitles[eventCode]
	if title == "" {
		title = humanizeCode(eventCode)
	}
	return title, intelSummary(detail)
}

// FormatAudit renders an audit row as "<actor> <predicate>". The actor is
// the recorded actor_label, falling back to a readable actor_type. The raw
// resource_id (a UUID) is intentionally NOT placed in the title; the
// resource_type provides lightweight context in the summary.
func FormatAudit(action, actorLabel, actorType, resourceType string) (title, summary string) {
	actor := strings.TrimSpace(actorLabel)
	if actor == "" {
		actor = actorWord(actorType)
	}
	pred, ok := auditPredicates[action]
	if !ok {
		pred = strings.ToLower(humanizeCode(action))
	}
	title = actor + " " + pred
	if resourceType != "" {
		summary = titleCaseWord(resourceType)
	}
	return title, summary
}

// ---- helpers ----

func statusWord(status string) string {
	switch status {
	case "pass":
		return "Pass"
	case "fail":
		return "Fail"
	case "skipped":
		return "Skipped"
	case "error":
		return "Error"
	default:
		return titleCaseWord(status)
	}
}

// actorWord renders a readable actor when no actor_label was recorded. An
// empty/unknown actor_type means the event was NOT attributed to a person
// (real user actions record the user) — so it reads as automated ("The
// system"), never the misleading "Someone".
func actorWord(actorType string) string {
	switch actorType {
	case "system", "":
		return "The system"
	case "scheduler":
		return "The scheduler"
	case "api_key", "api_token":
		return "An API token"
	case "agent":
		return "An agent"
	case "user":
		return "A user"
	default:
		return titleCaseWord(actorType)
	}
}

// humanizeCode turns a dotted/underscored code into a capitalized phrase
// ("account.user.created" -> "Account user created"). The safety net that
// guarantees no raw code ever reaches the UI.
func humanizeCode(code string) string {
	s := strings.TrimSpace(strings.NewReplacer(".", " ", "_", " ", "-", " ").Replace(code))
	if s == "" {
		return "Activity"
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// titleCaseWord capitalizes a single token, replacing separators with
// spaces ("scan_template" -> "Scan template").
func titleCaseWord(w string) string {
	s := strings.TrimSpace(strings.NewReplacer("_", " ", "-", " ").Replace(w))
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// intelSummary builds a concise phrase from an intelligence event's detail
// JSONB: a subject (the first present of a set of common keys) plus an
// optional "from -> to" transition. Returns "" when nothing useful is found.
func intelSummary(detail []byte) string {
	if len(detail) == 0 {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(detail, &m); err != nil {
		return ""
	}
	subject := firstStringField(m, "name", "package", "service", "unit",
		"username", "user", "account", "path", "file", "interface", "port", "rule")
	from := stringField(m["from"])
	to := stringField(m["to"])
	switch {
	case subject != "" && from != "" && to != "":
		return subject + ": " + from + " → " + to
	case subject != "" && to != "":
		return subject + " → " + to
	case subject != "":
		return subject
	case from != "" && to != "":
		return from + " → " + to
	default:
		return ""
	}
}

func firstStringField(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s := stringField(v); s != "" {
				return s
			}
		}
	}
	return ""
}

// stringField renders a JSON scalar as a short string. Non-scalars (objects,
// arrays) return "" so they never dump structure into a summary line.
func stringField(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		// Integers render without a trailing ".0"; keep it simple.
		if t == float64(int64(t)) {
			return itoa64(int64(t))
		}
		b, _ := json.Marshal(t)
		return string(b)
	default:
		return ""
	}
}

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [24]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// intelTitles maps each host_intelligence_events.event_code to a readable
// headline. Unmapped codes fall back to humanizeCode.
var intelTitles = map[string]string{
	"account.user.locked":                 "User account locked",
	"account.user.unlocked":               "User account unlocked",
	"account.user.created":                "User account created",
	"account.user.deleted":                "User account deleted",
	"account.user.privileged_group_added": "User added to a privileged group",
	"account.password.expired":            "Password expired",
	"account.password.expiring":           "Password expiring soon",
	"account.ssh_key.added":               "SSH key added",
	"account.ssh_key.removed":             "SSH key removed",
	"account.sudo.failure_threshold":      "Repeated sudo failures",
	"security.login.new_source_ip":        "Login from a new source IP",
	"security.login.failed_threshold":     "Repeated failed logins",
	"security.selinux.denied":             "SELinux denial",
	"security.apparmor.denied":            "AppArmor denial",
	"security.firewall.rule_changed":      "Firewall rule changed",
	"security.port.opened":                "Network port opened",
	"system.package.installed":            "Package installed",
	"system.package.updated":              "Package updated",
	"system.package.removed":              "Package removed",
	"system.kernel.updated":               "Kernel updated",
	"system.reboot.required":              "Reboot required",
	"system.reboot.completed":             "Reboot completed",
	"system.config.file_changed":          "Config file changed",
	"system.service.started":              "Service started",
	"system.service.stopped":              "Service stopped",
	"system.service.failed":               "Service failed",
	"system.filesystem.mounted":           "Filesystem mounted",
	"system.filesystem.unmounted":         "Filesystem unmounted",
}

// auditPredicates maps each audit action code to a verb phrase that reads
// naturally after the actor ("<actor> <predicate>"). Unmapped codes fall
// back to a lowercased humanizeCode.
var auditPredicates = map[string]string{
	// auth
	"auth.login.success":          "signed in",
	"auth.login.failure":          "failed to sign in",
	"auth.logout":                 "signed out",
	"auth.token.issued":           "was issued a token",
	"auth.token.refreshed":        "refreshed a token",
	"auth.token.revoked":          "revoked a token",
	"auth.mfa.enrolled":           "enrolled in MFA",
	"auth.mfa.validated":          "passed MFA",
	"auth.mfa.failed":             "failed MFA",
	"auth.mfa.disabled":           "disabled MFA",
	"auth.session.created":        "started a session",
	"auth.session.expired":        "session expired",
	"auth.session.revoked":        "revoked a session",
	"auth.password.changed":       "changed a password",
	"auth.password.policy_failed": "failed the password policy",
	"auth.api_key.created":        "created an API key",
	"auth.api_key.revoked":        "revoked an API key",
	"auth.policy.updated":         "updated the authentication policy",
	// authz
	"authz.permission.denied": "was denied permission",
	"authz.role.assigned":     "assigned a role",
	"authz.role.removed":      "removed a role",
	// host
	"host.created":                "created a host",
	"host.updated":                "updated a host",
	"host.deleted":                "deleted a host",
	"host.connectivity.checked":   "checked host connectivity",
	"host.platform.detected":      "detected a host platform",
	"host.discovery.completed":    "completed host discovery",
	"host.intelligence.refreshed": "refreshed host intelligence",
	"host.bulk_imported":          "bulk-imported hosts",
	// credential
	"credential.created": "created a credential",
	"credential.updated": "updated a credential",
	"credential.deleted": "deleted a credential",
	// scan
	"scan.queued":            "queued a scan",
	"scan.started":           "started a scan",
	"scan.completed":         "completed a scan",
	"scan.failed":            "reported a failed scan",
	"scan.cancelled":         "cancelled a scan",
	"scan.session.created":   "started a scan session",
	"scan.session.cancelled": "cancelled a scan session",
	"scan.template.created":  "created a scan template",
	"scan.template.updated":  "updated a scan template",
	"scan.template.deleted":  "deleted a scan template",
	// compliance
	"compliance.state.changed":        "recorded a compliance change",
	"finding.persisted":               "recorded a finding",
	"writer.apply.failed":             "failed to write scan results",
	"compliance.exception.requested":  "requested an exception",
	"compliance.exception.approved":   "approved an exception",
	"compliance.exception.rejected":   "rejected an exception",
	"compliance.exception.revoked":    "revoked an exception",
	"compliance.exception.expired":    "exception expired",
	"compliance.baseline.established": "established a baseline",
	"compliance.baseline.cleared":     "cleared a baseline",
	// account
	"account.user.locked":                 "locked a user account",
	"account.user.unlocked":               "unlocked a user account",
	"account.user.created":                "created a user account",
	"account.user.deleted":                "deleted a user account",
	"account.user.privileged_group_added": "added a user to a privileged group",
	"account.ssh_key.added":               "added an SSH key",
	"account.ssh_key.removed":             "removed an SSH key",
	// remediation
	"remediation.requested":   "requested remediation",
	"remediation.approved":    "approved remediation",
	"remediation.rejected":    "rejected remediation",
	"remediation.executed":    "executed remediation",
	"remediation.rolled_back": "rolled back remediation",
	// scheduler
	"scheduler.tick.dispatched":  "ran a scheduled tick",
	"scheduler.schedule.updated": "updated a scan schedule",
	// system lifecycle
	"system.startup":              "started up",
	"system.shutdown":             "shut down",
	"system.package.installed":    "installed a package",
	"system.package.updated":      "updated a package",
	"system.package.removed":      "removed a package",
	"system.kernel.updated":       "updated the kernel",
	"system.filesystem.mounted":   "mounted a filesystem",
	"system.filesystem.unmounted": "unmounted a filesystem",
	"system.service.started":      "started a service",
	"system.service.stopped":      "stopped a service",
	"system.service.failed":       "reported a failed service",
	"system.config.file_changed":  "changed a config file",
	"system.reboot.required":      "flagged a required reboot",
	"system.reboot.completed":     "completed a reboot",
	"system.config.changed":       "changed system configuration",
	"system.health.degraded":      "reported degraded health",
	// security
	"security.login.new_source_ip":    "logged in from a new source IP",
	"security.login.failed_threshold": "hit a failed-login threshold",
	"security.selinux.denied":         "triggered an SELinux denial",
	"security.apparmor.denied":        "triggered an AppArmor denial",
	"security.firewall.rule_changed":  "changed a firewall rule",
	"security.port.opened":            "opened a network port",
	// account
	"account.password.expired":       "had a password expire",
	"account.password.expiring":      "has a password expiring",
	"account.sudo.failure_threshold": "hit a sudo failure threshold",
	// notification / license / policy / admin
	"notification.dispatched":      "dispatched a notification",
	"notification.delivery.failed": "had a notification fail to deliver",
	"license.installed":            "installed a license",
	"license.expired":              "reported an expired license",
	"policy.loaded":                "loaded a policy",
	"policy.applied":               "applied a policy",
	"admin.user.created":           "created a user",
	"admin.user.deleted":           "deleted a user",
	"admin.role.changed":           "changed a role",
}
