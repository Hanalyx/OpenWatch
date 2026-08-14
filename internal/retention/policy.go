// Package retention holds one registry of retention policies and one
// sweeper that walks it. Every table the migrations create carries
// exactly one entry, and every entry carries a reason.
//
// Why the registry enumerates tables rather than columns. An earlier
// survey of this schema keyed on expires_at and missed auth_mfa_otp_uses
// entirely, because that table keys on used_at. Enumerating tables and
// demanding an explicit decision for each one is the only version that
// cannot miss a table.
//
// Why the registry exists at all. OpenWatch shipped two purge functions
// and no sweeper. internal/sso/store.go PurgeExpiredStates said "Called
// by a periodic sweeper" and had no caller. internal/identity/mfa.go
// PurgeStaleOTPs said "Called by a cron tick" and had no caller.
// Different authors, two months apart, same outcome. Both are deleted
// now, and their tables are swept from here.
//
// Spec: specs/system/retention-sweeper.spec.yaml.
package retention

import "time"

// State is the retention decision recorded for one table. Every table in
// the schema carries exactly one of these, and every entry carries a
// reason. Silence is not a state.
type State string

const (
	// StateSwept means the sweeper deletes rows past the grace.
	StateSwept State = "swept"

	// StateNever means rows are kept forever, on purpose. The reason
	// records why, so a later reader does not "fix" it.
	StateNever State = "never"

	// StateDeferred means a sweep is wanted but blocked on named work.
	// The reason names the work, and the entry carries the TTL column,
	// the grace and any Keep predicate the promotion will use, so
	// promoting is a one-word state change rather than a fresh design.
	StateDeferred State = "deferred"

	// StateUndecided means nobody has ruled on this table. It carries no
	// TTL column and no grace, because naming either would assert a
	// decision that was never taken.
	//
	// This is not the same as deferred. Deferred says "here is the
	// policy, here is what blocks it". Undecided says "nobody has
	// looked". Collapsing the two would make an unreviewed table read
	// like a reviewed one, which is the defect this registry exists to
	// prevent, one level up.
	StateUndecided State = "undecided"
)

// Policy is one table's retention decision.
//
// TTLColumn and Grace describe the delete: rows whose TTLColumn is older
// than Grace are eligible. Keep is an optional SQL predicate naming rows
// that survive regardless of age; the sweeper negates it in the WHERE
// clause.
type Policy struct {
	// Table is the table name as the migrations create it.
	Table string

	// TTLColumn is the timestamp column that decides a row's age.
	TTLColumn string

	// Grace is how long past TTLColumn a row survives.
	Grace time.Duration

	// State is the retention decision: swept, never, deferred, or
	// undecided.
	State State

	// Keep is an optional SQL predicate. A row matching it survives
	// past its grace.
	Keep string

	// Reason says why this table has the state it has. Never empty.
	Reason string
}

// Eligible reports whether the sweeper deletes from this table.
func (p Policy) Eligible() bool { return p.State == StateSwept }

// registry is the single source of truth. One entry per table created in
// the Up section of internal/db/migrations/*.sql. A new table without an
// entry here fails CI (spec AC-02).
//
// Ordered swept, never, deferred, undecided, so the three tables that
// actually lose rows are readable off the top of the list.
var registry = []Policy{
	// ---- swept ----------------------------------------------------
	{
		Table:     "idempotency_keys",
		TTLColumn: "expires_at",
		Grace:     24 * time.Hour,
		State:     StateSwept,
		Reason: "Replay lookup already filters on expires_at > now(), so a row " +
			"past its expiry is unreadable before it is swept. The 24h grace " +
			"keeps a recently expired key around long enough to debug a " +
			"duplicate-submit report against it.",
	},
	{
		Table:     "sso_auth_states",
		TTLColumn: "expires_at",
		Grace:     time.Hour,
		State:     StateSwept,
		Reason: "An auth state is single-use and is rejected once expired, so " +
			"the sweep only reclaims abandoned logins. The callback consumes " +
			"the row it matches (internal/sso/store.go consumeAuthState); this " +
			"sweep collects the states nobody ever came back for.",
	},
	{
		Table: "auth_mfa_otp_uses",
		// Note the column. This table has no expires_at, and keying a
		// retention survey on expires_at is what missed it before.
		TTLColumn: "used_at",
		Grace:     24 * time.Hour,
		State:     StateSwept,
		Reason: "This Grace IS the OTP replay-rejection window, not a capacity " +
			"setting. identity.VerifyMFA rejects a replay by inserting " +
			"(user_id, otp) with ON CONFLICT DO NOTHING, so a used OTP is " +
			"rejected exactly as long as its row survives. Deleting the row " +
			"makes the OTP replayable again. The floor is the TOTP acceptance " +
			"window, 90 seconds (period 30s, skew 1, three steps); 24h is far " +
			"above it. Do not lower this without reading spec C-10.",
	},

	// ---- never ----------------------------------------------------
	{
		Table:  "api_tokens",
		State:  StateNever,
		Reason: reasonAPITokens,
	},
	{
		Table:  "compliance_exceptions",
		State:  StateNever,
		Reason: reasonComplianceExceptions,
	},
	{
		Table:  "host_rule_state",
		State:  StateNever,
		Reason: reasonHostRuleState,
	},

	// ---- deferred: decided, blocked on named work ------------------
	//
	// The Grace on these two is a placeholder, and each Reason says so.
	// The label has to travel with the data: anything rendering the
	// registry for an operator reads Grace, not this comment, and a
	// consumer showing an invented number as a fact is the defect this
	// registry exists to remove. The TTLColumn and the Keep predicate
	// are not placeholders. Those are settled.
	{
		Table:     "sessions",
		TTLColumn: "absolute_expires_at",
		Grace:     30 * 24 * time.Hour,
		State:     StateDeferred,
		Reason: "Blocked on a migration: it needs a non-partial index on " +
			"absolute_expires_at. The predicate must use absolute_expires_at, " +
			"because expires_at slides forward on every request and would " +
			"never settle. The only index today is idx_sessions_expires_at, " +
			"which is partial (WHERE revoked_at IS NULL) and on the wrong " +
			"column, so a sweep is a sequential scan over live session " +
			"history. Deleting session history is not reversible. " +
			"The 30 day grace is a placeholder to satisfy the registry's " +
			"shape rule, not a retention decision. Choose the real window at " +
			"promotion.",
	},
	{
		Table:     "refresh_tokens",
		TTLColumn: "expires_at",
		Grace:     30 * 24 * time.Hour,
		State:     StateDeferred,
		// Carried now, not at promotion. A reuse_detected_at row is the
		// only durable artifact of a detected token theft, and the
		// criterion that proves Keep works is tested before the
		// promotion rather than with it (spec AC-09).
		Keep: "reuse_detected_at IS NOT NULL",
		Reason: "Blocked on a migration: there is no index on expires_at at " +
			"all, so a sweep today is a sequential scan. The delete must be " +
			"oldest-first because rotated_to_id references this same table " +
			"with NO ACTION, and a newest-first batch violates it. A row with " +
			"reuse_detected_at set is the only durable record of a detected " +
			"token theft, so the Keep predicate above must survive promotion. " +
			"The 30 day grace is a placeholder to satisfy the registry's " +
			"shape rule, not a retention decision. Choose the real window at " +
			"promotion.",
	},

	// ---- undecided: nobody has ruled on these ----------------------
	//
	// Every entry below carries the same stock reason. That is
	// deliberate. The value of an undecided entry is that a new table
	// cannot be added without someone picking a state; the prose is not
	// doing the work, and 39 hand-written variations would only invite
	// the reader to mistake description for a decision.
	//
	// These are pinned by name, not by count (C-13). A count ratchet
	// would let a promotion pay for a newly added undecided table while
	// the total held steady. With names pinned, adding one means editing
	// a reviewed list.
	//
	// Two things worth knowing before anyone rules on them, recorded
	// here rather than in 39 separate Reason strings:
	//
	// Growing without bound, and this is the first place in the
	// codebase that says so: audit_events, job_queue, notifications,
	// host_monitoring_history (one row per host per probe, the fastest
	// of them), host_intelligence_events, posture_snapshots (one row
	// per host per framework per day), transactions, policy_history,
	// alerts, scan_runs, scan_results, scan_evidence,
	// remediation_requests, remediation_transactions, report_snapshots
	// and report_faces.
	//
	// Three of those cannot be swept per table even after a decision.
	// scan_results references scan_runs, hosts and scan_evidence with
	// RESTRICT, so any sweep there has to delete in dependency order.
	// scan_evidence is content-addressed and shared, so removing a body
	// is reference counting rather than age. host_intelligence_events
	// and transactions reference hosts with RESTRICT, so those rows
	// outlive the host they describe.
	//
	// The rest hold current state rather than history. Their row count
	// tracks the number of live objects, so they grow with the fleet and
	// not with time, and age is the wrong key for all of them.
	{Table: "audit_events", State: StateUndecided, Reason: reasonUndecided},
	{Table: "job_queue", State: StateUndecided, Reason: reasonUndecided},
	{Table: "notifications", State: StateUndecided, Reason: reasonUndecided},
	{Table: "host_monitoring_history", State: StateUndecided, Reason: reasonUndecided},
	{Table: "host_intelligence_events", State: StateUndecided, Reason: reasonUndecided},
	{Table: "posture_snapshots", State: StateUndecided, Reason: reasonUndecided},
	{Table: "transactions", State: StateUndecided, Reason: reasonUndecided},
	{Table: "policy_history", State: StateUndecided, Reason: reasonUndecided},
	{Table: "alerts", State: StateUndecided, Reason: reasonUndecided},
	{Table: "scan_runs", State: StateUndecided, Reason: reasonUndecided},
	{Table: "scan_results", State: StateUndecided, Reason: reasonUndecided},
	{Table: "scan_evidence", State: StateUndecided, Reason: reasonUndecided},
	{Table: "remediation_requests", State: StateUndecided, Reason: reasonUndecided},
	{Table: "remediation_transactions", State: StateUndecided, Reason: reasonUndecided},
	{Table: "report_snapshots", State: StateUndecided, Reason: reasonUndecided},
	{Table: "report_faces", State: StateUndecided, Reason: reasonUndecided},
	{Table: "users", State: StateUndecided, Reason: reasonUndecided},
	{Table: "roles", State: StateUndecided, Reason: reasonUndecided},
	{Table: "user_roles", State: StateUndecided, Reason: reasonUndecided},
	{Table: "groups", State: StateUndecided, Reason: reasonUndecided},
	{Table: "group_members", State: StateUndecided, Reason: reasonUndecided},
	{Table: "hosts", State: StateUndecided, Reason: reasonUndecided},
	{Table: "credentials", State: StateUndecided, Reason: reasonUndecided},
	{Table: "system_config", State: StateUndecided, Reason: reasonUndecided},
	{Table: "auth_policy", State: StateUndecided, Reason: reasonUndecided},
	{Table: "license_clock_watermark", State: StateUndecided, Reason: reasonUndecided},
	{Table: "notification_channels", State: StateUndecided, Reason: reasonUndecided},
	{Table: "report_schedules", State: StateUndecided, Reason: reasonUndecided},
	{Table: "sso_providers", State: StateUndecided, Reason: reasonUndecided},
	{Table: "sso_identities", State: StateUndecided, Reason: reasonUndecided},
	{Table: "ssh_known_hosts", State: StateUndecided, Reason: reasonUndecided},
	{Table: "auth_mfa_secrets", State: StateUndecided, Reason: reasonUndecided},
	{Table: "host_connection_profile", State: StateUndecided, Reason: reasonUndecided},
	{Table: "host_liveness", State: StateUndecided, Reason: reasonUndecided},
	{Table: "host_backoff_state", State: StateUndecided, Reason: reasonUndecided},
	{Table: "host_compliance_schedule", State: StateUndecided, Reason: reasonUndecided},
	{Table: "host_intelligence_state", State: StateUndecided, Reason: reasonUndecided},
	{Table: "host_system_info", State: StateUndecided, Reason: reasonUndecided},
}

// reasonUndecided is shared by every table nobody has ruled on. The
// entry's value is that a new table cannot be added without picking a
// state; the prose is not doing the work.
const reasonUndecided = "No retention decision has been taken for this table. See bugs/OW-013."

// reasonHostRuleState records why this table is swept by nothing, ever.
// Spec system-current-corpus C-09.
const reasonHostRuleState = "Never swept. Two reasons, and the second is the load-bearing one. " +
	"The rows record what a host used to be measured against, which an assessor may ask for. " +
	"And the host_rule_state_current view derives a host's corpus from these rows, so deleting " +
	"any of them does not merely lose history: it CHANGES past compliance answers, silently and " +
	"with no way to tell that it happened. A rule that has left the corpus already contributes " +
	"to no current score, so a sweep would buy nothing and cost that."

// reasonAPITokens and reasonComplianceExceptions are held apart from the
// table above only because they are long. Both record a decision that a
// later reader would otherwise be tempted to reverse.
const (
	reasonAPITokens = "Kept forever on purpose. The operator UI lists expired " +
		"tokens deliberately: internal/apitoken/apitoken.go filters neither " +
		"expires_at nor revoked_at. expires_at is nullable, and NULL means the " +
		"token never expires, so an age-based sweep has nothing to key on for " +
		"those rows. The row is also a forensic record, carrying created_by, " +
		"last_used_at and revoked_at, which is exactly what an investigator " +
		"needs after a token is abused."

	reasonComplianceExceptions = "Kept forever on purpose. Expiry here is " +
		"already a status transition rather than a deletion, run by " +
		"exception.Service.Run, and the table's partial unique index depends " +
		"on expired rows persisting. This table is the model this registry " +
		"follows, not a defect it corrects."
)

// Registry returns the retention policies, one per table. The slice is a
// copy, so a caller cannot mutate the registry.
func Registry() []Policy {
	out := make([]Policy, len(registry))
	copy(out, registry)
	return out
}

// Lookup returns the policy for one table.
func Lookup(table string) (Policy, bool) {
	for _, p := range registry {
		if p.Table == table {
			return p, true
		}
	}
	return Policy{}, false
}
