-- Remediation outcome vocabulary (api-remediation v1.2.0, C-09 / AC-09..11).
--
-- WHY: remediation reported exactly two terminal outcomes, executed and failed,
-- and "failed" conflated five situations that need five different operator
-- responses. The sharpest case is Kensa v0.8.0's new `staged` status: on a host
-- whose audit config is immutable (`auditctl -s` reports `enabled 2`) an
-- audit_rule_set apply writes the reboot-deferred persist layer and terminates
-- as staged. The host IS mutated. Before this migration OpenWatch recorded that
-- as failed with the message "No host change was committed", journalled it as
-- 'skipped', and then refused rollback because rollback requires 'executed'.
-- The change was on the host, invisible, and unreversible from the UI.
--
-- Two enums widen here:
--   remediation_requests.status   gains staged | reverted | not_applied |
--                                 partially_applied
--   remediation_transactions.phase_result gains the same, so the journal stops
--                                 collapsing every non-commit into 'skipped'
--
-- Semantics (see the spec for the normative text):
--   staged            persist layer written, runtime NOT converged. Host
--                     changed. Rule must NOT be flipped to pass. Rollback stays
--                     reachable.
--   reverted          Kensa auto-restored pre-state after a failed validation.
--                     Host untouched. This is the atomic model working, so it
--                     is deliberately NOT a red failure.
--   not_applied       engine refused without mutating (e.g. the v0.8.0
--                     duplicate-audit-action guard). Host untouched.
--   partially_applied stranded non-capturable steps. Host state unknown.
--
-- The in-flight set for the one-open-request-per-(host,rule) partial unique
-- index is deliberately NOT widened: every new value is terminal, so a staged
-- or reverted request must not block a fresh request for the same host+rule.

-- +goose Up

-- remediation_requests.status is CHECK-constrained by 0037 to the original
-- eight values, so the new terminal outcomes must be admitted explicitly or
-- every staged/reverted write fails on the constraint.
ALTER TABLE remediation_requests
    DROP CONSTRAINT IF EXISTS remediation_requests_status_check;

ALTER TABLE remediation_requests
    ADD CONSTRAINT remediation_requests_status_check
    CHECK (status IN (
        -- lifecycle
        'pending_approval', 'approved', 'rejected', 'dry_run_complete', 'executing',
        -- terminal, pre-0054
        'executed', 'rolled_back', 'failed',
        -- terminal, new in 0054
        'staged', 'reverted', 'not_applied', 'partially_applied'
    ));

-- The one-open-request-per-(host,rule) partial unique index (0037) keys on the
-- IN-FLIGHT set only. Every value added here is terminal, so the index is
-- deliberately left alone: a staged or reverted request is history and must not
-- block a fresh request for the same host and rule.

COMMENT ON COLUMN remediation_requests.status IS
    'Lifecycle + terminal outcome. Lifecycle: pending_approval, approved, rejected, dry_run_complete, executing. Terminal: executed, failed, rolled_back, staged, reverted, not_applied, partially_applied. NOTE: this column conflates lifecycle and outcome; splitting them into status + outcome is accepted debt, revisit when bulk remediation lands (see BACKLOG "Option C").';

-- remediation_transactions.phase_result IS CHECK-constrained (0037 line 73) to
-- committed | rolled_back | skipped. Widen it so the journal records the real
-- Kensa outcome instead of degrading through a default branch.
ALTER TABLE remediation_transactions
    DROP CONSTRAINT IF EXISTS remediation_transactions_phase_result_check;

ALTER TABLE remediation_transactions
    ADD CONSTRAINT remediation_transactions_phase_result_check
    CHECK (phase_result IS NULL OR phase_result IN (
        'committed',
        'rolled_back',
        'skipped',
        'staged',
        'reverted',
        'not_applied',
        'partially_applied'
    ));

COMMENT ON COLUMN remediation_transactions.phase_result IS
    'True per-transaction Kensa outcome. staged = persist written, runtime not converged, host changed, rollback still possible. reverted = auto-restored after failed validation, host untouched. not_applied = engine refused, host untouched. skipped is retained for historical rows written before migration 0054.';

-- +goose Down

-- Fold the new request statuses back before restoring the narrower CHECK, or
-- it fails to validate existing rows. staged folds to executed because the host
-- WAS mutated; the rest fold to failed, which is what the pre-0054 code
-- recorded for them.
UPDATE remediation_requests SET status = 'executed' WHERE status = 'staged';
UPDATE remediation_requests SET status = 'failed'
 WHERE status IN ('reverted', 'not_applied', 'partially_applied');

ALTER TABLE remediation_requests
    DROP CONSTRAINT IF EXISTS remediation_requests_status_check;

ALTER TABLE remediation_requests
    ADD CONSTRAINT remediation_requests_status_check
    CHECK (status IN ('pending_approval', 'approved', 'rejected',
                      'dry_run_complete', 'executing', 'executed',
                      'rolled_back', 'failed'));

ALTER TABLE remediation_transactions
    DROP CONSTRAINT IF EXISTS remediation_transactions_phase_result_check;

-- Collapse the new values back into the pre-0054 vocabulary before restoring
-- the narrower CHECK, or the constraint would fail to validate existing rows.
-- 'staged' folds to 'committed' because the host was in fact mutated; the
-- others fold to 'skipped', which is what the old code recorded for them.
UPDATE remediation_transactions SET phase_result = 'committed' WHERE phase_result = 'staged';
UPDATE remediation_transactions SET phase_result = 'skipped'
 WHERE phase_result IN ('reverted', 'not_applied', 'partially_applied');

ALTER TABLE remediation_transactions
    ADD CONSTRAINT remediation_transactions_phase_result_check
    CHECK (phase_result IS NULL OR phase_result IN ('committed', 'rolled_back', 'skipped'));

COMMENT ON COLUMN remediation_transactions.phase_result IS NULL;
COMMENT ON COLUMN remediation_requests.status IS NULL;
