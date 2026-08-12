-- +goose Up
-- Persist the per-phase Kensa transaction journal.
--
-- Kensa returns TransactionResult.Steps (one StepResult per Capture/Apply/
-- Validate/Commit phase, each carrying a human-readable Detail) and
-- TransactionResult.PreStates (the captured pre-change state). OpenWatch
-- discarded both: mapTxns reduced the journal to a step COUNT in the evidence
-- summary, so a failed remediation could report only "reverted, host
-- unchanged" while the reason sat unread in Detail.
--
-- pre_state and mechanism are NOT added here. Both columns have existed since
-- migration 0037 and have never been written; the insert now populates them.
ALTER TABLE remediation_transactions
    ADD COLUMN IF NOT EXISTS steps JSONB NOT NULL DEFAULT '[]'::jsonb;

COMMENT ON COLUMN remediation_transactions.steps IS
    'Per-phase Kensa journal: [{index, mechanism, detail, success, capturable, staged, stranded}]. Detail is the failure reason.';

COMMENT ON COLUMN remediation_transactions.pre_state IS
    'Captured pre-change state per step, from Kensa PreStates. Data is mechanism-specific and opaque to OpenWatch.';

-- +goose Down
ALTER TABLE remediation_transactions DROP COLUMN IF EXISTS steps;
