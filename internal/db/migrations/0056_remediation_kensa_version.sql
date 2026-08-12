-- +goose Up
-- Stamp each recorded transaction with the Kensa version that produced it.
--
-- Needed before the pre-state summary lands, not after. Kensa's describer
-- output carries NO stability guarantee: it is not semver-frozen, not
-- parseable, and may change in any release including a patch. OpenWatch will
-- persist those summaries at ingest, so a release that CORRECTS a describer
-- leaves stale and possibly wrong strings in this table with nothing marking
-- them stale. A summary that was wrong and got fixed upstream is worse than
-- one that was never there.
--
-- With the version recorded, a re-backfill after a Kensa bump targets only the
-- rows a describer change actually affected. Without it the only options are
-- re-running over all history or silently keeping stale text. Agreed with
-- kensa-agent on features/KN-OW-016; cheap now, a migration later.
ALTER TABLE remediation_transactions
    ADD COLUMN IF NOT EXISTS kensa_version TEXT;

COMMENT ON COLUMN remediation_transactions.kensa_version IS
    'Kensa version that produced this transaction. Scopes a re-backfill of derived display strings, whose output is explicitly not stable across releases.';

-- +goose Down
ALTER TABLE remediation_transactions DROP COLUMN IF EXISTS kensa_version;
