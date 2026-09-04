-- 0062_score_and_corpus_provenance.sql
--
-- Reserve nullable storage for the compliance-scoring redesign: a score that
-- can be absent, the formula that produced it, and the identity of the rule
-- corpus a scan measured against.
--
-- NOTHING IS BACKFILLED. Every column added here is NULL on every existing row,
-- and stays NULL. That is the point of the migration, not a limitation of it.
--
--   score_pct        existing values keep the number they meant, at the one
--                    decimal they have always been presented at. The column
--                    changes from REAL to numeric(4,1) because float4 cannot
--                    hold one decimal; see the ALTER below. They were computed as
--                    passing over every outcome, and recomputing them from the
--                    stored counts would produce a number consistent with the
--                    new formula but inconsistent with the corpus scope those
--                    counts were gathered under, which changed in 0060.
--
--   formula_version  NULL on existing rows, and it stays NULL. NOT 1.
--                    The arithmetic behind a legacy row is knowable: every
--                    pre-migration row used passing over total. Its CORPUS
--                    semantics are not. Migration 0060 changed which rules a
--                    score counts, and nothing recorded which corpus produced
--                    any given historical row. Labelling those rows with a
--                    formula version would imply they are comparable to
--                    version-2 rows on the same axis, and they are not: the
--                    formula is only half of what makes two scores comparable.
--                    NULL is the honest answer, and a later migration must not
--                    relabel them.
--
--   corpus fields    NULL on existing rows, permanently. A NEW completed scan
--                    records status 'unavailable' with no version and no
--                    digest: scanruns.MarkCompleted writes it. The two are
--                    different facts. NULL means the row predates the column;
--                    'unavailable' means the scan happened and its corpus
--                    identity cannot be read, because Kensa
--                    features/KN-KN-030 DescribeCorpus has not shipped.
--                    Asking which corpus is installed now would assert a
--                    measurement nobody made.
--
-- Spec: system-compliance-scoring C-09 to C-11, system-posture-snapshots.

-- +goose Up

-- posture_snapshots: a score that can be absent, and what produced it.
--
-- score_pct becomes nullable. NULL means no rule produced a verdict; 0 means
-- every evaluated rule failed. Those are different operational states and the
-- NOT NULL DEFAULT 0 could not tell them apart, which is the same defect as
-- bugs/OW-023 and OW-024 one layer down.
ALTER TABLE posture_snapshots ALTER COLUMN score_pct DROP NOT NULL;
ALTER TABLE posture_snapshots ALTER COLUMN score_pct DROP DEFAULT;

-- score_pct also stops being REAL.
--
-- A score is presented to one decimal, and REAL (float4) cannot hold one. It
-- stores 66.7 as 66.69999694824219, so a score read back never equals the score
-- computed. system-compliance-scoring C-14 requires the SQL aggregate and the Go
-- implementation to AGREE, and under float4 they cannot: every comparison needs
-- a tolerance, and a tolerance is a place for a real disagreement to hide.
-- numeric(4,1) holds every value the column is allowed to hold, exactly.
--
-- RATIFIED by the founder on 2026-09-02, in these terms: this migration may
-- canonicalize existing non-null score_pct values from REAL representation to
-- numeric(4,1), preserving the score's established one-decimal value. It must
-- not recompute a score from counts, assign a formula version, infer corpus
-- identity, or change historical signed artifacts. It does none of those.
--
-- This is NOT a recomputation of history. Every stored value was produced by
-- ROUND(x * 1000) / 10 and has always been PRESENTED at one decimal, so rounding
-- to one decimal recovers the number the row already meant. What changes is the
-- representation error, not the score.
--
-- OPERATIONAL IMPACT. Changing a column type REWRITES THE TABLE and holds an
-- ACCESS EXCLUSIVE lock on posture_snapshots for the duration. Reads and writes
-- of that table block while it runs. posture_snapshots holds one row per host
-- per day per framework series, so the time scales with fleet size times
-- retention. The rollup is hourly and simply runs late; the trend endpoints
-- block. See the upgrade runbook.
ALTER TABLE posture_snapshots
    ALTER COLUMN score_pct TYPE numeric(4,1)
    USING round(score_pct::numeric, 1);

ALTER TABLE posture_snapshots
    ADD COLUMN formula_version    INTEGER,
    ADD COLUMN aggregation_method TEXT,
    ADD COLUMN engine_version     TEXT,
    ADD COLUMN corpus_identity_status TEXT,
    ADD COLUMN corpus_version     TEXT,
    ADD COLUMN corpus_digest      TEXT;

-- A snapshot row is one host on one date under one lens, so it can never be a
-- mix of corpora. mixed and partially_identified describe an AGGREGATE computed
-- from many snapshots and are derived at read time, never stored here.
-- Constraining the column to the two reachable values means an aggregate status
-- cannot be written into a per-host row by mistake.
ALTER TABLE posture_snapshots
    ADD CONSTRAINT posture_snapshots_corpus_status_check
    CHECK (corpus_identity_status IS NULL
           OR corpus_identity_status IN ('unavailable', 'identified'));

-- scan_runs: which corpus measured this scan.
ALTER TABLE scan_runs
    ADD COLUMN corpus_identity_status TEXT,
    ADD COLUMN corpus_version         TEXT,
    ADD COLUMN corpus_digest          TEXT;

ALTER TABLE scan_runs
    ADD CONSTRAINT scan_runs_corpus_status_check
    CHECK (corpus_identity_status IS NULL
           OR corpus_identity_status IN ('unavailable', 'identified'));

-- The three shape rules from decision records 08 and 09, enforced in the schema
-- rather than trusted to every writer:
--
--   1. A version without a digest is impossible. A curated corpus has a digest
--      and no version (decision 09); nothing has a version and no digest,
--      because the version names a release whose contents hash to something.
--   2. identified requires a digest. unavailable forbids both values.
--   3. An empty string is never a value. Decision 08 says a missing value is
--      null; "" is the sentinel that rule exists to forbid, and it is what
--      bugs/OW-009 shows becomes indistinguishable from a real value.
-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['posture_snapshots', 'scan_runs'] LOOP
        EXECUTE format($f$
            ALTER TABLE %I ADD CONSTRAINT %I CHECK (
                -- a version never exists without a digest
                (corpus_version IS NULL OR corpus_digest IS NOT NULL)
                -- identified carries a digest; unavailable carries neither
                AND (corpus_identity_status IS DISTINCT FROM 'identified'
                     OR corpus_digest IS NOT NULL)
                AND (corpus_identity_status IS DISTINCT FROM 'unavailable'
                     OR (corpus_digest IS NULL AND corpus_version IS NULL))
                -- a null status is not a licence to carry values. A row with no
                -- status and a digest is a half-claim: it asserts a corpus while
                -- refusing to say whether the identity is known.
                AND (corpus_identity_status IS NOT NULL
                     OR (corpus_digest IS NULL AND corpus_version IS NULL))
                -- no empty strings, anywhere
                AND (corpus_version IS NULL OR corpus_version <> '')
                AND (corpus_digest IS NULL OR corpus_digest <> '')
                AND (corpus_identity_status IS NULL OR corpus_identity_status <> '')
            )$f$, t, t || '_corpus_shape_check');
    END LOOP;
END $$;
-- +goose StatementEnd

-- Scoring metadata is all-or-nothing, and the values are pinned.
--
-- A row carrying formula_version 2 with a null aggregation method describes
-- half of how its number was produced, which is not interpretable later and is
-- the same partial-claim defect the corpus rules forbid. A legacy row carries
-- none of the three; a row written under this formula carries all three.
--
-- aggregation_method is 'none' because a snapshot is ONE host on one date under
-- one lens. It aggregates nothing. equal_host_mean belongs to a fleet or group
-- number computed from many of these rows, and storing it here would claim this
-- row averaged something.
--
-- score_pct is bounded because a percentage of rules that passed cannot fall
-- outside 0 to 100. compliance.ScoreFromPercent rejects the same values, and a
-- rule enforced in one place only is a rule that holds until someone writes
-- from somewhere else.
ALTER TABLE posture_snapshots
    ADD CONSTRAINT posture_snapshots_scoring_shape_check
    CHECK (
        (
            (formula_version IS NULL AND aggregation_method IS NULL AND engine_version IS NULL)
            OR (formula_version = 2 AND aggregation_method = 'none'
                AND engine_version IS NOT NULL AND engine_version <> '')
        )
        AND (score_pct IS NULL OR (score_pct >= 0 AND score_pct <= 100))
    );

COMMENT ON COLUMN posture_snapshots.score_pct IS
    'Nullable. NULL means no rule produced a verdict on that date; 0 means every '
    'evaluated rule failed. Rows written before migration 0062 keep the value '
    'the passing-over-total formula produced and carry formula_version NULL.';

COMMENT ON COLUMN posture_snapshots.formula_version IS
    'Which scoring formula produced score_pct. NULL on rows written before '
    'migration 0062. 2 is passing over passing plus failing. Never backfilled: '
    'see the migration header.';

COMMENT ON COLUMN scan_runs.corpus_identity_status IS
    'unavailable or identified. NULL on rows written before migration 0062. '
    'Stays unavailable on new rows until Kensa features/KN-KN-030 ships '
    'DescribeCorpus; the installed corpus is never used to infer it.';

-- +goose Down

ALTER TABLE posture_snapshots DROP CONSTRAINT IF EXISTS posture_snapshots_scoring_shape_check;
ALTER TABLE posture_snapshots DROP CONSTRAINT IF EXISTS posture_snapshots_corpus_shape_check;
ALTER TABLE posture_snapshots DROP CONSTRAINT IF EXISTS posture_snapshots_corpus_status_check;
ALTER TABLE scan_runs DROP CONSTRAINT IF EXISTS scan_runs_corpus_shape_check;
ALTER TABLE scan_runs DROP CONSTRAINT IF EXISTS scan_runs_corpus_status_check;

ALTER TABLE scan_runs
    DROP COLUMN IF EXISTS corpus_digest,
    DROP COLUMN IF EXISTS corpus_version,
    DROP COLUMN IF EXISTS corpus_identity_status;

ALTER TABLE posture_snapshots
    DROP COLUMN IF EXISTS corpus_digest,
    DROP COLUMN IF EXISTS corpus_version,
    DROP COLUMN IF EXISTS corpus_identity_status,
    DROP COLUMN IF EXISTS engine_version,
    DROP COLUMN IF EXISTS aggregation_method,
    DROP COLUMN IF EXISTS formula_version;

-- score_pct returns to NOT NULL DEFAULT 0, and the downgrade REFUSES when any
-- row holds NULL.
--
-- The earlier version of this rollback wrote those rows back to 0. That is the
-- fabricated verdict bugs/OW-023 and OW-024 are about, recreated deliberately by
-- the code meant to undo them: a host nothing could assess would come back as
-- zero percent compliant. A downgrade that destroys the distinction it was
-- written to protect should stop and say so, not do it quietly.
--
-- To downgrade, decide what those hosts should read and set it explicitly first.
-- +goose StatementBegin
DO $$
DECLARE
    n integer;
BEGIN
    SELECT count(*) INTO n FROM posture_snapshots WHERE score_pct IS NULL;
    IF n > 0 THEN
        RAISE EXCEPTION
            'downgrade refused: % snapshot(s) hold no score. Rolling back would write them to 0, which is the fabricated verdict this migration exists to prevent. Set an explicit value for those rows first.',
            n;
    END IF;
END $$;
-- +goose StatementEnd
ALTER TABLE posture_snapshots
    ALTER COLUMN score_pct TYPE REAL USING score_pct::real;
ALTER TABLE posture_snapshots ALTER COLUMN score_pct SET DEFAULT 0;
ALTER TABLE posture_snapshots ALTER COLUMN score_pct SET NOT NULL;
