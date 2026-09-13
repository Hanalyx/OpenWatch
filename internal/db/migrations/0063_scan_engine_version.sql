-- 0063_scan_engine_version.sql
--
-- Record WHICH scan engine produced a scan's outcomes, on the scan run itself.
--
-- Every score-bearing response has to name the engine behind its number
-- (system-compliance-scoring C-15). Until now two different processes answered
-- that question about themselves rather than about the scan:
--
--   GET /fleet/score       reported the SERVING process's linked Kensa.
--   posture.Rollup         reported the ROLLUP process's linked Kensa.
--
-- Neither is the engine that produced the outcomes. In a rolling upgrade the
-- API and the workers run different builds at the same time, and in a split
-- deployment they always do, so a response could name an engine that never
-- touched the host it was describing. That is false provenance, and provenance
-- that can be false is worse than none: it is believed.
--
-- The value is stamped by the worker at completion, so it is the version of the
-- process that actually ran the scan.
--
-- NOT BACKFILLED. Every existing row keeps NULL, because nothing recorded which
-- engine produced those outcomes and the engine linked into whatever process
-- runs this migration is not evidence about a scan from last week. A consumer
-- reads NULL as "not recorded", never as "the current one".
--
-- Spec: system-scan-runs C-06, system-compliance-scoring C-15.

-- +goose Up

ALTER TABLE scan_runs ADD COLUMN engine_version TEXT;

-- No empty strings. Decision record 08's rule holds here for the same reason it
-- holds for the corpus fields: "" is the sentinel that becomes indistinguishable
-- from a real value.
ALTER TABLE scan_runs
    ADD CONSTRAINT scan_runs_engine_version_check
    CHECK (engine_version IS NULL OR engine_version <> '');

COMMENT ON COLUMN scan_runs.engine_version IS
    'The scan engine version of the WORKER that produced this run''s outcomes, '
    'stamped at completion. NULL on rows written before migration 0063: '
    'nothing recorded it, and the engine linked into a reader today is not '
    'evidence about a scan from before. Never inferred from the reading '
    'process. Spec system-scan-runs C-06.';

-- A version-2 snapshot may now have an UNKNOWN engine.
--
-- Migration 0062 required a non-empty engine_version alongside formula_version
-- 2, because at the time the rollup stamped its own linked version and could
-- always supply one. It supplied the wrong thing: its own build, not the one
-- that ran the scan.
--
-- Now that the value is COPIED from the producing scan run, a snapshot built
-- from a run that predates this migration has no engine to name. The formula is
-- still version 2, because this release computed it; the producer is unknown,
-- because nothing recorded it. Those are separate facts and the schema should
-- let them differ. Requiring a value here would only force the rollup back to
-- inventing one.
--
-- Empty string stays forbidden. Null means not recorded; "" means nothing.
ALTER TABLE posture_snapshots DROP CONSTRAINT IF EXISTS posture_snapshots_scoring_shape_check;
ALTER TABLE posture_snapshots
    ADD CONSTRAINT posture_snapshots_scoring_shape_check
    CHECK (
        (
            (formula_version IS NULL AND aggregation_method IS NULL AND engine_version IS NULL)
            OR (formula_version = 2 AND aggregation_method = 'none'
                AND (engine_version IS NULL OR engine_version <> ''))
        )
        AND (score_pct IS NULL OR (score_pct >= 0 AND score_pct <= 100))
    );

-- +goose Down

-- Restore 0062's stricter rule. It refuses when any version-2 row has no engine
-- version, because rolling back would otherwise leave rows the reinstated
-- constraint forbids.
-- +goose StatementBegin
DO $$
DECLARE
    n integer;
BEGIN
    SELECT count(*) INTO n FROM posture_snapshots
     WHERE formula_version = 2 AND engine_version IS NULL;
    IF n > 0 THEN
        RAISE EXCEPTION
            'downgrade refused: % snapshot(s) name no engine version. 0062 requires one alongside formula 2, and this migration is what allowed them. Set an explicit value first.',
            n;
    END IF;
END $$;
-- +goose StatementEnd

ALTER TABLE posture_snapshots DROP CONSTRAINT IF EXISTS posture_snapshots_scoring_shape_check;
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

ALTER TABLE scan_runs DROP CONSTRAINT IF EXISTS scan_runs_engine_version_check;
ALTER TABLE scan_runs DROP COLUMN IF EXISTS engine_version;
