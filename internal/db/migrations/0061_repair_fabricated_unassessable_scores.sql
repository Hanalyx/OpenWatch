-- 0061_repair_fabricated_unassessable_scores.sql
--
-- bugs/OW-024. Repair schedule rows that record a fabricated compliance score
-- for a host nothing could assess.
--
-- internal/worker divided passing outcomes by EVERY outcome, so a scan that
-- returned only skipped rows produced 0.0 rather than "no score".
-- scheduler.StateFromScore took a bare float64 with no way to express absence,
-- so 0.0 fell through its default branch and the host was stored, and reported
-- through the public compliance_state enum, as critically non-compliant.
--
-- The producer is fixed in the same change. This repairs what it already wrote,
-- because a producer fix only corrects a host at its next scan and an upgraded
-- deployment would keep reporting known-unassessable hosts as critical until
-- then.
--
-- WHY THE SELECTION IS NOT compliance_score = 0
--
-- A host whose every evaluated rule failed has a real score of 0 and must keep
-- it. Selecting on the stored zero would relabel that host as unassessable.
--
-- The development fleet cannot demonstrate the difference: measured 2026-08-31,
-- it holds 2 hosts with zero verdicts and ZERO hosts with a genuine zero, so
-- the unsafe selector picks exactly the right rows there and every test run
-- against dev passes. The discriminating fixture has to be built on purpose.
--
-- Eligibility comes from the most recent COMPLETED scan run's own outcome
-- counts: rules_pass = 0 AND rules_fail = 0, both non-null.
--
-- Not from host_rule_state. An earlier version of this migration required rule
-- state to exist, which silently missed the worse case. The old worker
-- initialized score := 0.0 and persisted it even when the scan returned NO
-- outcomes at all, and a zero-outcome scan writes no host_rule_state rows. Those
-- hosts have the same fabricated critical/zero row and would have been left
-- there. scan_runs.rules_pass and rules_fail are written by
-- scanruns.MarkCompleted for every completed run, including as zeros, so they
-- are the evidence that distinguishes the three cases:
--
--   never scanned                  no completed run          leave alone
--   completed, zero verdicts       pass = 0 AND fail = 0     repair
--   genuine zero percent           pass = 0 AND fail > 0     leave alone
--
-- A completed run whose counts are NULL is left alone. Null is missing evidence,
-- not evidence of zero, and guessing which it meant is how the defect being
-- repaired here started.
--
-- WHAT THIS DELIBERATELY DOES NOT TOUCH
--
--   has_critical_findings      preserved. It is derived from failing outcomes,
--                              so it cannot be true on an affected row; the
--                              migration asserts that rather than assuming it.
--   next_scheduled_scan        untouched, so it can never move later. The
--                              compliance-scoring design forbids a migration
--                              from postponing a scheduled scan.
--   current_interval_minutes   untouched. It self-corrects at the next scan,
--                              and the unknown tier is now clamped to no more
--                              than critical, so the stale value cannot be
--                              slower than what the row will get.
--   never-scanned hosts        out of scope. No completed run means no
--                              fabricated score to repair.
--
-- Idempotent: the predicate excludes rows already repaired, so a second run
-- matches nothing. Transactional: goose wraps this statement.
--
-- AUDIT CONTRACT. system-scheduler C-09 requires every update to
-- host_compliance_schedule to emit scheduler.schedule.updated. C-09 was amended
-- on 2026-09-02 to govern RUNTIME APPLICATION updates only, exempting versioned
-- data migrations, and this migration relies on that exemption.
--
-- Why the exemption rather than an event: a migration has no authenticated actor
-- and no request correlation id, so emitting one would mean inventing both.
-- Synthesizing provenance to satisfy a rule about provenance is worse than the
-- gap it closes. Boot-time reconciliation was the alternative and was rejected:
-- it trades a one-time schema correction for recurring startup mutation and
-- multi-process coordination.
--
-- The provenance for this repair is therefore: this migration's version, the
-- CHANGELOG entry naming the reconciliation and the fields it touches, the
-- migration result, and system-scheduler AC-21.
--
-- RATIFIED by the founder on 2026-09-02. Runtime application updates remain
-- fully audited. Versioned data migrations must not fabricate actor or
-- correlation provenance, and instead rely on the migration version, the
-- execution result, the CHANGELOG entry and deterministic reconciliation tests.
--
-- Stated in full here rather than cited. The engineering decision record lives
-- under docs/engineering/, which is gitignored, so a path reference would be
-- dead in any other checkout. Once accepted decisions become tracked, replace
-- this paragraph with the citation.

-- +goose Up

-- +goose StatementBegin
DO $$
DECLARE
    bad_rows integer;
BEGIN
    -- An affected row cannot carry a critical finding, because that flag is
    -- derived from failing outcomes and these hosts produced none. Fail the
    -- migration rather than silently discard a state nobody predicted.
    SELECT count(*) INTO bad_rows
      FROM host_compliance_schedule s
      JOIN (SELECT DISTINCT ON (sr.host_id)
                   sr.host_id, sr.rules_pass, sr.rules_fail
              FROM scan_runs sr
             WHERE sr.status = 'completed'
             ORDER BY sr.host_id, sr.finished_at DESC NULLS LAST, sr.id DESC) l
        ON l.host_id = s.host_id
     WHERE s.has_critical_findings
       AND l.rules_pass IS NOT NULL AND l.rules_fail IS NOT NULL
       AND l.rules_pass = 0 AND l.rules_fail = 0;
    IF bad_rows > 0 THEN
        RAISE EXCEPTION
            'OW-024 repair: % row(s) have has_critical_findings with no pass or fail verdict; investigate before repairing',
            bad_rows;
    END IF;
END $$;
-- +goose StatementEnd

UPDATE host_compliance_schedule s
   SET compliance_state = 'unknown',
       compliance_score = NULL,
       updated_at       = now()
  FROM (SELECT DISTINCT ON (sr.host_id)
               sr.host_id, sr.rules_pass, sr.rules_fail
          FROM scan_runs sr
         WHERE sr.status = 'completed'
         -- Same ordering as host_rule_state_current and
         -- scanruns.LatestCompletedForHost. Two definitions of "most recent
         -- completed scan" that order differently is not a cosmetic mismatch.
         ORDER BY sr.host_id, sr.finished_at DESC NULLS LAST, sr.id DESC) l
 WHERE l.host_id = s.host_id
   AND l.rules_pass IS NOT NULL AND l.rules_fail IS NOT NULL
   AND l.rules_pass = 0 AND l.rules_fail = 0
   AND (s.compliance_state <> 'unknown' OR s.compliance_score IS NOT NULL);

-- +goose Down

-- Deliberately empty.
--
-- The prior values were fabricated: a score of 0 for a host that produced no
-- verdict, and a critical state derived from it. Restoring them would put
-- invented data back, and there is no record of which rows held which invented
-- value. Rolling back the code without this migration is safe: the producer
-- simply resumes writing the old shape, and re-applying repairs it again.
SELECT 1;
