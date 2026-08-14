-- +goose Up
-- Scope compliance scores to the rules a host's last scan actually ran.
--
-- host_rule_state holds one row per (host, rule) and is only ever UPSERTed.
-- Nothing prunes it. When a rule leaves the corpus, because it was merged,
-- renamed, dropped, or because the host moved to a curated corpus, its last
-- verdict stays in the table forever and keeps counting toward every score.
--
-- A rule that was failing when it left stays failing forever. No scan clears
-- it, because it is never evaluated again. No remediation fixes it, because
-- Kensa has no handler for a rule it no longer ships. The row is unreachable
-- by every mechanism that could change it, and it still votes. The Kensa
-- v0.10.0 rule merge freezes 34 rows across 17 hosts this way, so each
-- affected host gets scored on a merged rule and on both dead predecessors.
--
-- Spec: system-current-corpus C-01, C-12, C-16.

-- The definition lives here and only here. A Go helper pasting the same
-- predicate into every caller would leave the twelfth read site free to skip
-- it, and no guard could tell a missing call from a hand-rolled one. As a
-- view, the rule the guard enforces is simply that no current-score read may
-- name the bare table.
--
-- The column set MUST match host_rule_state exactly, so moving a read is a
-- one-word change to its FROM clause. SELECT * captures that by construction:
-- Postgres freezes the column list at creation time, so a later ALTER TABLE
-- does not silently change what the view exposes.
CREATE VIEW host_rule_state_current AS
SELECT hrs.*
  FROM host_rule_state hrs
 WHERE hrs.last_scan_id = (
       SELECT sr.id
         FROM scan_runs sr
        WHERE sr.host_id = hrs.host_id
          AND sr.status = 'completed'
        ORDER BY sr.finished_at DESC NULLS LAST, sr.id DESC
        LIMIT 1);

COMMENT ON VIEW host_rule_state_current IS
    'Rows the host''s most recent completed scan evaluated. The only '
    'definition of a host''s current corpus; every current-score read uses '
    'it. A host with no completed scan yields no rows, which callers render '
    'as no data, never as zero percent. Spec system-current-corpus C-01.';

-- ORDER BY above is character-for-character scanruns.LatestCompletedForHost,
-- which backs the compliance lens scan_context: the line telling an operator
-- WHICH scan the score in front of them describes. Two definitions of "most
-- recent completed scan" that order differently is not a cosmetic mismatch.
-- Rows are written by whichever scan finished LAST, so last_scan_id follows
-- finished_at. Ordering by queued_at would name a run matching no rows, and
-- a host holding a complete set of fresh results would show an EMPTY corpus.
-- That is the characteristic OpenWatch defect: a declared surface silently
-- carrying nothing. Change one ordering and you MUST change the other.

-- scan_runs_host_recent is keyed (host_id, queued_at DESC) and carries no
-- status, so it cannot serve the lookup above. scan_runs grows one row per
-- host per scan forever, so without this the view sorts a host's whole scan
-- history on every probe. Partial on completed keeps it small, and carrying
-- id DESC puts the tiebreak in the probe rather than in a sort on top of it.
--
-- NULLS LAST is written out rather than left to the default. In Postgres
-- DESC implies NULLS FIRST, so an index declared (finished_at DESC) does not
-- match an ORDER BY of (finished_at DESC NULLS LAST) and the planner puts a
-- Sort on top of the index scan, which is the cost this index exists to
-- remove. Verified on the plan: without NULLS LAST the probe sorts.
CREATE INDEX scan_runs_host_latest_completed
    ON scan_runs (host_id, finished_at DESC NULLS LAST, id DESC)
    WHERE status = 'completed';

-- Repair rows an earlier remediation corrupted.
--
-- worker.flipRuleToPass built a result carrying no framework refs, so Go
-- marshaled a nil map to the JSON scalar null and the UPSERT wrote it
-- through. JSON null is not SQL NULL, so the column's NOT NULL DEFAULT '{}'
-- never applied and the row landed holding a scalar. posture.Rollup calls
-- jsonb_object_keys over every live host in ONE statement, so a single such
-- row aborts it and NO host gets a snapshot that day. The writer no longer
-- produces these, but existing rows keep failing the rollup fleet-wide on
-- every attempt until each affected rule is rescanned.
--
-- The values are recoverable. scan_results is the audit memory: it holds
-- framework_refs and severity per (scan_id, rule_id) for every rule of every
-- scan, and no remediation path writes to it.
--
-- What this does NOT do. It restores the mapping the most recent scan
-- recorded, not today's mapping. A rule whose framework mapping changed
-- since that scan gets the older one, which corrects on its next scan. This
-- is a repair, not a recovery of intent.
--
-- Runs of ANY status are eligible here, deliberately, unlike the view above
-- which admits only completed runs. The two are answering different
-- questions. The view asks which rules a host is currently measured against,
-- where a partial run must not count. This asks what a rule's framework
-- mapping is, which comes from the rule definition and is the same whether
-- the scan that recorded it went on to finish. Filtering to completed runs
-- would drop rows to the '{}' floor below that we can actually recover.
UPDATE host_rule_state hrs
   SET framework_refs = latest.framework_refs,
       severity       = COALESCE(hrs.severity, latest.severity)
  FROM (
      SELECT DISTINCT ON (sr2.host_id, sr2.rule_id)
             sr2.host_id, sr2.rule_id, sr2.framework_refs, sr2.severity
        FROM scan_results sr2
        JOIN scan_runs run ON run.id = sr2.scan_id
       ORDER BY sr2.host_id, sr2.rule_id,
                run.finished_at DESC NULLS LAST, run.id DESC
  ) latest
 WHERE hrs.host_id = latest.host_id
   AND hrs.rule_id = latest.rule_id
   AND hrs.framework_refs = 'null'::jsonb;

-- Floor for rows written before migration 0029 created scan_results, which
-- therefore have no scan_results row to recover from. For these the original
-- refs really are gone. This converts a fleet-wide rollup failure into a
-- per-rule scoring gap that self-heals on the rule's next scan.
UPDATE host_rule_state
   SET framework_refs = '{}'::jsonb
 WHERE framework_refs = 'null'::jsonb;

-- +goose Down
DROP INDEX IF EXISTS scan_runs_host_latest_completed;
DROP VIEW IF EXISTS host_rule_state_current;
