// Package posture maintains daily per-host compliance posture
// snapshots and serves the trend reads built on them.
//
// The rollup runs on an hourly cron tick (plus once at boot): it
// UPSERTs today's row per scanned host from the live host_rule_state
// aggregate. Intra-day re-scans refresh today's numbers; the row
// freezes when the date rolls over. History therefore accumulates
// going forward - there is no retroactive reconstruction from the
// transactions log.
//
// score_pct is passing over passing plus failing, the one formula in
// internal/compliance. A rule that produced no verdict argues neither
// way about the host, so it enters neither the numerator nor the
// denominator. A host whose scan produced no verdict at all stores no
// score: the column is NULL, which is a different fact from zero.
//
// Each row also records how its number was produced (formula_version,
// aggregation_method, engine_version) and which rule corpus it measured
// against, copied from the scan run the rule state came from. A score
// with no record of the formula and corpus behind it cannot be compared
// with a later one, which is what made the pre-0062 history unusable.
//
// Spec: system-posture-snapshots v1.3.0, system-compliance-scoring.
package posture

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/compliance"
	"github.com/Hanalyx/openwatch/internal/cron"
	"github.com/Hanalyx/openwatch/internal/framework"
)

// ruleStateCorpus is the corpus identity of the scan run that supplied a host's
// current rule state.
//
// It joins scan_runs on last_scan_id rather than re-deriving "the latest
// completed run". host_rule_state_current already filters to exactly that run,
// so every row carries its id, and rediscovering it meant a second copy of the
// ordering that had to stay character-for-character identical to the view's
// forever. Joining the id ties the provenance MECHANICALLY to the run that
// produced the rows being scored: the two cannot disagree, because they are the
// same row.
//
// A run written before migration 0062 has no status, and the caller turns that
// into 'unavailable': the scan happened and its corpus cannot be identified,
// which is not the same as the column not existing yet.
const ruleStateCorpus = `
		  JOIN scan_runs c ON c.id = s.last_scan_id`

// latestCompletedRun is the host's most recent completed scan, with the outcome
// counts it RECORDED and the corpus it measured against.
//
// The counts are the evidence. "This host has no rule state" is a fact about
// rule state, not about the scan, and the two come apart: a run that recorded
// nothing (NULL counts) and a run that recorded outcomes whose rows are missing
// both look identical from host_rule_state_current. Only the run itself can say
// which happened.
//
// This is the one place the rollup still has to say "latest completed run" in
// its own words, and it is unavoidable: the host has NO rule state, so there is
// no last_scan_id to join through. The scored branches join the id instead.
// Ordering matches the host_rule_state_current view, scanruns.LatestCompletedForHost
// and migration 0061.
const latestCompletedRun = `
		SELECT sr.rules_pass, sr.rules_fail, sr.rules_skipped, sr.rules_error,
		       sr.engine_version,
		       sr.corpus_identity_status, sr.corpus_version, sr.corpus_digest
		  FROM scan_runs sr
		 WHERE sr.host_id = h.id AND sr.status = 'completed'
		 ORDER BY sr.finished_at DESC NULLS LAST, sr.id DESC
		 LIMIT 1`

// RollupInterval is the production cadence of the snapshot rollup.
// Hourly is plenty: the row only needs to be right by midnight, and
// each pass is one aggregate UPSERT over a bounded table.
const RollupInterval = time.Hour

// Rollup UPSERTs today's snapshot rows for every live host that has a
// current corpus (internal/corpus): rules the host's most recent
// completed scan actually evaluated. A host with no completed scan has
// no posture to record, and a rule that has left the corpus stops
// counting rather than freezing its last verdict into the trend.
//
// It writes the all-rules series (framework = ”) PLUS one row per
// framework FAMILY the host has rules in, each OS-RESOLVED: a RHEL 9
// host's "stig" row scores its stig_rhel9 rules only (never stig_rhel10),
// matching the host-detail hero tile and list column. Storing every
// family means switching the org default lens just selects a different
// pre-computed series — no recompute, no broken history (compliance-lens
// Phase 3c). Returns the number of rows written (all-rules + per-family).
func Rollup(ctx context.Context, pool *pgxpool.Pool, asOf time.Time) (int, error) {
	// The per-family series expands each rule to the family of its
	// OS-compatible key: a key with no OS suffix (regexp_replace is a no-op,
	// so fk = fam) is OS-neutral (nist_800_53, pci_dss_4, srg); a key equal to
	// fam + '_' + <host os token> is the host's own OS variant (stig_rhel9 on
	// a RHEL 9 host). A wrong-OS variant (stig_rhel10 on a RHEL 9 host) matches
	// neither and is excluded, so a rule contributes to a family at most once.
	computed := `
		SELECT s.host_id, $1::date AS snapshot_date, '' AS framework,
		       COUNT(*) FILTER (WHERE s.current_status = 'pass') AS passing,
		       COUNT(*) FILTER (WHERE s.current_status = 'fail') AS failing,
		       COUNT(*) FILTER (WHERE s.current_status = 'skipped') AS skipped,
		       COUNT(*) FILTER (WHERE s.current_status = 'error') AS error,
		       COUNT(*) AS total,
		       ` + compliance.ScoreSQL(compliance.StatusCountSQL("s", "'pass'"), compliance.StatusCountSQL("s", "'pass','fail'")) + ` AS score_pct,
		       BOOL_OR(s.current_status = 'fail' AND s.severity = 'critical') AS has_critical_findings,
		       2 AS formula_version, 'none' AS aggregation_method, c.engine_version,
		       COALESCE(c.corpus_identity_status, 'unavailable') AS corpus_identity_status,
		       c.corpus_version, c.corpus_digest
		  FROM host_rule_state_current s
		  JOIN hosts h ON h.id = s.host_id AND h.deleted_at IS NULL
		  ` + ruleStateCorpus + `
		 GROUP BY s.host_id, c.engine_version,
		          c.corpus_identity_status, c.corpus_version, c.corpus_digest
		UNION ALL
		SELECT e.host_id, $1::date, e.fam,
		       COUNT(*) FILTER (WHERE e.current_status = 'pass'),
		       COUNT(*) FILTER (WHERE e.current_status = 'fail'),
		       COUNT(*) FILTER (WHERE e.current_status = 'skipped'),
		       COUNT(*) FILTER (WHERE e.current_status = 'error'),
		       COUNT(*),
		       ` + compliance.ScoreSQL(compliance.StatusCountSQL("e", "'pass'"), compliance.StatusCountSQL("e", "'pass','fail'")) + `,
		       BOOL_OR(e.current_status = 'fail' AND e.severity = 'critical'),
		       2, 'none', e.engine_version,
		       COALESCE(e.corpus_identity_status, 'unavailable'),
		       e.corpus_version, e.corpus_digest
		  FROM (
		      SELECT s.host_id, s.current_status, s.severity, c.engine_version,
		             c.corpus_identity_status, c.corpus_version, c.corpus_digest,
		             regexp_replace(fk, '` + framework.OSSuffixSQL + `', '') AS fam
		        FROM host_rule_state_current s
		        JOIN hosts h ON h.id = s.host_id AND h.deleted_at IS NULL
		        ` + ruleStateCorpus + `
		        CROSS JOIN LATERAL jsonb_object_keys(s.framework_refs) AS fk
		       WHERE fk = regexp_replace(fk, '` + framework.OSSuffixSQL + `', '')
		          OR fk = regexp_replace(fk, '` + framework.OSSuffixSQL + `', '')
		                  || '_' || lower(h.os_family) || split_part(h.os_version, '.', 1)
		  ) e
		 GROUP BY e.host_id, e.fam, e.engine_version,
		          e.corpus_identity_status, e.corpus_version, e.corpus_digest
		UNION ALL
		-- The scanned host that produced NOTHING.
		--
		-- host_rule_state_current has no row for it, so neither branch above
		-- emits one and the UPSERT has nothing to update. Without this branch a
		-- host whose newest scan returned no outcome either vanishes from the
		-- day entirely or keeps the score its PREVIOUS scan wrote, presented as
		-- current. That is bugs/OW-024 one layer out: the absence of source rows
		-- preserving a stale verdict.
		--
		-- THE EVIDENCE IS THE SCAN RUN, NOT THE MISSING ROWS. "No rule state"
		-- has several causes and only one of them is "the scan assessed nothing".
		-- A run whose counts are NULL recorded no evidence either way, and a run
		-- reporting outcomes whose rule-state write is missing is a broken write,
		-- not an unassessable host. Writing zero counts for either would invent
		-- the measurement, which is the exact mistake migration 0061 exists to
		-- undo. So all four counts must be present AND zero.
		--
		-- All FOUR counts, not just pass and fail: a skipped rule writes rule
		-- state like any other, so a run reporting forty skips and no rows is a
		-- broken write too. The only run that proves nothing was assessed is one
		-- that recorded nothing at all.
		--
		-- The IS NOT NULL clauses are redundant with the equalities: NULL = 0 is
		-- NULL, not true, so three-valued logic already rejects a run with no
		-- counts. They are kept because they state the rule the equalities only
		-- imply, and they are what still holds if someone rewrites the
		-- comparison as COALESCE(rules_pass, 0) = 0, which reads as a tidy-up
		-- and would silently make every NULL-count run qualify.
		--
		-- Fail-closed: a host that does not meet that bar contributes NO row
		-- here. It is then absent from computed entirely, so the prune skips it
		-- too and the day is left exactly as it was. Saying nothing is the only
		-- honest option when the evidence does not say anything.
		SELECT h.id, $1::date, '',
		       0, 0, 0, 0, 0,
		       NULL::numeric,
		       false,
		       2, 'none', r.engine_version,
		       COALESCE(r.corpus_identity_status, 'unavailable'),
		       r.corpus_version, r.corpus_digest
		  FROM hosts h
		  JOIN LATERAL (` + latestCompletedRun + `) r ON true
		 WHERE h.deleted_at IS NULL
		   AND r.rules_pass IS NOT NULL AND r.rules_fail IS NOT NULL
		   AND r.rules_skipped IS NOT NULL AND r.rules_error IS NOT NULL
		   AND r.rules_pass = 0 AND r.rules_fail = 0
		   AND r.rules_skipped = 0 AND r.rules_error = 0
		   AND NOT EXISTS (SELECT 1 FROM host_rule_state_current s2
		                    WHERE s2.host_id = h.id)`

	// ONE statement, so both halves read ONE database snapshot.
	//
	// This was two statements in a transaction, which proved rollback atomicity
	// and nothing else: under Read Committed each statement takes a FRESH
	// snapshot, so a scan completing between them let the upsert see scan A
	// while the prune saw scan B, committing a day that reflects neither.
	//
	// MATERIALIZED forces computed to be evaluated exactly once and shared. The
	// two data-modifying CTEs touch disjoint rows by construction (the upsert
	// writes what IS in computed, the prune deletes what is NOT), so the order
	// PostgreSQL runs them in cannot matter.
	q := `
		WITH computed AS MATERIALIZED (` + computed + `),
		upserted AS (
		INSERT INTO posture_snapshots
			(host_id, snapshot_date, framework, passing, failing, skipped, error, total,
			 score_pct, has_critical_findings, updated_at,
			 formula_version, aggregation_method, engine_version,
			 corpus_identity_status, corpus_version, corpus_digest)
		SELECT host_id, snapshot_date, framework, passing, failing, skipped, error, total,
		       score_pct, has_critical_findings, now(),
		       formula_version, aggregation_method, engine_version,
		       corpus_identity_status, corpus_version, corpus_digest
		  FROM computed
		ON CONFLICT (host_id, snapshot_date, framework) DO UPDATE
		   SET passing               = EXCLUDED.passing,
		       failing               = EXCLUDED.failing,
		       skipped               = EXCLUDED.skipped,
		       error                 = EXCLUDED.error,
		       total                 = EXCLUDED.total,
		       score_pct             = EXCLUDED.score_pct,
		       has_critical_findings = EXCLUDED.has_critical_findings,
		       updated_at            = now(),
		       -- The provenance is refreshed with the number. Leaving these out
		       -- would let today's row, first written by an older release, keep
		       -- a NULL formula version beside a score this release computed:
		       -- a number described by provenance that does not belong to it.
		       formula_version        = EXCLUDED.formula_version,
		       aggregation_method     = EXCLUDED.aggregation_method,
		       engine_version         = EXCLUDED.engine_version,
		       corpus_identity_status = EXCLUDED.corpus_identity_status,
		       corpus_version         = EXCLUDED.corpus_version,
		       corpus_digest          = EXCLUDED.corpus_digest
		   RETURNING 1
		),
		-- Prune today's rows the current scan no longer produces.
		--
		-- A framework series is written only while the host carries rules mapped
		-- to that family. When the newest scan stops producing one, the UPSERT
		-- simply never touches that row, and yesterday's stig score sits in
		-- today's slot reading as current. Same defect as the zero-outcome
		-- branch above, one series in rather than one host.
		--
		-- Scoped to hosts the pass actually covered: a host absent from computed
		-- was not measured by this pass, whether because it has never completed
		-- a scan or because its latest run carries no usable evidence. Its rows
		-- are left alone rather than deleted for not being recomputed.
		pruned AS (
		DELETE FROM posture_snapshots p
		 WHERE p.snapshot_date = $1::date
		   AND EXISTS (SELECT 1 FROM computed c WHERE c.host_id = p.host_id)
		   AND NOT EXISTS (SELECT 1 FROM computed c
		                    WHERE c.host_id = p.host_id AND c.framework = p.framework)
		   RETURNING 1
		)
		SELECT (SELECT count(*) FROM upserted)::int,
		       (SELECT count(*) FROM pruned)::int`

	// version.Kensa() is deliberately NOT passed. The engine version comes from
	// each host's own scan run, so a rollup process on a different build cannot
	// stamp its own version onto outcomes another process produced.
	var written, pruned int
	if err := pool.QueryRow(ctx, q, asOf.UTC()).Scan(&written, &pruned); err != nil {
		return 0, fmt.Errorf("posture: rollup: %w", err)
	}
	return written, nil
}

// Run wires the rollup to an hourly cron tick, with one immediate
// pass at start so a fresh boot (or fresh install) has today's row
// without waiting an hour. Mirrors the scheduler's Run shape.
func Run(ctx context.Context, pool *pgxpool.Pool, interval time.Duration) *cron.Scheduler {
	if interval == 0 {
		interval = RollupInterval
	}
	// Immediate first pass: the ticker's first fire is one full
	// interval out, and a fresh boot should have today's row now.
	if n, err := Rollup(ctx, pool, time.Now()); err != nil {
		slog.WarnContext(ctx, "posture boot rollup failed", "err", err)
	} else {
		slog.InfoContext(ctx, "posture rollup started", "hosts", n,
			"interval", interval.String())
	}
	tick := cron.New(interval, func(ctx context.Context) error {
		n, err := Rollup(ctx, pool, time.Now())
		if err != nil {
			slog.ErrorContext(ctx, "posture rollup failed", "err", err)
			return err
		}
		slog.DebugContext(ctx, "posture rollup", "hosts", n)
		return nil
	})
	tick.Start(ctx)
	return tick
}

// DayPoint is one day of a host's trend.
//
// Score can be absent. A day whose rules produced no verdict has no score, and
// a bare float64 here would have to render that as 0.0, putting the host at the
// bottom of the chart for a day nothing could be measured. That is the defect
// bugs/OW-023 and OW-024 record, one surface further out.
type DayPoint struct {
	Date time.Time
	// FormulaStatus is identified or legacy_unknown, never mixed. A snapshot row
	// is one host on one date under one lens, so it holds a single formula and
	// there is nothing on a host point for versions to disagree about. The
	// FLEET point is where they can meet, which is why mixed exists at all.
	FormulaStatus compliance.FormulaStatus
	Score         compliance.Score
	Passing       int
	Failing       int
	Total         int

	// Provenance recorded ON THE SNAPSHOT, not read from this process. Engines
	// is empty for a point whose scan predates migration 0063, which means
	// nothing recorded which engine produced it.
	Engines       []compliance.EngineContributor
	CorpusStatus  compliance.CorpusIdentityStatus
	CorpusVersion *string
	CorpusDigest  *string
}

// HostTrend returns the host's snapshots for one LENS over the trailing
// N days (today inclusive), oldest first. lens is a framework FAMILY id
// (stig, cis, nist_800_53, …) whose stored series is the host's
// OS-resolved score for that family; "" is the all-rules series. A
// specific corpus key is normalized to its family (stig_rhel9 -> stig)
// since the snapshot stores per family. Days without a snapshot are
// simply absent - the chart renders the gaps.
func HostTrend(ctx context.Context, pool *pgxpool.Pool, hostID uuid.UUID, days int, lens string) ([]DayPoint, error) {
	rows, err := pool.Query(ctx, `
		SELECT snapshot_date, score_pct, passing, failing, total, formula_version,
		       engine_version, corpus_identity_status, corpus_version, corpus_digest
		  FROM posture_snapshots
		 WHERE host_id = $1
		   AND framework = $3
		   AND snapshot_date > current_date - $2::int
		 ORDER BY snapshot_date`, hostID, days, framework.FamilyOf(lens))
	if err != nil {
		return nil, fmt.Errorf("posture: host trend: %w", err)
	}
	defer rows.Close()
	var out []DayPoint
	for rows.Next() {
		var p DayPoint
		var pct *float64
		var formula *int
		var engine, corpusStatus *string
		if err := rows.Scan(&p.Date, &pct, &p.Passing, &p.Failing, &p.Total, &formula,
			&engine, &corpusStatus, &p.CorpusVersion, &p.CorpusDigest); err != nil {
			return nil, fmt.Errorf("posture: scan trend row: %w", err)
		}
		score, err := compliance.ScoreFromNullable(pct)
		if err != nil {
			return nil, fmt.Errorf("posture: host trend score: %w", err)
		}
		p.Score = score
		// A host point is one snapshot, so at most ONE contributor, and only
		// when that snapshot produced a score. A point with no score contributed
		// to none, which is what the envelope's counts have to reconcile with.
		if engine != nil && *engine != "" && score.Present() {
			p.Engines = []compliance.EngineContributor{
				{EngineVersion: *engine, ContributorsScored: 1},
			}
		}
		// A row with no recorded status predates migration 0062. It cannot name
		// a corpus, which is what unavailable says.
		p.CorpusStatus = compliance.CorpusUnavailable
		if corpusStatus != nil && *corpusStatus != "" {
			p.CorpusStatus = compliance.CorpusIdentityStatus(*corpusStatus)
		}
		p.FormulaStatus = compliance.FormulaLegacyUnknown
		if formula != nil && *formula == 2 {
			p.FormulaStatus = compliance.FormulaIdentified
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// FleetDayPoint is one day of the fleet trend.
//
// Score is the EQUAL-HOST MEAN of that day's per-host scores: every host counts
// once, whatever its rule count. Hosts is every host with a snapshot that day;
// HostsScored is how many of them produced a score. The two differ whenever a
// host could not be assessed, and reporting only the first would describe a
// mean over a population that did not produce it.
type FleetDayPoint struct {
	Date time.Time
	// FormulaStatus says which scoring formula produced the day's rows, so a
	// consumer can tell an identified score from a preserved legacy one, and
	// both from a day that has no score because its rows disagree. Score is
	// ABSENT when FormulaStatus is mixed, and when no host scored.
	FormulaStatus compliance.FormulaStatus
	Score         compliance.Score

	// Engines are every distinct engine version behind the day's snapshots,
	// sorted. More than one is normal mid-upgrade. HostsWithoutCorpusIdentity
	// counts the day's snapshots whose corpus could not be named.
	Engines                    []compliance.EngineContributor
	HostsWithoutEngineIdentity int
	Corpora                    []compliance.CorpusContributor
	HostsWithoutCorpusIdentity int

	Hosts             int
	HostsScored       int
	HostsWithoutScore int
	Failing           int
	CriticalHosts     int
}

// FleetTrend returns per-day fleet aggregates over the trailing N
// days, oldest first: average score across snapshotted hosts, host
// count, total failing rules, and hosts carrying critical findings.
// Soft-deleted hosts are excluded even when their snapshots linger.
func FleetTrend(ctx context.Context, pool *pgxpool.Pool, days int, lens string) ([]FleetDayPoint, error) {
	// AVG over one row per host IS the equal-host mean, and SQL AVG skips NULLs
	// rather than averaging them as zero, so an unassessable host is omitted
	// from the mean instead of dragging it down. That is the same rule as
	// compliance.MeanOfHostScores, and the conformance test proves the two
	// agree rather than trusting this comment.
	//
	// A version-2 row is aggregated from its STORED COUNTS, not from its stored
	// score_pct. score_pct is rounded to one decimal, and averaging rounded
	// values then rounding again is a different function: two hosts at 0/1 and
	// 2/3 give 33.3 from the counts and 33.4 from the rounded scores.
	//
	// A row written before the redesign carries no formula version and no usable
	// counts under this formula, so its stored score is used as it stands. Its
	// semantics are whatever they were on the day it was written, and this query
	// is not the place to reinterpret them.
	hostPct := `CASE WHEN p.formula_version = 2
	                 THEN ` + compliance.ScorePctSQL("p.passing", "p.passing + p.failing") + `
	                 ELSE p.score_pct::numeric END`

	// A day whose rows carry MORE THAN ONE formula version has no fleet score.
	//
	// Two formulas produce two different quantities. Averaging them yields a
	// number that is not a compliance score under either, and nothing in the
	// result would say so. This is reachable in normal operation, not just on
	// upgrade day: the rollup rewrites a host's row to version 2 only when it
	// can measure the host, so a host that fails closed keeps its legacy row
	// for as long as its scans produce no usable evidence.
	//
	// Publishing no score is the choice here, over publishing one point per
	// formula version. Two lines on one chart invite exactly the comparison
	// that is invalid. The day still reports its host counts and its formula
	// status, so a consumer can say WHY there is no number instead of showing a
	// gap. Ratified 2026-09-03; system-posture-snapshots C-11.
	status := compliance.FormulaStatusSQL("p.formula_version")

	rows, err := pool.Query(ctx, `
		SELECT p.snapshot_date,
		       CASE WHEN (`+status+`) = 'mixed' THEN NULL
		            ELSE `+compliance.MeanScoreSQL(hostPct)+` END,
		       `+status+`,
		       COUNT(*)::int,
		       COUNT(*) FILTER (WHERE `+hostPct+` IS NOT NULL)::int,
		       COUNT(*) FILTER (WHERE `+hostPct+` IS NULL)::int,
		       COALESCE(SUM(p.failing), 0)::int,
		       COUNT(*) FILTER (WHERE p.has_critical_findings)::int,
		       -- Provenance recorded on the day's SCORED snapshots, with counts.
		       -- Scored only, because the envelope counts contributors to a
		       -- SCORE: a snapshot with no score contributed to none, and
		       -- including it made the accounting disagree with hosts_scored.
		       COALESCE(
		           (SELECT jsonb_agg(jsonb_build_object(
		                       'engine_version', e.engine_version,
		                       'contributors_scored', e.n)
		                   ORDER BY e.engine_version)
		              FROM (SELECT p2.engine_version, COUNT(*)::int AS n
		                      FROM posture_snapshots p2
		                      JOIN hosts h2 ON h2.id = p2.host_id AND h2.deleted_at IS NULL
		                     WHERE p2.snapshot_date = p.snapshot_date
		                       AND p2.framework = $2
		                       AND p2.engine_version IS NOT NULL
		                       AND (CASE WHEN p2.formula_version = 2
		                                 THEN p2.passing + p2.failing > 0
		                                 ELSE p2.score_pct IS NOT NULL END)
		                     GROUP BY p2.engine_version) e),
		           '[]'::jsonb),
		       COUNT(*) FILTER (WHERE `+hostPct+` IS NOT NULL
		                          AND p.engine_version IS NULL)::int,
		       COUNT(*) FILTER (WHERE `+hostPct+` IS NOT NULL
		                          AND p.corpus_identity_status IS DISTINCT FROM 'identified')::int,
		       -- Corpus contributors over the SCORED snapshots, same shape as
		       -- the engines. Without them the handler could only assert
		       -- "unavailable" and had to count every scored host as lacking an
		       -- identity, which contradicted a day where some named one.
		       COALESCE(
		           (SELECT jsonb_agg(jsonb_build_object(
		                       'corpus_version', c.corpus_version,
		                       'corpus_digest', c.corpus_digest,
		                       'contributors_scored', c.n)
		                   ORDER BY c.corpus_digest)
		              FROM (SELECT p3.corpus_version, p3.corpus_digest, COUNT(*)::int AS n
		                      FROM posture_snapshots p3
		                      JOIN hosts h3 ON h3.id = p3.host_id AND h3.deleted_at IS NULL
		                     WHERE p3.snapshot_date = p.snapshot_date
		                       AND p3.framework = $2
		                       AND p3.corpus_identity_status = 'identified'
		                       AND p3.corpus_digest IS NOT NULL
		                       AND (CASE WHEN p3.formula_version = 2
		                                 THEN p3.passing + p3.failing > 0
		                                 ELSE p3.score_pct IS NOT NULL END)
		                     GROUP BY p3.corpus_version, p3.corpus_digest) c),
		           '[]'::jsonb)
		  FROM posture_snapshots p
		  JOIN hosts h ON h.id = p.host_id AND h.deleted_at IS NULL
		 WHERE p.framework = $2
		   AND p.snapshot_date > current_date - $1::int
		 GROUP BY p.snapshot_date
		 ORDER BY p.snapshot_date`, days, framework.FamilyOf(lens))
	if err != nil {
		return nil, fmt.Errorf("posture: fleet trend: %w", err)
	}
	defer rows.Close()
	var out []FleetDayPoint
	for rows.Next() {
		var p FleetDayPoint
		var avg *float64
		var status string
		var engineRows []struct {
			EngineVersion      string `json:"engine_version"`
			ContributorsScored int    `json:"contributors_scored"`
		}
		var corpusRows []struct {
			CorpusVersion      *string `json:"corpus_version"`
			CorpusDigest       string  `json:"corpus_digest"`
			ContributorsScored int     `json:"contributors_scored"`
		}
		if err := rows.Scan(&p.Date, &avg, &status, &p.Hosts, &p.HostsScored,
			&p.HostsWithoutScore, &p.Failing, &p.CriticalHosts,
			&engineRows, &p.HostsWithoutEngineIdentity,
			&p.HostsWithoutCorpusIdentity, &corpusRows); err != nil {
			return nil, fmt.Errorf("posture: scan fleet row: %w", err)
		}
		p.FormulaStatus = compliance.FormulaStatus(status)
		if !p.FormulaStatus.Valid() {
			return nil, fmt.Errorf("posture: fleet trend: unknown formula status %q", status)
		}
		for _, e := range engineRows {
			p.Engines = append(p.Engines, compliance.EngineContributor{
				EngineVersion: e.EngineVersion, ContributorsScored: e.ContributorsScored,
			})
		}
		for _, c := range corpusRows {
			p.Corpora = append(p.Corpora, compliance.CorpusContributor{
				Version: c.CorpusVersion, Digest: c.CorpusDigest,
				ContributorsScored: c.ContributorsScored,
			})
		}
		score, err := compliance.ScoreFromNullable(avg)
		if err != nil {
			return nil, fmt.Errorf("posture: fleet trend score: %w", err)
		}
		p.Score = score
		out = append(out, p)
	}
	return out, rows.Err()
}
