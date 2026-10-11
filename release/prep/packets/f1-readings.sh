# shellcheck shell=sh
# F1 server readings (release-packets): one scan's records, read-only, after
# the release captain ran it from the UI. Inputs: OW_SCAN_ID (a UUID, checked
# by the tool), OW_URL.
version_endpoint() {
    code=$(curl -sk --connect-timeout 3 --max-time 10 -o "$WORK/version.json" \
        -w '%{http_code}' "$OW_URL/api/v1/version") || return 1
    cat -- "$WORK/version.json"
    echo
    echo "http $code"
    [ "$code" = 200 ]
}
scan_run() {
    read_sql -v scan="$OW_SCAN_ID" -f - <<'SQL'
\pset tuples_only off
SELECT id, host_id, trigger_source, requested_by, status, queued_at, started_at,
       finished_at, rules_pass, rules_fail, rules_skipped, rules_error,
       engine_version, corpus_version, corpus_digest, correlation_id
  FROM scan_runs WHERE id = :'scan';
SQL
}
result_counts() {
    read_sql -v scan="$OW_SCAN_ID" -f - <<'SQL'
SELECT status, count(*) FROM scan_results WHERE scan_id = :'scan'
 GROUP BY status ORDER BY status;
SQL
}
skip_reasons() {
    read_sql -v scan="$OW_SCAN_ID" -f - <<'SQL'
SELECT count(*), COALESCE(skip_reason, '(none recorded)') FROM scan_results
 WHERE scan_id = :'scan' AND status = 'skipped'
 GROUP BY skip_reason ORDER BY count(*) DESC, 2;
SQL
}
# The scan's audit trail. scan.queued names the scan in its detail; the
# worker emits scan.started, completed or failed under the correlation id the
# run row records (queue.Dequeue restores the job's id). Bound by id, never
# by a time window.
audit_trail() {
    read_sql -v scan="$OW_SCAN_ID" -f - <<'SQL'
SELECT e.occurred_at, e.action, e.actor_type, COALESCE(e.actor_id, ''),
       COALESCE(e.actor_label, ''), e.correlation_id
  FROM audit_events e, scan_runs r
 WHERE r.id = :'scan'
   AND ((e.action = 'scan.queued' AND e.detail->>'scan_id' = r.id::text)
     OR (e.action IN ('scan.started', 'scan.completed', 'scan.failed')
         AND e.correlation_id = r.correlation_id
         AND e.detail->>'host_id' = r.host_id::text))
 ORDER BY e.occurred_at, e.action;
SQL
}
# The run's counts are integer and count(*) is bigint; PostgreSQL will not
# compare records whose columns differ in type, so the run side is cast.
# Exits 1 unless the run completed, has result rows, its own counts equal the
# rows by status, and its trail holds exactly one queued and one completed
# event and no failed one. The readings above are printed either way.
consistent() {
    read_sql -v scan="$OW_SCAN_ID" -t -f - > "$WORK/check" <<'SQL'
WITH r AS (SELECT * FROM scan_runs WHERE id = :'scan'),
     c AS (SELECT count(*) FILTER (WHERE status = 'pass') AS p,
                  count(*) FILTER (WHERE status = 'fail') AS f,
                  count(*) FILTER (WHERE status = 'skipped') AS s,
                  count(*) FILTER (WHERE status = 'error') AS e,
                  count(*) AS n
             FROM scan_results WHERE scan_id = :'scan'),
     a AS (SELECT count(*) FILTER (WHERE e.action = 'scan.queued') AS q,
                  count(*) FILTER (WHERE e.action = 'scan.completed') AS d,
                  count(*) FILTER (WHERE e.action = 'scan.failed') AS x
             FROM audit_events e, r
            WHERE (e.action = 'scan.queued' AND e.detail->>'scan_id' = r.id::text)
               OR (e.action IN ('scan.completed', 'scan.failed')
                   AND e.correlation_id = r.correlation_id
                   AND e.detail->>'host_id' = r.host_id::text))
SELECT CASE
  WHEN NOT EXISTS (SELECT 1 FROM r) THEN 'no such scan'
  WHEN (SELECT status FROM r) <> 'completed' THEN 'scan is ' || (SELECT status FROM r)
  WHEN (SELECT n FROM c) = 0 THEN 'no result rows'
  WHEN (SELECT (rules_pass::bigint, rules_fail::bigint, rules_skipped::bigint,
                rules_error::bigint) FROM r)
       IS DISTINCT FROM (SELECT (p, f, s, e) FROM c)
       THEN 'run counts differ from result rows'
  WHEN (SELECT q FROM a) <> 1 THEN 'scan.queued events: ' || (SELECT q FROM a)
  WHEN (SELECT d FROM a) <> 1 THEN 'scan.completed events: ' || (SELECT d FROM a)
  WHEN (SELECT x FROM a) <> 0 THEN 'scan.failed events: ' || (SELECT x FROM a)
  ELSE 'consistent' END;
SQL
    rc=$?
    cat -- "$WORK/check"
    [ "$rc" -eq 0 ] && [ "$(cat -- "$WORK/check")" = consistent ]
}
section "hostname" hostname
section "machine-id" cat -- "$R/etc/machine-id"
section "openwatch --version" openwatch --version
section "version endpoint" version_endpoint
section "scan run" scan_run
section "result counts" result_counts
section "skip reasons" skip_reasons
section "audit trail" audit_trail
section "consistency" consistent
finish "F1 readings"
