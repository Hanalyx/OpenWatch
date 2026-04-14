"""
Celery task for backfilling host_rule_state from historical scan_findings.

Populates the current-state table and writes transaction rows only for
actual status changes (first seen + each pass<->fail transition), not
for every historical scan.

This replaces the naive backfill_transactions_from_scans approach that
created one transaction per scan_findings row (1.58M rows for 7 hosts).
"""

import json
import logging
import time
from typing import Any, Dict

from sqlalchemy import text

from app.database import SessionLocal
from app.utils.mutation_builders import InsertBuilder

logger = logging.getLogger(__name__)

_FIND_HOST_RULES_SQL = """
SELECT DISTINCT s.host_id, sf.rule_id
FROM scan_findings sf
JOIN scans s ON s.id = sf.scan_id
WHERE NOT EXISTS (
    SELECT 1 FROM host_rule_state hrs
    WHERE hrs.host_id = s.host_id AND hrs.rule_id = sf.rule_id
)
ORDER BY s.host_id, sf.rule_id
LIMIT :chunk_size
"""

_RULE_HISTORY_SQL = """
SELECT sf.status, sf.severity, sf.evidence, sf.framework_refs, sf.created_at
FROM scan_findings sf
JOIN scans s ON s.id = sf.scan_id
WHERE s.host_id = :host_id AND sf.rule_id = :rule_id
ORDER BY sf.created_at ASC
"""

_LATEST_SCAN_ID_SQL = """
SELECT sf.scan_id
FROM scan_findings sf
JOIN scans s ON s.id = sf.scan_id
WHERE s.host_id = :host_id AND sf.rule_id = :rule_id
ORDER BY sf.created_at DESC
LIMIT 1
"""


def _build_envelope(evidence_json, status_str):
    validate_data = None
    if evidence_json:
        try:
            if isinstance(evidence_json, str):
                validate_data = json.loads(evidence_json)
            elif isinstance(evidence_json, (dict, list)):
                validate_data = evidence_json
        except (json.JSONDecodeError, TypeError):
            pass

    return json.dumps(
        {
            "schema_version": "0.9",
            "kensa_version": "unknown",
            "phases": {
                "capture": None,
                "apply": None,
                "validate": validate_data,
                "commit": {"status": status_str},
                "rollback": None,
            },
        }
    )


def _json_str(val):
    if val is None:
        return None
    if isinstance(val, str):
        return val
    return json.dumps(val)


def backfill_host_rule_state(self, chunk_size: int = 5000) -> Dict[str, Any]:
    """Backfill host_rule_state and write transactions only for state changes.

    For each unique (host_id, rule_id) pair in scan_findings:
    1. Read the full history in chronological order
    2. Insert host_rule_state with the latest values
    3. Write transaction rows only for the first occurrence and each
       status change (pass->fail or fail->pass)

    Resumable: skips (host_id, rule_id) pairs that already exist in
    host_rule_state. Idempotent on re-run.
    """
    db = SessionLocal()
    total_pairs = 0
    total_transactions = 0
    chunk_number = 0
    overall_start = time.monotonic()

    try:
        while True:
            chunk_number += 1
            chunk_start = time.monotonic()

            pairs = db.execute(
                text(_FIND_HOST_RULES_SQL),
                {"chunk_size": chunk_size},
            ).fetchall()

            if not pairs:
                break

            for pair in pairs:
                host_id = str(pair.host_id)
                rule_id = pair.rule_id

                history = db.execute(
                    text(_RULE_HISTORY_SQL),
                    {"host_id": host_id, "rule_id": rule_id},
                ).fetchall()

                if not history:
                    continue

                latest_scan = db.execute(
                    text(_LATEST_SCAN_ID_SQL),
                    {"host_id": host_id, "rule_id": rule_id},
                ).fetchone()
                latest_scan_id = str(latest_scan.scan_id) if latest_scan else None

                first = history[0]
                last = history[-1]

                last_framework = _json_str(last.framework_refs)
                envelope = _build_envelope(last.evidence, last.status or "unknown")

                prev_status = None
                last_changed = first.created_at
                if len(history) > 1:
                    for i in range(len(history) - 1, 0, -1):
                        if history[i].status != history[i - 1].status:
                            last_changed = history[i].created_at
                            prev_status = history[i - 1].status
                            break

                state_insert = (
                    InsertBuilder("host_rule_state")
                    .columns(
                        "host_id",
                        "rule_id",
                        "current_status",
                        "severity",
                        "evidence_envelope",
                        "framework_refs",
                        "first_seen_at",
                        "last_checked_at",
                        "last_changed_at",
                        "check_count",
                        "previous_status",
                    )
                    .values(
                        host_id,
                        rule_id,
                        last.status,
                        last.severity,
                        envelope,
                        last_framework,
                        first.created_at,
                        last.created_at,
                        last_changed,
                        len(history),
                        prev_status,
                    )
                    .on_conflict_do_nothing("host_id", "rule_id")
                )
                q, p = state_insert.build()
                db.execute(text(q), p)

                prev = None
                for row in history:
                    if prev is None or prev.status != row.status:
                        ev_json = _json_str(row.evidence)
                        fw_json = _json_str(row.framework_refs)
                        env = _build_envelope(row.evidence, row.status or "unknown")

                        txn_insert = (
                            InsertBuilder("transactions")
                            .columns(
                                "host_id",
                                "rule_id",
                                "scan_id",
                                "phase",
                                "status",
                                "severity",
                                "initiator_type",
                                "validate_result",
                                "evidence_envelope",
                                "framework_refs",
                                "started_at",
                                "completed_at",
                            )
                            .values(
                                host_id,
                                rule_id,
                                latest_scan_id,
                                "validate",
                                row.status,
                                row.severity,
                                "scheduler",
                                ev_json,
                                env,
                                fw_json,
                                row.created_at,
                                row.created_at,
                            )
                        )
                        tq, tp = txn_insert.build()
                        db.execute(text(tq), tp)
                        total_transactions += 1

                    prev = row

                total_pairs += 1

            db.commit()

            chunk_elapsed = int((time.monotonic() - chunk_start) * 1000)
            logger.info(
                "State backfill chunk %d: %d host-rule pairs, %d transactions (%dms)",
                chunk_number,
                len(pairs),
                total_transactions,
                chunk_elapsed,
            )

            if len(pairs) < chunk_size:
                break

        elapsed = int((time.monotonic() - overall_start) * 1000)
        logger.info(
            "State backfill complete: %d pairs, %d transactions in %dms",
            total_pairs,
            total_transactions,
            elapsed,
        )

        return {
            "total_pairs": total_pairs,
            "total_transactions": total_transactions,
            "elapsed_ms": elapsed,
            "chunks": chunk_number,
        }

    except TimeoutError:
        logger.error(
            "State backfill exceeded time limit after %d pairs, %d transactions",
            total_pairs,
            total_transactions,
        )
        raise

    except Exception as exc:
        logger.exception("State backfill failed: %s", exc)
        raise

    finally:
        db.close()
