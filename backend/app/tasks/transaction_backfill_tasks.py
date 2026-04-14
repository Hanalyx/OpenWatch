"""
Celery task for backfilling historical scan_findings into the transactions table.

This task migrates rows from scan_findings that do not yet have a corresponding
transactions row. It is resumable (LEFT JOIN excludes already-backfilled rows)
and idempotent (running twice produces no duplicates).

Historical rows are marked with evidence_envelope.schema_version = "0.9" to
distinguish them from live dual-written rows (schema_version = "1.0").
"""

import json
import logging
import time
from typing import Any, Dict

from sqlalchemy import text

from app.database import SessionLocal
from app.utils.mutation_builders import InsertBuilder

logger = logging.getLogger(__name__)

# SQL to find scan_findings rows not yet backfilled to transactions.
# Joins through scans to get host_id. LEFT JOIN transactions to find gaps.
_FIND_UNBACKFILLED_SQL = """
SELECT
    sf.scan_id,
    sf.rule_id,
    s.host_id,
    sf.status,
    sf.severity,
    sf.evidence,
    sf.framework_refs,
    sf.created_at
FROM scan_findings sf
JOIN scans s ON s.id = sf.scan_id
LEFT JOIN transactions t
    ON t.scan_id = sf.scan_id AND t.rule_id = sf.rule_id
WHERE t.id IS NULL
ORDER BY sf.created_at ASC
LIMIT :chunk_size
"""


def _build_evidence_envelope(evidence_json: str, status_str: str) -> str:
    """Build a minimal evidence envelope for backfilled historical rows.

    Args:
        evidence_json: Raw evidence JSON string from scan_findings.evidence.
        status_str: The finding status (pass/fail/skipped).

    Returns:
        JSON string with schema_version "0.9" envelope.
    """
    validate_data = None
    if evidence_json:
        try:
            validate_data = json.loads(evidence_json) if isinstance(evidence_json, str) else evidence_json
        except (json.JSONDecodeError, TypeError):
            validate_data = None

    envelope = {
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
    return json.dumps(envelope)


def backfill_transactions_from_scans(self, chunk_size: int = 10000) -> Dict[str, Any]:
    """Backfill transactions table from historical scan_findings rows.

    Processes in chunks, resumable on interruption, idempotent on re-run.
    Historical rows get evidence_envelope with schema_version = "0.9".

    Args:
        chunk_size: Number of rows to process per chunk (default 10000).

    Returns:
        Dict with total_backfilled count and elapsed_ms.
    """
    db = SessionLocal()
    total_backfilled = 0
    chunk_number = 0
    overall_start = time.monotonic()

    try:
        while True:
            chunk_number += 1
            chunk_start = time.monotonic()

            rows = db.execute(
                text(_FIND_UNBACKFILLED_SQL),
                {"chunk_size": chunk_size},
            ).fetchall()

            if not rows:
                break

            for row in rows:
                evidence_raw = row.evidence
                if isinstance(evidence_raw, dict):
                    evidence_json_str = json.dumps(evidence_raw)
                elif isinstance(evidence_raw, str):
                    evidence_json_str = evidence_raw
                else:
                    evidence_json_str = None

                framework_refs_val = row.framework_refs
                if isinstance(framework_refs_val, dict):
                    framework_refs_json = json.dumps(framework_refs_val)
                elif isinstance(framework_refs_val, str):
                    framework_refs_json = framework_refs_val
                else:
                    framework_refs_json = None

                envelope = _build_evidence_envelope(evidence_json_str, row.status or "unknown")

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
                        "initiator_id",
                        "pre_state",
                        "apply_plan",
                        "validate_result",
                        "post_state",
                        "evidence_envelope",
                        "framework_refs",
                        "baseline_id",
                        "remediation_job_id",
                        "started_at",
                        "completed_at",
                        "duration_ms",
                        "tenant_id",
                    )
                    .values(
                        str(row.host_id),
                        row.rule_id,
                        str(row.scan_id),
                        "validate",
                        row.status,
                        row.severity,
                        "scheduler",
                        None,
                        None,
                        None,
                        evidence_json_str,
                        None,
                        envelope,
                        framework_refs_json,
                        None,
                        None,
                        row.created_at,
                        row.created_at,
                        None,
                        None,
                    )
                )
                query, params = txn_insert.build()
                db.execute(text(query), params)

            db.commit()

            chunk_count = len(rows)
            total_backfilled += chunk_count
            chunk_elapsed_ms = int((time.monotonic() - chunk_start) * 1000)

            logger.info(
                "Backfilled %d transactions (%dms, chunk %d)",
                chunk_count,
                chunk_elapsed_ms,
                chunk_number,
            )

            # If we got fewer rows than chunk_size, we are done
            if chunk_count < chunk_size:
                break

        overall_elapsed_ms = int((time.monotonic() - overall_start) * 1000)
        logger.info(
            "Transaction backfill complete: %d total rows in %dms (%d chunks)",
            total_backfilled,
            overall_elapsed_ms,
            chunk_number,
        )

        return {
            "total_backfilled": total_backfilled,
            "elapsed_ms": overall_elapsed_ms,
            "chunks": chunk_number,
        }

    except TimeoutError:
        logger.error(
            "Transaction backfill exceeded soft time limit after %d rows",
            total_backfilled,
        )
        raise

    except Exception as exc:
        logger.exception("Transaction backfill failed after %d rows: %s", total_backfilled, exc)
        raise

    finally:
        db.close()
