"""Write-on-change compliance state management.

Updates host_rule_state on every scan check and writes transaction rows
only when the rule's status changes (pass->fail, fail->pass, first seen).

This module is shared between the Celery scan task and the synchronous
route handler to avoid duplicating write-on-change logic.

Spec: host-rule-state.spec.yaml
"""

import logging
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.utils.mutation_builders import InsertBuilder, UpdateBuilder

logger = logging.getLogger(__name__)


def process_rule_result(
    db: Session,
    host_id: str,
    scan_id: str,
    rule_result: Any,
    status_str: str,
    evidence_json: Optional[str],
    envelope_json: Optional[str],
    framework_json: Optional[str],
    start_time: datetime,
    end_time: datetime,
    duration_ms: int,
    initiator_type: str = "scheduler",
    initiator_id: Optional[str] = None,
) -> bool:
    """Process a single rule result: update state, conditionally write transaction.

    On every call, host_rule_state is updated (last_checked_at, check_count,
    evidence). A transaction row is only written when the status differs from
    the stored state or when the rule is first seen for this host.

    Args:
        db: Database session (caller manages commit).
        host_id: UUID string of the target host.
        scan_id: UUID string of the current scan.
        rule_result: Kensa result object (needs .rule_id, .severity).
        status_str: Normalized status ("pass", "fail", "skipped").
        evidence_json: Serialized evidence for scan_findings/transactions.
        envelope_json: Four-phase evidence envelope JSON string.
        framework_json: Serialized framework references JSON string.
        start_time: Scan start time (UTC).
        end_time: Scan end time (UTC).
        duration_ms: Scan duration in milliseconds.
        initiator_type: "user" or "scheduler".
        initiator_id: User UUID string if initiator_type is "user".

    Returns:
        True if a transaction was written (status changed or first seen),
        False if only the state row was touched (no change).
    """
    existing = db.execute(
        text("SELECT current_status FROM host_rule_state" " WHERE host_id = :hid AND rule_id = :rid"),
        {"hid": host_id, "rid": rule_result.rule_id},
    ).fetchone()

    severity = rule_result.severity or "medium"

    if existing is None:
        # AC-2: First seen -- INSERT state + INSERT transaction
        _insert_state(
            db,
            host_id,
            rule_result.rule_id,
            status_str,
            severity,
            envelope_json,
            framework_json,
            end_time,
        )
        _insert_transaction(
            db,
            host_id,
            rule_result.rule_id,
            scan_id,
            status_str,
            severity,
            evidence_json,
            envelope_json,
            framework_json,
            start_time,
            end_time,
            duration_ms,
            initiator_type,
            initiator_id,
        )
        return True

    elif existing.current_status != status_str:
        # AC-4: Status changed -- UPDATE state + INSERT transaction
        _update_state_changed(
            db,
            host_id,
            rule_result.rule_id,
            status_str,
            severity,
            existing.current_status,
            envelope_json,
            framework_json,
            end_time,
        )
        _insert_transaction(
            db,
            host_id,
            rule_result.rule_id,
            scan_id,
            status_str,
            severity,
            evidence_json,
            envelope_json,
            framework_json,
            start_time,
            end_time,
            duration_ms,
            initiator_type,
            initiator_id,
        )
        return True

    else:
        # AC-3: No change -- UPDATE state only (last_checked_at, check_count, evidence)
        _update_state_unchanged(
            db,
            host_id,
            rule_result.rule_id,
            severity,
            envelope_json,
            framework_json,
            end_time,
        )
        return False


def _insert_state(
    db: Session,
    host_id: str,
    rule_id: str,
    status_str: str,
    severity: str,
    envelope_json: Optional[str],
    framework_json: Optional[str],
    end_time: datetime,
) -> None:
    """Insert a new host_rule_state row (first seen)."""
    builder = (
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
            "check_count",
        )
        .values(
            host_id,
            rule_id,
            status_str,
            severity,
            envelope_json,
            framework_json,
            end_time,
            end_time,
            1,
        )
    )
    q, p = builder.build()
    db.execute(text(q), p)


def _update_state_changed(
    db: Session,
    host_id: str,
    rule_id: str,
    status_str: str,
    severity: str,
    previous_status: str,
    envelope_json: Optional[str],
    framework_json: Optional[str],
    end_time: datetime,
) -> None:
    """Update host_rule_state when status has changed."""
    builder = (
        UpdateBuilder("host_rule_state")
        .set("previous_status", previous_status)
        .set("current_status", status_str)
        .set("severity", severity)
        .set("evidence_envelope", envelope_json)
        .set("framework_refs", framework_json)
        .set("last_checked_at", end_time)
        .set("last_changed_at", end_time)
        .set_raw("check_count", "check_count + 1")
        .where("host_id = :hid", host_id, "hid")
        .where("rule_id = :rid", rule_id, "rid")
    )
    q, p = builder.build()
    db.execute(text(q), p)


def _update_state_unchanged(
    db: Session,
    host_id: str,
    rule_id: str,
    severity: str,
    envelope_json: Optional[str],
    framework_json: Optional[str],
    end_time: datetime,
) -> None:
    """Update host_rule_state when status has NOT changed (evidence refresh only)."""
    builder = (
        UpdateBuilder("host_rule_state")
        .set("severity", severity)
        .set("evidence_envelope", envelope_json)
        .set("framework_refs", framework_json)
        .set("last_checked_at", end_time)
        .set_raw("check_count", "check_count + 1")
        .where("host_id = :hid", host_id, "hid")
        .where("rule_id = :rid", rule_id, "rid")
    )
    q, p = builder.build()
    db.execute(text(q), p)


def _insert_transaction(
    db: Session,
    host_id: str,
    rule_id: str,
    scan_id: str,
    status_str: str,
    severity: str,
    evidence_json: Optional[str],
    envelope_json: Optional[str],
    framework_json: Optional[str],
    start_time: datetime,
    end_time: datetime,
    duration_ms: int,
    initiator_type: str,
    initiator_id: Optional[str],
) -> None:
    """Write a transaction row for a state change or first-seen event."""
    builder = (
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
            "validate_result",
            "post_state",
            "evidence_envelope",
            "framework_refs",
            "started_at",
            "completed_at",
            "duration_ms",
        )
        .values(
            host_id,
            rule_id,
            scan_id,
            "validate",
            status_str,
            severity,
            initiator_type,
            initiator_id,
            None,
            evidence_json,
            None,
            envelope_json,
            framework_json,
            start_time,
            end_time,
            duration_ms,
        )
    )
    q, p = builder.build()
    db.execute(text(q), p)
