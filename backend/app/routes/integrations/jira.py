"""Jira webhook receiver and field-mapping admin for bidirectional sync.

Inbound: receives Jira issue state transitions and updates OpenWatch
compliance exceptions when issues created by OpenWatch are resolved.
Admin: provides a field-mapping configuration endpoint per Jira project.

Spec: specs/services/infrastructure/jira-sync.spec.yaml (AC-4, AC-5, AC-6)
"""

import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.database import get_db
from app.utils.mutation_builders import UpdateBuilder

router = APIRouter(prefix="/jira", tags=["Jira Integration"])
logger = logging.getLogger(__name__)


@router.post("/webhook")
async def receive_jira_webhook(
    request: Request,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Receive Jira issue state transitions.

    When a Jira issue created by OpenWatch changes state (e.g. resolved),
    update the corresponding OpenWatch compliance exception.  Issues are
    correlated via the ``openwatch`` and ``rule-<id>`` labels.

    Args:
        request: FastAPI request containing the Jira webhook JSON body.
        db: Database session.

    Returns:
        Status dict indicating what action was taken.
    """
    body = await request.json()

    event_type = body.get("webhookEvent", "")
    issue = body.get("issue", {})
    fields = issue.get("fields", {})
    labels = fields.get("labels", [])

    # Only process issues created by OpenWatch
    if "openwatch" not in labels:
        return {"status": "ignored", "reason": "not an openwatch issue"}

    if event_type == "jira:issue_updated":
        status_name = fields.get("status", {}).get("name", "").lower()

        if status_name in ("done", "resolved", "closed"):
            # Correlate via rule-<id> labels
            rule_labels = [lbl for lbl in labels if lbl.startswith("rule-")]
            if rule_labels:
                rule_id = rule_labels[0].replace("rule-", "", 1)

                builder = (
                    UpdateBuilder("compliance_exceptions")
                    .set("status", "resolved")
                    .set_raw("updated_at", "CURRENT_TIMESTAMP")
                    .where("rule_id = :rid", rule_id, "rid")
                    .where("status = :cur_status", "approved", "cur_status")
                    .returning("id")
                )
                query, params = builder.build()
                result = db.execute(text(query), params)
                rows = result.fetchall()
                db.commit()

                logger.info(
                    "Jira webhook resolved rule %s -- %d exception(s) updated",
                    rule_id,
                    len(rows),
                )
                return {"status": "updated", "rule_id": rule_id, "rows_affected": len(rows)}

    return {"status": "ok"}


@router.get("/field-mapping")
async def get_field_mapping(
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Return the current Jira field mapping configuration.

    Field mappings define how OpenWatch alert fields map to Jira issue
    fields per project.  Stored in the system_settings table.

    Returns:
        Dict with field_mapping data.
    """
    row = db.execute(
        text("SELECT value FROM system_settings WHERE key = :key"),
        {"key": "jira_field_mapping"},
    ).fetchone()

    if row:
        import json
        return {"field_mapping": json.loads(row[0])}
    return {"field_mapping": {}}


@router.put("/field-mapping")
async def update_field_mapping(
    request: Request,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Update the Jira field mapping configuration.

    Body should be a JSON object with a ``field_mapping`` key containing
    a dict of OpenWatch field names to Jira field names.

    Args:
        request: Request with JSON body.
        db: Database session.

    Returns:
        Confirmation dict.
    """
    import json

    body = await request.json()
    mapping = body.get("field_mapping", {})
    mapping_json = json.dumps(mapping)

    # Upsert into system_settings
    existing = db.execute(
        text("SELECT id FROM system_settings WHERE key = :key"),
        {"key": "jira_field_mapping"},
    ).fetchone()

    if existing:
        builder = (
            UpdateBuilder("system_settings")
            .set("value", mapping_json)
            .set_raw("updated_at", "CURRENT_TIMESTAMP")
            .where("key = :key", "jira_field_mapping", "key")
        )
        query, params = builder.build()
        db.execute(text(query), params)
    else:
        from app.utils.mutation_builders import InsertBuilder
        builder = (
            InsertBuilder("system_settings")
            .columns("key", "value")
            .values("jira_field_mapping", mapping_json)
        )
        query, params = builder.build()
        db.execute(text(query), params)

    db.commit()
    return {"status": "updated", "field_mapping": mapping}
