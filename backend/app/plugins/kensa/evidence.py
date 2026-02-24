"""
Evidence serialization helpers for Kensa scan results.

Converts Kensa Evidence dataclass(es) into JSON-serializable strings
suitable for PostgreSQL JSONB columns via InsertBuilder.

InsertBuilder passes values through as-is, so JSONB columns need
explicit json.dumps() — returning a Python dict would fail at INSERT.
"""

import json
import logging
from datetime import datetime
from typing import Any, Optional

logger = logging.getLogger(__name__)


def _evidence_to_dict(evidence: Any) -> dict:
    """Convert a single Evidence object to a JSON-serializable dict.

    Args:
        evidence: Kensa Evidence dataclass instance.

    Returns:
        Dict with string-safe values.
    """
    d = {}
    for field in ("method", "command", "stdout", "stderr", "expected", "actual"):
        val = getattr(evidence, field, None)
        if val is not None:
            d[field] = str(val)

    exit_code = getattr(evidence, "exit_code", None)
    if exit_code is not None:
        d["exit_code"] = int(exit_code)

    ts = getattr(evidence, "timestamp", None)
    if ts is not None:
        if isinstance(ts, datetime):
            d["timestamp"] = ts.isoformat()
        else:
            d["timestamp"] = str(ts)

    return d


def serialize_evidence(result: Any) -> Optional[str]:
    """Convert Kensa result evidence to JSON string for JSONB column.

    Handles single Evidence object or list of Evidence objects
    (compound checks). Returns json.dumps(list_of_dicts) or None
    if no evidence is present.

    Args:
        result: Kensa result object with optional ``evidence`` attribute.

    Returns:
        JSON string for JSONB INSERT, or None for SQL NULL.
    """
    evidence = getattr(result, "evidence", None)
    if evidence is None:
        return None

    try:
        if isinstance(evidence, list):
            items = [_evidence_to_dict(e) for e in evidence if e is not None]
        else:
            items = [_evidence_to_dict(evidence)]

        if not items:
            return None

        return json.dumps(items)
    except Exception:
        logger.debug("Failed to serialize evidence for %s", getattr(result, "rule_id", "?"))
        return None


def serialize_framework_refs(result: Any) -> Optional[str]:
    """Convert Kensa result framework_refs to JSON string for JSONB column.

    Args:
        result: Kensa result object with optional ``framework_refs`` attribute.

    Returns:
        JSON string for JSONB INSERT, or None for SQL NULL.
    """
    refs = getattr(result, "framework_refs", None)
    if not refs:
        return None

    try:
        if isinstance(refs, dict):
            return json.dumps(refs)
        return json.dumps(dict(refs))
    except Exception:
        logger.debug(
            "Failed to serialize framework_refs for %s",
            getattr(result, "rule_id", "?"),
        )
        return None
