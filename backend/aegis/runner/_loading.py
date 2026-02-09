"""Rule loading and platform filtering."""

from __future__ import annotations

from pathlib import Path

import yaml


def load_rules(
    path: str | None = None,
    *,
    severity: list[str] | None = None,
    tags: list[str] | None = None,
    category: str | None = None,
) -> list[dict]:
    """Load rules from a file or directory (recursive). Apply optional filters."""
    if path is None:
        raise ValueError("No rules path specified")

    p = Path(path)
    if p.is_file():
        files = [p]
    elif p.is_dir():
        files = sorted(p.rglob("*.yml")) + sorted(p.rglob("*.yaml"))
    else:
        raise FileNotFoundError(f"Rules path not found: {path}")

    rules = []
    for f in files:
        try:
            data = yaml.safe_load(f.read_text())
        except yaml.YAMLError:
            continue
        if not isinstance(data, dict) or "id" not in data:
            continue
        rules.append(data)

    # Apply filters
    if severity:
        sev_set = {s.lower() for s in severity}
        rules = [r for r in rules if r.get("severity", "").lower() in sev_set]
    if tags:
        tag_set = {t.lower() for t in tags}
        rules = [r for r in rules if tag_set & {t.lower() for t in r.get("tags", [])}]
    if category:
        rules = [r for r in rules if r.get("category", "").lower() == category.lower()]

    return rules


def rule_applies_to_platform(rule: dict, family: str, version: int) -> bool:
    """Check if a rule's platforms: constraint matches the detected host.

    Returns True (rule applies) when:
      - The rule has no platforms field at all
      - Any platform entry matches the given family and version range
    """
    platforms = rule.get("platforms")
    if platforms is None:
        return True
    if not platforms:
        return False

    for p in platforms:
        if p.get("family", "") != family:
            continue
        min_v = p.get("min_version", 0)
        max_v = p.get("max_version", 99)
        if min_v <= version <= max_v:
            return True
    return False
