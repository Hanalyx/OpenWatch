"""Implementation selection based on capability gates."""

from __future__ import annotations


def evaluate_when(when, capabilities: dict[str, bool]) -> bool:
    """Evaluate a capability gate.

    Supports:
        when: "cap_name"           -> single capability
        when: { all: [...] }       -> all must be true
        when: { any: [...] }       -> at least one true
    """
    if when is None:
        return True
    if isinstance(when, str):
        return capabilities.get(when, False)
    if isinstance(when, dict):
        if "all" in when:
            return all(capabilities.get(c, False) for c in when["all"])
        if "any" in when:
            return any(capabilities.get(c, False) for c in when["any"])
    return False


def select_implementation(rule: dict, capabilities: dict[str, bool]) -> dict | None:
    """Select the first matching implementation by capability gate.

    Non-default implementations are checked in order; the first whose `when`
    gate passes wins.  If none match, the `default: true` implementation is
    returned.
    """
    default_impl = None
    for impl in rule.get("implementations", []):
        if impl.get("default"):
            default_impl = impl
            continue
        if evaluate_when(impl.get("when"), capabilities):
            return impl
    return default_impl
