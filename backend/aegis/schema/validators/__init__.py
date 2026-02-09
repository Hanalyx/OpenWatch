"""Validation modules for Aegis rule and mapping files.

This package contains modular validators for different validation types:
- rule: Per-rule YAML validation (schema + business rules)
- mapping: Framework mapping file validation (future)
- graph: Cross-rule dependency validation (future)
- capabilities: Capability name validation (future)

Example:
    >>> from schema.validators import rule, ValidationError
    >>> errors = rule.validate_rule(Path("rules/access-control/ssh-disable-root-login.yml"), schema)
    >>> for e in errors:
    ...     print(f"{e.severity}: {e.message}")

"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    """Validation error severity levels."""

    ERROR = "error"
    WARNING = "warning"


@dataclass
class ValidationError:
    """A single validation error or warning.

    Attributes:
        code: Machine-readable error code (e.g., "id-mismatch", "schema-error").
        message: Human-readable description of the issue.
        path: File path or JSON path where the issue was found.
        severity: Either "error" or "warning".

    """

    code: str
    message: str
    path: str
    severity: str = "error"

    def as_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "code": self.code,
            "message": self.message,
            "path": self.path,
            "severity": self.severity,
        }

    def github_annotation(self) -> str:
        """Format as GitHub Actions annotation.

        Returns:
            String like "::error file=path::message" or "::warning file=path::message".

        """
        level = "error" if self.severity == "error" else "warning"
        return f"::{level} file={self.path}::{self.message}"


__all__ = ["ValidationError", "Severity"]
