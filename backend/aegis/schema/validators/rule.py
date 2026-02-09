"""Per-rule validation module.

This module validates individual rule YAML files against:
1. JSON Schema (rule.schema.json)
2. Business rules:
   - id matches filename
   - category matches parent directory
   - Exactly one default implementation
   - Non-default implementations have 'when' field

Example:
    >>> from pathlib import Path
    >>> from schema.validators.rule import validate_rule
    >>> import json
    >>> schema = json.load(open("schema/rule.schema.json"))
    >>> errors = validate_rule(Path("rules/access-control/ssh-disable-root-login.yml"), schema)
    >>> print(f"Found {len(errors)} error(s)")

"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import jsonschema
import yaml
from schema.validators import ValidationError

if TYPE_CHECKING:
    pass


def validate_yaml_parse(filepath: Path) -> tuple[dict | None, list[ValidationError]]:
    """Parse YAML file and return data with any parse errors.

    Args:
        filepath: Path to the YAML file.

    Returns:
        Tuple of (parsed data or None, list of validation errors).

    """
    try:
        with open(filepath) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        return None, [
            ValidationError(
                code="yaml-parse",
                message=f"Failed to parse YAML: {exc}",
                path=str(filepath),
            )
        ]

    if not isinstance(data, dict):
        return None, [
            ValidationError(
                code="yaml-parse",
                message=f"File does not contain a YAML mapping (got {type(data).__name__})",
                path=str(filepath),
            )
        ]

    return data, []


def validate_rule_schema(
    data: dict,
    schema: dict,
    filepath: Path,
) -> list[ValidationError]:
    """Validate rule data against JSON Schema.

    Args:
        data: Parsed rule YAML data.
        schema: JSON Schema dict.
        filepath: Path for error reporting.

    Returns:
        List of validation errors found.

    """
    validator_cls = jsonschema.Draft202012Validator
    validator = validator_cls(schema)
    errors = []

    for error in sorted(validator.iter_errors(data), key=lambda e: list(e.path)):
        path = " -> ".join(str(p) for p in error.absolute_path) if error.absolute_path else "(root)"
        errors.append(
            ValidationError(
                code="schema-error",
                message=f"{path}: {error.message}",
                path=str(filepath),
            )
        )

    return errors


def validate_rule_business(data: dict, filepath: Path) -> list[ValidationError]:
    """Validate business rules beyond JSON Schema.

    Checks:
    - id field matches filename (without .yml)
    - category field matches parent directory name
    - Exactly one implementation has default: true
    - All non-default implementations have a 'when' field

    Args:
        data: Parsed rule YAML data.
        filepath: Path to the rule file.

    Returns:
        List of validation errors found.

    """
    errors = []

    # Rule 1: id must match filename (without .yml)
    expected_id = filepath.stem
    actual_id = data.get("id", "")
    if actual_id != expected_id:
        errors.append(
            ValidationError(
                code="id-mismatch",
                message=f"id field is '{actual_id}' but filename is '{filepath.name}' "
                f"(expected id: '{expected_id}')",
                path=str(filepath),
            )
        )

    # Rule 2: category must match parent directory name
    expected_category = filepath.parent.name
    actual_category = data.get("category", "")
    if actual_category != expected_category:
        errors.append(
            ValidationError(
                code="category-mismatch",
                message=f"category is '{actual_category}' but parent directory is " f"'{expected_category}'",
                path=str(filepath),
            )
        )

    # Rule 3 & 4: implementation default / when constraints
    implementations = data.get("implementations", [])
    if implementations:
        default_count = sum(1 for impl in implementations if impl.get("default") is True)
        if default_count == 0:
            errors.append(
                ValidationError(
                    code="no-default",
                    message="No implementation has 'default: true' (exactly one is required)",
                    path=str(filepath),
                )
            )
        elif default_count > 1:
            errors.append(
                ValidationError(
                    code="multi-default",
                    message=f"{default_count} implementations have 'default: true' " "(exactly one is required)",
                    path=str(filepath),
                )
            )

        for i, impl in enumerate(implementations):
            is_default = impl.get("default") is True
            has_when = "when" in impl
            if not is_default and not has_when:
                errors.append(
                    ValidationError(
                        code="missing-when",
                        message=f"implementations[{i}] is not the default but has no 'when' field",
                        path=str(filepath),
                    )
                )

    return errors


def validate_rule(filepath: Path, schema: dict) -> list[ValidationError]:
    """Validate a single rule file.

    Performs YAML parsing, JSON Schema validation, and business rule validation.

    Args:
        filepath: Path to the rule YAML file.
        schema: JSON Schema dict for rule validation.

    Returns:
        List of all validation errors found.

    """
    # Parse YAML
    data, parse_errors = validate_yaml_parse(filepath)
    if parse_errors or data is None:
        return parse_errors

    errors: list[ValidationError] = []

    # JSON Schema validation
    errors.extend(validate_rule_schema(data, schema, filepath))

    # Business rule validation
    errors.extend(validate_rule_business(data, filepath))

    return errors


def validate_all_rules(
    rules_dir: Path,
    schema: dict,
) -> dict[Path, list[ValidationError]]:
    """Validate all rule files in a directory.

    Args:
        rules_dir: Directory containing rule YAML files.
        schema: JSON Schema dict for rule validation.

    Returns:
        Dict mapping file paths to their validation errors.

    Note:
        Excludes non-rule files:
        - defaults.yml (variable configuration)
        - rules.d/*.yml (user overrides)

    """
    results = {}

    # Files and directories to exclude (not rules)
    excluded_names = {"defaults.yml"}
    excluded_dirs = {"rules.d"}

    for filepath in sorted(rules_dir.rglob("*.yml")):
        # Skip excluded files
        if filepath.name in excluded_names:
            continue
        # Skip files in excluded directories
        if any(d in filepath.parts for d in excluded_dirs):
            continue
        errors = validate_rule(filepath, schema)
        results[filepath] = errors

    return results
