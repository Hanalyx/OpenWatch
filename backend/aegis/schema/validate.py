#!/usr/bin/env python3
"""Aegis Validation Orchestrator.

Validates rule files, mapping files, and cross-rule dependencies.

Usage:
    python3 schema/validate.py                     # Validate all rules
    python3 schema/validate.py rules/access-control/ssh-disable-root-login.yml
    python3 schema/validate.py --format json       # JSON output
    python3 schema/validate.py --format github     # GitHub Actions annotations
    python3 schema/validate.py --strict            # Warnings become errors

"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from schema.validators import ValidationError
from schema.validators.rule import validate_all_rules, validate_rule

# -- Paths -------------------------------------------------------------------
SCHEMA_DIR = Path(__file__).resolve().parent
RULES_DIR = SCHEMA_DIR.parent / "rules"
RULE_SCHEMA_PATH = SCHEMA_DIR / "rule.schema.json"


def load_schema(path: Path) -> dict:
    """Load and return a JSON Schema."""
    with open(path) as f:
        return json.load(f)


def render_text(
    results: dict[Path, list[ValidationError]],
    base_dir: Path,
    strict: bool = False,
) -> tuple[int, int, int]:
    """Render validation results as human-readable text.

    Args:
        results: Dict mapping file paths to validation errors.
        base_dir: Base directory for relative path display.
        strict: If True, treat warnings as errors.

    Returns:
        Tuple of (passed_count, failed_count, warning_count).

    """
    passed = 0
    failed = 0
    warnings = 0
    failure_details = []

    for filepath, errors in results.items():
        rel = (
            filepath.relative_to(base_dir) if base_dir in filepath.parents or filepath.parent == base_dir else filepath
        )

        # Count by severity
        error_count = sum(1 for e in errors if e.severity == "error")
        warning_count = sum(1 for e in errors if e.severity == "warning")

        if strict:
            # In strict mode, warnings become errors
            error_count += warning_count
            warning_count = 0

        if error_count == 0:
            if warning_count > 0:
                print(f"  WARN  {rel}")
                for err in errors:
                    print(f"          [{err.code}] {err.message}")
                warnings += warning_count
            else:
                print(f"  PASS  {rel}")
            passed += 1
        else:
            print(f"  FAIL  {rel}")
            for err in errors:
                print(f"          [{err.code}] {err.message}")
            failed += 1
            failure_details.append((filepath, errors))

    return passed, failed, warnings


def render_json(
    results: dict[Path, list[ValidationError]],
    strict: bool = False,
) -> dict:
    """Render validation results as JSON.

    Args:
        results: Dict mapping file paths to validation errors.
        strict: If True, treat warnings as errors in counts.

    Returns:
        JSON-serializable dict with results.

    """
    output: dict[str, Any] = {
        "files": [],
        "summary": {
            "total": len(results),
            "passed": 0,
            "failed": 0,
            "warnings": 0,
        },
    }

    for filepath, errors in results.items():
        error_count = sum(1 for e in errors if e.severity == "error")
        warning_count = sum(1 for e in errors if e.severity == "warning")

        if strict:
            error_count += warning_count
            warning_count = 0

        file_entry = {
            "path": str(filepath),
            "passed": error_count == 0,
            "errors": [e.as_dict() for e in errors],
        }
        output["files"].append(file_entry)

        if error_count == 0:
            output["summary"]["passed"] += 1
            output["summary"]["warnings"] += warning_count
        else:
            output["summary"]["failed"] += 1

    return output


def render_github(
    results: dict[Path, list[ValidationError]],
    strict: bool = False,
) -> None:
    """Render validation results as GitHub Actions annotations.

    Args:
        results: Dict mapping file paths to validation errors.
        strict: If True, emit warnings as errors.

    """
    for _filepath, errors in results.items():
        for err in errors:
            if strict and err.severity == "warning":
                # Upgrade warning to error
                modified_err = ValidationError(
                    code=err.code,
                    message=err.message,
                    path=err.path,
                    severity="error",
                )
                print(modified_err.github_annotation())
            else:
                print(err.github_annotation())


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Validate Aegis rule and mapping files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "files",
        nargs="*",
        help="Specific files to validate (default: all rules)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "github"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat warnings as errors",
    )
    parser.add_argument(
        "--rules-dir",
        type=Path,
        default=RULES_DIR,
        help=f"Rules directory (default: {RULES_DIR})",
    )

    args = parser.parse_args()

    # Load schema
    if args.format == "text":
        print(f"Loading schema: {RULE_SCHEMA_PATH}")

    try:
        rule_schema = load_schema(RULE_SCHEMA_PATH)
    except (json.JSONDecodeError, FileNotFoundError) as exc:
        if args.format == "text":
            print(f"FATAL: Cannot load schema: {exc}")
        elif args.format == "json":
            print(json.dumps({"error": f"Cannot load schema: {exc}"}))
        elif args.format == "github":
            print(f"::error::Cannot load schema: {exc}")
        return 2

    # Collect files to validate
    if args.files:
        # Validate specific files
        results = {}
        for file_arg in args.files:
            filepath = Path(file_arg)
            if not filepath.exists():
                if args.format == "text":
                    print(f"WARNING: File not found: {filepath}")
                continue
            if filepath.is_dir():
                # Validate all rules in directory
                results.update(validate_all_rules(filepath, rule_schema))
            else:
                results[filepath] = validate_rule(filepath, rule_schema)
    else:
        # Validate all rules
        if args.format == "text":
            rule_files = list(args.rules_dir.rglob("*.yml"))
            if not rule_files:
                print(f"WARNING: No .yml files found under {args.rules_dir}")
                return 1
            print(f"Found {len(rule_files)} rule file(s) under {args.rules_dir}\n")
            print("=" * 78)

        results = validate_all_rules(args.rules_dir, rule_schema)

    if not results:
        if args.format == "text":
            print("No files to validate.")
        elif args.format == "json":
            print(json.dumps({"error": "No files to validate", "files": []}))
        return 1

    # Render output
    if args.format == "text":
        passed, failed, warnings = render_text(results, args.rules_dir, args.strict)

        print("=" * 78)
        print()
        print("VALIDATION SUMMARY")
        print(f"  Total files : {len(results)}")
        print(f"  Passed      : {passed}")
        print(f"  Failed      : {failed}")
        if warnings > 0 and not args.strict:
            print(f"  Warnings    : {warnings}")

        print()
        if failed == 0:
            print("Result: ALL RULES VALID")
        else:
            print(f"Result: {failed} RULE(S) INVALID")

        return 0 if failed == 0 else 1

    elif args.format == "json":
        output = render_json(results, args.strict)
        print(json.dumps(output, indent=2))
        return 0 if output["summary"]["failed"] == 0 else 1

    elif args.format == "github":
        render_github(results, args.strict)
        # Count errors for exit code
        error_count = sum(
            1
            for errors in results.values()
            for e in errors
            if e.severity == "error" or (args.strict and e.severity == "warning")
        )
        return 0 if error_count == 0 else 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
