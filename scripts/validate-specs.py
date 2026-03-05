#!/usr/bin/env python3
"""Validate all .spec.yaml files against the spec JSON Schema.

Usage:
    python scripts/validate-specs.py [--strict]

Exit codes:
    0 - All specs pass validation
    1 - One or more specs failed validation
"""

import json
import sys
from pathlib import Path

import jsonschema
import yaml


def find_spec_files(specs_dir: Path) -> list[Path]:
    """Find all .spec.yaml files under the specs directory."""
    return sorted(specs_dir.rglob("*.spec.yaml"))


def load_schema(schema_path: Path) -> dict:
    """Load and return the JSON Schema."""
    with open(schema_path) as f:
        return json.load(f)


def validate_spec(spec_path: Path, schema: dict, specs_dir: Path) -> list[str]:
    """Validate a single spec file against the schema.

    Returns a list of error messages (empty if valid).
    """
    errors = []
    relative = spec_path.relative_to(specs_dir.parent)

    try:
        with open(spec_path) as f:
            content = f.read()
    except OSError as e:
        return [f"{relative}: Could not read file: {e}"]

    if not content.strip():
        return [f"{relative}: File is empty"]

    # Parse YAML — spec files may use multiple documents separated by ---
    # Only the FIRST document is validated against the schema (spec metadata).
    # Subsequent documents contain behavioral content (state machines, matrices,
    # test definitions, etc.) and may reuse top-level keys like `version:` with
    # different semantics.
    try:
        docs = list(yaml.safe_load_all(content))
    except yaml.YAMLError as e:
        return [f"{relative}: YAML parse error: {e}"]

    first_doc = docs[0] if docs else None
    if not isinstance(first_doc, dict) or not first_doc:
        return [f"{relative}: First YAML document must be a non-empty mapping"]

    # Validate against schema
    validator = jsonschema.Draft202012Validator(schema)
    for error in validator.iter_errors(first_doc):
        path = ".".join(str(p) for p in error.absolute_path) if error.absolute_path else "(root)"
        errors.append(f"{relative}: {path}: {error.message}")

    return errors


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    specs_dir = repo_root / "specs"
    schema_path = specs_dir / "spec-schema.json"

    if not schema_path.exists():
        print(f"ERROR: Schema not found at {schema_path}")
        return 1

    schema = load_schema(schema_path)
    spec_files = find_spec_files(specs_dir)

    if not spec_files:
        print("WARNING: No .spec.yaml files found")
        return 0

    all_errors: list[str] = []
    passed = 0
    failed = 0

    for spec_file in spec_files:
        errors = validate_spec(spec_file, schema, specs_dir)
        if errors:
            failed += 1
            all_errors.extend(errors)
        else:
            passed += 1

    # Report results
    print(f"Spec validation: {passed} passed, {failed} failed, {len(spec_files)} total")
    print()

    if all_errors:
        print("ERRORS:")
        for error in all_errors:
            print(f"  - {error}")
        print()
        print("FAILED: Fix the errors above and re-run.")
        return 1

    print("All specs pass schema validation.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
