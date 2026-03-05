#!/usr/bin/env python3
"""Check spec-to-test traceability for Active specs.

For each Active spec with acceptance_criteria, searches test files for
AC-{id} annotations and reports coverage.

Usage:
    python scripts/check-spec-coverage.py [--enforce-active]

Options:
    --enforce-active    Exit non-zero if any Active spec has uncovered ACs

Exit codes:
    0 - All checks passed (or informational mode)
    1 - Uncovered ACs found in Active specs (only with --enforce-active)
"""

import re
import sys
from pathlib import Path

import yaml


def find_spec_files(specs_dir: Path) -> list[Path]:
    """Find all .spec.yaml files under the specs directory."""
    return sorted(specs_dir.rglob("*.spec.yaml"))


def load_spec(spec_path: Path) -> dict | None:
    """Load a spec file, merging multi-document YAML."""
    try:
        with open(spec_path) as f:
            content = f.read()
    except OSError:
        return None

    if not content.strip():
        return None

    try:
        docs = list(yaml.safe_load_all(content))
    except yaml.YAMLError:
        return None

    merged = {}
    for doc in docs:
        if isinstance(doc, dict):
            merged.update(doc)

    return merged if merged else None


def find_test_files(repo_root: Path) -> list[Path]:
    """Find all Python test files in the repository."""
    test_dirs = [
        repo_root / "backend" / "tests",
        repo_root / "tests",
    ]
    test_files = []
    for d in test_dirs:
        if d.exists():
            test_files.extend(d.rglob("test_*.py"))
            test_files.extend(d.rglob("*_test.py"))
    # Also check packaging tests
    pkg_tests = repo_root / "packaging" / "tests"
    if pkg_tests.exists():
        test_files.extend(pkg_tests.rglob("test_*"))
    return test_files


def search_tests_for_acs(
    test_files: list[Path], ac_ids: list[str], spec_path: str
) -> dict[str, list[str]]:
    """Search test files for AC annotations.

    Returns a dict mapping AC IDs to list of files where they appear.
    """
    coverage: dict[str, list[str]] = {ac_id: [] for ac_id in ac_ids}

    # Also search for spec file reference
    spec_ref_pattern = re.compile(re.escape(spec_path))

    for test_file in test_files:
        try:
            content = test_file.read_text(errors="replace")
        except OSError:
            continue

        for ac_id in ac_ids:
            # Match AC-N in docstrings, comments, or annotations
            if re.search(rf"\b{re.escape(ac_id)}\b", content):
                coverage[ac_id].append(str(test_file))

    return coverage


def main() -> int:
    enforce = "--enforce-active" in sys.argv

    repo_root = Path(__file__).resolve().parent.parent
    specs_dir = repo_root / "specs"

    spec_files = find_spec_files(specs_dir)
    test_files = find_test_files(repo_root)

    if not spec_files:
        print("No spec files found.")
        return 0

    total_acs = 0
    covered_acs = 0
    uncovered_active: list[tuple[str, str]] = []  # (spec, ac_id)

    print("Spec-to-Test Traceability Report")
    print("=" * 60)
    print()

    for spec_file in spec_files:
        spec = load_spec(spec_file)
        if not spec:
            continue

        status = spec.get("status", "draft")
        spec_name = spec.get("spec", spec_file.stem)
        acs = spec.get("acceptance_criteria", [])

        if not acs:
            continue

        relative = spec_file.relative_to(specs_dir)
        ac_ids = [ac["id"] for ac in acs if "id" in ac]

        if not ac_ids:
            continue

        total_acs += len(ac_ids)

        coverage = search_tests_for_acs(
            test_files, ac_ids, str(relative)
        )

        spec_covered = sum(1 for files in coverage.values() if files)
        covered_acs += spec_covered
        spec_total = len(ac_ids)
        pct = (spec_covered / spec_total * 100) if spec_total else 0

        status_label = f"[{status.upper()}]"
        print(f"{status_label:12s} {relative}")
        print(f"             Coverage: {spec_covered}/{spec_total} ACs ({pct:.0f}%)")

        for ac_id, files in coverage.items():
            if files:
                short_files = [
                    str(Path(f).relative_to(repo_root)) for f in files
                ]
                print(f"               {ac_id}: {', '.join(short_files)}")
            else:
                marker = "MISSING" if status == "active" else "not yet tested"
                print(f"               {ac_id}: {marker}")
                if status == "active":
                    uncovered_active.append((str(relative), ac_id))

        print()

    # Summary
    print("-" * 60)
    overall_pct = (covered_acs / total_acs * 100) if total_acs else 0
    print(f"Total: {covered_acs}/{total_acs} ACs covered ({overall_pct:.0f}%)")

    if uncovered_active:
        print()
        print(f"Active specs with uncovered ACs: {len(uncovered_active)}")
        for spec_path, ac_id in uncovered_active:
            print(f"  - {spec_path}: {ac_id}")

        if enforce:
            print()
            print("FAILED: Active specs must have 100% AC coverage.")
            return 1

    print()
    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
