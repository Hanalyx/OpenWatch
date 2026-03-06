#!/usr/bin/env python3
"""Advisory check: warn when spec-covered code changes without a spec update.

Compares changed files in the current git diff against known spec-covered
source paths. If covered source files changed but no *.spec.yaml file was
updated in the same changeset, prints a warning and exits 0 (advisory only).

Usage:
    python scripts/check-spec-changes.py [--base BASE_REF]

Options:
    --base BASE_REF     Git ref to diff against (default: HEAD~1 for push,
                        or origin/main for PRs via GITHUB_BASE_REF env var)

Exit codes:
    0 - Always (advisory only; warnings are printed but do not block CI)
"""

import subprocess
import sys
from pathlib import Path


# Directories whose Python source files are covered by active specs.
# Grouped by spec category for clear warning messages.
SPEC_COVERED_DIRS: dict[str, list[str]] = {
    "api/scans": [
        "backend/app/routes/scans/",
    ],
    "api/compliance": [
        "backend/app/routes/compliance/",
    ],
    "api/remediation": [
        "backend/app/routes/compliance/remediation",
    ],
    "api/auth": [
        "backend/app/routes/auth/",
    ],
    "system/error-model": [
        "backend/app/main.py",
    ],
    "services/compliance": [
        "backend/app/services/compliance/",
    ],
    "services/remediation": [
        "backend/app/services/remediation/",
    ],
    "plugins/orsa": [
        "backend/app/plugins/kensa/",
    ],
    "pipelines/scan-execution": [
        "backend/app/tasks/",
        "backend/app/engine/",
    ],
    "services/ssh": [
        "backend/app/services/ssh/",
        "backend/app/ssh/",
    ],
    "services/auth": [
        "backend/app/services/auth/",
    ],
}


def get_changed_files(base_ref: str) -> list[str]:
    """Return list of changed file paths relative to repo root."""
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", base_ref, "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        files = [f.strip() for f in result.stdout.splitlines() if f.strip()]
        return files
    except subprocess.CalledProcessError as exc:
        print(f"[spec-changes] Warning: could not run git diff: {exc}", file=sys.stderr)
        return []


def determine_base_ref(cli_base: str | None) -> str:
    """Determine the base git ref to diff against."""
    import os

    if cli_base:
        return cli_base

    # GitHub Actions PR: GITHUB_BASE_REF is the target branch name
    gh_base = os.environ.get("GITHUB_BASE_REF")
    if gh_base:
        return f"origin/{gh_base}"

    # GitHub Actions push: compare with parent commit
    if os.environ.get("GITHUB_SHA"):
        return "HEAD~1"

    # Local: compare with main
    return "origin/main"


def find_covered_changes(changed_files: list[str]) -> dict[str, list[str]]:
    """Map spec category -> list of changed files covered by that spec."""
    hits: dict[str, list[str]] = {}
    for changed in changed_files:
        for category, paths in SPEC_COVERED_DIRS.items():
            for prefix in paths:
                if changed.startswith(prefix) and changed.endswith(".py"):
                    hits.setdefault(category, []).append(changed)
                    break
    return hits


def any_spec_changed(changed_files: list[str]) -> bool:
    """Return True if any *.spec.yaml file was updated."""
    return any(f.endswith(".spec.yaml") for f in changed_files)


def main() -> int:
    # Parse --base argument
    base_ref: str | None = None
    args = sys.argv[1:]
    if "--base" in args:
        idx = args.index("--base")
        if idx + 1 < len(args):
            base_ref = args[idx + 1]

    base = determine_base_ref(base_ref)
    changed = get_changed_files(base)

    if not changed:
        print("[spec-changes] No changed files detected; skipping check.")
        return 0

    covered_changes = find_covered_changes(changed)
    spec_changed = any_spec_changed(changed)

    if not covered_changes:
        print("[spec-changes] No spec-covered source files changed.")
        return 0

    if spec_changed:
        print("[spec-changes] Spec-covered source files changed and at least one spec was updated.")
        for category, files in covered_changes.items():
            print(f"  - {category}: {len(files)} file(s) changed")
        return 0

    # Advisory warning: covered code changed but no spec updated
    print()
    print("=" * 72)
    print("[spec-changes] ADVISORY WARNING")
    print("=" * 72)
    print("Spec-covered source files were modified, but no *.spec.yaml file")
    print("was updated in this changeset.")
    print()
    print("If you changed behavior, update the relevant spec before merging:")
    print()
    for category, files in covered_changes.items():
        print(f"  Spec: specs/{category}.spec.yaml")
        for f in files:
            print(f"    Modified: {f}")
    print()
    print("This is an advisory warning. The build is NOT blocked.")
    print("To suppress, update the spec file alongside the code change.")
    print("=" * 72)
    print()

    return 0  # Advisory only — never block CI


if __name__ == "__main__":
    sys.exit(main())
