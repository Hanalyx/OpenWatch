#!/usr/bin/env python3
"""Validate commit messages against OpenWatch commit conventions.

Checks:
  - Conventional Commits format
  - No banned planning/process terms in the subject line
  - Subject describes a concrete deliverable

Usage:
    python3 scripts/check-commit-message.py --message "feat: add auth module"
    python3 scripts/check-commit-message.py --file .git/COMMIT_EDITMSG

Exit codes:
    0 - Message passes all checks
    1 - Message fails one or more checks
"""
# Spec: specs/release/commit-conventions.spec.yaml

import argparse
import re
import sys

# Conventional commit types (must match .commitlintrc.json)
VALID_TYPES = [
    "feat", "fix", "docs", "style", "refactor", "perf",
    "test", "build", "ci", "chore", "revert",
]

# Planning/process terms banned from subject lines
BANNED_TERMS = [
    "phase", "step", "stage", "milestone", "sprint",
    "iteration", "backlog", "epic", "story", "task", "ticket",
]

# Conventional commit pattern
CC_PATTERN = re.compile(
    r"^(" + "|".join(VALID_TYPES) + r")"
    r"(\([a-z][a-z0-9-]*\))?"
    r": "
    r"(.+)$"
)

MAX_HEADER_LENGTH = 100


def check_message(title: str) -> list[str]:
    """Check a commit/PR title against conventions.

    Returns a list of error messages (empty if valid).
    """
    errors = []

    # Strip leading/trailing whitespace
    title = title.strip()

    if not title:
        return ["Title is empty"]

    # Check max length
    if len(title) > MAX_HEADER_LENGTH:
        errors.append(
            f"Title exceeds {MAX_HEADER_LENGTH} characters "
            f"({len(title)} chars)"
        )

    # Check conventional commit format
    match = CC_PATTERN.match(title)
    if not match:
        errors.append(
            "Title must follow Conventional Commits format: "
            "<type>[(<scope>)]: <subject>"
        )
        # Can't check further without a valid format
        return errors

    subject = match.group(3)

    # Check for trailing period
    if subject.endswith("."):
        errors.append("Subject must not end with a period")

    # Check for banned planning/process terms
    subject_lower = subject.lower()
    for term in BANNED_TERMS:
        # Match whole word only (e.g., "phase" but not "phased")
        if re.search(rf"\b{term}\b", subject_lower):
            errors.append(
                f'Subject contains banned planning term "{term}". '
                f"Describe the deliverable, not the planning stage."
            )

    # Check for vague subjects
    vague_patterns = [
        r"^(various|misc|some|minor)\s",
        r"^update(d)?\s+stuff",
        r"^(changes|updates|improvements)$",
    ]
    for pattern in vague_patterns:
        if re.search(pattern, subject_lower):
            errors.append(
                "Subject is too vague. Describe what was specifically "
                "built, fixed, or changed."
            )
            break

    return errors


# Patterns that indicate AI attribution in commit bodies
AI_ATTRIBUTION_PATTERNS = [
    r"Co-Authored-By:.*Claude",
    r"Co-Authored-By:.*Copilot",
    r"Co-Authored-By:.*AI",
    r"Generated with.*Claude",
    r"Generated with.*Copilot",
]


def check_body_for_ai_attribution(body: str) -> list[str]:
    """Check the full commit message body for AI attribution lines.

    Returns a list of error messages (empty if valid).
    """
    errors = []
    for pattern in AI_ATTRIBUTION_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            errors.append(
                "Commit message contains AI attribution. "
                "The committer is solely responsible for all changes."
            )
            break
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate commit messages against OpenWatch conventions"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--message", "-m",
        help="Commit message title to check"
    )
    group.add_argument(
        "--file", "-f",
        help="File containing the commit message (e.g., .git/COMMIT_EDITMSG)"
    )
    args = parser.parse_args()

    full_body = ""
    if args.file:
        try:
            with open(args.file) as f:
                full_body = f.read()
                title = full_body.split("\n", 1)[0].strip()
        except OSError as e:
            print(f"ERROR: Could not read file: {e}")
            return 1
    else:
        title = args.message
        full_body = args.message

    errors = check_message(title)
    errors.extend(check_body_for_ai_attribution(full_body))

    if errors:
        print(f"Commit message check FAILED for: {title}")
        for error in errors:
            print(f"  - {error}")
        print()
        print("See specs/release/commit-conventions.spec.yaml for rules.")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
