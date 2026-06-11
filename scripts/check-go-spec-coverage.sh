#!/usr/bin/env bash
# Pre-commit hook: source-walk spec coverage for the Go rebuild.
#
# Runs `specter coverage --strictness annotation --failing` from the repo root.
# This mode walks source files for // @ac AC-NN annotations — no test
# results required, no .specter-results.json — so it catches the exact
# class of failure that put PR #455 through three CI re-runs: a tier-1
# spec landed with tests but without the @ac comments specter coverage
# expects.
#
# Why a shell wrapper instead of calling specter directly:
#   - specter v0.13.2 prints "Pipeline failed at coverage phase." on
#     failure but exits 0 on this host (and possibly others). We parse
#     the output for "N failing" and exit non-zero ourselves.
#   - Skips cleanly when specter is not installed (don't block commits
#     on a tool the dev doesn't have; CI is the strict gate).

set -u

cd "$(git rev-parse --show-toplevel)" 2>/dev/null || {
    echo "[spec-coverage] not run: repo root not found" >&2
    exit 0
}

if ! command -v specter &>/dev/null; then
    echo "[spec-coverage] skipping: specter not installed (CI is the strict gate)"
    exit 0
fi

OUT=$(specter coverage --strictness annotation --failing 2>&1)
RC=$?

# Surface specter crashes (exit non-zero AND no recognizable output)
if [ "$RC" -ne 0 ] && ! echo "$OUT" | grep -qE "[0-9]+ failing|All [0-9]+ specs"; then
    echo "[spec-coverage] specter crashed (exit=$RC):" >&2
    echo "$OUT" >&2
    exit 1
fi

# Count failing specs from the summary line "N specs: M passing, K failing".
FAILING=$(echo "$OUT" | grep -oE "[0-9]+ failing" | tail -1 | awk '{print $1}')
FAILING=${FAILING:-0}

if [ "$FAILING" -gt 0 ]; then
    echo ""
    echo "[spec-coverage] BLOCKED — ${FAILING} spec(s) below source-walk coverage threshold:"
    echo ""
    echo "$OUT" | sed -n '/Spec ID/,/specs: /p' | head -100
    echo ""
    echo "[spec-coverage] How to fix:"
    echo "  - Each uncovered AC needs '// @ac AC-NN' (Go) or '// @ac AC-NN' (TS)"
    echo "    on the line above its test function. See internal/server/api_activity_test.go"
    echo "    for the canonical pattern."
    echo "  - If the spec is genuinely not yet implemented, mark its status: 'draft'"
    echo "    in the spec file (drafts are exempt from the gate)."
    exit 1
fi

echo "[spec-coverage] OK — all specs covered (source-walk)"
exit 0
