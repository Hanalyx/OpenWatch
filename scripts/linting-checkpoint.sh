#!/bin/bash
#
# OpenWatch Linting Remediation Checkpoint Script
#
# Purpose: Captures linting state and creates git checkpoint for rollback capability
#
# CLAUDE.md Compliance:
# - Follows modular architecture (single responsibility: checkpoint management)
# - Implements safety checks and error handling per security standards
# - Provides descriptive, instructive comments explaining WHY, not just WHAT
#
# Usage:
#   ./scripts/linting-checkpoint.sh <stage-number>
#
# Example:
#   ./scripts/linting-checkpoint.sh 1
#   Creates checkpoint file: docs/linting-checkpoint-stage-1.txt
#   Creates git commit: "chore: Linting remediation Stage 1 checkpoint"
#
# Security:
# - No user input is executed (prevents command injection)
# - Stage number is validated before use
# - Git operations are atomic
#
# Per LINTING_REMEDIATION_PLAN.md Stage 0, this script provides:
# - Automated capture of linting state for comparison
# - Git checkpoint creation for safe rollback
# - Timestamped audit trail of remediation progress
#

set -euo pipefail  # Exit on error, undefined variables, pipe failures

# Color codes for terminal output (improves readability, per CLAUDE.md clarity standards)
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m' # No Color

# Constants for file paths (centralized configuration)
# shellcheck disable=SC2155  # Intentional: cd && pwd is safe and readable
readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly FRONTEND_DIR="${REPO_ROOT}/frontend"
readonly DOCS_DIR="${REPO_ROOT}/docs"

# Function: Display error message and exit
# Why: Consistent error handling across script, per CLAUDE.md error handling standards
error_exit() {
    echo -e "${RED}ERROR: $1${NC}" >&2
    exit 1
}

# Function: Display success message
# Why: Clear user feedback improves debugging experience
success_message() {
    echo -e "${GREEN}SUCCESS: $1${NC}"
}

# Function: Display warning message
# Why: Important notices without stopping execution
warning_message() {
    echo -e "${YELLOW}WARNING: $1${NC}"
}

# Validate command line arguments
# Why: Prevent script execution with invalid inputs (OWASP A03:2021 - Input Validation)
STAGE=$1

if [ -z "${STAGE:-}" ]; then
    error_exit "Stage number required\nUsage: $0 <stage-number>\nExample: $0 1"
fi

# Validate stage number is numeric
# Why: Prevents command injection via non-numeric stage values
if ! [[ "${STAGE}" =~ ^[0-9]+$ ]]; then
    error_exit "Stage number must be numeric, got: ${STAGE}"
fi

# Validate stage number is within expected range (0-5)
# Why: Stage numbers outside this range indicate misconfiguration
if [ "${STAGE}" -lt 0 ] || [ "${STAGE}" -gt 5 ]; then
    warning_message "Stage ${STAGE} is outside expected range (0-5)"
fi

# Verify we're in a git repository
# Why: Git operations will fail if not in a repo, better to fail early with clear message
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    error_exit "Not in a git repository. Run this script from OpenWatch root directory."
fi

# Verify frontend directory exists
# Why: npm commands will fail if frontend directory doesn't exist
if [ ! -d "${FRONTEND_DIR}" ]; then
    error_exit "Frontend directory not found at: ${FRONTEND_DIR}"
fi

# Create docs directory if it doesn't exist
# Why: Checkpoint files need a destination directory
mkdir -p "${DOCS_DIR}"

# Define checkpoint file path
readonly CHECKPOINT_FILE="${DOCS_DIR}/linting-checkpoint-stage-${STAGE}.txt"

echo "OpenWatch Linting Remediation Checkpoint - Stage ${STAGE}"
echo "=============================================="
echo ""

# Capture current linting state
# Why: Enables before/after comparison and regression detection (per LINTING_REMEDIATION_PLAN.md)
# Note: Using 2>&1 to capture both stdout and stderr for complete error context
echo "Capturing linting state for Stage ${STAGE}..."
cd "${FRONTEND_DIR}"

# Run linting and capture output
# Why: Tee command allows us to both display output AND save to file
# Note: We allow non-zero exit codes here because linting errors are expected during remediation
set +e  # Temporarily allow non-zero exit codes
npm run lint 2>&1 | tee "${CHECKPOINT_FILE}"
set -e  # Re-enable strict error checking

# Analyze linting results
# Why: Provide immediate feedback on current state vs. expected state
TOTAL_ISSUES=$(grep -c "warning\|error" "${CHECKPOINT_FILE}" || echo "0")
ERROR_COUNT=$(grep -c "error" "${CHECKPOINT_FILE}" || echo "0")
WARNING_COUNT=$(grep -c "warning" "${CHECKPOINT_FILE}" || echo "0")

echo ""
echo "Linting Summary for Stage ${STAGE}:"
echo "  Total Issues: ${TOTAL_ISSUES}"
echo "  Errors: ${ERROR_COUNT}"
echo "  Warnings: ${WARNING_COUNT}"
echo "  Checkpoint saved to: ${CHECKPOINT_FILE}"
echo ""

# Create git checkpoint
# Why: Provides rollback capability if remediation introduces regressions (per LINTING_REMEDIATION_PLAN.md)
echo "Creating git checkpoint..."

# Check if there are any changes to commit
# Why: Git will fail if there are no changes, better to check first
if git diff --quiet && git diff --cached --quiet; then
    warning_message "No changes to commit. Checkpoint file created but no git commit needed."
else
    # Stage all changes
    # Why: Capture complete state of codebase at this checkpoint
    git add -A

    # Create commit with descriptive message
    # Why: Clear commit messages enable easy navigation of remediation history
    # Format follows CLAUDE.md commit message standards
    git commit -m "chore: Linting remediation Stage ${STAGE} checkpoint

Automated checkpoint created by linting-checkpoint.sh

Current linting state:
- Total issues: ${TOTAL_ISSUES}
- Errors: ${ERROR_COUNT}
- Warnings: ${WARNING_COUNT}

Checkpoint file: ${CHECKPOINT_FILE}

Per LINTING_REMEDIATION_PLAN.md, this checkpoint enables:
- Rollback capability if regressions are introduced
- Before/after comparison for each stage
- Audit trail of remediation progress"

    # Get commit hash for reference
    COMMIT_HASH=$(git rev-parse --short HEAD)

    success_message "Git checkpoint created: ${COMMIT_HASH}"
fi

echo ""
success_message "Stage ${STAGE} checkpoint complete!"
echo ""
echo "Next Steps:"
echo "  1. Review checkpoint file: cat ${CHECKPOINT_FILE}"
echo "  2. Proceed with Stage ${STAGE} remediation per LINTING_REMEDIATION_PLAN.md"
echo "  3. To rollback if needed: git reset --hard HEAD~1"
echo ""
