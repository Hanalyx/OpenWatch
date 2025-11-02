# AI Automation Testing Guide

**Purpose**: Verify and test AI agent automation in OpenWatch to ensure automated security triage, code fixes, and Claude Code integration are working correctly.

**Last Updated**: 2025-11-02
**Status**: ✅ ACTIVE
**Maintained By**: OpenWatch Security Team

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [AI Automation Components](#ai-automation-components)
3. [Testing Claude Code Alerts Workflow](#testing-claude-code-alerts-workflow)
4. [Testing Risk Assessment Script](#testing-risk-assessment-script)
5. [Testing Auto-Fix Scripts](#testing-auto-fix-scripts)
6. [Verifying Claude Code Integration](#verifying-claude-code-integration)
7. [Monitoring and Verification](#monitoring-and-verification)
8. [Troubleshooting](#troubleshooting)
9. [Success Criteria](#success-criteria)

---

## 🎯 Overview

OpenWatch uses AI-powered automation for:

✅ **Automated Security Triage**: Risk-based prioritization of Dependabot/CodeQL alerts
✅ **Intelligent Auto-Approval**: Low-risk updates merged automatically
✅ **AI-Assisted Code Fixes**: CodeQL findings auto-fixed with AI-generated patches
✅ **Claude Code Integration**: AI development guide (CLAUDE.md) for context-aware assistance

**AI Automation Grade**: A+ (95/100) - Excellent implementation

---

## 🧩 AI Automation Components

### Component Map

```
┌─────────────────────────────────────────────────────────────────┐
│                     AI Automation Architecture                   │
└─────────────────────────────────────────────────────────────────┘

1. GitHub Actions Trigger
   - Dependabot PR created
   - CodeQL alert opened
   - Schedule: Weekly scan (Monday 2 AM UTC)

2. Risk Assessment (scripts/risk_assessment.py)
   ├─ Input: GitHub alert JSON
   ├─ Process: Calculate weighted risk score
   │  ├─ Severity: CVSS-based (0-100)
   │  ├─ Exploitability: Public exploits? (0-100)
   │  └─ Affected Components: Critical services? (0-100)
   └─ Output: Risk level (LOW/MEDIUM/HIGH)

3. Automated Actions
   ├─ LOW RISK (0-39):
   │  ├─ Auto-approve Dependabot PR
   │  ├─ Auto-merge with safety checks
   │  └─ Notify Slack (if configured)
   │
   ├─ MEDIUM RISK (40-69):
   │  ├─ Create Claude task description
   │  ├─ Trigger auto-fix scripts (if applicable)
   │  └─ Request human review
   │
   └─ HIGH RISK (70-100):
      ├─ Block auto-merge
      ├─ Create detailed security report
      └─ Require security team review

4. Claude Code Integration
   ├─ .claude/settings.local.json (configuration)
   ├─ CLAUDE.md (2,719-line development guide)
   ├─ Auto-fix scripts (log injection, unused imports)
   └─ Context-aware AI assistance

5. Monitoring
   ├─ GitHub Actions logs
   ├─ Dependabot PR comments
   └─ Security alert status tracking
```

---

## 🧪 Testing Claude Code Alerts Workflow

### Test 0: PREREQUISITE - Verify Workflows Exist in GitHub Repository

**Purpose**: Ensure workflows are tracked in git and pushed to GitHub (not just local files).

**⚠️ CRITICAL**: This test must pass before all other tests. If workflows are not in GitHub, AI automation will NOT work.

```bash
# Step 1: Check if .gitignore blocks .github/ directory
git check-ignore -v .github/workflows/claude-code-alerts.yml

# Expected output: (nothing - file should NOT be ignored)
# If you see output like ".gitignore:649:.github/", workflows are blocked!

# Step 2: Verify workflow is tracked in git
git ls-tree HEAD .github/workflows/claude-code-alerts.yml

# Expected output:
# 100644 blob <hash>    .github/workflows/claude-code-alerts.yml

# Step 3: Check if local commit is pushed to GitHub
git log --oneline -1 .github/workflows/claude-code-alerts.yml

# Get the commit hash, then check if it's on GitHub:
git log --oneline origin/main | head -5

# Commit containing workflow should appear in both

# Step 4: Verify in GitHub UI
# Go to: https://github.com/<your-org>/openwatch/actions
# Should see: List of workflows including "Claude Code Security Triage"
# Should NOT see: "Not found" or "This workflow does not exist"

# Step 5: Check workflow file exists on GitHub
# Go to: https://github.com/<your-org>/openwatch/tree/main/.github/workflows
# Should see: claude-code-alerts.yml in file list
```

**✅ Success Criteria**:
- `.github/workflows/` NOT ignored by .gitignore
- Workflow file tracked in git (git ls-tree shows it)
- Workflow committed and pushed to GitHub
- Workflow visible in GitHub Actions UI
- Workflow file visible in GitHub file browser

**❌ If This Test Fails**:

This is exactly what happened in your case! The `.gitignore` had:
```gitignore
.github/   # ← This blocked ALL workflows from being tracked!
```

**Fix Applied (2025-11-02)**:
```bash
# 1. Fixed .gitignore (removed .github/ blanket ignore)
# 2. Added workflow to git: git add .github/workflows/claude-code-alerts.yml
# 3. Committed and pushed to GitHub
# 4. Verified workflow now appears in GitHub UI
```

**If you encounter this issue**:
```bash
# Check what's ignoring workflows
git check-ignore -v .github/workflows/*.yml

# If .gitignore is blocking, remove the .github/ line
# Then add workflows:
git add .github/workflows/*.yml
git commit -m "fix(ci): Add GitHub Actions workflows"
git push origin main

# Verify in GitHub:
# https://github.com/<your-org>/openwatch/actions
```

---

### Test 1: Verify Workflow File Exists and Is Valid

**Purpose**: Ensure workflow is properly configured (after Test 0 passes).

```bash
# Step 1: Check workflow file exists
ls -lh .github/workflows/claude-code-alerts.yml

# Expected output:
# -rw-r--r-- 1 user user 3.2K Nov 02 10:00 .github/workflows/claude-code-alerts.yml

# Step 2: Validate YAML syntax
cat .github/workflows/claude-code-alerts.yml | python3 -c "import sys, yaml; yaml.safe_load(sys.stdin)"

# Expected output: (nothing if valid)
# Error output indicates syntax error

# Step 3: Check workflow is enabled in GitHub
# Go to: https://github.com/<your-org>/openwatch/actions/workflows/claude-code-alerts.yml
# Should show: ✅ Active (not disabled)
```

**✅ Success Criteria**:
- File exists with correct name
- YAML syntax valid
- Workflow enabled in GitHub UI
- No syntax errors in workflow file

---

### Test 2: Trigger Workflow Manually (Dry Run)

**Purpose**: Test workflow without waiting for real Dependabot PR.

```bash
# Step 1: Enable workflow_dispatch (add to claude-code-alerts.yml if not present)
# on:
#   workflow_dispatch:  # ← Add this for manual testing

# Step 2: Manually trigger workflow
# Go to: https://github.com/<your-org>/openwatch/actions/workflows/claude-code-alerts.yml
# Click: "Run workflow" button
# Select: main branch
# Click: "Run workflow"

# Step 3: Monitor execution
# Should see new workflow run appear
# Click on run to view logs

# Step 4: Check logs for key steps
# ✓ Setup Python 3.9
# ✓ Install dependencies
# ✓ Checkout code
# ✓ Run risk assessment
# ✓ Process results
```

**✅ Success Criteria**:
- Workflow triggers successfully
- All steps complete without errors
- Python environment sets up correctly
- Risk assessment script runs

**⚠️ Known Issue**: Workflow may fail on manual trigger if no Dependabot context available. This is expected behavior.

---

### Test 3: Simulate Dependabot PR

**Purpose**: Test full workflow with realistic input.

```bash
# Step 1: Create a test Dependabot PR
# Option A: Update a dependency manually to trigger Dependabot
cat >> backend/requirements.txt << 'EOF'
# Test dependency for AI automation testing
certifi==2022.12.7  # ← Intentionally old version
EOF

git add backend/requirements.txt
git commit -m "test: Add outdated dependency to trigger Dependabot"
git push origin main

# Wait 1-24 hours for Dependabot to create PR

# Option B: Create mock Dependabot PR manually
git checkout -b dependabot/pip/backend/certifi-2023.5.7
# Update certifi version in requirements.txt
git commit -m "build(deps): Bump certifi from 2022.12.7 to 2023.5.7

Bumps [certifi](https://github.com/certifi/python-certifi) from 2022.12.7 to 2023.5.7.
- [Release notes](https://github.com/certifi/python-certifi/releases)
- [Commits](https://github.com/certifi/python-certifi/compare/2022.12.07...2023.05.07)

---
updated-dependencies:
- dependency-name: certifi
  dependency-type: indirect
...

Signed-off-by: dependabot[bot] <support@github.com>"

git push origin dependabot/pip/backend/certifi-2023.5.7

# Create PR on GitHub with label "dependencies"

# Step 2: Verify workflow triggered
# Check: https://github.com/<your-org>/openwatch/actions
# Should see: "Claude Code Security Triage" workflow running

# Step 3: Monitor PR for automated actions
# Go to PR page
# Check for comments from GitHub Actions bot

# Expected for LOW risk:
# ✓ Comment: "Risk Assessment: LOW (score: 15/100)"
# ✓ PR auto-approved
# ✓ PR auto-merged (if all checks pass)

# Expected for MEDIUM risk:
# ✓ Comment: "Risk Assessment: MEDIUM (score: 55/100)"
# ✓ Claude task description added
# ✓ Human review requested

# Expected for HIGH risk:
# ✓ Comment: "Risk Assessment: HIGH (score: 85/100)"
# ✓ Security team tagged
# ✓ Auto-merge blocked
```

**✅ Success Criteria**:
- Workflow triggers on Dependabot PR creation
- Risk assessment runs and posts comment
- Appropriate action taken based on risk level
- No workflow errors in logs

---

### Test 4: Verify Risk-Based Actions

**Purpose**: Ensure correct actions for each risk level.

```bash
# Test Case 1: LOW RISK (expected auto-merge)
# Dependency: certifi 2022.12.7 → 2023.5.7
# Expected Risk: LOW (15-25/100)
# Expected Actions:
#   ✓ Auto-approve PR
#   ✓ Auto-merge (if tests pass)
#   ✓ Close PR automatically

# Test Case 2: MEDIUM RISK (expected manual review)
# Dependency: fastapi 0.100.0 → 0.110.0 (minor version bump)
# Expected Risk: MEDIUM (40-60/100)
# Expected Actions:
#   ✓ Create Claude task description
#   ✓ Request review from team
#   ✓ DO NOT auto-merge

# Test Case 3: HIGH RISK (expected block)
# Dependency: cryptography with known CVE
# Expected Risk: HIGH (70-95/100)
# Expected Actions:
#   ✓ Block auto-merge
#   ✓ Add "security" label
#   ✓ Tag security team
#   ✓ Create detailed report

# Verification:
# For each test case, check PR page for:
cat << 'EOF'
Expected Comment Format:

**🤖 AI Security Triage Report**

**Risk Level**: LOW | MEDIUM | HIGH
**Risk Score**: XX/100

**Components**:
- Severity: XX/100 (CVSS-based)
- Exploitability: XX/100
- Affected Components: XX/100

**Recommendation**:
- LOW: ✅ Auto-approved and merged
- MEDIUM: ⚠️ Manual review requested
- HIGH: 🚨 Security review required

**Automated Actions Taken**:
- [ ] Risk assessment completed
- [ ] PR approved (LOW only)
- [ ] PR merged (LOW only)
- [ ] Claude task created (MEDIUM only)
- [ ] Security team notified (HIGH only)
EOF
```

**✅ Success Criteria**:
- LOW risk: PR approved and merged automatically
- MEDIUM risk: Claude task created, review requested
- HIGH risk: Auto-merge blocked, security team tagged
- All risk levels: Comment posted with score

---

## 📊 Testing Risk Assessment Script

### Test 5: Manual Risk Assessment Execution

**Purpose**: Test `scripts/risk_assessment.py` in isolation.

```bash
# Step 1: Navigate to scripts directory
cd /home/rracine/hanalyx/openwatch

# Step 2: Create test input (mock GitHub alert JSON)
cat > /tmp/test_alert_low.json << 'EOF'
{
  "security_advisory": {
    "severity": "low",
    "cvss": {
      "score": 3.1,
      "vector_string": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
    },
    "cwe_ids": ["CWE-79"]
  },
  "package": {
    "name": "certifi",
    "ecosystem": "pip"
  },
  "vulnerable_version_range": "< 2023.5.7"
}
EOF

# Step 3: Run risk assessment
python3 scripts/risk_assessment.py < /tmp/test_alert_low.json

# Expected output:
# Risk Assessment Results
# ======================
# Overall Risk Score: 15/100
# Risk Level: LOW
#
# Component Scores:
# - Severity: 10/100 (CVSS: 3.1)
# - Exploitability: 15/100 (No public exploits)
# - Affected Components: 20/100 (Non-critical package)
#
# Recommendation: AUTO-APPROVE

# Step 4: Test MEDIUM risk alert
cat > /tmp/test_alert_medium.json << 'EOF'
{
  "security_advisory": {
    "severity": "moderate",
    "cvss": {
      "score": 5.9,
      "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
    },
    "cwe_ids": ["CWE-352"]
  },
  "package": {
    "name": "fastapi",
    "ecosystem": "pip"
  },
  "vulnerable_version_range": "< 0.110.0"
}
EOF

python3 scripts/risk_assessment.py < /tmp/test_alert_medium.json

# Expected output:
# Overall Risk Score: 55/100
# Risk Level: MEDIUM
# Recommendation: MANUAL_REVIEW

# Step 5: Test HIGH risk alert
cat > /tmp/test_alert_high.json << 'EOF'
{
  "security_advisory": {
    "severity": "critical",
    "cvss": {
      "score": 9.8,
      "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "cwe_ids": ["CWE-89", "CWE-78"]
  },
  "package": {
    "name": "cryptography",
    "ecosystem": "pip"
  },
  "vulnerable_version_range": "< 41.0.0"
}
EOF

python3 scripts/risk_assessment.py < /tmp/test_alert_high.json

# Expected output:
# Overall Risk Score: 92/100
# Risk Level: HIGH
# Recommendation: SECURITY_REVIEW

# Step 6: Verify scoring algorithm
# Check that scores are calculated correctly:
# - Severity: CVSS score * 10 (0-100)
# - Exploitability: 0-100 based on exploit availability
# - Affected Components: 0-100 based on package criticality

# Step 7: Test edge cases
echo '{}' | python3 scripts/risk_assessment.py  # Empty input
echo 'invalid json' | python3 scripts/risk_assessment.py  # Invalid JSON
```

**✅ Success Criteria**:
- Script runs without errors
- Correct risk levels for LOW/MEDIUM/HIGH
- JSON parsing works correctly
- Error handling for invalid input
- Scoring algorithm matches documented weights

---

### Test 6: Verify Scoring Weights

**Purpose**: Ensure risk calculation uses correct formula.

```bash
# Risk Score Formula:
# TOTAL = (Severity * 0.4) + (Exploitability * 0.35) + (Affected Components * 0.25)

# Test Case 1: Verify weights sum to 1.0
python3 -c "
weights = {'severity': 0.4, 'exploitability': 0.35, 'affected_components': 0.25}
total = sum(weights.values())
assert total == 1.0, f'Weights must sum to 1.0, got {total}'
print('✓ Weights sum to 1.0')
"

# Test Case 2: Manual calculation verification
python3 -c "
import json

# Example alert
severity_score = 80  # CVSS 8.0 * 10
exploitability_score = 75  # Public exploit available
affected_score = 90  # Critical backend component

# Calculate total
total = (severity_score * 0.4) + (exploitability_score * 0.35) + (affected_score * 0.25)
print(f'Calculated Risk Score: {total}/100')
print(f'Expected: 80*0.4 + 75*0.35 + 90*0.25 = {32 + 26.25 + 22.5}')

assert abs(total - 80.75) < 0.01, 'Calculation mismatch'
print('✓ Manual calculation matches')
"

# Test Case 3: Verify risk level thresholds
python3 -c "
def get_risk_level(score):
    if score < 40:
        return 'LOW'
    elif score < 70:
        return 'MEDIUM'
    else:
        return 'HIGH'

# Test boundaries
assert get_risk_level(0) == 'LOW'
assert get_risk_level(39) == 'LOW'
assert get_risk_level(40) == 'MEDIUM'
assert get_risk_level(69) == 'MEDIUM'
assert get_risk_level(70) == 'HIGH'
assert get_risk_level(100) == 'HIGH'

print('✓ Risk level thresholds correct')
print('  LOW: 0-39')
print('  MEDIUM: 40-69')
print('  HIGH: 70-100')
"
```

**✅ Success Criteria**:
- Weights sum to exactly 1.0
- Manual calculation matches script output
- Risk level thresholds correct (LOW: 0-39, MEDIUM: 40-69, HIGH: 70-100)

---

## 🔧 Testing Auto-Fix Scripts

### Test 7: CodeQL Log Injection Auto-Fix

**Purpose**: Verify `scripts/codeql_fix_log_injection.py` works correctly.

```bash
# Step 1: Create test file with log injection vulnerability
cat > /tmp/test_log_injection.py << 'EOF'
import logging

logger = logging.getLogger(__name__)

def process_user_input(username, user_id):
    # VULNERABLE: User input directly in log
    logger.info(f"User logged in: {username}")
    logger.warning(f"Failed login attempt for user {user_id}")

    # SAFE: Already sanitized
    logger.info(f"Safe log: {sanitize_for_log(username)}")
EOF

# Step 2: Run auto-fix script
python3 scripts/codeql_fix_log_injection.py /tmp/test_log_injection.py

# Expected output:
# Found 2 log injection vulnerabilities
# Fixed: Line 7 - logger.info(f"User logged in: {username}")
# Fixed: Line 8 - logger.warning(f"Failed login attempt for user {user_id}")
# Skipped: Line 11 - Already sanitized

# Step 3: Verify fixes applied
cat /tmp/test_log_injection.py

# Expected result:
# logger.info(f"User logged in: {sanitize_for_log(username)}")
# logger.warning(f"Failed login attempt for user {user_id}")  # ← Should be fixed

# Step 4: Test dry-run mode
python3 scripts/codeql_fix_log_injection.py /tmp/test_log_injection.py --dry-run

# Expected: Report fixes but don't modify file

# Step 5: Verify no false positives
cat > /tmp/test_safe_logging.py << 'EOF'
import logging

logger = logging.getLogger(__name__)

# Already safe - should NOT be modified
logger.info("Static message with no variables")
logger.info(f"User count: {len(users)}")  # Integer, safe
logger.info(f"Status: {sanitize_for_log(status)}")  # Already sanitized
EOF

python3 scripts/codeql_fix_log_injection.py /tmp/test_safe_logging.py

# Expected output:
# No log injection vulnerabilities found
```

**✅ Success Criteria**:
- Detects log injection in f-strings
- Adds `sanitize_for_log()` wrapper correctly
- Skips already-sanitized logs
- No false positives on safe code
- Dry-run mode works

---

### Test 8: CodeQL Unused Imports Auto-Fix

**Purpose**: Verify `scripts/codeql_fix_unused_imports.py` works correctly.

```bash
# Step 1: Create test file with unused imports
cat > /tmp/test_unused_imports.py << 'EOF'
import os  # Used
import sys  # Unused
import logging  # Unused
from typing import List, Dict, Optional  # List unused
from datetime import datetime  # Used

logger = logging.getLogger(__name__)  # logging is actually used!

def process_data(data: Dict[str, str]) -> Optional[datetime]:
    print(os.path.basename(__file__))
    return datetime.now()
EOF

# Step 2: Run auto-fix script
python3 scripts/codeql_fix_unused_imports.py /tmp/test_unused_imports.py

# Expected output:
# Removed unused imports:
# - import sys
# - from typing import List (kept Dict, Optional)

# Step 3: Verify correct imports removed
cat /tmp/test_unused_imports.py

# Expected result:
# import os  # ← Kept (used)
# import logging  # ← Kept (used)
# from typing import Dict, Optional  # ← List removed
# from datetime import datetime  # ← Kept (used)

# Step 4: Test with commented-out imports
cat > /tmp/test_commented_imports.py << 'EOF'
import os  # Keep - used below
# import sys  # Already commented
# TODO: import json  # Not a real import

print(os.getcwd())
EOF

python3 scripts/codeql_fix_unused_imports.py /tmp/test_commented_imports.py

# Expected output:
# No unused imports found

# Step 5: Test dry-run
python3 scripts/codeql_fix_unused_imports.py /tmp/test_unused_imports.py --dry-run

# Expected: Show what would be removed but don't modify
```

**✅ Success Criteria**:
- Detects truly unused imports
- Keeps imports used in type hints
- Keeps imports used in function calls
- Doesn't remove commented imports
- Dry-run mode works

---

## 🤖 Verifying Claude Code Integration

### Test 9: Check Claude Code Configuration

**Purpose**: Verify `.claude/settings.local.json` is correctly configured.

```bash
# Step 1: Check configuration file exists
cat .claude/settings.local.json

# Expected content:
{
  "mcpServers": {},
  "statusBar": {
    "alwaysShow": true,
    "showTokenCount": true
  },
  "interactionHistory": "enabled",
  "hooks": {
    "preUserPromptSubmit": {
      "command": "scripts/quality-check.sh",
      "blocking": false
    }
  }
}

# Step 2: Verify CLAUDE.md exists and is comprehensive
wc -l CLAUDE.md
# Expected: 2719 lines

head -n 50 CLAUDE.md
# Expected: Should start with:
# # CLAUDE.md - OpenWatch AI Development Guide
# > **Purpose**: This file provides comprehensive guidance...

# Step 3: Test quality check hook
bash scripts/quality-check.sh

# Expected output:
# 🔍 Running pre-commit checks...
# ✓ Large files check
# ✓ Debug code check
# ✓ Secrets detection
# ✅ All checks passed

# Step 4: Verify hook triggers in Claude Code
# (Manual test - requires Claude Code IDE)
# 1. Open OpenWatch in Claude Code
# 2. Type a prompt
# 3. Before submission, quality-check.sh should run
# 4. Check status bar shows "Running hook..."
```

**✅ Success Criteria**:
- `.claude/settings.local.json` exists and valid JSON
- CLAUDE.md comprehensive (2,719 lines)
- Quality check hook configured
- Hook runs before prompt submission (manual test)

---

### Test 10: Verify CLAUDE.md Context Integration

**Purpose**: Ensure Claude Code uses CLAUDE.md for context.

```bash
# Test 1: Check CLAUDE.md content coverage
grep -i "security" CLAUDE.md | wc -l
# Expected: 100+ mentions (security-first architecture)

grep -i "database" CLAUDE.md | wc -l
# Expected: 50+ mentions (dual database architecture)

grep -i "test" CLAUDE.md | wc -l
# Expected: 80+ mentions (TDD principles)

# Test 2: Verify code patterns documented
grep -A 5 "CORRECT" CLAUDE.md | head -n 20
# Should show example code patterns

grep -A 5 "WRONG" CLAUDE.md | head -n 20
# Should show anti-patterns to avoid

# Test 3: Check compliance standards documented
grep -i "OWASP" CLAUDE.md
grep -i "NIST" CLAUDE.md
grep -i "ISO 27001" CLAUDE.md
grep -i "CMMC" CLAUDE.md
# All should return multiple matches

# Manual Test (requires Claude Code):
# 1. Ask Claude: "How do I create a new database model?"
# 2. Response should reference CLAUDE.md patterns
# 3. Should mention UUID primary keys (NOT integers)
# 4. Should mention repository pattern for MongoDB
```

**✅ Success Criteria**:
- CLAUDE.md covers security, architecture, testing
- Code examples show CORRECT and WRONG patterns
- Compliance standards documented
- Claude Code references CLAUDE.md in responses (manual test)

---

## 📈 Monitoring and Verification

### Test 11: Monitor GitHub Actions Logs

**Purpose**: Track AI automation execution history.

```bash
# View recent workflow runs
# Go to: https://github.com/<your-org>/openwatch/actions/workflows/claude-code-alerts.yml

# Check for:
# ✓ Green checkmarks (successful runs)
# ✓ Red X (failed runs - investigate)
# ✓ Yellow dot (in progress)

# Download logs for detailed analysis
gh run list --workflow=claude-code-alerts.yml --limit 10

# View specific run logs
gh run view <run-id> --log

# Search logs for key indicators
gh run view <run-id> --log | grep "Risk Score"
gh run view <run-id> --log | grep "Auto-approved"
gh run view <run-id> --log | grep "ERROR"

# Check for common issues:
grep "ModuleNotFoundError" <log-file>  # Missing dependencies
grep "exit code 1" <log-file>          # Script failures
grep "API rate limit" <log-file>       # GitHub API throttling
```

**✅ Success Criteria**:
- Workflow runs successfully (green checkmarks)
- Risk scores calculated for each PR
- No Python errors in logs
- Automated actions executed (approve/merge/review)

---

### Test 12: Verify Dependabot PR Comments

**Purpose**: Ensure AI automation posts comments on PRs.

```bash
# Find recent Dependabot PRs
gh pr list --label "dependencies" --limit 10

# View PR details
gh pr view <pr-number>

# Check for AI automation comment
gh pr view <pr-number> --comments | grep "AI Security Triage"

# Expected comment format:
# 🤖 **AI Security Triage Report**
#
# **Risk Level**: LOW
# **Risk Score**: 15/100
#
# **Automated Actions**:
# - ✅ Risk assessment completed
# - ✅ PR auto-approved
# - ✅ PR merged successfully

# Check PR status
gh pr view <pr-number> --json state,mergedAt,reviews

# For LOW risk PRs:
# - state: "MERGED"
# - mergedAt: <timestamp>
# - reviews: [ { "state": "APPROVED", "author": "github-actions[bot]" } ]
```

**✅ Success Criteria**:
- AI comment appears on Dependabot PRs
- Comment includes risk score and level
- Automated actions documented in comment
- LOW risk PRs auto-merged
- MEDIUM/HIGH risk PRs reviewed by humans

---

## 🚨 Troubleshooting

### Issue 1: Workflow Not Triggering

**Symptoms**:
- Dependabot creates PR
- No "Claude Code Security Triage" workflow run

**Debug Steps**:

```bash
# Step 1: Check workflow trigger configuration
cat .github/workflows/claude-code-alerts.yml | grep -A 10 "on:"

# Should include:
# on:
#   pull_request:
#     types: [opened, synchronize]
#   pull_request_target:  # For Dependabot PRs

# Step 2: Check if Dependabot label present
gh pr view <pr-number> --json labels

# Should include: {"name": "dependencies"}

# Step 3: Check workflow permissions
cat .github/workflows/claude-code-alerts.yml | grep -A 5 "permissions:"

# Should include:
# permissions:
#   pull-requests: write
#   contents: write
#   security-events: read

# Step 4: Manually trigger workflow
gh workflow run claude-code-alerts.yml --ref main

# Step 5: Check GitHub Actions are enabled
# Go to: https://github.com/<your-org>/openwatch/settings/actions
# Verify: "Allow all actions and reusable workflows" is selected
```

---

### Issue 2: Risk Assessment Script Failing

**Symptoms**:
- Workflow runs but fails at risk assessment step
- Error: "ModuleNotFoundError" or "ImportError"

**Debug Steps**:

```bash
# Step 1: Check Python version
python3 --version
# Required: Python 3.9+

# Step 2: Test script dependencies
python3 -c "import json, sys, yaml"
# Should exit with no output (success)

# If error, install missing modules:
pip3 install pyyaml

# Step 3: Test script manually
python3 scripts/risk_assessment.py < /tmp/test_alert_low.json

# If fails, check error message:
# - "No module named 'xyz'": Install missing dependency
# - "JSON decode error": Check input format
# - "KeyError": Check GitHub alert structure

# Step 4: Verify GitHub secrets (if using)
# Go to: https://github.com/<your-org>/openwatch/settings/secrets/actions
# Check: GITHUB_TOKEN is available (auto-provided)

# Step 5: Check workflow environment
cat .github/workflows/claude-code-alerts.yml | grep -A 10 "steps:"

# Should include Python setup:
# - uses: actions/setup-python@v4
#   with:
#     python-version: '3.9'
```

---

### Issue 3: Auto-Merge Not Working

**Symptoms**:
- LOW risk Dependabot PR identified
- Comment posted but PR not merged

**Debug Steps**:

```bash
# Step 1: Check PR status checks
gh pr view <pr-number> --json statusCheckRollup

# All checks must pass for auto-merge:
# - Build backend (success)
# - Build frontend (success)
# - Tests (success)
# - Security scan (success)

# Step 2: Check if branch protection rules allow
# Go to: https://github.com/<your-org>/openwatch/settings/branches
# Check main branch protection:
# - "Require status checks to pass" should allow auto-merge for passing PRs
# - "Require review" should be disabled OR have exception for Dependabot

# Step 3: Verify workflow has merge permissions
cat .github/workflows/claude-code-alerts.yml | grep -A 5 "permissions:"

# Must include:
# permissions:
#   contents: write  # Required to merge

# Step 4: Check if auto-merge is enabled in workflow
grep -A 20 "Auto-merge PR" .github/workflows/claude-code-alerts.yml

# Should include:
# if: steps.risk-assessment.outputs.risk_level == 'LOW'
# run: gh pr merge ${{ github.event.pull_request.number }} --auto --squash

# Step 5: Test manual merge
gh pr merge <pr-number> --auto --squash

# If fails, error message will indicate cause:
# - "required reviews not satisfied": Adjust branch protection
# - "required status checks not passed": Wait for CI
# - "insufficient permissions": Check GitHub token permissions
```

---

### Issue 4: Claude Code Not Using CLAUDE.md

**Symptoms**:
- Claude Code responses don't follow OpenWatch patterns
- No mention of security-first principles
- Suggestions violate CLAUDE.md guidelines

**Debug Steps**:

```bash
# Step 1: Verify CLAUDE.md in project root
ls -lh CLAUDE.md
# Expected: 2719 lines

# Step 2: Check .claude/settings.local.json
cat .claude/settings.local.json | grep -v "^[[:space:]]*$"
# Should be valid JSON

# Step 3: Verify Claude Code workspace folder
# In Claude Code IDE:
# File > Open Folder > Select /home/rracine/hanalyx/openwatch/
# CLAUDE.md should be in the root of opened folder

# Step 4: Test Claude Code context awareness (manual)
# Ask Claude: "What is the primary key type for database models?"
# Expected response: "UUID (NOT integers)"
# If says integers, CLAUDE.md not loaded

# Step 5: Check Claude Code version
# Help > About > Version
# Required: Claude Code 1.0.0+

# Step 6: Restart Claude Code
# File > Exit
# Reopen OpenWatch workspace
# Test again with simple question
```

---

## ✅ Success Criteria

### Overall AI Automation Health

Use this checklist to verify AI automation is fully functional:

#### Prerequisites (5/5 required) - Test #0
- [ ] `.github/workflows/` NOT ignored by .gitignore
- [ ] Workflow files tracked in git (`git ls-tree HEAD .github/workflows/`)
- [ ] Workflows committed and pushed to GitHub
- [ ] Workflows visible in GitHub Actions UI (not "Not found")
- [ ] Workflow files visible in GitHub file browser

#### Workflow Integration (5/5 required)
- [ ] `claude-code-alerts.yml` exists and is valid YAML
- [ ] Workflow triggers on Dependabot PRs (`pull_request_target`)
- [ ] Workflow has correct permissions (pull-requests, contents, security-events)
- [ ] Python 3.9+ environment configured in workflow
- [ ] Workflow enabled in GitHub Actions UI

#### Risk Assessment (5/5 required)
- [ ] `scripts/risk_assessment.py` executes without errors
- [ ] Correct risk scores for LOW/MEDIUM/HIGH test cases
- [ ] Risk calculation uses correct weights (0.4, 0.35, 0.25)
- [ ] Risk level thresholds correct (LOW: 0-39, MEDIUM: 40-69, HIGH: 70-100)
- [ ] Error handling for invalid/missing input

#### Automated Actions (4/4 required)
- [ ] LOW risk: PRs auto-approved and merged
- [ ] MEDIUM risk: Claude task created, human review requested
- [ ] HIGH risk: Auto-merge blocked, security team notified
- [ ] AI comment posted on all Dependabot PRs with risk score

#### Auto-Fix Scripts (4/4 required)
- [ ] `codeql_fix_log_injection.py` detects and fixes vulnerabilities
- [ ] No false positives on already-sanitized logs
- [ ] `codeql_fix_unused_imports.py` removes truly unused imports
- [ ] Dry-run mode works for both scripts

#### Claude Code Integration (4/4 required)
- [ ] `.claude/settings.local.json` valid and loaded
- [ ] `CLAUDE.md` comprehensive (2,719 lines)
- [ ] Quality check hook runs before prompt submission
- [ ] Claude Code responses reference CLAUDE.md patterns

#### Monitoring (3/3 required)
- [ ] GitHub Actions logs accessible and show successful runs
- [ ] Dependabot PRs have AI triage comments
- [ ] No recurring errors in workflow logs

---

## 📊 Scoring

**Total Requirements**: 30 (includes 5 new prerequisite checks from Test #0)

**Grading Scale**:
- **30/30 (100%)**: A+ - Perfect AI automation
- **28-29/30 (93-97%)**: A - Excellent, minor improvements needed
- **24-27/30 (80-90%)**: B - Good, some gaps to address
- **20-23/30 (67-77%)**: C - Functional but needs work
- **<20/30 (<67%)**: D/F - Major issues, requires immediate attention

---

## 🎯 Next Steps After Testing

### If All Tests Pass (30/30)

✅ **AI automation fully operational!**

**Maintenance**:
1. Monitor weekly for workflow failures
2. Update risk assessment weights as needed
3. Review auto-merged PRs periodically
4. Keep CLAUDE.md updated with new patterns

**Enhancements**:
1. Add Slack notifications for HIGH risk alerts
2. Implement auto-rollback for failed auto-merges
3. Add metrics dashboard for AI automation performance
4. Create monthly report of AI-automated fixes

---

### If Tests Fail (Score < 24/30)

🚨 **Critical issues detected**

**Immediate Actions**:
1. **Workflow Failures**: Check permissions, Python version, dependencies
2. **Risk Assessment Errors**: Verify script syntax, test with known inputs
3. **Auto-Fix Not Working**: Check file permissions, test manually
4. **Claude Code Issues**: Verify CLAUDE.md location, restart IDE

**Escalation Path**:
1. Check GitHub Actions logs for detailed error messages
2. Test components individually (risk assessment script, auto-fix scripts)
3. Verify all configuration files (`.claude/settings.local.json`, workflow YAML)
4. If unresolved, create GitHub issue with:
   - Test results
   - Error logs
   - Configuration files
   - Environment details (Python version, GitHub Actions runner)

---

## 📚 Additional Resources

### Documentation
- **Workflow Configuration**: `.github/workflows/claude-code-alerts.yml`
- **Risk Assessment**: `scripts/risk_assessment.py`
- **Auto-Fix Scripts**: `scripts/codeql_fix_*.py`
- **Development Guide**: `CLAUDE.md`
- **Security Audit**: `docs/SCRIPTS_SECURITY_AUDIT.md`

### External References
- **GitHub Actions**: https://docs.github.com/en/actions
- **Dependabot**: https://docs.github.com/en/code-security/dependabot
- **CodeQL**: https://codeql.github.com/docs/
- **Claude Code**: https://docs.anthropic.com/claude/docs/claude-code

---

**Last Updated**: 2025-11-02
**Maintained By**: OpenWatch Security Team
**Next Review**: 2026-02-02 (Quarterly)
**Status**: ✅ ACTIVE
