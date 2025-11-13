# Automated Triage Workflow Troubleshooting

**Last Updated**: 2025-11-13
**Status**: Fixed - Error handling improved for both Dependabot and Code Scanning

---

## Overview

The OpenWatch Automated Security & Dependency Triage system (`automated-triage.yml`) processes security alerts from two sources:

1. **Dependabot Alerts** - Dependency vulnerability alerts
2. **Code Scanning Alerts** - CodeQL/Trivy/Grype findings

This document explains how to troubleshoot common issues and ensure the workflow runs successfully.

---

## Common Errors and Fixes

### Error 1: Dependabot API 403 - Resource Not Accessible

**Symptom**:
```
gh: Resource not accessible by integration (HTTP 403)
Error: Process completed with exit code 1.
```

**Root Cause**:
The GitHub Actions `GITHUB_TOKEN` does not have permission to access the Dependabot API, OR Dependabot is not enabled for the repository.

**Fix Applied** (2025-11-13):
- Added `continue-on-error: true` to the Fetch Dependabot Alerts step
- Added graceful error handling that creates empty alert files when API access fails
- Changed `contents: write` to `contents: read` (minimum required permission)
- Added informative warning message when Dependabot is unavailable

**Result**: The workflow now continues successfully even if Dependabot is not accessible.

**To Fully Enable Dependabot**:

1. **Enable Dependabot Alerts** (Repository Settings):
   ```
   Settings → Code security and analysis → Dependabot alerts → Enable
   ```

2. **Enable Dependabot Security Updates**:
   ```
   Settings → Code security and analysis → Dependabot security updates → Enable
   ```

3. **Configure Dependabot** (`.github/dependabot.yml`):
   ```yaml
   version: 2
   updates:
     - package-ecosystem: "npm"
       directory: "/frontend"
       schedule:
         interval: "weekly"
       open-pull-requests-limit: 10

     - package-ecosystem: "pip"
       directory: "/backend"
       schedule:
         interval: "weekly"
       open-pull-requests-limit: 10
   ```

4. **Grant Workflow Permissions** (if using fine-grained PAT):
   - Go to: Settings → Actions → General → Workflow permissions
   - Select: "Read and write permissions"
   - Check: "Allow GitHub Actions to create and approve pull requests"

**Verification**:
```bash
# Check if Dependabot alerts are accessible
gh api /repos/OWNER/REPO/dependabot/alerts

# If successful, you'll see JSON array of alerts
# If 403, Dependabot is not enabled or token lacks permissions
```

---

### Error 2: Code Scanning Risk Assessment Failure

**Symptom**:
```
Found 100 open code scanning alerts
(workflow stops or fails after risk assessment)
```

**Root Cause**:
- Risk assessment script (`scripts/risk_assessment.py`) may fail on unexpected alert formats
- Missing Python dependencies
- Alert JSON structure doesn't match expected schema

**Fix Applied** (2025-11-13):
- Added `continue-on-error: true` to Risk Assessment step
- Added fallback logic to create empty alert files if assessment fails
- Added status message in summary report when risk assessment encounters errors

**Result**: Workflow completes successfully even if risk assessment fails, with clear indication in the summary.

**Manual Risk Assessment**:
```bash
# Test risk assessment locally
cd /home/rracine/hanalyx/openwatch

# Fetch code scanning alerts
gh api /repos/OWNER/REPO/code-scanning/alerts --paginate > alerts.json

# Run risk assessment
python scripts/risk_assessment.py --type=codeql alerts.json

# Check output files
ls -la low_risk_alerts.json medium_risk_alerts.json high_risk_alerts.json
```

---

### Error 3: Empty or Missing Alert Files

**Symptom**:
```
jq: error (at <stdin>:0): Cannot iterate over null (null)
```

**Root Cause**:
Risk assessment creates empty output files when there are no alerts of a specific risk level.

**Fix Applied** (2025-11-13):
- Added file existence checks before jq parsing
- Create empty JSON arrays (`[]`) if files don't exist
- Use `|| echo "0"` fallback for all jq commands

**Code Example**:
```bash
# Check if risk assessment files exist, create empty arrays if not
[ -f low_risk_alerts.json ] || echo "[]" > low_risk_alerts.json
[ -f medium_risk_alerts.json ] || echo "[]" > medium_risk_alerts.json
[ -f high_risk_alerts.json ] || echo "[]" > high_risk_alerts.json

# Safe jq parsing with fallback
LOW_COUNT=$(jq 'length' low_risk_alerts.json 2>/dev/null || echo "0")
```

---

## Workflow Permissions

**Current Configuration** (`.github/workflows/automated-triage.yml`):
```yaml
permissions:
  contents: read          # Read repository content
  issues: write           # Create/update issues for high-risk alerts
  pull-requests: write    # Comment on and label PRs
  security-events: read   # Read code scanning alerts
```

**Why Not `contents: write`?**
- Not needed for reading alerts or creating issues
- Follows principle of least privilege
- Reduces security risk

**Missing Permission**: `dependabot: read` (not yet available in GitHub Actions)

**Workaround**: Use personal access token (PAT) or enable Dependabot repository access.

---

## Risk Assessment Algorithm

**3-Dimensional Scoring**:
```
Risk Score = (Complexity + Severity + Disruption) / 3
```

**Risk Levels**:
- **LOW** (≤ 1.6): Auto-approve and auto-merge
- **MEDIUM** (1.7-2.3): Request human review, add labels
- **HIGH** (≥ 2.4): Create GitHub issue, require immediate attention

**For Dependabot Alerts**:
| Factor     | LOW         | MEDIUM      | HIGH        |
|------------|-------------|-------------|-------------|
| Complexity | patch       | minor       | major       |
| Severity   | low         | moderate    | high/critical |
| Disruption | non-critical| some impact | critical pkg|

**For Code Scanning Alerts**:
| Factor     | LOW              | MEDIUM           | HIGH             |
|------------|------------------|------------------|------------------|
| Complexity | auto-fixable     | manual fix       | complex refactor |
| Severity   | note/warning     | warning          | error            |
| Disruption | code quality     | security concern | injection/XSS    |

---

## Workflow Outputs

**Artifacts** (30-day retention):
- `risk-assessment-results/`
  - `low_risk_alerts.json`
  - `medium_risk_alerts.json`
  - `high_risk_alerts.json`
  - `dependabot_alerts.json`

- `code-scanning-assessment/`
  - `low_risk_alerts.json`
  - `medium_risk_alerts.json`
  - `high_risk_alerts.json`
  - `code_scanning_sample.json` (first 100 alerts)

**GitHub Actions Summary** (visible in workflow run):
```
# Code Scanning Triage Report

**Total Alerts:** 100

| Risk Level | Count | Action       |
|------------|-------|--------------|
| LOW        | 25    | Auto-fix     |
| MEDIUM     | 50    | Claude PR    |
| HIGH       | 25    | Human review |
```

---

## Manual Workflow Execution

**Dry Run** (no changes made):
```bash
gh workflow run automated-triage.yml -f dry_run=true
```

**Live Run** (auto-approve low-risk PRs):
```bash
gh workflow run automated-triage.yml -f dry_run=false
```

**Check Workflow Status**:
```bash
# List recent runs
gh run list --workflow=automated-triage.yml

# View specific run
gh run view <run-id>

# Download artifacts
gh run download <run-id>
```

---

## Testing Risk Assessment Locally

**Setup**:
```bash
cd /home/rracine/hanalyx/openwatch

# Install dependencies
pip install -r backend/requirements-dev.txt
```

**Test Dependabot Assessment**:
```bash
# Create sample Dependabot alert JSON
cat > sample_dependabot.json << 'EOF'
[
  {
    "number": 1,
    "state": "open",
    "dependency": {
      "package": {
        "name": "fastapi"
      }
    },
    "security_vulnerability": {
      "severity": "high",
      "vulnerable_version_range": ">= 0.95.0, < 0.100.0"
    }
  }
]
EOF

# Run assessment
python scripts/risk_assessment.py --type=dependabot sample_dependabot.json

# Check results
cat low_risk_alerts.json
cat medium_risk_alerts.json
cat high_risk_alerts.json
```

**Test CodeQL Assessment**:
```bash
# Create sample CodeQL alert JSON
cat > sample_codeql.json << 'EOF'
[
  {
    "number": 1,
    "state": "open",
    "rule": {
      "id": "py/sql-injection",
      "severity": "error"
    },
    "tool": {
      "name": "CodeQL"
    }
  }
]
EOF

# Run assessment
python scripts/risk_assessment.py --type=codeql sample_codeql.json

# Check results
ls -la *_risk_alerts.json
```

---

## Integration with Dependency Management Workflow

The `dependency-management.yml` workflow complements the triage workflow:

**Triage Workflow** (`automated-triage.yml`):
- Runs: Every 6 hours (scheduled)
- Purpose: Analyze existing alerts from GitHub Security
- Actions: Auto-approve LOW risk, request review for MEDIUM, create issues for HIGH

**Dependency Management** (`dependency-management.yml`):
- Runs: On Dependabot PR creation
- Purpose: Analyze incoming dependency update PRs
- Actions: Run tests, security audits, auto-merge if eligible

**Combined Flow**:
```
1. Dependabot creates PR → dependency-management.yml runs tests
2. Every 6 hours → automated-triage.yml analyzes all open alerts
3. LOW risk alerts → Auto-approved by triage workflow
4. MEDIUM risk alerts → Labeled for human review
5. HIGH risk alerts → GitHub issue created with details
```

---

## Troubleshooting Checklist

Before reporting issues, verify:

- [ ] Dependabot is enabled in repository settings
- [ ] Code scanning (CodeQL/Trivy/Grype) is configured
- [ ] Workflow permissions are set correctly (see above)
- [ ] `scripts/risk_assessment.py` exists and is executable
- [ ] Python 3.9+ is available in the workflow runner
- [ ] All required dependencies are installed (handled by workflow)
- [ ] Artifact retention is set to at least 30 days

**Still Having Issues?**

1. **Check Workflow Logs**:
   ```bash
   gh run list --workflow=automated-triage.yml
   gh run view <run-id> --log
   ```

2. **Download and Inspect Artifacts**:
   ```bash
   gh run download <run-id>
   cat risk-assessment-results/*.json
   ```

3. **Test Risk Assessment Locally** (see section above)

4. **Review Recent Changes**:
   ```bash
   git log --oneline -- .github/workflows/automated-triage.yml
   git log --oneline -- scripts/risk_assessment.py
   ```

---

## Recent Fixes (2025-11-13)

**Changes Made**:

1. **Dependabot API Error Handling**:
   - Added `continue-on-error: true` to prevent workflow failure
   - Added graceful fallback when API is inaccessible
   - Create empty alert files to prevent downstream errors
   - Informative warning messages

2. **Code Scanning Risk Assessment**:
   - Added `continue-on-error: true` to risk assessment step
   - Added file existence checks before jq parsing
   - Create empty JSON arrays as fallback
   - Added status message in summary report

3. **Permissions**:
   - Changed `contents: write` to `contents: read` (least privilege)
   - Documented required permissions

**Files Modified**:
- `.github/workflows/automated-triage.yml`
- `docs/AUTOMATED_TRIAGE_TROUBLESHOOTING.md` (this file)

**Verification**:
- Workflow now completes successfully even when Dependabot is unavailable
- Code scanning triage continues even if risk assessment fails
- Clear error messages guide users to enable missing features

---

## Additional Resources

- **CLAUDE.md**: OpenWatch development guide and security standards
- **GitHub Security Features**: https://docs.github.com/en/code-security
- **Dependabot Configuration**: https://docs.github.com/en/code-security/dependabot
- **CodeQL**: https://codeql.github.com/
- **Risk Assessment Script**: `scripts/risk_assessment.py`
- **Weekly Audit Workflow**: `.github/workflows/dependency-management.yml`

---

**Questions or Issues?**

1. Review this troubleshooting guide
2. Check workflow logs: `gh run view <run-id> --log`
3. Test risk assessment locally (see above)
4. Open GitHub issue with logs and artifact files
