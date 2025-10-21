# Automated GitHub Triage & Auto-Fix System

**Status:** Design Document
**Date Created:** October 20, 2025
**Owner:** OpenWatch Development Team

---

## 🎯 Executive Summary

This document describes an **intelligent automated triage and auto-fix system** that processes GitHub Issues, Pull Requests, security findings, and Dependabot alerts using a **risk-based decision matrix** to determine if Claude AI can auto-fix or if human review is required.

**Key Innovation:** Risk matrix (Complexity × Severity × Disruption) → Auto-fix decision

---

## 📊 Problem Statement

### Current Challenges:
1. **20+ open issues** requiring manual triage
2. **138 open PRs** (many stale, need review/merge/close)
3. **8,756 code scanning alerts** (Trivy, Grype, CodeQL)
4. **25 Dependabot alerts** requiring dependency updates
5. **Manual triage** for all findings (time-consuming, error-prone)

### Desired State:
- ✅ Automated triage of all findings
- ✅ Risk-based auto-fix decisions
- ✅ Claude AI handles low-risk fixes autonomously
- ✅ Human-in-the-loop for high-risk changes
- ✅ Continuous monitoring and remediation

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    GitHub Event Sources                         │
├─────────────────────────────────────────────────────────────────┤
│  • New Issues                                                   │
│  • Pull Requests                                                │
│  • Dependabot Alerts                                            │
│  • Code Scanning Alerts (CodeQL, Trivy, Grype)                 │
│  • Security Advisories                                          │
└──────────────────┬──────────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────────┐
│              GitHub Actions Workflow (Orchestrator)             │
│  .github/workflows/automated-triage.yml                         │
├─────────────────────────────────────────────────────────────────┤
│  1. Event Detection & Classification                            │
│  2. Risk Assessment (Complexity × Severity × Disruption)        │
│  3. Decision Routing                                            │
└──────────────┬─────────────────┬────────────────────────────────┘
               │                 │
       ┌───────┴───────┐  ┌──────┴────────┐
       │               │  │               │
       ▼               ▼  ▼               ▼
┌─────────────┐  ┌──────────────┐  ┌─────────────┐
│  Auto-Fix   │  │  Claude AI   │  │   Human     │
│  (Low Risk) │  │  (Med Risk)  │  │ (High Risk) │
├─────────────┤  ├──────────────┤  ├─────────────┤
│ • Dependency│  │ • Create PR  │  │ • Create    │
│   updates   │  │ • Add tests  │  │   issue     │
│ • Format    │  │ • Request    │  │ • Request   │
│   fixes     │  │   review     │  │   review    │
│ • Unused    │  │              │  │ • Label for │
│   imports   │  │              │  │   human     │
└─────────────┘  └──────────────┘  └─────────────┘
       │                 │                 │
       └─────────────────┴─────────────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │  Monitoring & Metrics│
              │  • Auto-fix success  │
              │  • Human review rate │
              │  • Time to resolution│
              └──────────────────────┘
```

---

## 🎲 Risk Matrix Decision Framework

### Risk Score Calculation

```
Risk Score = (Complexity + Severity + Disruption) / 3

Where each dimension is scored:
  Low    = 1
  Medium = 2
  High   = 3

Risk Level:
  1.0 - 1.6 = LOW    → Auto-fix (no human review)
  1.7 - 2.3 = MEDIUM → Claude creates PR, requests review
  2.4 - 3.0 = HIGH   → Human assessment required
```

### Dimension Definitions

#### 1. **Complexity** (Implementation Difficulty)

| Level  | Score | Criteria | Examples |
|--------|-------|----------|----------|
| **Low** | 1 | • Single file change<br>• No logic changes<br>• Well-documented fix | • Dependency version bump<br>• Unused import removal<br>• Code formatting |
| **Medium** | 2 | • 2-5 file changes<br>• Minor logic changes<br>• Requires testing | • TypeScript type fixes<br>• API parameter changes<br>• Database migration |
| **High** | 3 | • Multi-module changes<br>• Significant refactoring<br>• Architecture changes | • Authentication overhaul<br>• Database schema redesign<br>• Framework migration |

#### 2. **Severity** (Impact if NOT Fixed)

| Level  | Score | Criteria | Examples |
|--------|-------|----------|----------|
| **Low** | 1 | • No security impact<br>• No functionality impact<br>• Nice-to-have | • Code style issues<br>• Documentation typos<br>• Low-priority CVEs |
| **Medium** | 2 | • Minor security risk<br>• Affects non-critical features<br>• Performance degradation | • Medium CVEs<br>• Non-auth API bugs<br>• Memory leaks |
| **High** | 3 | • Critical security vulnerability<br>• Data loss risk<br>• System unavailable | • Critical CVEs (CVSS ≥ 9.0)<br>• SQL injection<br>• Auth bypass |

#### 3. **Disruption** (Risk if Fix Fails)

| Level  | Score | Criteria | Examples |
|--------|-------|----------|----------|
| **Low** | 1 | • No breaking changes<br>• Backward compatible<br>• Easy rollback | • Dependency patch updates<br>• CSS changes<br>• Log format changes |
| **Medium** | 2 | • Minor breaking changes<br>• Config changes needed<br>• Some downtime | • API schema changes<br>• Database migrations<br>• Dependency minor version |
| **High** | 3 | • Major breaking changes<br>• Data migration required<br>• Extended downtime | • Python 2→3 upgrade<br>• React 17→18 migration<br>• Database engine change |

---

## 🤖 Automation Capabilities

### What Dependabot Can Do (Native)

✅ **Automatic dependency updates**
- Version bumps (patch, minor, major)
- Security vulnerability fixes
- Creates PRs automatically
- Groups updates by severity

✅ **Alerting**
- Security vulnerability notifications
- Ecosystem-specific alerts (npm, pip, Docker)
- CVSS scoring

❌ **What Dependabot CANNOT Do:**
- Custom risk assessment
- Intelligent auto-merging based on risk
- Code scanning alert triage
- Issue management
- Custom fix implementation

### What We Need to Build (GitHub Actions + Scripts)

✅ **Enhanced Triage System**
- Risk matrix scoring
- Intelligent routing
- Custom auto-fix logic
- Claude AI integration

---

## 🔧 Implementation Components

### 1. GitHub Actions Workflows

#### A. **Dependabot Alert Triage** (`.github/workflows/dependabot-triage.yml`)

```yaml
name: Dependabot Alert Triage

on:
  schedule:
    - cron: '0 */6 * * *'  # Every 6 hours
  workflow_dispatch:

jobs:
  triage-dependabot:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Get Dependabot Alerts
        id: alerts
        run: |
          gh api /repos/${{ github.repository }}/dependabot/alerts \
            --jq '.[] | {number, severity, package, vulnerable_version, patched_version}' \
            > dependabot_alerts.json
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Risk Assessment
        id: risk
        run: python scripts/risk_assessment.py dependabot_alerts.json

      - name: Auto-fix Low Risk
        if: steps.risk.outputs.has_low_risk == 'true'
        run: |
          # Enable Dependabot auto-merge for low-risk updates
          for PR in $(cat low_risk_prs.txt); do
            gh pr merge $PR --auto --squash
          done
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Request Review for Medium Risk
        if: steps.risk.outputs.has_medium_risk == 'true'
        run: |
          # Add reviewers and labels
          for PR in $(cat medium_risk_prs.txt); do
            gh pr edit $PR --add-label "review-required" --add-reviewer "${{ github.repository_owner }}"
          done
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Create Issues for High Risk
        if: steps.risk.outputs.has_high_risk == 'true'
        run: python scripts/create_high_risk_issues.py high_risk_alerts.json
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

#### B. **Code Scanning Alert Triage** (`.github/workflows/security-triage.yml`)

```yaml
name: Security Alert Triage

on:
  schedule:
    - cron: '0 8 * * 1'  # Every Monday at 8 AM
  code_scanning_alert:
    types: [created, reopened]

jobs:
  triage-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Get Code Scanning Alerts
        run: |
          # Get all open alerts
          gh api /repos/${{ github.repository }}/code-scanning/alerts \
            --paginate \
            --jq '.[] | select(.state == "open") |
                  {number, rule: .rule.id, severity: .rule.severity,
                   tool: .tool.name, file: .most_recent_instance.location.path}' \
            > security_alerts.json
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Categorize Alerts
        run: python scripts/categorize_security_alerts.py security_alerts.json

      - name: Dismiss False Positives
        run: |
          # Auto-dismiss known false positives
          python scripts/dismiss_false_positives.py false_positives.json
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Create Fix PRs for Low Risk
        run: |
          # Run automated fix scripts
          python scripts/auto_fix_security.py low_risk_alerts.json
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

#### C. **Issue Triage** (`.github/workflows/issue-triage.yml`)

```yaml
name: Issue Triage

on:
  issues:
    types: [opened, reopened]
  schedule:
    - cron: '0 0 * * *'  # Daily

jobs:
  triage-issues:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Classify Issue
        uses: actions/github-script@v6
        with:
          script: |
            const issue = context.payload.issue;
            const body = issue.body.toLowerCase();

            // Auto-label based on content
            let labels = [];
            if (body.includes('bug') || body.includes('error')) labels.push('bug');
            if (body.includes('feature') || body.includes('enhancement')) labels.push('enhancement');
            if (body.includes('security')) labels.push('security');
            if (body.includes('documentation')) labels.push('documentation');

            // Add labels
            if (labels.length > 0) {
              await github.rest.issues.addLabels({
                owner: context.repo.owner,
                repo: context.repo.repo,
                issue_number: issue.number,
                labels: labels
              });
            }

      - name: Check for Stale Issues
        uses: actions/stale@v8
        with:
          days-before-stale: 60
          days-before-close: 7
          stale-issue-label: 'stale'
          stale-issue-message: 'This issue has been inactive for 60 days and will be closed in 7 days if no activity occurs.'
```

#### D. **PR Auto-Merge** (`.github/workflows/pr-auto-merge.yml`)

```yaml
name: PR Auto-Merge

on:
  pull_request:
    types: [opened, synchronize]
  check_suite:
    types: [completed]

jobs:
  auto-merge:
    runs-on: ubuntu-latest
    if: github.actor == 'dependabot[bot]' || contains(github.event.pull_request.labels.*.name, 'auto-merge')
    steps:
      - name: Check PR Criteria
        id: check
        uses: actions/github-script@v6
        with:
          script: |
            const pr = context.payload.pull_request;

            // Get file changes
            const files = await github.rest.pulls.listFiles({
              owner: context.repo.owner,
              repo: context.repo.repo,
              pull_number: pr.number
            });

            // Risk assessment
            const complexity = files.data.length <= 3 ? 1 : (files.data.length <= 10 ? 2 : 3);
            const changedLines = files.data.reduce((sum, f) => sum + f.changes, 0);
            const disruption = changedLines <= 50 ? 1 : (changedLines <= 200 ? 2 : 3);

            // Check labels for severity
            const hasSecurityLabel = pr.labels.some(l => l.name === 'security');
            const severity = hasSecurityLabel ? 3 : 1;

            const riskScore = (complexity + severity + disruption) / 3;

            core.setOutput('risk_score', riskScore);
            core.setOutput('can_auto_merge', riskScore <= 1.6);

      - name: Enable Auto-Merge
        if: steps.check.outputs.can_auto_merge == 'true'
        run: gh pr merge ${{ github.event.pull_request.number }} --auto --squash
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Request Review
        if: steps.check.outputs.can_auto_merge != 'true'
        run: |
          gh pr edit ${{ github.event.pull_request.number }} \
            --add-label "review-required" \
            --add-reviewer "${{ github.repository_owner }}"

          # Add risk score comment
          gh pr comment ${{ github.event.pull_request.number }} \
            --body "⚠️ Risk Score: ${{ steps.check.outputs.risk_score }} - Human review required"
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

### 2. Risk Assessment Script (`scripts/risk_assessment.py`)

```python
#!/usr/bin/env python3
"""
Risk Assessment Engine for GitHub Automation
Calculates risk scores based on Complexity, Severity, and Disruption
"""

import json
import sys
from typing import Dict, List, Tuple
from dataclasses import dataclass
from enum import Enum


class RiskLevel(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3


@dataclass
class RiskScore:
    complexity: RiskLevel
    severity: RiskLevel
    disruption: RiskLevel

    @property
    def average(self) -> float:
        """Calculate average risk score"""
        return (self.complexity.value + self.severity.value + self.disruption.value) / 3

    @property
    def level(self) -> str:
        """Determine overall risk level"""
        score = self.average
        if score <= 1.6:
            return "LOW"
        elif score <= 2.3:
            return "MEDIUM"
        else:
            return "HIGH"

    def __str__(self) -> str:
        return f"Risk(C:{self.complexity.name}, S:{self.severity.name}, D:{self.disruption.name}) = {self.average:.2f} ({self.level})"


class DependabotRiskAssessor:
    """Assess risk for Dependabot alerts"""

    # CVE severity mapping
    CVE_SEVERITY_MAP = {
        "critical": RiskLevel.HIGH,
        "high": RiskLevel.HIGH,
        "moderate": RiskLevel.MEDIUM,
        "low": RiskLevel.LOW,
    }

    # Package update type complexity
    UPDATE_COMPLEXITY = {
        "patch": RiskLevel.LOW,     # 1.0.0 → 1.0.1
        "minor": RiskLevel.MEDIUM,  # 1.0.0 → 1.1.0
        "major": RiskLevel.HIGH,    # 1.0.0 → 2.0.0
    }

    def assess_alert(self, alert: Dict) -> RiskScore:
        """
        Assess risk for a Dependabot alert

        Args:
            alert: Dependabot alert data

        Returns:
            RiskScore with complexity, severity, disruption
        """
        # Determine complexity based on update type
        update_type = self._determine_update_type(
            alert.get("vulnerable_version", ""),
            alert.get("patched_version", "")
        )
        complexity = self.UPDATE_COMPLEXITY.get(update_type, RiskLevel.MEDIUM)

        # Determine severity from CVE score
        severity_str = alert.get("severity", "low").lower()
        severity = self.CVE_SEVERITY_MAP.get(severity_str, RiskLevel.LOW)

        # Determine disruption based on package type
        package_name = alert.get("package", {}).get("name", "")
        disruption = self._assess_disruption(package_name, update_type)

        return RiskScore(complexity, severity, disruption)

    def _determine_update_type(self, current: str, patched: str) -> str:
        """Determine if update is patch, minor, or major"""
        try:
            current_parts = [int(x) for x in current.split(".")[:3]]
            patched_parts = [int(x) for x in patched.split(".")[:3]]

            if current_parts[0] != patched_parts[0]:
                return "major"
            elif current_parts[1] != patched_parts[1]:
                return "minor"
            else:
                return "patch"
        except:
            return "minor"  # Default to medium complexity

    def _assess_disruption(self, package: str, update_type: str) -> RiskLevel:
        """Assess disruption based on package criticality"""
        # Core framework packages = higher disruption
        critical_packages = [
            "react", "fastapi", "sqlalchemy", "celery",
            "typescript", "webpack", "vite"
        ]

        if any(pkg in package.lower() for pkg in critical_packages):
            if update_type == "major":
                return RiskLevel.HIGH
            elif update_type == "minor":
                return RiskLevel.MEDIUM

        return RiskLevel.LOW


class CodeScanningRiskAssessor:
    """Assess risk for CodeQL/Trivy/Grype alerts"""

    # Severity mapping
    SEVERITY_MAP = {
        "error": RiskLevel.HIGH,
        "warning": RiskLevel.MEDIUM,
        "note": RiskLevel.LOW,
    }

    # Rule complexity (how hard to fix)
    RULE_COMPLEXITY = {
        "py/unused-import": RiskLevel.LOW,
        "py/log-injection": RiskLevel.MEDIUM,
        "py/sql-injection": RiskLevel.HIGH,
        "CVE-": RiskLevel.MEDIUM,  # Default for CVEs
    }

    def assess_alert(self, alert: Dict) -> RiskScore:
        """Assess risk for code scanning alert"""
        rule_id = alert.get("rule", {}).get("id", "")
        severity_str = alert.get("rule", {}).get("severity", "note")
        tool = alert.get("tool", {}).get("name", "")

        # Determine complexity
        complexity = self._assess_complexity(rule_id, tool)

        # Determine severity
        severity = self.SEVERITY_MAP.get(severity_str, RiskLevel.LOW)

        # Determine disruption
        disruption = self._assess_disruption(rule_id, tool)

        return RiskScore(complexity, severity, disruption)

    def _assess_complexity(self, rule_id: str, tool: str) -> RiskLevel:
        """Assess fix complexity"""
        # Check known rules
        for pattern, level in self.RULE_COMPLEXITY.items():
            if pattern in rule_id:
                return level

        # CVE fixes in dependencies = medium complexity
        if tool in ["Trivy", "Grype"]:
            return RiskLevel.MEDIUM

        return RiskLevel.MEDIUM  # Default

    def _assess_disruption(self, rule_id: str, tool: str) -> RiskLevel:
        """Assess deployment disruption"""
        # Security issues = higher disruption if not fixed carefully
        if "injection" in rule_id or "xss" in rule_id:
            return RiskLevel.HIGH

        # Dependency updates
        if tool in ["Trivy", "Grype"]:
            return RiskLevel.MEDIUM

        # Code quality issues = low disruption
        if "unused" in rule_id or "format" in rule_id:
            return RiskLevel.LOW

        return RiskLevel.MEDIUM


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print("Usage: risk_assessment.py <alerts_file.json>")
        sys.exit(1)

    alerts_file = sys.argv[1]

    with open(alerts_file, 'r') as f:
        alerts = json.load(f)

    # Determine alert type
    assessor = None
    if "package" in str(alerts):
        assessor = DependabotRiskAssessor()
    else:
        assessor = CodeScanningRiskAssessor()

    # Categorize by risk level
    low_risk = []
    medium_risk = []
    high_risk = []

    for alert in alerts:
        score = assessor.assess_alert(alert)
        print(f"Alert {alert.get('number', '?')}: {score}")

        if score.level == "LOW":
            low_risk.append(alert)
        elif score.level == "MEDIUM":
            medium_risk.append(alert)
        else:
            high_risk.append(alert)

    # Output results
    with open("low_risk_alerts.json", 'w') as f:
        json.dump(low_risk, f, indent=2)

    with open("medium_risk_alerts.json", 'w') as f:
        json.dump(medium_risk, f, indent=2)

    with open("high_risk_alerts.json", 'w') as f:
        json.dump(high_risk, f, indent=2)

    # Set GitHub Actions outputs
    print(f"::set-output name=has_low_risk::{len(low_risk) > 0}")
    print(f"::set-output name=has_medium_risk::{len(medium_risk) > 0}")
    print(f"::set-output name=has_high_risk::{len(high_risk) > 0}")

    # Summary
    print(f"\n📊 Risk Assessment Summary:")
    print(f"  LOW Risk:    {len(low_risk)} alerts → Auto-fix")
    print(f"  MEDIUM Risk: {len(medium_risk)} alerts → Claude creates PR")
    print(f"  HIGH Risk:   {len(high_risk)} alerts → Human review required")


if __name__ == "__main__":
    main()
```

---

## 🔄 Claude AI Integration

### Claude as GitHub App (Recommended Approach)

**Option 1: Claude via GitHub Actions**

```yaml
- name: Let Claude Fix Medium Risk Issues
  if: steps.risk.outputs.has_medium_risk == 'true'
  run: |
    # Use Claude API to generate fix
    python scripts/claude_auto_fix.py medium_risk_alerts.json
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**Option 2: Custom GitHub App with Claude Backend**

Create a GitHub App that:
1. Listens for security alerts / Dependabot PRs
2. Assesses risk using risk matrix
3. Calls Claude API for fix generation
4. Creates PR with Claude's fix
5. Requests human review for medium/high risk

---

## 📋 Implementation Roadmap

### Phase 1: Foundation (Week 1)
- [ ] Create risk assessment script
- [ ] Implement Dependabot triage workflow
- [ ] Test auto-merge for low-risk updates
- [ ] Create monitoring dashboard

### Phase 2: Security Triage (Week 2)
- [ ] Implement code scanning triage
- [ ] Create false positive dismissal logic
- [ ] Build alert categorization
- [ ] Test auto-fix for unused imports

### Phase 3: Claude Integration (Week 3)
- [ ] Design Claude API integration
- [ ] Build fix generation pipeline
- [ ] Create PR automation
- [ ] Implement review request workflow

### Phase 4: Issue Management (Week 4)
- [ ] Implement issue auto-labeling
- [ ] Create stale issue detection
- [ ] Build PR cleanup automation
- [ ] Full system integration testing

---

## ✅ Success Criteria

1. **≥ 80% of low-risk alerts auto-fixed** within 24 hours
2. **≥ 60% of medium-risk alerts** have Claude-generated PRs within 48 hours
3. **100% of high-risk alerts** flagged for human review within 6 hours
4. **Zero false positive auto-merges**
5. **Reduce manual triage time by 70%**

---

## 🔒 Safety Mechanisms

1. **Dry-run mode** - Test without making changes
2. **Rollback capability** - Auto-revert failed auto-merges
3. **Human override** - Manual review can always override
4. **Audit logging** - All decisions logged
5. **Rate limiting** - Max 10 auto-merges per day initially

---

## 💰 Cost Estimation

**Claude API Usage:**
- Estimated 50 medium-risk fixes/month
- ~10,000 tokens per fix
- Cost: ~$5-10/month

**GitHub Actions:**
- Within free tier for public repos
- Private repos: ~$50/month for heavy automation

**Total:** $55-60/month for full automation

---

**Last Updated:** October 20, 2025
**Status:** Design Complete - Ready for Implementation
