# OpenWatch Branch Management Workflow

This document provides a comprehensive guide to the automated branch management system implemented for OpenWatch, including dependency updates, security fixes, and general maintenance workflows.

## Overview

The OpenWatch project uses an automated branch management system that:

- **Automates dependency updates** via Dependabot with intelligent merge strategies
- **Provides security-first dependency management** with daily security scans
- **Implements comprehensive testing** for all dependency changes
- **Supports manual override** for complex updates
- **Maintains branch hygiene** through automated cleanup

## Architecture

### Components

1. **GitHub Actions Workflows** (`.github/workflows/dependency-management.yml`)
2. **Dependabot Configuration** (`.github/dependabot.yml`)
3. **Branch Protection Rules** (configured in GitHub)
4. **Quality Gates** (automated testing and validation)

### Flow Diagram

```
Dependabot PR Created
         ↓
   Analyze Changes
    (Risk Assessment)
         ↓
    Run Test Suite
  (Frontend/Backend/Integration)
         ↓
   Security Audit
    (npm audit, safety)
         ↓
    Decision Gate
         ↓
┌────────────────┬────────────────┐
│   Auto-merge   │ Manual Review  │
│   (Low Risk)   │  (High Risk)   │
└────────────────┴────────────────┘
```

## Automated Decision Matrix

### Auto-merge Criteria

| Update Type | Security | Risk Level | Auto-merge | Reason |
|-------------|----------|------------|------------|---------|
| Patch (x.x.X) | Any | Low | ✅ Yes | Minimal breaking change risk |
| Security | Any | Critical | ✅ Yes | Security takes priority |
| Development deps | Patch/Minor | Low/Medium | ✅ Yes | No production impact |
| GitHub Actions | Patch | Low | ✅ Yes | Infrastructure improvements |

### Manual Review Required

| Update Type | Security | Risk Level | Auto-merge | Reason |
|-------------|----------|------------|------------|---------|
| Major (X.x.x) | Any | High | ❌ No | Potential breaking changes |
| Minor (x.X.x) | Non-security | Medium | ❌ No | API changes possible |
| Core frameworks | Any | High | ❌ No | Application-critical |
| Database drivers | Any | Medium | ❌ No | Data integrity concerns |

## Workflow Stages

### 1. Dependency Analysis

**Trigger**: New Dependabot PR created

**Actions**:
- Parse PR title to determine update type (major/minor/patch)
- Check if update is security-related
- Assess risk level based on dependency importance
- Generate analysis report as PR comment

**Outputs**:
- Update type classification
- Security flag
- Risk assessment
- Auto-merge eligibility

### 2. Testing Phase

**Parallel Test Execution**:

**Frontend Tests**:
```bash
npm ci
npm run lint
npm run build
# Lighthouse performance audit
lhci autorun --collect.staticDistDir=dist
```

**Backend Tests**:
```bash
pip install -r requirements.txt
bandit -r . -ll  # Security scan
python -m pytest tests/
# Import validation
python -c "from app.main import app"
```

**Integration Tests**:
```bash
docker-compose -f docker-compose.yml config
# Full stack build validation
```

### 3. Security Audit

**Frontend Security**:
```bash
npm audit --audit-level=moderate --format=json
# Extract vulnerability counts
# Generate security report
```

**Backend Security**:
```bash
safety check --json
pip-audit --format=json
# Aggregate security issues
```

**Outputs**:
- Vulnerability counts by severity
- Security recommendations
- Risk scoring

### 4. Decision Gate

**Auto-merge Path**:
- All tests pass ✅
- Security audit clean ✅
- Meets auto-merge criteria ✅
- Automatic squash merge to main
- Success notification

**Manual Review Path**:
- Add appropriate labels
- Assign to relevant maintainer
- Generate review checklist
- Notify security team if needed

### 5. Post-merge Actions

**Success**:
- Delete feature branch
- Update dependency tracking
- Generate changelog entry

**Failure**:
- Create incident report
- Rollback if necessary
- Manual intervention required

## Configuration Files

### Dependabot Schedule

**Regular Updates** (Weekly - Monday/Tuesday):
- Frontend: Monday 10:00 UTC
- Backend: Monday 09:00 UTC
- Docker: Tuesday 09:00 UTC
- GitHub Actions: Tuesday 10:00 UTC

**Security Updates** (Daily):
- Frontend: Daily 06:00 UTC
- Backend: Daily 06:00 UTC

### Auto-merge Rules

```yaml
# Frontend auto-merge
allow:
  - dependency-type: "development"
    update-type: "version-update:semver-patch"
  - dependency-type: "production" 
    update-type: "version-update:semver-patch"

# Backend auto-merge
allow:
  - dependency-type: "all"
    update-type: "version-update:semver-patch"

# Security auto-merge (all ecosystems)
allow:
  - dependency-type: "all"
    update-type: "security-update"
```

### Ignored Dependencies

**Major Version Updates Blocked**:
- `react` - Requires coordination
- `@mui/material` - Breaking changes likely
- `fastapi` - API compatibility concerns
- `sqlalchemy` - Database schema impact
- `node` - Runtime environment changes
- `python` - Runtime environment changes
- `postgres` - Data migration required

## Manual Workflows

### Emergency Security Update

```bash
# 1. Identify security vulnerability
# 2. Create hotfix branch
git checkout -b hotfix/security-cve-2024-xxxx main

# 3. Apply minimal fix
# 4. Test thoroughly
npm run test:security
python -m pytest tests/security/

# 5. Fast-track merge
gh pr create --title "SECURITY: Fix CVE-2024-XXXX" \
             --body "Emergency security fix" \
             --label "security,hotfix,critical"

# 6. Deploy immediately after merge
```

### Complex Dependency Update

```bash
# 1. Create feature branch
git checkout -b feature/upgrade-react-18 main

# 2. Update dependencies
npm install react@18 react-dom@18

# 3. Fix breaking changes
# 4. Comprehensive testing
npm run test:full
npm run test:e2e

# 5. Create detailed PR
gh pr create --title "Upgrade React to v18" \
             --body-file upgrade-notes.md \
             --label "dependencies,breaking-changes"
```

### Branch Cleanup

```bash
# Weekly automated cleanup
git branch --merged main | grep -v main | xargs -r git branch -d
git remote prune origin

# Manual cleanup of stale branches
git for-each-ref --format='%(refname:short) %(committerdate)' refs/heads \
  | sort -k2 \
  | head -20  # Review oldest branches
```

## Monitoring and Metrics

### Key Performance Indicators

**Automation Effectiveness**:
- Auto-merge success rate (target: >85%)
- Time to merge (target: <24h for patches)
- Failed merge rate (target: <5%)

**Security Response**:
- Time to security fix (target: <4h)
- Vulnerability exposure time (minimize)
- Security update success rate (target: >95%)

**Developer Experience**:
- Manual intervention frequency (minimize)
- False positive rate (target: <10%)
- Developer satisfaction scores

### Weekly Reports

**Dependency Health Report**:
- Updates processed
- Security vulnerabilities addressed
- Failed automation attempts
- Manual interventions required

**Branch Health Report**:
- Active branch count
- Stale branch identification
- Merge frequency trends
- Quality gate failures

## Troubleshooting Guide

### Common Issues

**1. Auto-merge Failed - Test Failures**
```bash
# Check test logs in GitHub Actions
# If legitimate failure:
git checkout dependabot/branch-name
npm run test:debug
# Fix issues and commit
git push
```

**2. Security Audit False Positives**
```bash
# Review npm audit report
npm audit
# If false positive, create audit override:
npm audit --audit-level=moderate --registry=https://registry.npmjs.org/
```

**3. Merge Conflicts in Dependabot PR**
```bash
# Manually resolve conflicts
git checkout dependabot/branch-name
git rebase main
# Resolve conflicts
git add .
git rebase --continue
git push --force-with-lease
```

**4. Auto-merge Criteria Not Met**
```bash
# Check PR labels and analysis
# Override if safe (admin only):
gh pr merge --auto --merge
```

### Escalation Procedures

**Level 1**: Automated retry (built into workflow)
**Level 2**: Team lead manual review
**Level 3**: Architecture team consultation
**Level 4**: Emergency hotfix process

## Future Enhancements

### Planned Features

**AI-Powered Risk Assessment**:
- Machine learning models for breaking change prediction
- Historical impact analysis
- Smart batching of related updates

**Enhanced Testing**:
- Visual regression testing
- Performance impact analysis
- Database migration validation

**Integration Improvements**:
- Slack notifications for manual review requests
- Jira integration for tracking dependency debt
- Dashboard for dependency health metrics

### Experimental Features

**Canary Deployments**:
- Auto-deploy to staging for low-risk updates
- Automated rollback on performance regression
- Gradual rollout for production updates

**Dependency Insights**:
- Supply chain risk analysis
- License compliance checking
- Update impact prediction

## Best Practices

### For Maintainers

1. **Review Auto-merge Results**: Check daily auto-merge activity
2. **Monitor Quality Metrics**: Weekly review of success rates
3. **Update Ignore Lists**: Quarterly review of blocked dependencies
4. **Security First**: Prioritize security updates over features

### For Contributors

1. **Avoid Manual Dependency Updates**: Let Dependabot handle routine updates
2. **Test Locally**: Always test dependency changes locally first
3. **Document Breaking Changes**: Clear commit messages for major updates
4. **Coordinate Major Updates**: Discuss framework upgrades with team

### For Security Team

1. **Daily Security Review**: Monitor security update auto-merges
2. **Vulnerability Response**: <4 hour response time for critical CVEs
3. **Audit Trail**: Maintain records of all security decisions
4. **Threat Intelligence**: Monitor for zero-day vulnerabilities

---

## Quick Reference

### Commands
- **View active branches**: `git branch -r | grep dependabot`
- **Check auto-merge status**: `gh pr list --label "auto-merge-eligible"`
- **Force security update**: `gh workflow run "Dependency Management" -f merge_strategy=security-only`
- **Disable auto-merge**: Add `manual-review-required` label to PR

### Links
- [GitHub Actions Workflow](../../.github/workflows/dependency-management.yml)
- [Dependabot Configuration](../../.github/dependabot.yml)
- [Branch Management Policy](../../.github/BRANCH_MANAGEMENT.md)
- [Security Response Procedures](../SECURITY.md)

### Support
- **Slack**: `#openwatch-dev`
- **Email**: `dev-team@hanalyx.com`
- **Issues**: GitHub Issues with `workflow` label