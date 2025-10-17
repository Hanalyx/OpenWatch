# GitHub Deprecation Tracking Guide for system_credentials

**Purpose:** Use GitHub features to track and manage gradual deprecation of `system_credentials` table
**Duration:** 2-3 weeks (Option B: Gradual Deprecation)
**Goal:** Zero breaking changes while systematically migrating to `unified_credentials`

---

## GitHub Features for Deprecation Tracking

### 1. GitHub Issues (Primary Tracking)

**Feature:** Issue tracking with labels, milestones, and assignees

**How to Use:**

#### Create Parent Issue: "Deprecate system_credentials Table"

```markdown
Title: [Tech Debt] Deprecate system_credentials table

Labels: technical-debt, deprecation, P2-medium

Description:
## Goal
Gradually deprecate `system_credentials` table in favor of `unified_credentials` with zero breaking changes.

## Background
- Phase 1-5 complete: Host authentication uses unified_credentials ✅
- Legacy system_credentials still used by Settings UI APIs
- Need to migrate 12 code references without breaking production

## Approach
Option B: Gradual Deprecation (2-3 weeks)

## Tasks
- [ ] Week 1: Add deprecation warnings (#issue-number)
- [ ] Week 2: Migrate API routes (#issue-number)
- [ ] Week 3: Drop table when safe (#issue-number)

## Success Criteria
- [ ] All API routes migrated to unified_credentials
- [ ] Frontend using v2/credentials API
- [ ] Zero usage of system_credentials in logs
- [ ] Table successfully dropped
- [ ] All 7 hosts remain online

## Reference
See: SYSTEM_CREDENTIALS_REMOVAL_ASSESSMENT.md

## Related
- Closes #XXX (original tech debt issue)
- Blocks #YYY (future credential enhancements)
```

---

#### Create Sub-Issues for Each Week

**Week 1 Issue:**
```markdown
Title: [Deprecation Week 1] Add warnings to system_credentials usage

Labels: technical-debt, deprecation, week-1

Description:
## Objective
Add deprecation warnings to all system_credentials API endpoints without breaking functionality.

## Tasks
- [ ] Add @deprecated decorator to credentials.py endpoints
- [ ] Log WARNING when system_credentials table queried
- [ ] Update API documentation to show deprecated status
- [ ] Add X-Deprecated-API header to responses
- [ ] Monitor logs for usage patterns

## Files to Modify
- backend/app/routes/credentials.py
- backend/app/routes/system_settings.py

## Testing
- [ ] Verify warnings appear in logs
- [ ] Verify APIs still function correctly
- [ ] Verify frontend unaffected

## Acceptance Criteria
- All legacy endpoints marked deprecated
- Warnings logged on every call
- Zero breaking changes
```

**Week 2 Issue:**
```markdown
Title: [Deprecation Week 2] Migrate API routes to unified_credentials

Labels: technical-debt, deprecation, week-2, breaking-change

Description:
## Objective
Migrate legacy API routes to use unified_credentials and update frontend.

## Tasks
### Backend
- [ ] Migrate credentials.py GET /default endpoint
- [ ] Migrate system_settings.py CRUD operations
- [ ] Add v2/credentials fallback routes
- [ ] Keep legacy routes active (compatibility)

### Frontend
- [ ] Update Settings UI to use v2/credentials API
- [ ] Test credential management flows
- [ ] Update API service layer

### Testing
- [ ] All credential management tests pass
- [ ] Settings UI works correctly
- [ ] Legacy routes still return data (deprecated)

## Acceptance Criteria
- Primary code paths use unified_credentials
- Legacy routes still work (deprecated)
- Frontend migrated to new API
```

**Week 3 Issue:**
```markdown
Title: [Deprecation Week 3] Monitor and drop system_credentials table

Labels: technical-debt, deprecation, week-3, database

Description:
## Objective
Verify zero usage and safely drop system_credentials table.

## Tasks
### Monitoring
- [ ] Check logs for system_credentials queries (should be 0)
- [ ] Verify all API calls use unified_credentials
- [ ] Confirm frontend not calling legacy endpoints

### Migration
- [ ] Backup system_credentials data
- [ ] Run data migration script
- [ ] Verify all data in unified_credentials

### Removal
- [ ] Run remove_legacy_credentials.py script
- [ ] Verify table dropped successfully
- [ ] Remove legacy API route code
- [ ] Update documentation

## Acceptance Criteria
- Zero system_credentials queries in logs (48hr monitoring)
- Table dropped successfully
- All tests passing
- All 7 hosts online
```

---

### 2. GitHub Milestones

**Feature:** Group related issues and track progress

**How to Create:**

```
Milestone: system_credentials Deprecation
Due Date: [3 weeks from start]
Description: Gradually deprecate system_credentials table with zero downtime

Issues:
- Parent issue
- Week 1 sub-issue
- Week 2 sub-issue
- Week 3 sub-issue

Progress: Automatically tracked (0/4, 1/4, 2/4, etc.)
```

**Benefits:**
- Visual progress bar
- Due date tracking
- Automatic closure when all issues done

---

### 3. GitHub Projects (Kanban Board)

**Feature:** Visual project board for workflow tracking

**How to Set Up:**

#### Create Project: "Credential System Migration"

**Columns:**
1. **📋 Backlog** - Issues to be started
2. **🔄 In Progress** - Currently working on
3. **✅ Code Review** - PR submitted, awaiting review
4. **🧪 Testing** - Testing in staging/dev
5. **📊 Monitoring** - Deployed, monitoring usage
6. **✔️ Done** - Completed and verified

**Cards:**
- Week 1 deprecation warnings
- Week 2 API migration
- Week 2 frontend migration
- Week 3 monitoring
- Week 3 table removal

**Automation:**
- Move to "In Progress" when issue assigned
- Move to "Code Review" when PR linked
- Move to "Done" when issue closed

---

### 4. GitHub Actions (Automated Checks)

**Feature:** CI/CD automation to prevent regressions

#### Action 1: Deprecation Usage Scanner

**File:** `.github/workflows/deprecation-scanner.yml`

```yaml
name: Deprecation Usage Scanner

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  scan-system-credentials:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Scan for system_credentials usage
        run: |
          echo "Scanning for system_credentials table references..."

          # Count references (excluding migrations and comments)
          COUNT=$(grep -r "FROM system_credentials" backend/app \
            --include="*.py" \
            --exclude-dir=migrations \
            | grep -v "^[[:space:]]*#" \
            | wc -l)

          echo "Found $COUNT active references to system_credentials"

          # Fail if usage increases
          if [ $COUNT -gt 12 ]; then
            echo "❌ ERROR: system_credentials usage increased!"
            echo "Goal is to decrease to 0 over next 3 weeks"
            exit 1
          fi

          # Warn if not decreasing
          if [ $COUNT -eq 12 ]; then
            echo "⚠️  WARNING: No progress on deprecation"
            echo "Expected: Decreasing usage over time"
          fi

          # Success if decreasing
          if [ $COUNT -lt 12 ]; then
            echo "✅ Progress! Down to $COUNT references (was 12)"
          fi

          # Celebrate when zero
          if [ $COUNT -eq 0 ]; then
            echo "🎉 SUCCESS! Zero references to system_credentials!"
            echo "Ready to drop table"
          fi

      - name: Comment on PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v6
        with:
          script: |
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## Deprecation Scanner Results\n\nsystem_credentials references: **${{ steps.scan.outputs.count }}**\n\nGoal: Reduce to 0 over 3 weeks`
            })
```

**Benefits:**
- Automatic scanning on every PR
- Prevents adding new system_credentials usage
- Tracks progress toward zero usage
- Comments on PRs with current status

---

#### Action 2: Deprecation Warning Checker

**File:** `.github/workflows/check-deprecated-endpoints.yml`

```yaml
name: Check Deprecated Endpoints

on:
  schedule:
    - cron: '0 9 * * *'  # Daily at 9 AM UTC

jobs:
  check-usage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Check if deprecated endpoints still called
        run: |
          # Parse application logs (if accessible)
          # Or query monitoring service

          echo "Checking deprecated endpoint usage..."

          # Example: Check if endpoints have @deprecated decorator
          DEPRECATED_COUNT=$(grep -r "@deprecated" backend/app/routes \
            --include="*.py" \
            | wc -l)

          echo "Found $DEPRECATED_COUNT deprecated endpoints"

          # Create issue if usage detected after week 2
          if [ "${{ github.event.schedule }}" == "week2-complete" ]; then
            if [ $USAGE_COUNT -gt 0 ]; then
              # Create GitHub issue via API
              echo "Creating issue for remaining usage"
            fi
          fi

      - name: Create issue if still used after Week 2
        if: steps.check.outputs.usage > 0
        uses: actions/github-script@v6
        with:
          script: |
            github.rest.issues.create({
              owner: context.repo.owner,
              repo: context.repo.repo,
              title: '[Alert] Deprecated system_credentials still in use',
              body: 'Deprecated endpoints still receiving traffic after Week 2 migration. Investigation needed.',
              labels: ['deprecation', 'alert']
            })
```

---

### 5. GitHub Labels

**Feature:** Categorize and filter issues

**Recommended Labels:**

| Label | Color | Description | When to Use |
|-------|-------|-------------|-------------|
| `technical-debt` | `#d73a4a` | Code cleanup needed | All deprecation issues |
| `deprecation` | `#fbca04` | Deprecating functionality | All related issues |
| `breaking-change` | `#d93f0b` | May break existing code | Week 2 migration |
| `week-1`, `week-2`, `week-3` | `#0075ca` | Timeline tracking | Sub-issues |
| `monitoring` | `#7057ff` | Requires observation | Week 3 |
| `database` | `#1d76db` | Database changes | Week 3 removal |
| `P1-high`, `P2-medium`, `P3-low` | `#e99695` | Priority levels | All issues |

**Benefits:**
- Filter issues by timeline (week-1, week-2, etc.)
- See all deprecation work at a glance
- Track breaking vs non-breaking changes

---

### 6. GitHub Code Owners

**Feature:** Auto-assign reviewers for specific files

**File:** `.github/CODEOWNERS`

```
# System credentials deprecation - require security team review
backend/app/routes/credentials.py @security-team @backend-lead
backend/app/routes/system_settings.py @security-team @backend-lead
backend/app/services/auth_service.py @security-team

# Database migrations - require DBA review
backend/app/migrations/ @dba-team @backend-lead
```

**Benefits:**
- Automatic reviewer assignment
- Ensures right people review deprecation changes
- Prevents accidental system_credentials additions

---

### 7. GitHub Code Scanning (CodeQL)

**Feature:** Automated code analysis

**How to Set Up:**

#### Create Custom CodeQL Query

**File:** `.github/codeql/detect-system-credentials.ql`

```ql
/**
 * @name system_credentials table usage
 * @description Detects queries to deprecated system_credentials table
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id python/deprecated-system-credentials
 */

import python

from Call call
where
  call.getFunc().(Attribute).getName() = "execute" and
  call.getArg(0).toString().matches("%system_credentials%")
select call, "Deprecated: Query to system_credentials table. Use unified_credentials instead."
```

**Benefits:**
- Automatic detection in PRs
- Warning annotations on code
- Prevents new system_credentials usage

---

### 8. GitHub Discussions

**Feature:** Community communication

**How to Use:**

Create discussion: "system_credentials Deprecation Timeline"

```markdown
Category: Announcements

Title: 📢 Deprecation Timeline: system_credentials → unified_credentials

Description:
Over the next 3 weeks, we're deprecating the legacy `system_credentials`
table in favor of `unified_credentials` for better consistency and
maintainability.

## Timeline
- **Week 1 (Oct 16-22):** Deprecation warnings added
- **Week 2 (Oct 23-29):** API migration, frontend updates
- **Week 3 (Oct 30-Nov 5):** Monitoring and table removal

## What to Expect
- Zero breaking changes for users
- Settings UI may show deprecation notices
- All functionality remains intact during migration

## Questions?
Reply to this discussion or contact @security-team

## Progress Tracking
Follow milestone: [system_credentials Deprecation]
See issues: #XXX, #YYY, #ZZZ
```

**Benefits:**
- Team communication
- User awareness
- Centralized Q&A

---

### 9. Pull Request Templates

**Feature:** Standardized PR descriptions

**File:** `.github/pull_request_template.md`

```markdown
## Description
<!-- Describe your changes -->

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Deprecation (system_credentials migration)

## Deprecation Checklist (if applicable)
- [ ] This PR reduces system_credentials usage
- [ ] Added deprecation warnings if modifying legacy code
- [ ] Updated to use unified_credentials
- [ ] Tests updated
- [ ] Documentation updated

## Related Issues
Closes #XXX
Part of milestone: system_credentials Deprecation

## Testing
- [ ] All tests passing
- [ ] Manual testing completed
- [ ] No increase in system_credentials usage
```

---

### 10. GitHub Webhooks + Slack Integration

**Feature:** Real-time notifications

**How to Set Up:**

#### Slack Channel: #system-credentials-deprecation

**Webhook Configuration:**
```
Repository: openwatch
Events:
  - Issues (opened, closed, labeled)
  - Pull requests (opened, merged)
  - GitHub Actions (completed)

Filter: Label = "deprecation"
```

**Notifications:**
- New deprecation issue created
- Week 1 issue completed → ping team for Week 2
- PR merged reducing system_credentials usage
- CI scan detects usage increase (alert)

---

## Recommended Workflow

### Week 1: Setup

```
Day 1:
  1. Create milestone "system_credentials Deprecation"
  2. Create parent issue with all tasks
  3. Create Week 1 sub-issue
  4. Set up GitHub Actions scanner
  5. Add deprecation labels

Day 2-3:
  6. Add @deprecated decorators to legacy endpoints
  7. Implement deprecation logging
  8. Submit PR with "week-1" label
  9. Merge after CI passes

Day 4-5:
  10. Monitor logs for usage patterns
  11. Document which endpoints called most
  12. Plan Week 2 migration priority
```

### Week 2: Migration

```
Day 1-2:
  1. Create Week 2 sub-issue
  2. Migrate highest-traffic endpoint first
  3. Submit PR, link to issue
  4. Merge after review

Day 3-4:
  5. Migrate remaining backend routes
  6. Update frontend to v2/credentials API
  7. Test Settings UI thoroughly

Day 5:
  8. Deploy to staging
  9. Monitor for errors
  10. Check deprecation scanner shows progress
```

### Week 3: Cleanup

```
Day 1-2:
  1. Create Week 3 sub-issue
  2. Monitor logs for 48 hours
  3. Verify zero system_credentials queries

Day 3-4:
  4. Backup legacy table
  5. Run migration script
  6. Run remove_legacy_credentials.py
  7. Submit PR removing legacy code

Day 5:
  8. Merge table removal PR
  9. Close all issues
  10. Close milestone
  11. Post success message in Discussions
```

---

## Automated Reminders

### GitHub Actions: Weekly Reminder

**File:** `.github/workflows/deprecation-reminder.yml`

```yaml
name: Deprecation Progress Reminder

on:
  schedule:
    - cron: '0 9 * * MON'  # Every Monday 9 AM

jobs:
  remind:
    runs-on: ubuntu-latest
    steps:
      - name: Check milestone progress
        uses: actions/github-script@v6
        with:
          script: |
            const milestone = await github.rest.issues.getMilestone({
              owner: context.repo.owner,
              repo: context.repo.repo,
              milestone_number: 1  // system_credentials Deprecation
            });

            const progress = (milestone.data.closed_issues / milestone.data.open_issues) * 100;

            await github.rest.issues.create({
              owner: context.repo.owner,
              repo: context.repo.repo,
              title: `[Reminder] system_credentials Deprecation Progress: ${progress}%`,
              body: `
## Weekly Deprecation Progress Report

**Milestone:** ${milestone.data.title}
**Progress:** ${progress}% (${milestone.data.closed_issues}/${milestone.data.open_issues} issues)
**Due Date:** ${milestone.data.due_on}

### This Week
Review open issues and continue migration.

### Next Steps
- [ ] Check if current week's issue is complete
- [ ] Start next week's tasks if ready
- [ ] Monitor logs for usage patterns

cc: @security-team @backend-team
              `,
              labels: ['deprecation', 'reminder']
            });
```

---

## Monitoring Dashboard

### GitHub Insights

**Use Built-in Insights Tab:**
- **Pulse:** Weekly activity on deprecation issues
- **Contributors:** Who's working on migration
- **Code Frequency:** Lines added/removed
- **Network:** Branch activity

**Custom Queries:**
```
Label: deprecation
Milestone: system_credentials Deprecation
Status: Open/Closed
```

---

## Success Metrics

### Track in GitHub Issues

Create tracking issue: "[Metrics] system_credentials Deprecation Progress"

**Weekly Updates:**
```markdown
## Week 1 (Oct 16-22)
- system_credentials references: 12 → 10 ✅
- Deprecated endpoints: 0 → 12 ✅
- Breaking changes: 0 ✅
- Hosts online: 7/7 ✅

## Week 2 (Oct 23-29)
- system_credentials references: 10 → 3 ✅
- Frontend migrated: 60% → 100% ✅
- Legacy API calls: 1000/day → 10/day ✅
- Hosts online: 7/7 ✅

## Week 3 (Oct 30-Nov 5)
- system_credentials references: 3 → 0 ✅
- Legacy API calls: 10/day → 0/day ✅
- Table dropped: ✅
- Hosts online: 7/7 ✅
```

---

## Conclusion

### Best GitHub Features for Deprecation:

1. ⭐ **GitHub Issues** - Primary tracking mechanism
2. ⭐ **GitHub Milestones** - Progress visualization
3. ⭐ **GitHub Actions** - Automated scanning and reminders
4. ⭐ **GitHub Labels** - Organization and filtering
5. ⭐ **GitHub Projects** - Kanban workflow

### Implementation Priority:

**Week 0 (Setup):**
1. Create milestone
2. Create issues (parent + sub-issues)
3. Add labels
4. Set up deprecation scanner GitHub Action

**Week 1-3:**
5. Use GitHub Projects to track daily progress
6. Comment on issues with updates
7. Link PRs to issues
8. Monitor GitHub Actions output

**Completion:**
9. Close all issues
10. Close milestone
11. Archive project board
12. Document lessons learned

---

**Last Updated:** 2025-10-16
**Guide By:** DevOps & Project Management Team
**Tool:** GitHub Features
**Duration:** 3 weeks (Option B: Gradual Deprecation)
