# ✅ Deprecation Tracking Setup Complete

**Date:** 2025-10-16
**Status:** Ready to begin Week 1 implementation
**Slack Channel:** #ow-deprecation (created and integrated)

---

## What's Been Set Up

### 1. ✅ GitHub Issues Structure

**Parent Issue:**
- **#108**: [DEPRECATION] Remove system_credentials table - 3 Week Timeline
  - Complete overview of deprecation plan
  - Links to all sub-issues
  - Success criteria defined

**Sub-Issues (Weekly Tasks):**
- **#109**: [Week 1] Add Deprecation Warnings to Legacy Endpoints
- **#110**: [Week 2] Migrate Backend API Routes to unified_credentials
- **#111**: [Week 2] Migrate Frontend Settings UI to v2/credentials API
- **#112**: [Week 3] Monitor Usage and Remove system_credentials Table

### 2. ✅ GitHub Milestone

**Name:** system-credentials-removal
**Due Date:** November 20, 2025 (3 weeks)
**URL:** https://github.com/Hanalyx/OpenWatch/milestone/1

**Current Status:**
- 5 issues total (1 parent + 4 sub-issues)
- 0% complete (all issues open)
- 21 days remaining

### 3. ✅ GitHub Labels Created

- `technical-debt` - Code that needs refactoring
- `deprecation` - Code marked for removal
- `week-1` - Week 1 timeline tasks
- `week-2` - Week 2 timeline tasks
- `week-3` - Week 3 timeline tasks

### 4. ✅ GitHub Actions Workflow

**File:** `.github/workflows/deprecation-monitor.yml`

**Features:**
- ✅ **Weekly Reports**: Every Monday at 9 AM EST
- ✅ **PR Regression Check**: Prevents increasing system_credentials usage
- ✅ **Milestone Tracking**: Automatic progress calculation
- ✅ **Slack Integration**: Posts weekly status to #ow-deprecation
- ✅ **Manual Trigger**: Can run anytime with `gh workflow run`

**Workflow runs:**
1. **Scheduled**: Every Monday morning (automatic)
2. **PR Check**: When files in credentials/system_settings are modified
3. **Manual**: Anytime via GitHub Actions UI or CLI

### 5. ✅ Slack Integration Guide

**File:** `SLACK_WEBHOOK_SETUP.md`

**Next Action Required:** Add webhook URL to GitHub secrets
```bash
gh secret set SLACK_DEPRECATION_WEBHOOK --body "YOUR_WEBHOOK_URL"
```

---

## Your Next Steps

### Immediate (Today)

1. **Configure Slack Webhook**
   ```bash
   # Get webhook URL from Slack (#ow-deprecation → Integrations → Incoming WebHooks)
   cd /home/rracine/hanalyx/openwatch
   gh secret set SLACK_DEPRECATION_WEBHOOK --body "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
   ```

2. **Subscribe GitHub to Slack Channel**
   ```
   In #ow-deprecation Slack channel:
   /github subscribe Hanalyx/OpenWatch issues pulls
   /github subscribe Hanalyx/OpenWatch issues +label:"deprecation"
   ```

3. **Test the Workflow**
   ```bash
   gh workflow run deprecation-monitor.yml
   ```
   Check #ow-deprecation for the status report.

4. **Commit and Push the GitHub Actions Workflow**
   ```bash
   cd /home/rracine/hanalyx/openwatch
   git add .github/workflows/deprecation-monitor.yml
   git add SLACK_WEBHOOK_SETUP.md
   git add DEPRECATION_TRACKING_SETUP_COMPLETE.md
   git commit -m "Add automated deprecation monitoring workflow

   - Weekly status reports to #ow-deprecation Slack channel
   - PR regression checks prevent increasing deprecated usage
   - Milestone progress tracking
   - Manual trigger support

   Related: #108 system_credentials deprecation"
   git push
   ```

### Week 1 (Starting Now - Due Nov 6)

**Issue:** #109 - Add Deprecation Warnings

**Tasks:**
1. Add deprecation warning headers to legacy endpoints
2. Add usage metrics logging
3. Update API documentation
4. Test that existing functionality unchanged

**Files to modify:**
- `backend/app/routes/credentials.py`
- `backend/app/routes/system_settings.py`

**Success Criteria:**
- All legacy endpoints return X-Deprecation-Warning header
- Usage metrics logged for analysis
- Zero breaking changes

### Week 2 (Nov 6-13)

**Issues:** #110, #111

**Backend (#110):**
- Migrate credentials.py to use CentralizedAuthService
- Migrate system_settings.py to use unified_credentials
- Keep backward compatibility

**Frontend (#111):**
- Update Settings UI to use /api/v2/credentials
- Update credentialsService.ts
- Test all CRUD operations

### Week 3 (Nov 13-20)

**Issue:** #112

**Tasks:**
- Monitor usage metrics (should be zero)
- Remove deprecated code
- Drop system_credentials table
- Update documentation

---

## Tracking Progress

### View Milestone Progress

```bash
gh milestone view 1
```

### View All Deprecation Issues

```bash
gh issue list --label "deprecation"
```

### View Current Week Issues

```bash
# Week 1
gh issue list --label "week-1"

# Week 2
gh issue list --label "week-2"

# Week 3
gh issue list --label "week-3"
```

### Run Deprecation Scan Manually

```bash
gh workflow run deprecation-monitor.yml
gh run watch  # Watch it execute in real-time
```

---

## Automated Monitoring

### What Gets Monitored Automatically

1. **Code References**: Counts system_credentials usage in Python files
2. **Milestone Progress**: Tracks completed vs open issues
3. **Timeline**: Calculates current week (1-3)
4. **Regression**: Blocks PRs that increase deprecated usage

### Weekly Report Contents

Every Monday at 9 AM EST, #ow-deprecation receives:
- Total code references remaining
- Milestone completion percentage
- Open issues count
- Per-file breakdown
- Links to milestone and parent issue

### PR Checks

When you create a PR modifying credentials/system_settings:
- ✅ **Pass**: If usage decreases or stays same
- ❌ **Fail**: If usage increases (blocks merge)

---

## Project Board Setup (Optional)

The GitHub CLI needs additional permissions to create projects. To set up manually:

1. Go to https://github.com/orgs/Hanalyx/projects
2. Click **New project**
3. Name: "System Credentials Deprecation"
4. Template: "Board"
5. Add issues #108, #109, #110, #111, #112
6. Create columns:
   - 📋 Backlog
   - 🏗️ Week 1
   - 🏗️ Week 2
   - 🏗️ Week 3
   - ✅ Complete

---

## Documentation Files

All documentation created for this deprecation:

1. **SYSTEM_CREDENTIALS_REMOVAL_ASSESSMENT.md** - Why we need to deprecate
2. **GITHUB_DEPRECATION_TRACKING_GUIDE.md** - Complete feature guide
3. **SLACK_WEBHOOK_SETUP.md** - Step-by-step Slack integration
4. **DEPRECATION_TRACKING_SETUP_COMPLETE.md** - This file (next steps)
5. **.github/workflows/deprecation-monitor.yml** - Automated monitoring

---

## Success Metrics

### Week 1 Target
- [ ] Deprecation warnings added to all endpoints
- [ ] Usage metrics being logged
- [ ] Zero breaking changes
- [ ] All 7 hosts remain online

### Week 2 Target
- [ ] Backend migrated to unified_credentials (0 references to SystemCredentials)
- [ ] Frontend Settings UI uses v2/credentials API
- [ ] All tests passing
- [ ] 100% backward compatibility

### Week 3 Target
- [ ] Zero usage of deprecated endpoints (verified in logs)
- [ ] system_credentials table dropped
- [ ] Documentation updated
- [ ] Milestone 100% complete

---

## Rollback Plan

If any issues arise during deprecation:

1. **Pause**: Stop current week's work
2. **Assess**: Analyze what went wrong
3. **Extend**: Add 1 week to timeline (update milestone due date)
4. **Communicate**: Post update in #ow-deprecation
5. **Resume**: Continue with adjusted plan

**Emergency Rollback:**
- Legacy system_credentials code remains intact until Week 3
- Can revert to legacy system anytime during Week 1-2
- Database backup created before table drop

---

## Team Communication

### Slack Channel: #ow-deprecation

**Purpose:**
- Weekly automated status reports
- GitHub issue/PR notifications
- Team discussions
- Progress updates

**Best Practices:**
- Use thread replies for discussions
- Pin important messages (deadlines, blockers)
- Post daily progress updates during implementation weeks
- Tag team members for reviews

---

## Current System State

**Before Deprecation (Current):**
- ✅ unified_credentials: 2 system credentials (owadmin)
- ⚠️ system_credentials: 1 legacy credential (root)
- ❌ 12 code references in production

**After Deprecation (Target):**
- ✅ unified_credentials: All credentials (system, host, group)
- ✅ system_credentials: TABLE DROPPED
- ✅ 0 code references (clean codebase)

**Architecture Change:**
```
BEFORE: Settings UI → /api/v1/credentials → system_credentials table
AFTER:  Settings UI → /api/v2/credentials → unified_credentials (scope='system')
```

---

## Ready to Start?

### ✅ Setup Complete Checklist

- [x] Parent issue #108 created
- [x] Sub-issues #109, #110, #111, #112 created
- [x] Milestone "system-credentials-removal" created (due Nov 20)
- [x] GitHub labels created (technical-debt, deprecation, week-1/2/3)
- [x] GitHub Actions workflow created (deprecation-monitor.yml)
- [x] Slack integration guide created (SLACK_WEBHOOK_SETUP.md)
- [x] Documentation complete
- [ ] **TODO: Add Slack webhook to GitHub secrets** ⬅️ YOUR NEXT ACTION
- [ ] **TODO: Subscribe GitHub App to #ow-deprecation** ⬅️ YOUR NEXT ACTION
- [ ] **TODO: Commit and push workflow file** ⬅️ YOUR NEXT ACTION

### Start Week 1 Implementation

Once Slack integration is tested, head to **Issue #109** to begin Week 1 tasks!

**Issue URL:** https://github.com/Hanalyx/OpenWatch/issues/109

---

🎉 **Deprecation tracking system is ready!** Follow the next steps above to complete Slack integration and start Week 1.
