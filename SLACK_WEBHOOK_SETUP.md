# Slack Webhook Setup for Deprecation Tracking

**Date:** 2025-10-16
**Channel:** #ow-deprecation
**Purpose:** Receive automated GitHub notifications for system_credentials deprecation

---

## Step 1: Create Incoming Webhook in Slack

1. Go to your Slack workspace settings
2. Navigate to **Apps** → **Manage** → **Custom Integrations**
3. Click **Incoming WebHooks** → **Add to Slack**
4. Select channel: **#ow-deprecation**
5. Click **Add Incoming WebHooks Integration**
6. Copy the **Webhook URL** (looks like: `https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX`)

---

## Step 2: Add Webhook to GitHub Secrets

### Option A: Using GitHub CLI

```bash
cd /home/rracine/hanalyx/openwatch

# Add secret for deprecation workflow
gh secret set SLACK_DEPRECATION_WEBHOOK --body "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
```

### Option B: Using GitHub Web UI

1. Go to https://github.com/Hanalyx/OpenWatch/settings/secrets/actions
2. Click **New repository secret**
3. Name: `SLACK_DEPRECATION_WEBHOOK`
4. Value: Paste your webhook URL
5. Click **Add secret**

---

## Step 3: Configure GitHub App for Slack Channel

To get GitHub notifications in #ow-deprecation:

1. In Slack, type `/github subscribe Hanalyx/OpenWatch`
2. Select what to subscribe to:
   ```
   /github subscribe Hanalyx/OpenWatch issues pulls commits:all releases
   ```

3. Filter to deprecation-related items only:
   ```
   /github subscribe Hanalyx/OpenWatch issues pulls
   /github unsubscribe Hanalyx/OpenWatch commits
   /github subscribe Hanalyx/OpenWatch issues +label:"deprecation"
   /github subscribe Hanalyx/OpenWatch pulls +label:"deprecation"
   ```

---

## Step 4: Test the Setup

### Test 1: Manual Workflow Run

```bash
cd /home/rracine/hanalyx/openwatch
gh workflow run deprecation-monitor.yml
```

Check #ow-deprecation for the weekly status report message.

### Test 2: Create Test Issue

```bash
gh issue create --title "Test deprecation notification" --label "deprecation"
```

Check #ow-deprecation for the issue creation notification.

---

## Expected Slack Messages

### Weekly Status Report (Every Monday 9 AM)

```
📊 Weekly Deprecation Status Report

🗑️ system_credentials Deprecation - Week 1

Code References: 12 remaining
Milestone Progress: 25% complete
Open Issues: 3 remaining
Files Affected: 2 files

📈 Detailed Breakdown
• credentials.py: 1 refs
• system_settings.py: 11 refs

[View Milestone] [View Parent Issue]
```

### GitHub Issue Notifications

```
🔔 [Hanalyx/OpenWatch] Issue opened: #109
[Week 1] Add Deprecation Warnings to Legacy Endpoints
Labels: deprecation, week-1
```

### Pull Request Notifications

```
🔔 [Hanalyx/OpenWatch] PR opened: #123
Migrate credentials.py to unified_credentials
Labels: deprecation, week-2

✅ Deprecation scan passed: Reduced usage by 3 references
```

---

## Verification Checklist

- [ ] Slack webhook URL added to GitHub secrets
- [ ] GitHub App installed in #ow-deprecation channel
- [ ] Subscribed to issues with "deprecation" label
- [ ] Subscribed to PRs with "deprecation" label
- [ ] Test workflow run successful
- [ ] Weekly report received in #ow-deprecation

---

## Troubleshooting

### No messages in Slack?

1. **Check webhook URL**: Verify SLACK_DEPRECATION_WEBHOOK secret exists
   ```bash
   gh secret list | grep SLACK
   ```

2. **Check workflow runs**: View recent executions
   ```bash
   gh run list --workflow=deprecation-monitor.yml
   ```

3. **Check workflow logs**: See what happened
   ```bash
   gh run view $(gh run list --workflow=deprecation-monitor.yml --limit 1 --json databaseId --jq '.[0].databaseId')
   ```

### GitHub notifications not showing?

1. **Verify GitHub App**: In #ow-deprecation, type `/github subscribe list`
2. **Re-subscribe**: Run subscription commands again
3. **Check filters**: Ensure "deprecation" label filter is active

---

## Security Notes

⚠️ **Webhook URL is sensitive** - treat it like a password:
- Don't commit webhook URLs to code
- Don't share publicly
- Store in GitHub Secrets only
- Rotate if accidentally exposed

---

## Next Steps After Setup

Once Slack integration is working:

1. ✅ Weekly automated status reports start arriving every Monday
2. ✅ GitHub issue/PR notifications appear in #ow-deprecation
3. ✅ Team stays informed of deprecation progress
4. ✅ Start Week 1 implementation (#109)

**Ready to begin?** Head to Issue #109 to start Week 1 tasks!
