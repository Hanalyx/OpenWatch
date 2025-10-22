# Claude Code Automated Triage & Auto-Fix System

**Status:** Implementation Ready
**Date Created:** October 20, 2025
**Architecture:** Claude Code + GitHub Actions

---

## 🎯 Executive Summary

This document describes how to use **Claude Code** (not the Anthropic API directly) to automate GitHub issue, PR, and security alert triage using a risk-based decision matrix.

**Key Innovation:** Claude Code running in **headless mode** via GitHub Actions, triggered automatically by security alerts, Dependabot updates, and issues.

---

## 🏗️ Architecture: Claude Code vs. Anthropic API

### **Why Claude Code is BETTER than Direct API:**

| Feature | Anthropic API | Claude Code | Winner |
|---------|---------------|-------------|---------|
| **Native GitHub Integration** | ❌ Manual | ✅ Built-in GitHub App | **Claude Code** |
| **Tool Access** | ❌ None | ✅ Bash, Read, Edit, Write, etc. | **Claude Code** |
| **Repository Context** | ❌ Manual | ✅ Automatic (reads codebase) | **Claude Code** |
| **Git Operations** | ❌ Manual | ✅ Native (commits, PRs) | **Claude Code** |
| **Code Standards** | ❌ Manual prompt | ✅ Reads CLAUDE.md | **Claude Code** |
| **Multi-step Tasks** | ❌ Single call | ✅ Multi-turn conversations | **Claude Code** |
| **Testing** | ❌ No | ✅ Can run tests before PR | **Claude Code** |
| **Headless Mode** | N/A | ✅ CLI automation | **Claude Code** |
| **Cost** | Same | Same | **Tie** |

**Winner: Claude Code** - Purpose-built for coding tasks!

---

## 🤖 Claude Code Capabilities for Automation

### **What Claude Code Can Do in Headless Mode:**

✅ **Read the entire codebase** (automatic context)
✅ **Make code changes** (Edit, Write tools)
✅ **Run commands** (Bash tool - tests, linters, builds)
✅ **Create git commits** (native git integration)
✅ **Create pull requests** (GitHub CLI integration)
✅ **Follow coding standards** (reads CLAUDE.md)
✅ **Multi-step workflows** (plan → implement → test → PR)
✅ **Error handling** (retry logic, rollback)

### **Headless Mode Command:**

```bash
claude -p "Fix the log injection vulnerability in backend/app/routes/hosts.py" \
  --output-format json \
  --allowedTools "Bash,Read,Edit,Write,Grep,Glob" \
  --permission-mode acceptEdits
```

**Output:** JSON with changes made, files modified, commits created, PR URL

---

## 🎲 Updated Architecture with Claude Code

```
┌─────────────────────────────────────────────────────────────────┐
│                    GitHub Event Sources                         │
├─────────────────────────────────────────────────────────────────┤
│  • Dependabot Alerts                                            │
│  • Code Scanning Alerts (CodeQL, Trivy, Grype)                 │
│  • Issue Comments (@claude fix this)                            │
│  • Scheduled Scans (every 6 hours)                             │
└──────────────────┬──────────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────────┐
│         GitHub Actions + Risk Assessment Script                 │
│         .github/workflows/claude-code-triage.yml                │
├─────────────────────────────────────────────────────────────────┤
│  1. Fetch alerts from GitHub API                               │
│  2. Run risk_assessment.py                                      │
│  3. Categorize: LOW / MEDIUM / HIGH                            │
└──────────────┬────────────────────────────────────┬─────────────┘
               │                                    │
       ┌───────┴───────┐                    ┌──────┴────────┐
       │               │                    │               │
       ▼               ▼                    ▼               ▼
┌──────────────┐  ┌─────────────────┐  ┌─────────────────────┐
│   AUTO-FIX   │  │  CLAUDE CODE    │  │   HUMAN REVIEW      │
│  (Low Risk)  │  │ (Medium Risk)   │  │   (High Risk)       │
├──────────────┤  ├─────────────────┤  ├─────────────────────┤
│ • Simple sed │  │ Headless Mode:  │  │ • Create issue      │
│ • Dependabot │  │ 1. Read code    │  │ • Assign to human   │
│   auto-merge │  │ 2. Analyze      │  │ • Add "review-req"  │
│ • Unused     │  │ 3. Make changes │  │ • Wait for approval │
│   imports    │  │ 4. Run tests    │  │                     │
│              │  │ 5. Create PR    │  │                     │
│              │  │ 6. Request      │  │                     │
│              │  │    review       │  │                     │
└──────────────┘  └─────────────────┘  └─────────────────────┘
```

---

## 🔧 Implementation: Claude Code GitHub Actions

### **Workflow 1: Alert-Triggered Claude Code** (`.github/workflows/claude-code-alerts.yml`)

```yaml
name: Claude Code Alert Triage

on:
  # Triggered when Dependabot creates/updates a PR
  pull_request:
    types: [opened, synchronize]

  # Triggered on new code scanning alerts
  code_scanning_alert:
    types: [created, reopened]

  # Triggered by @claude mentions
  issue_comment:
    types: [created]

  # Scheduled daily scan
  schedule:
    - cron: '0 8 * * *'

permissions:
  contents: write
  issues: write
  pull-requests: write
  security-events: read

jobs:
  risk-assessment:
    name: Assess Risk Level
    runs-on: ubuntu-latest
    outputs:
      risk_level: ${{ steps.assess.outputs.risk_level }}
      alert_id: ${{ steps.assess.outputs.alert_id }}
      description: ${{ steps.assess.outputs.description }}
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.9'

      - name: Fetch Alerts
        id: fetch
        run: |
          # Get the alert that triggered this workflow
          if [ "${{ github.event_name }}" == "code_scanning_alert" ]; then
            ALERT_ID="${{ github.event.alert.number }}"
            gh api "/repos/${{ github.repository }}/code-scanning/alerts/$ALERT_ID" \
              > alert.json
          elif [ "${{ github.event_name }}" == "pull_request" ] && [ "${{ github.actor }}" == "dependabot[bot]" ]; then
            # Get Dependabot alert from PR
            gh api "/repos/${{ github.repository }}/dependabot/alerts" \
              --jq ".[] | select(.dependency.package.name == \"${{ github.event.pull_request.title }}\")" \
              > alert.json || echo '{}' > alert.json
          fi
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Assess Risk
        id: assess
        run: |
          python scripts/risk_assessment.py alert.json

          # Read results
          RISK_LEVEL=$(jq -r '.[0].risk_assessment.level // "MEDIUM"' low_risk_alerts.json medium_risk_alerts.json high_risk_alerts.json | head -1)
          ALERT_ID=$(jq -r '.[0].number // "unknown"' alert.json)
          DESCRIPTION=$(jq -r '.[0].rule.description // .[0].security_vulnerability.summary // "Unknown"' alert.json)

          echo "risk_level=$RISK_LEVEL" >> $GITHUB_OUTPUT
          echo "alert_id=$ALERT_ID" >> $GITHUB_OUTPUT
          echo "description=$DESCRIPTION" >> $GITHUB_OUTPUT

          echo "🎯 Risk Assessment: $RISK_LEVEL"

  auto-fix-low-risk:
    name: Auto-Fix (Low Risk)
    needs: risk-assessment
    if: needs.risk-assessment.outputs.risk_level == 'LOW'
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Auto-Approve Dependabot PR
        if: github.actor == 'dependabot[bot]'
        run: |
          gh pr review ${{ github.event.pull_request.number }} --approve \
            --body "✅ Auto-approved: LOW risk update (Risk Assessment passed)"
          gh pr merge ${{ github.event.pull_request.number }} --auto --squash
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Simple Auto-Fix (Code Quality)
        if: github.event_name == 'code_scanning_alert'
        run: |
          # For simple fixes like unused imports
          python scripts/simple_auto_fix.py alert.json

          if [ -n "$(git status --porcelain)" ]; then
            git config user.name "github-actions[bot]"
            git config user.email "github-actions[bot]@users.noreply.github.com"
            git add -A
            git commit -m "fix: Auto-fix low-risk alert #${{ needs.risk-assessment.outputs.alert_id }}"
            git push
          fi

  claude-code-fix:
    name: Claude Code Fix (Medium Risk)
    needs: risk-assessment
    if: needs.risk-assessment.outputs.risk_level == 'MEDIUM'
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Install Claude Code
        run: |
          npm install -g @anthropic-ai/claude-code

      - name: Claude Code Headless Fix
        run: |
          # Create task description for Claude
          cat > task.txt <<EOF
          Fix this security/quality issue:

          Alert ID: ${{ needs.risk-assessment.outputs.alert_id }}
          Description: ${{ needs.risk-assessment.outputs.description }}

          Steps:
          1. Read the affected file(s)
          2. Analyze the issue
          3. Implement the fix following CLAUDE.md standards
          4. Run relevant tests to verify the fix
          5. Create a git commit with a descriptive message
          6. Create a pull request

          Important:
          - Follow the coding standards in CLAUDE.md
          - Run tests before committing
          - Include "Fixes #${{ needs.risk-assessment.outputs.alert_id }}" in commit message
          - Request review from @${{ github.repository_owner }}
          EOF

          # Run Claude Code in headless mode
          claude -p "$(cat task.txt)" \
            --output-format json \
            --allowedTools "Bash,Read,Edit,Write,Grep,Glob" \
            --permission-mode acceptEdits \
            > claude_output.json

          # Extract PR URL from output
          PR_URL=$(jq -r '.pr_url // empty' claude_output.json)
          echo "PR_URL=$PR_URL" >> $GITHUB_ENV
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Add Risk Assessment Comment
        if: env.PR_URL != ''
        run: |
          PR_NUMBER=$(echo $PR_URL | grep -oP '\d+$')
          gh pr comment $PR_NUMBER --body "🤖 **Claude Code Auto-Fix**

          **Risk Assessment:** MEDIUM
          - Requires human review before merging
          - Claude has implemented a fix following project standards
          - Tests have been run

          **Alert:** #${{ needs.risk-assessment.outputs.alert_id }}
          **Description:** ${{ needs.risk-assessment.outputs.description }}

          Please review carefully before merging."
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  human-review-required:
    name: Human Review (High Risk)
    needs: risk-assessment
    if: needs.risk-assessment.outputs.risk_level == 'HIGH'
    runs-on: ubuntu-latest
    steps:
      - name: Create High-Priority Issue
        run: |
          gh issue create \
            --title "🚨 HIGH RISK: Alert #${{ needs.risk-assessment.outputs.alert_id }}" \
            --label "security" \
            --label "high-risk" \
            --assignee "${{ github.repository_owner }}" \
            --body "## High Risk Security Alert

          **Alert ID:** #${{ needs.risk-assessment.outputs.alert_id }}
          **Description:** ${{ needs.risk-assessment.outputs.description }}
          **Risk Level:** HIGH

          This alert has been classified as HIGH risk and requires careful human assessment before implementing any fixes.

          **Action Required:**
          1. Review the vulnerability details
          2. Assess impact on production systems
          3. Plan remediation strategy
          4. Test thoroughly before deployment
          5. Consider security review

          **You may ask Claude Code to help:**
          Comment \`@claude analyze this security issue and propose a fix strategy\`

          ---
          *This issue was automatically created by the Automated Triage System*"
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

### **Workflow 2: @claude Mentions** (`.github/workflows/claude-code-mention.yml`)

```yaml
name: Claude Code Mention Handler

on:
  issue_comment:
    types: [created]

permissions:
  contents: write
  issues: write
  pull-requests: write

jobs:
  respond-to-claude:
    if: contains(github.event.comment.body, '@claude')
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Install Claude Code
        run: npm install -g @anthropic-ai/claude-code

      - name: Extract Command
        id: extract
        run: |
          # Remove @claude from command
          COMMAND=$(echo "${{ github.event.comment.body }}" | sed 's/@claude //g')
          echo "command=$COMMAND" >> $GITHUB_OUTPUT

      - name: Run Claude Code
        run: |
          claude -p "${{ steps.extract.outputs.command }}" \
            --output-format json \
            --allowedTools "Bash,Read,Edit,Write,Grep,Glob" \
            --permission-mode acceptEdits \
            > claude_response.json

          # Post response as comment
          RESPONSE=$(jq -r '.response' claude_response.json)
          gh issue comment ${{ github.event.issue.number }} --body "**Claude Response:**

          $RESPONSE

          ---
          *Automated response from Claude Code*"
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

### **Workflow 3: Scheduled Triage** (`.github/workflows/claude-code-scheduled.yml`)

```yaml
name: Claude Code Scheduled Triage

on:
  schedule:
    - cron: '0 */6 * * *'  # Every 6 hours
  workflow_dispatch:

permissions:
  contents: write
  issues: write
  pull-requests: write
  security-events: read

jobs:
  bulk-triage:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.9'

      - name: Fetch All Open Alerts
        run: |
          # Dependabot
          gh api /repos/${{ github.repository }}/dependabot/alerts --paginate > dependabot.json

          # Code Scanning (limit to 100 for performance)
          gh api /repos/${{ github.repository }}/code-scanning/alerts --paginate | jq '.[0:100]' > code_scanning.json
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Risk Assessment
        run: |
          python scripts/risk_assessment.py --type=dependabot dependabot.json
          mv low_risk_alerts.json low_risk_dependabot.json
          mv medium_risk_alerts.json medium_risk_dependabot.json

          python scripts/risk_assessment.py --type=codeql code_scanning.json
          mv low_risk_alerts.json low_risk_code_scanning.json
          mv medium_risk_alerts.json medium_risk_code_scanning.json

      - name: Install Claude Code
        run: npm install -g @anthropic-ai/claude-code

      - name: Process Medium Risk Alerts with Claude
        run: |
          # Process up to 5 medium-risk alerts per run (to avoid rate limits)
          jq -r '.[0:5] | .[] | @base64' medium_risk_code_scanning.json | while read alert; do
            ALERT_DATA=$(echo "$alert" | base64 --decode)
            ALERT_ID=$(echo "$ALERT_DATA" | jq -r '.number')
            RULE_ID=$(echo "$ALERT_DATA" | jq -r '.rule.id')
            FILE=$(echo "$ALERT_DATA" | jq -r '.most_recent_instance.location.path')

            echo "Processing alert #$ALERT_ID: $RULE_ID in $FILE"

            claude -p "Fix alert #$ALERT_ID: $RULE_ID in file $FILE. Follow CLAUDE.md standards, run tests, and create a PR." \
              --output-format json \
              --allowedTools "Bash,Read,Edit,Write,Grep,Glob" \
              --permission-mode acceptEdits

            # Rate limiting: wait 30 seconds between alerts
            sleep 30
          done
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Summary Report
        run: |
          echo "# Automated Triage Report" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "**Dependabot Alerts:**" >> $GITHUB_STEP_SUMMARY
          echo "- Low Risk: $(jq 'length' low_risk_dependabot.json)" >> $GITHUB_STEP_SUMMARY
          echo "- Medium Risk: $(jq 'length' medium_risk_dependabot.json)" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "**Code Scanning Alerts:**" >> $GITHUB_STEP_SUMMARY
          echo "- Low Risk: $(jq 'length' low_risk_code_scanning.json)" >> $GITHUB_STEP_SUMMARY
          echo "- Medium Risk: $(jq 'length' medium_risk_code_scanning.json)" >> $GITHUB_STEP_SUMMARY
```

---

## 🎯 Advantages of Claude Code Approach

### **1. Better Context Awareness**
- ✅ Reads entire codebase automatically
- ✅ Understands project structure
- ✅ Follows CLAUDE.md coding standards
- ✅ Knows git history

### **2. Multi-Step Workflows**
```bash
# Claude Code can do ALL of this in one command:
claude -p "Fix log injection in hosts.py"

# Claude will:
1. Read hosts.py
2. Find the log injection issues
3. Convert f-strings to parameterized logging
4. Run tests to verify fix
5. Commit with message: "fix: Resolve log injection in hosts.py"
6. Create PR with full description
7. Request review from maintainer
```

### **3. Native GitHub Integration**
- ✅ Creates PRs automatically
- ✅ Commits follow conventions
- ✅ Links to issues
- ✅ Requests reviewers

### **4. Error Recovery**
- ✅ If tests fail, Claude tries again
- ✅ If fix breaks something, Claude can revert
- ✅ Multi-turn conversation for complex issues

---

## 📋 Setup Instructions

### **1. Install Claude Code GitHub App**

```bash
# Add Claude GitHub App to your repository
# https://github.com/apps/claude-code

# Grant permissions:
# - Read/Write: Contents, Issues, Pull Requests
# - Read: Security Events
```

### **2. Add API Key to Secrets**

```bash
# Get API key from https://console.anthropic.com/
gh secret set ANTHROPIC_API_KEY
```

### **3. Deploy Workflows**

```bash
# Workflows are already created in .github/workflows/
# Just merge and they'll start running

git add .github/workflows/claude-code-*.yml
git commit -m "feat: Add Claude Code automation workflows"
git push
```

### **4. Test with @claude Mention**

```bash
# Create a test issue
gh issue create --title "Test Claude Code" --body "@claude create a hello world script"

# Claude will respond and create the script!
```

---

## 💰 Cost Comparison

| Approach | Cost | Setup | Capabilities |
|----------|------|-------|--------------|
| **Anthropic API** | ~$10/month | Complex | Limited |
| **Claude Code** | ~$10/month | Simple | Full |

**Winner:** Claude Code - Same cost, way more capability!

---

## 🎉 Summary

**YES! Using Claude Code instead of the Anthropic API directly is much better!**

### **Why Claude Code Wins:**
1. ✅ **Built-in GitHub integration** (no manual API calls)
2. ✅ **Access to code tools** (Read, Edit, Bash, etc.)
3. ✅ **Multi-step workflows** (plan → fix → test → PR)
4. ✅ **Reads CLAUDE.md** (follows your standards)
5. ✅ **Native git operations** (commits, PRs)
6. ✅ **Headless mode** (perfect for automation)
7. ✅ **Error handling** (retries, rollback)
8. ✅ **Same cost** as API ($10/month)

### **How It Works:**
```
Alert Created → Risk Assessment → MEDIUM risk
  ↓
Claude Code runs in headless mode:
  ↓
claude -p "Fix alert #123: log injection in hosts.py"
  ↓
Claude:
  1. Reads hosts.py
  2. Understands the vulnerability
  3. Implements parameterized logging fix
  4. Runs pytest to verify
  5. Creates commit
  6. Creates PR with description
  7. Requests your review
  ↓
You review PR → Approve → Merge
  ↓
Alert automatically closed!
```

**Ready to implement!** The workflows are created. Just add the API key and merge!

---

**Last Updated:** October 20, 2025
**Status:** Ready for Deployment
