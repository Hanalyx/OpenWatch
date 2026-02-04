# GitHub Workflow - Pull Request Process

**Updated**: 2026-01-21
**Status**: ✅ Active - All changes must go through PRs

---

## Branch Protection Rules

The `main` branch is protected with the following rules:

### Required Checks
All PRs must pass these CI checks before merging:
- ✅ **Backend CI** - Linting, type checking, security scans, tests, Docker build
- ✅ **Frontend CI** - ESLint, TypeScript check, tests, build, Docker build
- ✅ **Integration Tests** - Docker Compose integration testing
- ✅ **E2E Tests** - Playwright end-to-end testing

### Protection Settings
- ✅ **Pull requests required** - No direct pushes to main
- ✅ **Status checks must pass** - All 4 CI jobs must succeed
- ✅ **Branches must be up to date** - Must merge latest main before merging PR
- ✅ **Force pushes blocked** - Cannot `git push --force`
- ✅ **Branch deletion blocked** - Cannot delete main branch
- ⚠️ **Reviews optional** - Currently set to 0 required reviews (can enable later)

---

## Development Workflow

### 1. Start New Work

```bash
# Ensure main is up to date
git checkout main
git pull origin main

# Create feature branch (use descriptive names)
git checkout -b feature/E1-S5-rules-package
# OR
git checkout -b fix/scan-accuracy-discrepancy
# OR
git checkout -b docs/update-api-migration-guide
```

**Branch Naming Conventions**:
- `feature/<epic-story>` - New features (e.g., `feature/E1-S5-rules-package`)
- `fix/<issue-description>` - Bug fixes (e.g., `fix/auth-token-expiry`)
- `docs/<description>` - Documentation (e.g., `docs/update-security-guide`)
- `refactor/<description>` - Code refactoring (e.g., `refactor/extract-ssh-service`)
- `test/<description>` - Test additions (e.g., `test/add-scan-service-coverage`)

### 2. Make Changes

```bash
# Make your code changes
# Edit files...

# Add and commit incrementally
git add backend/app/routes/rules/
git commit -m "refactor(routes): Create rules route package structure"

# Continue making changes
git add backend/app/main.py
git commit -m "refactor(routes): Update main.py for rules router"
```

**Commit Message Format**:
```
<type>(<scope>): <subject>

[optional body]

[optional footer]
```

**Types**: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`, `ci`

**Examples**:
```
feat(auth): Add session timeout with configurable duration
fix(scans): Resolve 35% compliance score discrepancy
docs(api): Add E1-S4 API migration guide for frontend
refactor(routes): Consolidate rules into modular package (E1-S5)
test(services): Add unit tests for FrameworkMetadataService
```

### 3. Push Feature Branch

```bash
# Push your feature branch to remote
git push origin feature/E1-S5-rules-package

# If you need to push additional commits
git push origin feature/E1-S5-rules-package
```

### 4. Create Pull Request

**Option A: GitHub CLI** (Recommended):
```bash
# Create PR with title and description
gh pr create \
  --title "refactor(routes): Create Rules Route Package (E1-S5)" \
  --body "$(cat <<'EOF'
## Summary
Consolidates flat rules files into modular `routes/rules/` package.

## Changes
- Created `routes/rules/` package with `__init__.py`
- Moved `rule_management.py` → `rules/management.py`
- Moved `rule_scanning.py` → `rules/scanning.py`
- Updated `main.py` imports and router registration
- Deleted old flat files

## Epic/Story
- **Epic**: E1 - Route Consolidation
- **Story**: E1-S5 (5 points)

## Acceptance Criteria
- [x] `routes/rules/` directory created
- [x] All rule endpoints preserved
- [x] Imports updated in main.py
- [x] Old flat files deleted
- [x] Backend compiles successfully

## Breaking Changes
⚠️ **BREAKING**: API paths changed:
- `/api/rules/*` → `/api/rules/*` (no change - prefix stays same)
- See `docs/cleanup/E1_S5_API_PATH_CHANGES.md`

## Testing
- ✓ Backend compiles (`python3 -m py_compile`)
- ✓ All endpoints preserved
- CI pipeline will run full test suite

## Frontend Impact
- ⚠️ Frontend migration required (if paths changed)
- See migration guide: `docs/cleanup/E1_S5_API_PATH_CHANGES.md`

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
EOF
  )"

# Or create PR interactively
gh pr create
```

**Option B: GitHub Web UI**:
1. Go to https://github.com/Hanalyx/OpenWatch/pulls
2. Click "New pull request"
3. Select your branch
4. Fill in title and description (use format above)
5. Click "Create pull request"

### 5. Wait for CI Checks

GitHub Actions will automatically run all CI checks:

```
✓ Backend CI (linting, tests, security, Docker build)
✓ Frontend CI (ESLint, TypeScript, tests, build)
✓ Integration Tests (Docker Compose)
✓ E2E Tests (Playwright)
```

**Monitor Progress**:
```bash
# Watch CI status
gh pr status

# View detailed checks
gh pr checks

# View CI logs if needed
gh run list --branch feature/E1-S5-rules-package
gh run view <run-id> --log
```

### 6. Address CI Failures (If Any)

If checks fail, fix the issues locally and push again:

```bash
# Fix the issue
# Edit files...

# Commit the fix
git add .
git commit -m "fix(ci): Resolve linting errors in rules package"

# Push to update PR
git push origin feature/E1-S5-rules-package

# CI will automatically re-run
```

### 7. Merge Pull Request

Once all checks pass:

**Option A: GitHub CLI**:
```bash
# Merge PR (squash commits for clean history)
gh pr merge --squash --delete-branch

# Or merge with merge commit
gh pr merge --merge --delete-branch

# Or rebase (maintains individual commits)
gh pr merge --rebase --delete-branch
```

**Option B: GitHub Web UI**:
1. Go to your PR page
2. Ensure all checks are green ✓
3. Click "Squash and merge" (recommended)
4. Confirm merge
5. Delete branch (checkbox)

### 8. Update Local Main

```bash
# Switch back to main
git checkout main

# Pull merged changes
git pull origin main

# Verify merge
git log --oneline -5
```

---

## Handling Dependabot PRs

Dependabot creates automated PRs for dependency updates. Handle these carefully:

### 1. Review Dependabot PR

```bash
# List Dependabot PRs
gh pr list --author app/dependabot

# View specific PR
gh pr view <PR-number>

# Check what dependency is being updated
gh pr diff <PR-number>
```

### 2. Group Related PRs (Optional)

For efficiency, you can group related Dependabot PRs:

```bash
# Create feature branch
git checkout -b deps/python-security-updates

# Merge multiple Dependabot branches
git merge origin/dependabot/pip/backend/cryptography-44.0.0
git merge origin/dependabot/pip/backend/pillow-12.0.1

# Resolve conflicts if any
# ...

# Push grouped update
git push origin deps/python-security-updates

# Create PR
gh pr create --title "chore(deps): Security updates for Python dependencies"

# Close original Dependabot PRs
gh pr close <PR-number> --comment "Merged into #<grouped-PR-number>"
```

### 3. Test Locally (For Critical Deps)

```bash
# Checkout Dependabot branch
gh pr checkout <PR-number>

# Test locally
./start-openwatch.sh --runtime docker --build

# Run specific tests
cd backend && pytest tests/ -v

# If tests pass, merge
gh pr merge <PR-number> --squash --delete-branch
```

---

## CI Pipeline Details

### Backend CI (`backend` job)

**What it checks**:
- ✅ Code formatting (Black)
- ✅ Linting (Flake8)
- ✅ Type checking (MyPy)
- ✅ Security scanning (Bandit, Safety)
- ✅ Unit/integration tests (Pytest)
- ✅ Code coverage (80% minimum)
- ✅ Docker build

**Requirements**:
- All tests must pass
- Code coverage ≥ 80%
- No security vulnerabilities (HIGH/CRITICAL)
- No linting errors

### Frontend CI (`frontend` job)

**What it checks**:
- ✅ ESLint (code quality)
- ✅ TypeScript type checking
- ✅ Unit tests (Jest/React Testing Library)
- ✅ Production build
- ✅ Docker build

**Requirements**:
- All tests must pass
- No TypeScript errors
- No ESLint errors
- Build succeeds

### Integration Tests (`integration` job)

**What it checks**:
- ✅ Docker Compose startup
- ✅ Service health checks
- ✅ Basic connectivity tests
- ✅ Container networking

**Requirements**:
- All containers start successfully
- Health checks pass
- Services respond to HTTP requests

### E2E Tests (`e2e` job)

**What it checks**:
- ✅ Full application flow (Playwright)
- ✅ User authentication
- ✅ Core feature workflows
- ✅ UI interactions

**Requirements**:
- All E2E scenarios pass
- No UI errors
- Screenshots on failure

---

## Troubleshooting

### PR Cannot Be Merged

**Symptom**: "Branch is out of date with the base branch"

**Solution**:
```bash
# Update your branch with latest main
git checkout feature/your-branch
git fetch origin
git merge origin/main

# Resolve conflicts if any
# Edit conflicting files...

git add .
git commit -m "chore: Merge main into feature branch"

# Push updated branch
git push origin feature/your-branch
```

### CI Checks Failing

**Check logs**:
```bash
# View failed check logs
gh pr checks

# View detailed run logs
gh run list --branch feature/your-branch
gh run view <run-id> --log
```

**Common issues**:
- **Linting errors**: Run `black backend/app/` and `flake8 backend/app/`
- **Type errors**: Run `mypy backend/app/` and fix type hints
- **Test failures**: Run `pytest tests/ -v` locally to debug
- **Build errors**: Check Docker build logs

### Accidentally Pushed to Main

**Symptom**: "Push declined due to repository rule violations"

**Solution**: You can't push directly - this is working as intended! Create a feature branch instead:

```bash
# If you have unpushed commits on main
git checkout -b feature/accidental-work
git push origin feature/accidental-work

# Create PR from this branch
gh pr create
```

---

## Best Practices

### Commit Messages
- ✅ Use conventional commit format: `type(scope): subject`
- ✅ Keep subject under 72 characters
- ✅ Use imperative mood: "Add feature" not "Added feature"
- ✅ Reference PRD stories: `(E1-S5)` in commit message

### Pull Requests
- ✅ One PR per story/feature (avoid mega PRs)
- ✅ Include acceptance criteria checklist
- ✅ Document breaking changes
- ✅ Add migration guides if needed
- ✅ Link to PRD epic/story

### Branch Management
- ✅ Delete merged branches
- ✅ Keep feature branches short-lived (< 1 week)
- ✅ Rebase frequently to avoid merge conflicts
- ✅ Use descriptive branch names

### Code Review (Optional, for team environments)
- ✅ Review your own PR before requesting review
- ✅ Respond to comments promptly
- ✅ Use GitHub suggestions for small fixes
- ✅ Resolve conversations when addressed

---

## Migration Notes

### Previous Direct Push Workflow

**Old workflow (deprecated)**:
```bash
git add .
git commit -m "changes"
git push origin main  # ❌ No longer allowed
```

**New workflow**:
```bash
git checkout -b feature/my-change
git add .
git commit -m "feat: my change"
git push origin feature/my-change
gh pr create
# Wait for CI
gh pr merge --squash --delete-branch
```

### Handling Existing Unpushed Commits

If you have commits on main that haven't been pushed:

```bash
# Create feature branch from current position
git checkout -b feature/existing-work

# Push feature branch
git push origin feature/existing-work

# Reset local main to match remote
git checkout main
git reset --hard origin/main

# Create PR from feature branch
gh pr create
```

---

## Future Enhancements

These can be enabled later as needed:

### Code Review Requirements
```bash
# Enable required reviews (1 approval needed)
gh api repos/Hanalyx/OpenWatch/branches/main/protection -X PUT \
  --field required_pull_request_reviews[required_approving_review_count]=1
```

### Code Owners
Create `.github/CODEOWNERS` to auto-assign reviewers:
```
# Auto-assign for specific paths
/backend/app/services/auth/ @security-team
/docs/ @documentation-team
*.md @documentation-team
```

### Auto-Merge for Dependabot
Enable auto-merge for minor/patch dependency updates:
```bash
# Enable auto-merge for specific Dependabot PR
gh pr merge <PR-number> --auto --squash
```

---

**END OF WORKFLOW GUIDE**
