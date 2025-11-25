# Branch Management Policy

This document outlines the branch management strategy, naming conventions, and automated workflows for the OpenWatch project.

## Branch Types and Naming Conventions

### Main Branches

- **`main`** - Production-ready code, protected branch
- **`develop`** - Integration branch for features (if using GitFlow)

### Feature Branches

**Format:** `feature/<issue-number>-<short-description>`

**Examples:**
- `feature/123-ssh-configuration-ui`
- `feature/456-scap-scanning-improvements`
- `feature/789-user-authentication-system`

**Rules:**
- All feature development happens in feature branches
- Branch from `main` (or `develop` if using GitFlow)
- Merge back to `main` via Pull Request
- Delete after successful merge

### Bug Fix Branches

**Format:** `bugfix/<issue-number>-<short-description>` or `fix/<short-description>`

**Examples:**
- `bugfix/234-auth-token-expiration`
- `fix/scan-results-parsing`
- `fix/docker-compose-networking`

**Rules:**
- For non-critical bug fixes
- Branch from `main`
- Merge back to `main` via Pull Request
- Delete after successful merge

### Hotfix Branches

**Format:** `hotfix/<version>-<critical-issue>`

**Examples:**
- `hotfix/1.2.1-security-vulnerability`
- `hotfix/1.2.2-database-connection-leak`

**Rules:**
- For critical production fixes only
- Branch from `main`
- Merge to both `main` and `develop` (if exists)
- Tag with version number after merge
- Delete after successful merge

### Dependency Update Branches

**Format:** `dependabot/<ecosystem>/<package-name>-<version>`

**Examples:**
- `dependabot/npm_and_yarn/frontend/vite-7.1.5`
- `dependabot/pip/backend/fastapi-0.104.1`
- `dependabot/docker/postgres-16.1`

**Rules:**
- Auto-created by Dependabot
- Handled by automated workflow
- Auto-merged for patch updates and security fixes
- Manual review required for major/minor updates

### Release Branches

**Format:** `release/<version>`

**Examples:**
- `release/1.2.0`
- `release/2.0.0-beta`

**Rules:**
- Branch from `develop` (if using GitFlow)
- Only bug fixes and documentation updates allowed
- Merge to `main` and tag when ready
- Delete after successful release

### Experimental/Research Branches

**Format:** `experiment/<description>` or `research/<topic>`

**Examples:**
- `experiment/new-authentication-system`
- `research/performance-optimization`

**Rules:**
- For experimental features or research
- May not follow standard review process
- Delete when experiment concludes or merge to feature branch

## Branch Protection Rules

### Main Branch Protection

The `main` branch is protected with the following rules:

- **Require pull request reviews before merging**
  - Required reviewers: 1
  - Dismiss stale reviews when new commits are pushed
  - Require review from code owners

- **Require status checks to pass before merging**
  - Frontend tests
  - Backend tests
  - Security audit
  - Build validation
  - Integration tests

- **Enforce restrictions for administrators**
- **Require linear history** (rebase and merge)
- **Do not allow bypassing the above settings**

### Additional Protections

- **Require signed commits** for security-critical changes
- **Restrict pushes that create public merge commits**
- **Require deployments to succeed** for certain environments

## Automated Branch Management

### Dependabot Configuration

```yaml
# .github/dependabot.yml
version: 2
updates:
  # Frontend dependencies
  - package-ecosystem: "npm"
    directory: "/frontend"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "09:00"
    reviewers:
      - "maintainers"
    assignees:
      - "sofia-alvarez"  # Frontend lead
    open-pull-requests-limit: 10

  # Backend dependencies
  - package-ecosystem: "pip"
    directory: "/backend"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "09:00"
    reviewers:
      - "maintainers"
    assignees:
      - "daniel-kim"  # Backend lead
    open-pull-requests-limit: 10

  # Docker dependencies
  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "tuesday"
      time: "09:00"
    reviewers:
      - "maintainers"
    assignees:
      - "marcus-rodriguez"  # DevOps lead
```

### Auto-merge Criteria

**Eligible for Auto-merge:**
- Patch version updates (x.x.X)
- Security updates (any version)
- Development dependencies (low risk)
- Documentation updates
- Docker base image updates (if tests pass)

**Requires Manual Review:**
- Major version updates (X.x.x)
- Minor version updates with breaking changes
- Production dependencies with high risk
- Updates that affect security configurations
- Updates that modify API contracts

### Branch Cleanup Automation

Automated cleanup occurs for:

- **Merged feature branches**: Deleted after 7 days
- **Abandoned branches**: Tagged for review after 30 days of inactivity
- **Dependabot branches**: Deleted immediately after merge/closure
- **Experiment branches**: Tagged for cleanup after 60 days

## Manual Branch Management Commands

### Common Operations

```bash
# Create and switch to feature branch
git checkout -b feature/123-new-feature main

# Update branch with latest main
git checkout feature/123-new-feature
git rebase main

# Clean up local branches after remote deletion
git remote prune origin
git branch -vv | grep ': gone]' | awk '{print $1}' | xargs git branch -d

# Force update local main with remote
git checkout main
git fetch origin
git reset --hard origin/main

# Interactive cleanup of local branches
git branch --merged main | grep -v main | xargs -p git branch -d
```

### Emergency Procedures

#### Rollback Bad Merge
```bash
# If bad merge just happened on main
git checkout main
git reset --hard HEAD~1
git push --force-with-lease origin main

# If merge is older, use revert
git checkout main
git revert -m 1 <merge-commit-hash>
git push origin main
```

#### Recover Accidentally Deleted Branch
```bash
# Find the commit hash from reflog
git reflog

# Recreate branch
git checkout -b recovered-branch <commit-hash>
```

## Branch Lifecycle

### Feature Branch Lifecycle

1. **Creation**
   - Branch from `main`
   - Follow naming convention
   - Set up tracking: `git push -u origin feature/123-description`

2. **Development**
   - Regular commits with meaningful messages
   - Keep branch updated with main: `git rebase main`
   - Run tests locally before pushing

3. **Review**
   - Create Pull Request when ready
   - Address review feedback
   - Ensure CI/CD passes

4. **Merge**
   - Squash commits for clean history
   - Update issue references
   - Delete branch after merge

5. **Cleanup**
   - Automated deletion of remote branch
   - Manual cleanup of local branch

### Hotfix Lifecycle

1. **Immediate Response**
   - Create hotfix branch from main
   - Implement minimal fix
   - Test thoroughly

2. **Fast-Track Review**
   - Emergency review process
   - Override normal waiting periods if critical
   - Document decision rationale

3. **Deployment**
   - Merge to main
   - Tag with patch version
   - Deploy immediately
   - Monitor for regressions

## Quality Gates

### Pre-merge Checks

All branches must pass:

- **Automated Tests**
  - Unit tests (≥80% coverage)
  - Integration tests
  - E2E tests for UI changes
  - Security scans

- **Code Quality**
  - Linting (ESLint, Pylint)
  - Type checking (TypeScript, mypy)
  - Code formatting (Prettier, Black)
  - Import sorting

- **Security**
  - Dependency vulnerability scan
  - SAST (Static Application Security Testing)
  - Secrets detection
  - License compliance

- **Performance**
  - Build time < 5 minutes
  - Bundle size analysis
  - Load time validation

### Review Requirements

- **Code Review**: At least one approving review
- **Security Review**: Required for authentication/authorization changes
- **Documentation Review**: Required for API changes
- **UX Review**: Required for UI/UX changes

## Metrics and Monitoring

### Branch Health Metrics

- **Average PR Lifetime**: Target < 3 days
- **Time to First Review**: Target < 1 day
- **Merge Frequency**: Measure deployment velocity
- **Hotfix Frequency**: Monitor stability
- **Failed CI/CD Rate**: Target < 5%

### Automated Reports

Weekly reports include:

- Active branches by age
- Dependabot merge success rate
- Branch protection compliance
- Security vulnerability trends
- Technical debt indicators

## Troubleshooting

### Common Issues

**Issue**: Merge conflicts in Dependabot PRs
**Solution**:
1. Checkout the branch locally
2. Rebase onto main: `git rebase main`
3. Resolve conflicts
4. Force push: `git push --force-with-lease`

**Issue**: CI/CD failing on auto-merge
**Solution**:
1. Review failure logs
2. If test failure: Fix and commit
3. If infrastructure: Retry workflow
4. If persistent: Disable auto-merge for that update

**Issue**: Branch protection bypass needed
**Solution**:
1. Document emergency justification
2. Temporary disable protection
3. Make necessary changes
4. Re-enable protection immediately
5. Follow up with incident review

## References

- [GitHub Flow](https://guides.github.com/introduction/flow/)
- [Semantic Versioning](https://semver.org/)
- [Conventional Commits](https://www.conventionalcommits.org/)
- [Dependabot Documentation](https://docs.github.com/en/code-security/dependabot)
