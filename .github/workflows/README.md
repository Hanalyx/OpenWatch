# GitHub Actions Workflows

This directory contains all the CI/CD workflows for OpenWatch. Below is an overview of each workflow and its purpose.

## 🔄 Core CI/CD Workflows

### `ci.yml` - Continuous Integration
**Triggers:** Push to main/develop, Pull Requests
- **Backend Testing:** Python linting, security checks, unit tests with coverage
- **Frontend Testing:** ESLint, TypeScript checking, build verification  
- **Integration Tests:** Full stack testing with Docker Compose
- **Docker Builds:** Multi-stage builds with caching for both backend and frontend
- **Artifacts:** Pushes images to GitHub Container Registry on main branch

### `deploy.yml` - Automated Deployment  
**Triggers:** Push to main, Manual dispatch
- **Staging Deployment:** Automatic deployment to staging environment
- **Production Deployment:** Manual approval required, blue-green deployment
- **Health Checks:** Automated smoke tests and rollback on failure
- **Notifications:** Slack integration for deployment status
- **Backup:** Database snapshots before production deployments

### `release.yml` - Release Automation
**Triggers:** Git tags (v*), Manual dispatch
- **Multi-arch Builds:** ARM64 and AMD64 Docker images
- **Release Assets:** Packaged distributions with configuration templates
- **Changelog:** Automated generation based on commits and PRs
- **Documentation:** Version updates and documentation deployment
- **Container Registry:** Tagged releases pushed to GHCR

## 🔒 Security Workflows

### `codeql.yml` - Static Analysis
**Triggers:** Push, Pull Requests, Weekly schedule
- **Multi-language:** Python and JavaScript/TypeScript analysis
- **Security Queries:** Comprehensive security and quality rule sets
- **Integration:** Results integrated with GitHub Security tab

### `container-security.yml` - Container Scanning
**Triggers:** Push, Pull Requests, Daily schedule  
- **Vulnerability Scanning:** Trivy and Grype scanners for container images
- **SARIF Reports:** Security findings uploaded to GitHub Security
- **Multi-component:** Separate scans for backend and frontend containers
- **Fail-fast:** Builds fail on critical/high severity vulnerabilities

## 📊 Code Quality Workflows

### `code-quality.yml` - Quality Assurance
**Triggers:** Push, Pull Requests
- **Python Quality:** Black, Flake8, Pylint, MyPy, Bandit analysis
- **JavaScript Quality:** ESLint, Prettier, TypeScript compilation
- **Coverage Reports:** Unit test coverage with Codecov integration
- **SonarCloud:** Comprehensive code quality and technical debt analysis
- **Artifacts:** Quality reports uploaded for review

## 📚 Documentation Workflows  

### `docs.yml` - Documentation Generation
**Triggers:** Push to main, Documentation changes
- **API Documentation:** Auto-generated from code annotations
- **User Documentation:** MkDocs-powered documentation site
- **TypeScript Docs:** TypeDoc generation for frontend APIs
- **GitHub Pages:** Automatic deployment to docs.openwatch.hanalyx.com
- **OpenAPI Spec:** Generated and published API specifications

## 🤖 Repository Management

### `issue-management.yml` - Issue Automation
**Triggers:** Issues, Pull Requests, Comments
- **Auto-assignment:** Based on labels and file paths changed
- **Auto-labeling:** PR labeling based on changed files
- **Size Labeling:** Automatic PR size categorization
- **Stale Management:** Mark and close inactive issues/PRs
- **Welcome Messages:** First-time contributor guidance

## 📦 Dependency Management

### `dependabot.yml` - Automated Updates
**Schedule:** Weekly on Mondays
- **Python Dependencies:** Backend package updates with security focus
- **NPM Dependencies:** Frontend dependency management with grouping
- **Docker Images:** Base image updates for security patches  
- **GitHub Actions:** Workflow dependency updates
- **Auto-merge:** Low-risk updates with comprehensive testing

## 🎯 Workflow Status

| Workflow | Status | Purpose | Priority |
|----------|--------|---------|----------|
| CI Pipeline | ✅ Active | Core testing and building | Critical |
| Security Scanning | ✅ Active | Vulnerability detection | Critical |
| Code Quality | ✅ Active | Code standards enforcement | High |
| Deployment | ✅ Active | Production releases | Critical |
| Release Automation | ✅ Active | Version management | High |
| Documentation | ✅ Active | Doc generation and hosting | Medium |
| Issue Management | ✅ Active | Repository maintenance | Medium |
| Dependabot | ✅ Active | Security updates | High |

## 🔧 Configuration Requirements

### Required Secrets
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` - AWS deployment credentials
- `SONAR_TOKEN` - SonarCloud integration
- `SLACK_WEBHOOK` - Deployment notifications
- `CODECOV_TOKEN` - Coverage reporting

### Repository Settings
- Branch protection rules for main/develop branches
- Required status checks for all CI workflows  
- GitHub Container Registry permissions
- GitHub Pages enabled for documentation
- Security alerts and Dependabot enabled

## 🚀 Getting Started

1. **Fork the Repository:** All workflows will run automatically on your fork
2. **Configure Secrets:** Add required secrets for full functionality
3. **Enable GitHub Pages:** For documentation deployment  
4. **Set up Branch Protection:** Configure branch rules for your workflow
5. **Review Dependabot:** Adjust update schedules as needed

## 📈 Metrics and Monitoring

All workflows include comprehensive logging and artifact collection:
- **Test Results:** Unit and integration test reports
- **Coverage Reports:** Code coverage tracking over time
- **Security Scans:** Vulnerability trends and resolution tracking
- **Build Times:** Performance monitoring of CI/CD pipelines
- **Deployment Success:** Release success rates and rollback frequency

For more information about specific workflows, see the individual workflow files or check the GitHub Actions tab in the repository.