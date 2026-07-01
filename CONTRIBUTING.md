# Contributing to OpenWatch

Thank you for your interest in contributing to OpenWatch! This guide will help you get started with contributing to the project.

## Code of Conduct

We are committed to providing a welcoming and inclusive environment for all contributors. Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting Started

### Prerequisites

- **Go**: 1.26 (backend, single binary that serves both the API and the embedded UI)
- **Node.js**: for the `frontend/` React app (Vite dev server)
- **PostgreSQL**: the only datastore (no MongoDB, Redis, or Celery)
- **Development Environment**: Linux (RHEL/Ubuntu recommended)
- **Git**: For version control

### Development Setup

1. **Fork the repository** on GitHub
2. **Clone your fork**:
   ```bash
   git clone https://github.com/yourusername/OpenWatch.git
   cd OpenWatch
   ```

3. **Set up development environment** (the Go tree is at the repo root):
   ```bash
   # Backend development (Go 1.26)
   go build ./...
   go build -o dist/openwatch ./cmd/openwatch
   ./dist/openwatch serve            # dev server on port 8443

   # Frontend development (new terminal)
   cd frontend
   npm install
   npm run dev                       # http://localhost:5173
   ```

   > The Python/FastAPI backend was archived to `~/hanalyx/OWAR/openwatch-python/`
   > and is no longer part of this repo. The legacy `docker compose` /
   > `uvicorn` / `pip` setup no longer applies.

4. **Install the spec-driven-development hooks**:
   ```bash
   pre-commit install                   # commit-time: format, lint, spec coverage (source-walk)
   specter init --install-hook          # pre-push: block impl changes with no @spec/@ac annotation
   ```
   The pre-push hook delegates to `specter pre-push-check` and skips cleanly if
   `specter` is not on your PATH. Bypass a single push with `git push --no-verify`.
   Spec coverage is enforced strictly in CI regardless (see [Testing](#testing)).

## How to Contribute

### Reporting Bugs

1. **Check existing issues** to avoid duplicates
2. **Use the bug report template** when creating new issues
3. **Include detailed information**:
   - Operating system and version
   - OpenWatch version (`openwatch --version`)
   - Steps to reproduce
   - Expected vs actual behavior
   - Log files and error messages

### Suggesting Features

1. **Check the recent direction** in [CHANGELOG.md](CHANGELOG.md) and open [GitHub Discussions](https://github.com/hanalyx/openwatch/discussions)
2. **Open a discussion** for major features before implementing
3. **Use the feature request template** for new issues
4. **Provide detailed use cases** and benefits

### Contributing Code

#### Branch Strategy

- **main**: Stable, production-ready code
- **develop**: Integration branch for features
- **feature/**: New features (`feature/host-liveness`)
- **fix/**: Bug fixes (`fix/auth-token-validation`)
- **docs/**: Documentation updates (`docs/api-reference`)

#### Development Workflow

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following our coding standards
3. **Test your changes** thoroughly
4. **Commit with meaningful messages**:
   ```bash
   git commit -m "feat: add compliance framework filtering

   - Add framework filter to the rule reference endpoint
   - Map Kensa rule references to framework controls
   - Include error handling for unknown framework IDs

   Closes #123"
   ```

5. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Create a Pull Request** with detailed description

#### Commit Message Format

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Formatting, no code change
- `refactor`: Code change that neither fixes bug nor adds feature
- `test`: Adding missing tests
- `chore`: Maintenance tasks

**Examples**:
```
feat(rules): add framework filter to reference endpoint
fix(auth): resolve session expiration handling
docs(api): update scanning endpoint documentation
```

## Testing

### Running Tests

```bash
# Backend tests (Go) — from the repo root
go test ./internal/... -count=1     # add -p 1 for DB-touching packages
specter check                        # spec schema validation
specter coverage                     # spec AC coverage

# Frontend tests
cd frontend
npx vitest run
```

### Test Requirements

- **Unit tests** for all new functions and packages
- **Behavioral coverage** via `specs/` ACs for specced modules
- **All tests must pass** before merging

### Writing Tests

- **Follow existing patterns** in the test directories
- **Use descriptive test names**: `TestRuleReference_FilterByUnknownFramework`
- **Include edge cases** and error conditions
- **Mock external dependencies** appropriately

## Code Style

### Go (Backend)

- **Run `gofmt -s -w`** before committing (CI lint is strict on gofmt)
- **`go vet ./...`** must pass
- **Lint** with `golangci-lint run` (see `.golangci.yml`)
- **One package per concern** under `internal/`; import from the package, not internal files
- **Doc comments** on all exported identifiers

### TypeScript/React (Frontend)

- **Use ESLint** rules: `npm run lint`
- **TypeScript strict mode** enabled (`npx tsc --noEmit`)
- **React functional components** with hooks
- **TanStack Router/Query** for routing and data fetching
- **MUI components** for consistency

### General Guidelines

- **Meaningful variable names**: `frameworkID` not `fid`
- **Small, focused functions**: Single responsibility principle
- **Error handling**: Comprehensive exception handling
- **Security-first**: Validate all inputs, sanitize outputs
- **Performance**: Consider efficiency in scanning operations

## Adding services

OpenWatch is organized as one Go package per concern under `internal/<concern>/`, wired
together in `cmd/openwatch/main.go`. New behavior is added as a focused service package, not
as a runtime plugin. Before adding a service, review the behavioral specs in
[specs/](specs/) (registered in [specter.yaml](specter.yaml)) and the existing packages under
[internal/](internal/), then:

- **Keep one responsibility per package** and import from the package, not its internal files
- **Wire the service** into the `.With` chain in `cmd/openwatch/main.go`
- **Define the contract first** in `api/openapi.yaml` for new HTTP surface, then run
  `make generate-api` to regenerate `internal/server/api/server.gen.go` and
  `frontend/src/api/schema.d.ts`
- **Add a behavioral spec** under `specs/` for specced modules and back it with tests

## Security

### Security Review Process

- **All PRs undergo security review** for sensitive areas
- **Security-focused changes** require additional approval
- **Vulnerability reports** should be sent to security@hanalyx.com
- **Security patches** take priority over feature development

### Security Guidelines

- **Validate all inputs** from users and external systems
- **Use parameterized queries** for database operations
- **Implement proper authentication** and authorization
- **Follow OWASP guidelines** for web application security
- **Keep dependencies updated** and scan for vulnerabilities

## Documentation

### Documentation Requirements

- **Update README.md** for significant changes
- **API documentation** for new endpoints
- **User guides** for new features
- **Architecture documentation** for design changes
- **Behavioral specs** under `specs/` for specced modules

### Documentation Style

- **Clear, concise language**
- **Step-by-step instructions** with examples
- **Screenshots** for UI changes
- **API examples** with request/response samples
- **Link to related documentation**

## Architecture Guidelines

### Core Principles

- **Modularity**: Clear separation between components (one package per concern under `internal/`)
- **Single binary**: One Go binary serves both the REST API and the embedded React UI
- **Security**: FIPS compliance and best practices
- **Performance**: Efficient scanning for 100+ hosts
- **OpenAPI-first**: `api/openapi.yaml` is the contract; generate server and client types from it

### Adding New Features

1. **Review existing architecture** in the behavioral specs ([specs/](specs/)) and the package layout under [internal/](internal/)
2. **Add a focused service package** under `internal/` rather than overloading an existing one
3. **Maintain API compatibility** when possible
4. **Follow established patterns** in the codebase
5. **Document architectural decisions** and rationale

## Pull Request Guidelines

### Before Submitting

- [ ] **Tests pass** locally
- [ ] **Code follows style guidelines**
- [ ] **Documentation updated** as needed
- [ ] **No merge conflicts** with target branch
- [ ] **Commit messages** follow conventions

### PR Description Template

```markdown
## Summary
Brief description of changes

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that causes existing functionality to change)
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing performed

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review of the code completed
- [ ] Documentation updated
- [ ] Tests added and passing
```

### Review Process

1. **Automated checks** must pass (CI/CD pipeline)
2. **Code review** by at least one maintainer
3. **Security review** for sensitive changes
4. **Documentation review** for user-facing changes
5. **Final approval** by project maintainer

## Recognition

Contributors are recognized in several ways:

- **Contributors section** in README.md
- **Release notes** acknowledgments
- **Community spotlights** in project updates
- **Maintainer privileges** for consistent contributors

## GitHub Actions Setup (For Maintainers)

### Required Repository Secrets

To enable all GitHub Actions workflows, configure these secrets in repository settings:

#### Essential Secrets

1. **SONAR_TOKEN** (Required for code quality analysis)
   - Visit [SonarCloud](https://sonarcloud.io)
   - Create an organization: `hanalyx`
   - Set up project: `Hanalyx_OpenWatch`
   - Generate a project token
   - Add to GitHub: Settings > Secrets and variables > Actions

#### Configuration Files

SonarCloud configuration lives in `sonar-project.properties`. SonarCloud is not currently
wired into a GitHub Actions workflow; configure `SONAR_TOKEN` only if you re-enable it.

#### Workflow Overview

- **Go CI** (`go-ci.yml`) - Tests, linting, and builds for the Go module and frontend
- **CodeQL** (`codeql.yml`) - Static security analysis
- **Package smoke test** (`package-smoke.yml`) - Installs the built RPM/DEB and verifies it runs
- **Release** (`release.yml`) - Tag-driven multi-arch RPM/DEB build, signing, and publishing to GitHub Releases

## Getting Help

### Community Resources

- **GitHub Discussions**: General questions and ideas
- **GitHub Issues**: Bug reports and feature requests
- **Discord**: Real-time community chat
- **Documentation**: Comprehensive guides and references

### Maintainer Contact

- **General questions**: GitHub Discussions
- **Security issues**: security@hanalyx.com
- **Partnership inquiries**: contact@hanalyx.com

## License

By contributing to OpenWatch, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE), the same license as the rest of the codebase (inbound = outbound, per Apache 2.0 Section 5).

Apache 2.0 is permissive:
- Anyone can use, modify, self-host, and redistribute OpenWatch, including commercially, with attribution.
- There is no copyleft or share-alike obligation on modifications.
- The compiled binary links the Kensa engine (BSL-1.1); see [NOTICE](NOTICE) for the combined-work terms.

---

**Thank you for contributing to OpenWatch!** Your contributions help make compliance scanning more accessible and effective for everyone.

*For more information, visit our [project documentation](README.md) or join our [community discussions](https://github.com/hanalyx/openwatch/discussions).*
