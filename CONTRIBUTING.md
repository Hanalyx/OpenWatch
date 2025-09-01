# Contributing to OpenWatch

Thank you for your interest in contributing to OpenWatch! This guide will help you get started with contributing to the project.

## 🤝 Code of Conduct

We are committed to providing a welcoming and inclusive environment for all contributors. Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## 🚀 Getting Started

### Prerequisites

- **Container Runtime**: Docker or Podman
- **Development Environment**: Linux (RHEL/Ubuntu recommended)
- **Resources**: 4GB RAM, 2CPU cores minimum
- **Git**: For version control

### Development Setup

1. **Fork the repository** on GitHub
2. **Clone your fork**:
   ```bash
   git clone https://github.com/yourusername/openwatch.git
   cd openwatch
   ```

3. **Set up development environment**:
   ```bash
   # Start dependencies
   docker compose up -d database redis
   
   # Backend development
   cd backend
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   uvicorn app.main:app --reload
   
   # Frontend development (new terminal)
   cd frontend
   npm install
   npm run dev
   ```

## 📋 How to Contribute

### 🐛 Reporting Bugs

1. **Check existing issues** to avoid duplicates
2. **Use the bug report template** when creating new issues
3. **Include detailed information**:
   - Operating system and version
   - Container runtime (Docker/Podman)
   - Steps to reproduce
   - Expected vs actual behavior
   - Log files and error messages

### 💡 Suggesting Features

1. **Check the roadmap** in our [README](README.md#roadmap)
2. **Open a discussion** for major features before implementing
3. **Use the feature request template** for new issues
4. **Provide detailed use cases** and benefits

### 🔧 Contributing Code

#### Branch Strategy

- **main**: Stable, production-ready code
- **develop**: Integration branch for features
- **feature/**: New features (`feature/scap-profiles`)
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
   git commit -m "feat: add SCAP profile validation
   
   - Implement OpenSCAP datastream validation
   - Add profile enumeration for uploaded content
   - Include error handling for malformed XML
   
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
feat(scap): add profile validation endpoint
fix(auth): resolve JWT token expiration handling
docs(api): update scanning endpoint documentation
```

## 🧪 Testing

### Running Tests

```bash
# Backend tests
cd backend
python -m pytest tests/ -v

# Frontend tests (when available)
cd frontend
npm test

# Integration tests
make test-integration
```

### Test Requirements

- **Unit tests** for all new functions and classes
- **Integration tests** for API endpoints
- **Test coverage** should not decrease below 80%
- **All tests must pass** before merging

### Writing Tests

- **Follow existing patterns** in the test directories
- **Use descriptive test names**: `test_scap_profile_validation_with_invalid_xml`
- **Include edge cases** and error conditions
- **Mock external dependencies** appropriately

## 🎨 Code Style

### Python (Backend)

- **Follow PEP 8** with 88-character line limit
- **Use Black** for formatting: `black .`
- **Use isort** for imports: `isort .`
- **Use mypy** for type checking: `mypy app/`
- **Docstrings** for all public functions and classes

### TypeScript/React (Frontend)

- **Follow Prettier** configuration: `npm run format`
- **Use ESLint** rules: `npm run lint`
- **TypeScript strict mode** enabled
- **React functional components** with hooks
- **Material-UI components** for consistency

### General Guidelines

- **Meaningful variable names**: `scap_profile` not `sp`
- **Small, focused functions**: Single responsibility principle
- **Error handling**: Comprehensive exception handling
- **Security-first**: Validate all inputs, sanitize outputs
- **Performance**: Consider efficiency in scanning operations

## 🔌 Plugin Development

OpenWatch supports a plugin architecture for extensibility.

### Plugin Structure

```
plugins/
├── my_plugin/
│   ├── __init__.py
│   ├── plugin.py          # Main plugin class
│   ├── routes.py          # API endpoints (optional)
│   ├── models.py          # Data models (optional)
│   └── requirements.txt   # Plugin dependencies
```

### Plugin Interface

```python
from openwatch.core.plugin import PluginBase

class MyPlugin(PluginBase):
    name = "my_plugin"
    version = "1.0.0"
    description = "My custom plugin"
    
    def load(self):
        """Called when plugin is loaded"""
        pass
    
    def scan_post_process(self, scan_result):
        """Called after scan completion"""
        return scan_result
```

### Plugin Guidelines

- **Follow the plugin interface** specifications
- **Document plugin capabilities** thoroughly
- **Include example configuration** and usage
- **Test plugin compatibility** with core system
- **Consider security implications** of plugin functionality

## 🔒 Security

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

## 📚 Documentation

### Documentation Requirements

- **Update README.md** for significant changes
- **API documentation** for new endpoints
- **User guides** for new features
- **Architecture documentation** for design changes
- **Plugin documentation** for extensibility features

### Documentation Style

- **Clear, concise language**
- **Step-by-step instructions** with examples
- **Screenshots** for UI changes
- **API examples** with request/response samples
- **Link to related documentation**

## 🏗️ Architecture Guidelines

### Core Principles

- **Modularity**: Clear separation between components
- **Extensibility**: Plugin-first architecture
- **Security**: FIPS compliance and best practices
- **Performance**: Efficient scanning for 100+ hosts
- **Container-first**: Docker/Podman deployment ready

### Adding New Features

1. **Review existing architecture** in [DIRECTORY_ARCHITECTURE.md](DIRECTORY_ARCHITECTURE.md)
2. **Consider plugin interfaces** before adding to core
3. **Maintain API compatibility** when possible
4. **Follow established patterns** in the codebase
5. **Document architectural decisions** and rationale

## 🎯 Pull Request Guidelines

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

## 🌟 Recognition

Contributors are recognized in several ways:

- **Contributors section** in README.md
- **Release notes** acknowledgments
- **Community spotlights** in project updates
- **Maintainer privileges** for consistent contributors

## ⚙️ GitHub Actions Setup (For Maintainers)

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

The following files are already configured for SonarCloud:
- `sonar-project.properties` - Project configuration
- `.github/workflows/code-quality.yml` - Quality pipeline

#### Workflow Overview

- **CI Pipeline** (`ci.yml`) - Tests, linting, builds
- **Code Quality** (`code-quality.yml`) - SonarCloud analysis, security scans
- **Documentation** (`docs.yml`) - API docs generation
- **Deploy** (`deploy.yml`) - Container publishing (main branch only)

## 🤔 Getting Help

### Community Resources

- **GitHub Discussions**: General questions and ideas
- **GitHub Issues**: Bug reports and feature requests
- **Discord**: Real-time community chat
- **Documentation**: Comprehensive guides and references

### Maintainer Contact

- **General questions**: GitHub Discussions
- **Security issues**: security@hanalyx.com
- **Partnership inquiries**: contact@hanalyx.com

## 📄 License

By contributing to OpenWatch, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).

---

**Thank you for contributing to OpenWatch!** Your contributions help make SCAP compliance more accessible and effective for everyone.

*For more information, visit our [project documentation](README.md) or join our [community discussions](https://github.com/hanalyx/openwatch/discussions).*