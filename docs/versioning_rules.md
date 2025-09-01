# OpenWatch Versioning Rules

This document defines the semantic versioning strategy for OpenWatch, ensuring consistent and predictable version increments that users can rely on for upgrade planning.

## Semantic Versioning Overview

OpenWatch follows [Semantic Versioning 2.0.0](https://semver.org/) with the format `MAJOR.MINOR.PATCH`:

- **MAJOR**: Breaking changes requiring user action
- **MINOR**: New features, backward-compatible additions  
- **PATCH**: Bug fixes, security updates, minor improvements

## Version Increment Rules

### MAJOR (v1.x.x → v2.x.x)
**Breaking changes that require user action**

#### API Breaking Changes
- Removing or significantly changing existing API endpoints
- Modifying request/response formats in incompatible ways
- Changing authentication mechanisms or token structures
- Removing or renaming required fields

#### Infrastructure Changes
- Database schema changes requiring migration with potential data loss
- Configuration file format changes (breaking existing configs)
- Container image architecture or base image changes
- Required environment variable changes (renaming/removing)

#### Security Model Changes
- RBAC system restructuring requiring permission reassignment
- FIPS compliance requirement changes
- Encryption key rotation requirements
- Authentication method deprecation

#### SCAP Integration Changes
- Breaking compatibility with existing SCAP content formats
- OpenSCAP version compatibility breaks requiring content updates
- Scan result format changes affecting integrations

**Examples:**
- Removing deprecated `/api/legacy` endpoints
- Changing JWT token structure
- Requiring new TLS certificate formats
- Database migration requiring manual data transformation

### MINOR (v1.1.x → v1.2.x)
**New features and backward-compatible additions**

#### New Functionality
- New API endpoints and resources
- Additional SCAP content type support
- New scanning engines or compliance frameworks
- Enhanced reporting capabilities

#### Feature Enhancements  
- Host groups and bulk management operations
- Scan templates and scheduling
- Webhook integrations and callbacks
- Advanced filtering and search capabilities

#### Integration Additions
- AEGIS automated remediation integration
- External SIEM connectivity
- Additional authentication providers (SAML, LDAP)
- Third-party security tool integrations

#### Database Additions
- New tables or columns (backward compatible)
- Additional indexes for performance
- New configuration options with defaults

#### UI Improvements
- New dashboards and visualization components
- Enhanced user experience features
- Additional accessibility options
- Mobile responsiveness improvements

**Examples:**
- Adding container image scanning capabilities
- Implementing NIST Cybersecurity Framework compliance
- Adding Slack webhook notifications
- New compliance dashboard with trend analysis

### PATCH (v1.2.1 → v1.2.2)
**Bug fixes, security updates, and minor improvements**

#### Bug Fixes
- Authentication and authorization failures
- SCAP content parsing errors
- Scan result generation issues  
- UI layout and validation problems

#### Security Updates
- Dependency vulnerability patches
- Security configuration improvements
- Audit logging enhancements
- Access control refinements

#### Performance Improvements
- Database query optimization
- Memory usage reductions
- Scan processing speed improvements
- UI responsiveness enhancements

#### Documentation and Configuration
- README and API documentation updates
- Default configuration improvements
- Logging format standardization
- Error message clarification

#### Dependency Management
- Library version updates (non-breaking)
- Container base image security updates
- Development tool updates

**Examples:**
- Fixing SCAP upload timeout errors
- Updating vulnerable npm dependencies
- Improving scan progress indicator accuracy
- Correcting API documentation examples

## Decision Framework

### Version Decision Flowchart

1. **"Will existing users need to change their configuration, code, or workflows?"**
   - Yes → **MAJOR**
   - No → Continue to step 2

2. **"Does this add new functionality or capabilities?"**
   - Yes → **MINOR**
   - No → Continue to step 3

3. **"Does this fix bugs, improve security, or enhance existing features without adding new ones?"**
   - Yes → **PATCH**
   - No → Re-evaluate the change

### OpenWatch-Specific Considerations

#### Security-First Approach
- Security patches are typically **PATCH** releases
- New security features are **MINOR** releases
- Security model changes are **MAJOR** releases

#### SCAP Compliance
- SCAP content format compatibility is critical for version classification
- Breaking SCAP compatibility requires **MAJOR** version increment
- Adding new SCAP profiles or benchmarks is **MINOR**

#### Enterprise Deployment
- Consider impact on automated deployment pipelines
- Breaking configuration changes affect enterprise users significantly
- Database migrations should be backwards compatible when possible

## Conventional Commit Integration

OpenWatch uses conventional commits to automate version determination:

```bash
feat: new feature          → MINOR release
fix: bug fix              → PATCH release  
security: security fix    → PATCH release
BREAKING CHANGE: footer   → MAJOR release
perf: performance         → PATCH release
docs: documentation       → PATCH release
```

## Release Automation

### GitHub Actions Workflow
The automated release process:
1. Analyzes conventional commits since last release
2. Determines appropriate version increment
3. Updates version in all relevant files
4. Generates changelog
5. Creates git tag
6. Builds and publishes container images
7. Creates GitHub release with assets

### Version Consistency
All version references must be updated simultaneously:
- `frontend/package.json`
- `backend/app/config.py`
- `backend/app/main.py`
- `pyproject.toml`
- Container image tags

## Release Frequency Guidelines

### Recommended Cadence
- **PATCH**: As needed (weekly to bi-weekly for critical fixes)
- **MINOR**: Monthly to quarterly for feature releases
- **MAJOR**: Annually or when significant architectural changes are required

### Emergency Releases
Security vulnerabilities may trigger immediate **PATCH** releases outside the normal cadence.

### Feature Freezes
Before **MAJOR** releases, implement feature freezes to ensure stability and thorough testing of breaking changes.

## Backward Compatibility Promise

### What We Guarantee
- **MINOR** and **PATCH** releases maintain API compatibility
- Configuration files remain compatible within **MINOR** versions
- Database migrations are non-destructive for **MINOR**/**PATCH**
- SCAP content continues to work within **MINOR** versions

### Deprecation Policy
- Features marked for removal get 2 **MINOR** versions notice
- Deprecated features are removed only in **MAJOR** releases
- Clear migration paths provided for all breaking changes

## Version Support Policy

### Long Term Support (LTS)
- **MAJOR** versions receive security updates for 12 months after next **MAJOR** release
- **MINOR** versions receive critical fixes for 6 months
- Latest **PATCH** version recommended for all deployments

### End of Life (EOL)
- Clear EOL timelines communicated 6 months in advance
- Security-only support available for enterprise customers

---

**Last Updated:** 2025-09-01  
**Next Review:** 2025-12-01