# PRD 05: Risk Assessment

**Document**: 05-RISKS.md
**Epic**: N/A (Foundation Document)
**Last Updated**: 2026-01-21

---

## 1. Risk Matrix

| Likelihood ↓ / Impact → | Low | Medium | High | Critical |
|-------------------------|-----|--------|------|----------|
| **High** | Monitor | Mitigate | Mitigate | Avoid |
| **Medium** | Accept | Monitor | Mitigate | Mitigate |
| **Low** | Accept | Accept | Monitor | Mitigate |

---

## 2. Technical Risks

### R1: Circular Import Dependencies
**Severity**: High | **Likelihood**: Medium

**Description**: Moving services may create circular import chains that break the application.

**Indicators**:
- `ImportError: cannot import name 'X' from partially initialized module`
- Tests fail with import errors
- Application won't start

**Mitigation**:
1. Map dependencies BEFORE moving files
2. Use dependency injection, not direct imports
3. Create interface modules for shared types
4. Test after EVERY file move

**Contingency**: Create compatibility shim that breaks cycle.

---

### R2: Breaking API Changes
**Severity**: High | **Likelihood**: Medium

**Description**: Route consolidation may inadvertently change API behavior.

**Indicators**:
- Frontend stops working
- Integration tests fail
- External clients report errors

**Mitigation**:
1. Compare endpoint signatures before/after
2. Run full API test suite after each change
3. Maintain backward compatibility aliases
4. Document any intentional changes

**Contingency**: Rollback to previous commit, investigate.

---

### R3: Test Suite Instability
**Severity**: Medium | **Likelihood**: High

**Description**: Existing tests may be flaky or fail after refactoring.

**Indicators**:
- Tests pass locally, fail in CI
- Random test failures
- Tests fail after code that shouldn't affect them

**Mitigation**:
1. Identify and fix flaky tests first
2. Use proper async handling
3. Isolate tests with proper fixtures
4. Run tests multiple times to verify stability

**Contingency**: Skip flaky tests temporarily, fix in dedicated sprint.

---

### R4: Database Migration Issues
**Severity**: Critical | **Likelihood**: Low

**Description**: Alembic migrations may fail or corrupt data.

**Indicators**:
- Migration errors
- Data inconsistency
- Application errors after migration

**Mitigation**:
1. Test migrations on staging first
2. Always backup before migration
3. Write rollback migrations
4. Verify data integrity after migration

**Contingency**: Restore from backup, fix migration, retry.

---

### R5: Performance Regression
**Severity**: Medium | **Likelihood**: Low

**Description**: Refactoring may introduce performance issues.

**Indicators**:
- Slower response times
- Higher CPU/memory usage
- Timeouts

**Mitigation**:
1. Establish performance baseline
2. Profile critical paths
3. Load test after major changes
4. Monitor in staging

**Contingency**: Profile to find bottleneck, optimize or rollback.

---

## 3. Process Risks

### R6: Human Review Bottleneck
**Severity**: Medium | **Likelihood**: High

**Description**: Single human reviewer may become a bottleneck.

**Indicators**:
- PRs waiting for review
- AI idle while waiting
- Timeline slipping

**Mitigation**:
1. Batch similar changes for efficient review
2. Establish clear review priorities
3. Use automated checks to reduce review burden
4. Timebox reviews (30 min max per session)

**Contingency**: Trust AI more for low-risk changes, defer reviews.

---

### R7: Scope Creep
**Severity**: Medium | **Likelihood**: Medium

**Description**: Discovery of additional issues expands scope.

**Indicators**:
- Stories taking longer than estimated
- New requirements emerging
- Timeline extending

**Mitigation**:
1. Strict adherence to PRD scope
2. Document discovered issues for future work
3. Resist "while we're here" improvements
4. Weekly scope reviews

**Contingency**: Defer non-critical items, focus on MVP.

---

### R8: Knowledge Loss Between Sessions
**Severity**: Low | **Likelihood**: Medium

**Description**: Context lost between AI sessions causes rework.

**Indicators**:
- AI asks same questions repeatedly
- Work duplicated
- Inconsistent approaches

**Mitigation**:
1. Update PRD status after each session
2. Leave TODO comments in code
3. Clear commit messages
4. Update CLAUDE.md with learnings

**Contingency**: Re-read PRD and recent commits to restore context.

---

## 4. Security Risks

### R9: Accidental Credential Exposure
**Severity**: Critical | **Likelihood**: Low

**Description**: Refactoring accidentally exposes secrets.

**Indicators**:
- Secrets in logs
- Credentials in commits
- Test fixtures with real data

**Mitigation**:
1. Use GitGuardian/pre-commit hooks
2. Never log sensitive data
3. Use fake credentials in tests
4. Review all changes touching auth/encryption

**Contingency**: Rotate exposed credentials immediately.

---

### R10: Security Regression
**Severity**: Critical | **Likelihood**: Low

**Description**: Refactoring weakens security controls.

**Indicators**:
- Security tests fail
- Audit logging missing
- Authorization bypassed

**Mitigation**:
1. Security-focused tests must pass
2. Review all auth/authz changes
3. Maintain security test coverage at 100%
4. Security review before production

**Contingency**: Rollback, fix security issue, security audit.

---

## 5. External Risks

### R11: Dependency Vulnerabilities
**Severity**: High | **Likelihood**: Medium

**Description**: Dependencies have known vulnerabilities.

**Indicators**:
- Dependabot alerts
- Security scans fail
- CVE announcements

**Mitigation**:
1. Regular dependency updates
2. Automated vulnerability scanning
3. Evaluate before adding dependencies
4. Have upgrade path for critical deps

**Contingency**: Upgrade or replace vulnerable dependency.

---

### R12: Infrastructure Changes
**Severity**: Medium | **Likelihood**: Low

**Description**: External infrastructure changes affect deployment.

**Indicators**:
- Docker/Podman updates break builds
- Cloud provider changes
- Database version changes

**Mitigation**:
1. Pin dependency versions
2. Test on multiple runtime versions
3. Monitor deprecation notices
4. Have fallback options

**Contingency**: Pin to working version, plan upgrade.

---

## 6. Risk Register

| ID | Risk | Impact | Likelihood | Score | Owner | Status |
|----|------|--------|------------|-------|-------|--------|
| R1 | Circular imports | High | Medium | 12 | AI | Open |
| R2 | Breaking API | High | Medium | 12 | AI | Open |
| R3 | Test instability | Medium | High | 12 | AI | Open |
| R4 | DB migration | Critical | Low | 12 | Human | Open |
| R5 | Performance | Medium | Low | 4 | AI | Open |
| R6 | Review bottleneck | Medium | High | 12 | Human | Open |
| R7 | Scope creep | Medium | Medium | 9 | Both | Open |
| R8 | Knowledge loss | Low | Medium | 4 | AI | Open |
| R9 | Credential exposure | Critical | Low | 12 | Both | Open |
| R10 | Security regression | Critical | Low | 12 | Human | Open |
| R11 | Vulnerabilities | High | Medium | 12 | Human | Open |
| R12 | Infrastructure | Medium | Low | 4 | Human | Open |

**Score**: Impact (1-4) × Likelihood (1-4)
- Critical=4, High=3, Medium=2, Low=1

---

## 7. Risk Response Strategies

### Avoid
- R9 (Credentials): Comprehensive scanning prevents exposure

### Mitigate
- R1, R2, R3: Test-driven approach reduces technical risks
- R4, R10: Security review process catches issues
- R6, R7: Process controls manage scope and reviews

### Monitor
- R5, R8, R12: Low impact, watch for changes

### Accept
- Minor risks with low impact and likelihood

---

## 8. Risk Review Schedule

| Review | Frequency | Focus |
|--------|-----------|-------|
| Daily | Daily standup | New blockers |
| Weekly | Friday review | Risk status update |
| Phase | End of phase | Major risk assessment |
| Incident | As needed | Post-incident review |

---

## 9. Escalation Matrix

| Severity | Response Time | Escalation Path |
|----------|---------------|-----------------|
| Critical | Immediate | Stop work, notify stakeholders |
| High | Same day | Assess, mitigate, continue if safe |
| Medium | This week | Add to backlog, mitigate in sprint |
| Low | Next review | Document, monitor |

---

## 10. Lessons Learned

(To be updated as project progresses)

| Date | Risk | Outcome | Lesson |
|------|------|---------|--------|
| | | | |

---

## 11. Risk Monitoring Dashboard

Track these metrics weekly:

| Metric | Target | Current |
|--------|--------|---------|
| Open critical risks | 0 | - |
| Open high risks | <3 | - |
| Tests passing | 100% | - |
| Security scan clean | Yes | - |
| Review queue size | <5 | - |
| Scope changes | 0 | - |
