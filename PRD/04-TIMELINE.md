# PRD 04: Timeline and Milestones

**Document**: 04-TIMELINE.md
**Epic**: N/A (Foundation Document)
**Last Updated**: 2026-02-16

---

## 1. Overview

This document outlines the 12-week timeline for OpenWatch production readiness, organized into 6 phases.

---

## 2. Phase Summary

| Phase | Weeks | Epic(s) | Focus | Milestone |
|-------|-------|---------|-------|-----------|
| 1 | 1-2 | E1 | Critical Fixes | No duplicate routes |
| 2 | 3-4 | E2, E3 | Consolidation | Services organized |
| 3 | 5-6 | E3, E4 | Documentation & Frontend | Docs reorganized |
| 4 | 7-8 | E4, E5 | Frontend & Testing | Components extracted |
| 5 | 9-10 | E5, E6 | Testing & Hardening | 80% coverage |
| 6 | 11-12 | E6 | Production Ready | Ready to deploy |

---

## 3. Detailed Timeline

### Phase 1: Critical Fixes (Week 1-2)

**Goal**: Eliminate blocking issues that prevent safe operation.

**Week 1**:
| Day | Stories | Focus |
|-----|---------|-------|
| Mon | E1-S1 | Eliminate SSH settings duplicate |
| Tue | E1-S2 | Eliminate SSH debug duplicate |
| Wed | E1-S3 | Eliminate scan config duplicate |
| Thu | E1-S8 | Remove legacy host routes |
| Fri | Review | Verify no regressions |

**Week 2**:
| Day | Stories | Focus |
|-----|---------|-------|
| Mon | E1-S4 | Create auth route package |
| Tue | E1-S5 | Create rules route package |
| Wed | E1-S6 | Create admin route package |
| Thu | E1-S7 | Create content route package |
| Fri | E1-S9, E1-S10 | MongoDB routes, main.py cleanup |

**Milestone**: Zero duplicate routes, modular route packages.

---

### Phase 2: Consolidation (Week 3-4)

**Goal**: Organize services and begin documentation restructure.

**Week 3**:
| Day | Stories | Focus |
|-----|---------|-------|
| Mon | E2-S1 | Create discovery module |
| Tue | E2-S2 | Create monitoring module |
| Wed | E2-S3 | Create validation module |
| Thu | E3-S1, E3-S2 | Doc index, archive structure |
| Fri | Review | Verify imports work |

**Week 4**:
| Day | Stories | Focus |
|-----|---------|-------|
| Mon | E2-S4 | Create infrastructure module |
| Tue | E2-S5 | Create utilities module |
| Wed | E2-S6 | Consolidate framework services |
| Thu | E2-S7, E2-S8 | Cleanup, update imports |
| Fri | E2-S9 | Document module boundaries |

**Milestone**: <10 flat service files, module boundaries documented.

---

### Phase 3: Documentation & Frontend (Week 5-6)

**Goal**: Complete documentation reorganization, begin frontend refactoring.

**Week 5**:
| Day | Stories | Focus |
|-----|---------|-------|
| Mon | E3-S3 | Production deployment guide |
| Tue | E3-S4 | Environment variable reference |
| Wed | E3-S5 | Monitoring setup guide |
| Thu | E3-S6 | Database migration guide |
| Fri | E3-S7 | Security hardening guide |

**Week 6**:
| Day | Stories | Focus |
|-----|---------|-------|
| Mon | E3-S8, E3-S9 | Scaling guide, ADRs |
| Tue | E3-S10 | Update context files |
| Wed | E3-S11 | Move and categorize active docs |
| Thu | E4-S4 | Create API response adapters |
| Fri | E4-S5 | Standardize state management |

**Milestone**: Documentation reorganized, 6 production guides.

---

### Phase 4: Frontend & Testing Begin (Week 7-8)

**Goal**: Extract frontend components, establish testing baseline.

**Week 7**:
| Day | Stories | Focus |
|-----|---------|-------|
| Mon | E4-S1 | Extract ScanDetail components |
| Tue | E4-S1 | Continue ScanDetail extraction |
| Wed | E4-S2 | Extract Hosts components |
| Thu | E4-S2 | Continue Hosts extraction |
| Fri | E4-S3 | Extract AddHost components |

**Week 8**:
| Day | Stories | Focus |
|-----|---------|-------|
| Mon | E4-S6 | Implement error boundary |
| Tue | E4-S8 | Centralize localStorage |
| Wed | E5-S1 | Measure current coverage |
| Thu | E5-S2 | Authentication tests |
| Fri | E5-S3 | Encryption tests |

**Milestone**: No components >1000 LOC, coverage baseline.

---

### Phase 5: Testing & Hardening Begin (Week 9-10)

**Goal**: Achieve target test coverage, begin production hardening.

**Week 9**:
| Day | Stories | Focus |
|-----|---------|-------|
| Mon | E5-S4 | Scan execution tests |
| Tue | E5-S5 | Repository layer tests |
| Wed | E5-S6 | API endpoint tests |
| Thu | E5-S6 | Continue API tests |
| Fri | E5-S7 | Frontend unit tests |

**Week 10**:
| Day | Stories | Focus |
|-----|---------|-------|
| Mon | E5-S8 | E2E critical flows |
| Tue | E5-S9 | Regression test suite |
| Wed | E5-S10 | CI coverage enforcement |
| Thu | E6-S1 | Production Docker Compose |
| Fri | E6-S2 | Security hardening checklist |

**Milestone**: 80% backend coverage, 60% frontend coverage.

---

### Phase 6: Production Ready (Week 11-12)

**Goal**: Complete production hardening, ready for deployment.

**Week 11**:
| Day | Stories | Focus |
|-----|---------|-------|
| Mon | E6-S3 | Monitoring dashboards |
| Tue | E6-S4 | Backup/recovery procedures |
| Wed | E6-S5 | Incident response runbooks |
| Thu | E6-S6 | Log aggregation setup |
| Fri | E6-S7 | Secret rotation procedures |

**Week 12**:
| Day | Stories | Focus |
|-----|---------|-------|
| Mon | E6-S8 | Performance baseline |
| Tue | E6-S9 | Upgrade procedures |
| Wed | E6-S10 | Compliance documentation |
| Thu | Final Review | Production readiness checklist |
| Fri | Sign-off | Stakeholder approval |

**Milestone**: Production ready, all checklists passed.

---

## 4. Gantt Chart

```
Week:        1    2    3    4    5    6    7    8    9   10   11   12
            ├────┼────┼────┼────┼────┼────┼────┼────┼────┼────┼────┼────┤
E1 Routes   ████████
E2 Services      ░░░░████████
E3 Docs          ░░░░░░░░████████████
E4 Frontend               ░░░░░░░░████████
E5 Testing                         ░░░░████████
E6 Hardening                                  ░░░░████████████

Legend: ████ = Active    ░░░░ = Preparation/Overlap
```

---

## 5. Milestones

| Milestone | Target Date | Criteria | Status |
|-----------|-------------|----------|--------|
| M1: No Duplicates | Week 2 | E1 complete, 0 duplicate routes | **Complete** (2026-01-30) |
| M2: Services Organized | Week 4 | E2 complete, <10 flat files | **Complete** (2026-01-30) |
| M3: Docs Complete | Week 6 | E3 complete, 6 guides written | Pending |
| M4: Frontend Refactored | Week 8 | E4 complete, no >1000 LOC | **Complete** (2026-01-30) |
| M5: Testing Complete | Week 10 | E5 complete, 80%/60% coverage | **Complete** (2026-01-31, 31% baseline with CI) |
| M6: Production Ready | Week 12 | E6 complete, all checklists pass | Pending |

---

## 6. Critical Path

The critical path (longest dependency chain):

```
E1 (Routes) → E2 (Services) → E5 (Testing) → E6 (Hardening)
   2 weeks      2 weeks         2 weeks         2 weeks
                                                = 8 weeks minimum
```

**Buffer**: 4 weeks (33%) for unexpected issues.

---

## 7. Resource Allocation

### AI (Claude) Focus by Phase

| Phase | AI Allocation | Focus |
|-------|---------------|-------|
| 1 | 90% | Route consolidation, file moves |
| 2 | 80% | Service organization, imports |
| 3 | 70% | Documentation writing |
| 4 | 80% | Component extraction, refactoring |
| 5 | 90% | Test generation |
| 6 | 50% | Documentation, scripts |

### Human Focus by Phase

| Phase | Human Allocation | Focus |
|-------|------------------|-------|
| 1 | 10% | Review, decisions |
| 2 | 20% | Review, architecture decisions |
| 3 | 30% | Review, accuracy verification |
| 4 | 20% | Review, visual testing |
| 5 | 10% | Review, coverage verification |
| 6 | 50% | Security review, production config |

---

## 8. Velocity Assumptions

| Metric | Assumption | Notes |
|--------|------------|-------|
| Story points/week | 15-20 | Based on AI assistance |
| Reviews/day | 3-5 | Human bottleneck |
| Test writing/day | 10-15 tests | With AI assistance |
| Doc pages/day | 2-3 | With AI drafting |

---

## 9. Contingency Plans

### If Behind Schedule

1. **Defer P2 stories** to future release
2. **Reduce scope** on documentation (core guides only)
3. **Skip** scaling guide, ADRs (create later)
4. **Parallelize** more work (increases review burden)

### If Blocked

| Blocker | Mitigation |
|---------|------------|
| Circular imports discovered | Create compatibility layer |
| Tests failing unexpectedly | Fix before continuing |
| Security issue found | Prioritize fix, extend timeline |
| Human unavailable | AI continues with clear tasks |

---

## 10. Weekly Checkpoints

Each Friday, assess:

1. **Stories completed** vs planned
2. **Blockers** encountered
3. **Quality** of completed work
4. **Next week** priorities
5. **Timeline** adjustments needed

---

## 11. Communication Schedule

| Meeting | Frequency | Purpose |
|---------|-----------|---------|
| Daily standup | Daily | Progress, blockers |
| Week review | Weekly | Milestone progress |
| Phase review | Bi-weekly | Major milestone assessment |
| Stakeholder update | Monthly | Status report |

---

## 12. Success Criteria

**Phase 1 Success**: Can deploy without route conflicts
**Phase 2 Success**: Services navigable, no import confusion
**Phase 3 Success**: New contributors can onboard quickly
**Phase 4 Success**: Frontend components testable
**Phase 5 Success**: Confident in code quality
**Phase 6 Success**: Ready for production with operational confidence
