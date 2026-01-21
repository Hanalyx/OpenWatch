# PRD 03: AI Collaboration Model

**Document**: 03-AI-COLLABORATION.md
**Epic**: N/A (Foundation Document)
**Last Updated**: 2026-01-21

---

## 1. Overview

This document defines how human developers and AI assistants (Claude) collaborate effectively on the OpenWatch project. The goal is to maximize productivity while maintaining quality and safety.

---

## 2. Collaboration Philosophy

### 2.1 Core Principles

1. **AI as Force Multiplier**: AI handles implementation, human handles decisions
2. **Trust but Verify**: AI work is trusted but always reviewed
3. **Fail Fast, Learn Fast**: Small iterations with quick feedback
4. **Documentation as Communication**: PRD and code comments bridge sessions
5. **Human Retains Authority**: AI recommends, human decides

### 2.2 Optimal Task Distribution

```
┌─────────────────────────────────────────────────────────────┐
│                    TASK SPECTRUM                            │
├─────────────────────────────────────────────────────────────┤
│ AI EXCELS                              HUMAN EXCELS         │
│ ◄────────────────────────────────────────────────────────►  │
│                                                             │
│ Boilerplate code    │    Architecture decisions            │
│ Pattern matching    │    Business requirements             │
│ Documentation       │    Security approval                 │
│ Test generation     │    Production deployment             │
│ Refactoring         │    Stakeholder management            │
│ Code analysis       │    Priority setting                  │
│ Search/research     │    Risk acceptance                   │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Task Ownership Matrix

### 3.1 AI Owns (Human Reviews)

| Task | AI Responsibility | Human Responsibility |
|------|-------------------|----------------------|
| **File moves/renames** | Execute refactoring | Approve plan |
| **Import updates** | Update all references | Verify completeness |
| **Test writing** | Generate test cases | Review coverage |
| **Documentation** | Draft content | Review accuracy |
| **Code formatting** | Apply standards | Verify consistency |
| **Boilerplate** | Generate scaffolding | Review structure |
| **Search/analysis** | Find patterns/issues | Interpret results |

### 3.2 AI Assists (Human Leads)

| Task | Human Responsibility | AI Responsibility |
|------|----------------------|-------------------|
| **Architecture** | Make decisions | Research options, recommend |
| **API design** | Define contracts | Implement endpoints |
| **Database schema** | Approve changes | Draft migrations |
| **Security code** | Review and approve | Implement with guidance |
| **Dependencies** | Approve additions | Research compatibility |
| **Performance** | Set requirements | Identify bottlenecks |

### 3.3 Human Owns (AI Informs)

| Task | Human Responsibility | AI Responsibility |
|------|----------------------|-------------------|
| **Production deploy** | Execute deployment | Provide checklist |
| **Secrets management** | Handle credentials | Never access secrets |
| **External APIs** | Configure integrations | Document usage |
| **Compliance decisions** | Accept/reject | Flag concerns |
| **Budget/resources** | Allocate | Estimate effort |

---

## 4. Session Workflow

### 4.1 Session Start

```
1. Human: Provides context and goal
   "Let's work on E1: Route Consolidation, starting with SSH routes"

2. AI: Acknowledges and confirms understanding
   - Reads relevant files
   - Reviews PRD epic
   - Identifies specific tasks

3. AI: Proposes plan
   - List of files to modify
   - Order of operations
   - Potential risks

4. Human: Approves or adjusts plan
```

### 4.2 During Session

```
1. AI: Implements in small increments
   - One logical change at a time
   - Tests after each change
   - Documents as it goes

2. Human: Reviews periodically
   - Approves direction
   - Corrects course if needed
   - Answers questions

3. Both: Communicate blockers immediately
```

### 4.3 Session End

```
1. AI: Provides session summary
   - Work completed
   - Work remaining
   - Blockers encountered
   - Recommendations

2. Human: Updates PRD status
   - Mark stories complete
   - Note any decisions
   - Set next session priorities

3. AI: Commits with clear messages
   - Reference PRD epic/story
   - Describe changes accurately
```

---

## 5. Communication Patterns

### 5.1 AI Asking for Clarification

**Good Pattern**:
```
I see two approaches for consolidating host discovery:

Option A: Create services/discovery/ with separate files
- Pros: Clear separation, easy to find
- Cons: More files to maintain

Option B: Single discovery_service.py with classes
- Pros: Fewer files
- Cons: Larger file, harder to navigate

I recommend Option A because it matches the pattern in engine/ and ssh/.
Would you like me to proceed with Option A?
```

**Bad Pattern**:
```
Should I create a new directory or not?
```

### 5.2 AI Reporting Progress

**Good Pattern**:
```
Completed: Moved ssh_settings.py to ssh/settings.py
- Updated 12 import statements
- All tests pass
- Deprecated old file with TODO marker

Next: Moving ssh_debug.py
Blocker: None

Remaining in this epic: 3 stories
```

**Bad Pattern**:
```
Done with the SSH stuff.
```

### 5.3 AI Flagging Concerns

**Good Pattern**:
```
CONCERN: While moving routes, I found that:
- routes/hosts_legacy.py has 3 endpoints also in routes/hosts/crud.py
- These have different implementations
- Risk: Users may be hitting the wrong endpoint

Recommendation: Before removing legacy file, we should:
1. Verify which implementation is correct
2. Add deprecation warning to legacy endpoints
3. Monitor for 1 week before removal

Should I proceed with deprecation warnings, or investigate first?
```

**Bad Pattern**:
```
Found some duplicate endpoints, I'll just delete the old ones.
```

---

## 6. Context Management

### 6.1 What AI Should Read First

For any task, AI should read in this order:

1. **CLAUDE.md** - Overall project guidance
2. **Relevant context file** - Topic-specific details
3. **PRD epic** - Task requirements and acceptance criteria
4. **Related source files** - Current implementation
5. **Related tests** - Expected behavior

### 6.2 Providing Context to AI

**Effective Context**:
```
Goal: Consolidate SSH routes (E1-S3)
Current state: routes/ssh_settings.py and routes/ssh/settings.py both exist
Expected outcome: Single implementation in routes/ssh/settings.py
Constraints: Must maintain all existing endpoints
Reference: See PRD/epics/E1-ROUTE-CONSOLIDATION.md
```

**Ineffective Context**:
```
Fix the SSH routes.
```

### 6.3 Cross-Session Continuity

To maintain context across sessions:

1. **Update PRD status** after each session
2. **Leave TODO comments** in code for next steps
3. **Commit frequently** with descriptive messages
4. **Update CLAUDE.md** with new patterns discovered
5. **Document decisions** in PRD appendices

---

## 7. Quality Assurance

### 7.1 AI Self-Review Checklist

Before presenting work to human, AI should verify:

- [ ] Code follows project conventions (Black, Flake8, MyPy)
- [ ] All imports are updated
- [ ] Tests pass
- [ ] No security concerns introduced
- [ ] Documentation updated
- [ ] Commit message follows conventions
- [ ] Changes are minimal and focused
- [ ] No commented-out code left behind

### 7.2 Human Review Checklist

When reviewing AI work:

- [ ] Logic is correct
- [ ] Edge cases handled
- [ ] Security implications considered
- [ ] Performance acceptable
- [ ] Matches acceptance criteria
- [ ] No unintended side effects
- [ ] Consistent with existing patterns

### 7.3 Test Requirements

| Change Type | Test Requirement |
|-------------|------------------|
| New endpoint | Unit test + integration test |
| Bug fix | Regression test |
| Refactoring | Existing tests must pass |
| New service | Unit tests for public methods |
| Security fix | Security-focused test |

---

## 8. Error Handling

### 8.1 When AI Makes Mistakes

1. **Human identifies issue**: Describes what's wrong
2. **AI acknowledges**: No defensiveness, just understanding
3. **AI proposes fix**: Explains correction
4. **Human approves**: Confirms approach
5. **AI implements**: Makes correction
6. **Both learn**: Update CLAUDE.md if pattern issue

### 8.2 When Requirements Are Unclear

1. **AI asks specific questions**: Not vague requests
2. **Human provides clarification**: With examples if possible
3. **AI confirms understanding**: Restates requirements
4. **Human approves**: Before implementation begins

### 8.3 When Blockers Occur

1. **AI identifies blocker**: Describes obstacle clearly
2. **AI proposes workarounds**: If any exist
3. **Human decides**: Workaround, defer, or escalate
4. **Document**: In PRD or code comments

---

## 9. Efficiency Patterns

### 9.1 Parallel Work

AI can work on multiple independent tasks:
```
Human: "Work on E1-S1, E1-S2, and E1-S3 in parallel"
AI: Implements all three, presents for batch review
```

### 9.2 Incremental Commits

Small, focused commits enable:
- Easy rollback if issues found
- Clear history of changes
- Simpler code review

### 9.3 Template Usage

For repetitive tasks, AI should:
1. Create a template from first instance
2. Apply template to remaining instances
3. Present template for human approval

### 9.4 Test-First Development

For new features:
1. AI writes failing test
2. Human reviews test (confirms requirements)
3. AI implements to pass test
4. Human reviews implementation

---

## 10. Anti-Patterns to Avoid

### 10.1 AI Anti-Patterns

| Anti-Pattern | Why Bad | Instead Do |
|--------------|---------|------------|
| Making decisions without asking | May conflict with human intent | Present options, recommend one |
| Large changes without checkpoints | Hard to review, risky | Small increments with verification |
| Assuming requirements | May build wrong thing | Ask clarifying questions |
| Ignoring existing patterns | Creates inconsistency | Study and follow existing code |
| Over-engineering | Wastes time, adds complexity | Minimum viable solution |
| Defensive responses | Wastes time, hurts trust | Acknowledge and fix |

### 10.2 Human Anti-Patterns

| Anti-Pattern | Why Bad | Instead Do |
|--------------|---------|------------|
| Vague requirements | AI can't deliver accurately | Specific acceptance criteria |
| Micromanaging | Defeats purpose of AI assistance | Trust with verification |
| Skipping reviews | Quality issues slip through | Always review AI work |
| Not providing context | AI makes wrong assumptions | Share relevant information |
| Changing direction mid-task | Wasted work | Complete or explicitly abandon |

---

## 11. Metrics and Improvement

### 11.1 Track These Metrics

| Metric | Target | How to Measure |
|--------|--------|----------------|
| AI task completion rate | >90% | Tasks completed vs assigned |
| Review rejection rate | <10% | Rejected reviews / total reviews |
| Rework rate | <5% | Times AI redoes same task |
| Session productivity | Increasing | Stories completed per session |

### 11.2 Retrospective Questions

After each phase:
1. What worked well in AI collaboration?
2. What was frustrating?
3. What patterns should we document?
4. What should AI do differently?
5. What should human do differently?

---

## 12. Special Scenarios

### 12.1 Debugging Together

```
Human: "There's a bug where X happens instead of Y"
AI:
1. Reads relevant code
2. Identifies potential causes
3. Proposes debugging steps
4. Implements fix with test
```

### 12.2 Learning New Codebase Areas

```
AI: Before working on unfamiliar area:
1. Reads README and docs
2. Studies existing patterns
3. Identifies similar implementations
4. Asks questions if unclear
```

### 12.3 Emergency Fixes

```
For urgent production issues:
1. Human provides context quickly
2. AI proposes minimal fix
3. Human reviews immediately
4. Deploy with monitoring
5. Follow up with proper fix later
```

---

## 13. References

- [CLAUDE.md](../CLAUDE.md) - Project-specific AI guidance
- [02-STAKEHOLDERS.md](02-STAKEHOLDERS.md) - Roles and responsibilities
- [Anthropic Claude Code Best Practices](https://www.anthropic.com/engineering/claude-code-best-practices)
