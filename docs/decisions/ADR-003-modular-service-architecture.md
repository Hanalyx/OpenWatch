# ADR-003: Modular Service Package Pattern

**Status**: Accepted
**Date**: 2025-12-02
**Deciders**: OpenWatch team

## Context

OpenWatch's backend started with flat service files in `backend/app/services/`:

```
services/
  scan_service.py          (800+ lines)
  ssh_service.py           (600+ lines)
  content_service.py       (500+ lines)
  compliance_service.py    (400+ lines)
  ... 50+ flat files
```

This structure caused:
- Large files with mixed responsibilities (scanning, parsing, orchestration in one file)
- Difficult navigation and code discovery
- Circular import risks between services
- Hard to test individual components in isolation
- No clear ownership boundaries

## Decision

Organize services into modular packages with internal structure:

```
services/
  engine/                  # Scan execution (v1.5.0)
    __init__.py            # Public API exports
    executors/             # SSH, local execution backends
    scanners/              # OpenSCAP, Kubernetes, unified
    result_parsers/        # XCCDF, ARF parsing
    orchestration/         # Multi-scanner coordination
  content/                 # SCAP content processing (v1.0.0)
    __init__.py
    parsers/               # Datastream, benchmark parsing
    transformation/        # Document transformation
    import_/               # Batch import with progress
  ssh/                     # SSH connection management
    __init__.py
    connection.py          # Connection lifecycle
    validation/            # Key validation, readiness
    policy/                # Security policies
  compliance/              # Compliance analysis
    __init__.py
    temporal.py            # Point-in-time posture
    exceptions.py          # Exception management
    alerts.py              # Alert management
    audit.py               # Audit queries
```

### Key rules:
1. **Import from `__init__.py` only** - Never import from internal module files
2. **Single responsibility** - Each sub-module handles one concern
3. **Package versioning** - Major packages carry version numbers (engine v1.5.0, content v1.0.0)
4. **Public API surface** - `__init__.py` re-exports the public interface

```python
# CORRECT - Import from package
from app.services.engine import SSHExecutor, OSCAPScanner

# WRONG - Import from internal file
from app.services.engine.scanners.oscap import OSCAPScanner
```

## Consequences

**Benefits:**
- Clear module boundaries and responsibilities
- Easier to navigate (find scan execution in `engine/`, SSH in `ssh/`)
- Testable in isolation (mock at package boundary)
- Reduced circular import risk (clear dependency direction)
- New developers can understand scope from package structure
- Independent development of modules

**Drawbacks:**
- More files and directories to manage
- `__init__.py` files must be maintained as the public API
- Some backward-compatibility aliases needed during migration
- Deeper import paths internally

**Applied to:**
- `services/engine/` - Scan execution (E2 epic, completed)
- `services/content/` - SCAP processing (E2 epic, completed)
- `services/ssh/` - Connection management (E2 epic, completed)
- `services/compliance/` - Temporal, exceptions, alerts, audit
- `plugins/aegis/` - Aegis integration bridge
- `services/plugins/orsa/` - ORSA plugin registry
