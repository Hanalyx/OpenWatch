# OpenWatch Import Standards

This document establishes consistent import patterns for the OpenWatch codebase to prevent import chain errors and maintain security.

## Standard Import Locations

### Core Models and Services

#### Authentication and Authorization
```python
# ✅ Correct
from ..auth import get_current_user
from ..database import User

# ❌ Incorrect 
from ..auth.middleware import get_current_user
from ..models.auth_models import User
```

#### Database Models
```python
# ✅ Correct - PostgreSQL models (primary data store)
from ..database import Host, User, ScanResult, ScanSession

# ❌ Incorrect - MongoDB models are for compliance rules only
from ..models.mongo_models import Host  # Host is not in mongo_models
```

#### Plugin Models
```python
# ✅ Correct
from ..models.plugin_models import (
    InstalledPlugin, PluginTrustLevel, PluginStatus,
    PluginAssociation, SecurityCheckResult, PluginExecutionRequest
)
```

#### Configuration
```python
# ✅ Correct - Use factory function
from ..config import get_settings

# Then in code:
settings = get_settings()

# ❌ Incorrect - settings variable doesn't exist
from ..config import settings
```

#### Cryptographic Services
```python
# ✅ Correct - Use standalone functions
from .crypto import encrypt_credentials, decrypt_credentials

# ❌ Incorrect - CryptoService class doesn't exist
from .crypto import CryptoService
```

## Data Model Architecture

### PostgreSQL Models (Primary Data Store)
- **Location**: `backend/app/database.py`
- **Purpose**: Core application data (hosts, users, scans, results)
- **Models**: `Host`, `User`, `ScanResult`, `ScanSession`, etc.

### MongoDB Models (Compliance Rules)
- **Location**: `backend/app/models/mongo_models.py`
- **Purpose**: Compliance rules and intelligence data
- **Models**: `ComplianceRule`, `RuleIntelligence`, `RemediationScript`

### Plugin Models
- **Location**: `backend/app/models/plugin_models.py`
- **Purpose**: Plugin management and execution
- **Models**: `InstalledPlugin`, `PluginExecutionRequest`, etc.

## Service Import Patterns

### Command Sandbox (Container Execution)
```python
# ✅ Correct - Runtime-agnostic sandbox
from .command_sandbox import CommandSandbox

# Usage supports both Docker and Podman
sandbox = CommandSandbox()  # Uses auto-detection
sandbox = CommandSandbox(runtime="docker")  # Force Docker
sandbox = CommandSandbox(runtime="podman")  # Force Podman
```

### Container Runtime Configuration
```python
# Environment variables (optional):
OPENWATCH_CONTAINER_RUNTIME=docker|podman|auto
OPENWATCH_CONTAINER_SOCKET=/custom/socket/path
```

## Import Error Prevention

### Common Issues and Solutions

1. **Missing Model Imports**
   - Always check if the model exists in the target file
   - Use consistent import paths across modules

2. **Configuration Access**
   - Always use `get_settings()` function
   - Cache settings at module level if needed: `settings = get_settings()`

3. **Service Dependencies**
   - Check if service classes exist before importing
   - Use function imports when class wrappers don't exist

4. **Runtime Dependencies**
   - Gracefully handle missing optional dependencies
   - Provide fallback implementations when appropriate

## Testing Import Paths

To verify imports work correctly:

```bash
# Test Python imports
cd backend
python -c "from app.config import get_settings; print('✅ Config OK')"
python -c "from app.database import Host, User; print('✅ Database models OK')"
python -c "from app.services.command_sandbox import CommandSandbox; print('✅ Command sandbox OK')"

# Test application startup
docker-compose logs backend | grep "Application startup complete"
```

## Security Considerations

### Import Security Guidelines

1. **Never import from untrusted sources**
2. **Validate all imported configurations**
3. **Use relative imports within the application**
4. **Avoid dynamic imports from user input**
5. **Maintain import path consistency for audit trails**

### Container Runtime Security

The container runtime abstraction supports:
- **Docker**: Standard container execution
- **Podman**: Rootless and enhanced security
- **Auto-detection**: Prefers Podman for security, falls back to Docker

Both runtimes maintain the same security model:
- Isolated execution environments
- Resource limits and timeouts
- Comprehensive audit logging
- FIPS-compliant cryptographic operations

## Troubleshooting

### Common Import Errors

1. **`ImportError: cannot import name 'X' from 'Y'`**
   - Check if the imported name exists in the target module
   - Verify the import path is correct
   - Look for typos in import statements

2. **`ModuleNotFoundError: No module named 'X'`**
   - Check if the module file exists
   - Verify the directory structure
   - Ensure `__init__.py` files exist in package directories

3. **Circular import errors**
   - Move shared imports to a common module
   - Use late imports (inside functions)
   - Restructure dependencies to remove cycles

### Recovery Steps

1. Check this documentation for correct import patterns
2. Verify the target module contains the expected exports
3. Test imports in Python REPL
4. Check application startup logs for detailed error messages