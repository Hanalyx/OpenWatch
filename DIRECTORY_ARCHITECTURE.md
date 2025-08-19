# OpenWatch Directory Architecture

**Status**: Optimized for Epic 1.1 (OpenWatch Core Foundation)  
**Last Updated**: 2025-08-19  
**Architecture Lead**: alex (Architecture Agent)

## Overview

OpenWatch follows a clean, modular directory structure designed to support:
- Plugin architecture extensibility (Epic OW-004)
- Clean repository separation for OSS release (Epic OW-001)
- Container-based deployment (Epic OW-005)
- Professional maintainability standards

## Directory Structure

```
openwatch/
├── backend/                    # Core backend services
│   ├── alembic/               # Database migrations
│   ├── app/                   # FastAPI application
│   └── venv/                  # Python virtual environment
├── frontend/                   # Core frontend application
│   ├── src/                   # React TypeScript source
│   ├── public/                # Static assets
│   └── build/                 # Production build output
├── cmd/owadm/                  # CLI administration utility
├── internal/owadm/             # Go internal packages
│   ├── cmd/                   # Command implementations
│   ├── runtime/               # Container runtime abstraction
│   └── utils/                 # Utility functions
├── docker/                     # Container configurations
│   ├── database/              # Database initialization
│   └── frontend/              # NGINX configurations
├── monitoring/                 # Observability stack
│   └── k6/                    # Performance testing
├── scripts/                    # Operational scripts
├── security/                   # Unified security management
│   ├── certs/                 # TLS certificates
│   └── keys/                  # Cryptographic keys
├── data/                       # Application data
│   ├── scap/                  # SCAP content files
│   ├── results/               # Scan results
│   └── uploads/               # File uploads
├── logs/                       # Unified logging
└── test-reports/               # Test output and results
```

## Architectural Principles

### 1. Core/Extension Separation
- **Core Components**: `backend/`, `frontend/` contain essential functionality
- **Extension Points**: Clean interfaces for plugin integration
- **Isolation**: Core and extensions maintain clear boundaries

### 2. Container-First Design
- **Consistent Paths**: All paths container-compatible (`/app/*`)
- **Volume Management**: Persistent data in dedicated volumes
- **Multi-Runtime**: Docker and Podman support via unified configuration

### 3. Security by Design
- **Unified Security**: Single `/security/` directory for all keys/certs
- **No Duplication**: Eliminated key synchronization risks
- **Access Control**: Proper file permissions and container isolation

### 4. Plugin Architecture Readiness
- **Service Discovery**: `backend/app/services/` for extensible services
- **Route Management**: `backend/app/routes/` for API extensibility
- **Component System**: `frontend/src/components/` for UI extensions
- **Configuration**: Centralized settings support plugin configuration

## Migration Summary

### Removed Empty Directories:
- `/tests/` (replaced by `/test-reports/`)
- `/backend/tests/` (unused)
- `/backend/migrations/` (using Alembic)
- `/backend/app/models/` (models in services)
- `/frontend/tests/` (unused)

### Consolidated Structures:
- **Logs**: `/backend/logs/` → `/logs/` (unified logging)
- **Security**: `/backend/security/keys/` removed (deduplicated)
- **Containers**: Unused container files removed

### Updated Configurations:
- ✅ Audit logging: `/app/logs/audit.log` (container path)
- ✅ Volume mappings: `app_logs:/app/logs` preserved
- ✅ Security paths: `/app/security/keys/` for all services

## Plugin Architecture Support

### Extension Points:
1. **Backend Services**: `backend/app/services/` for new service integrations
2. **API Routes**: `backend/app/routes/` for new endpoint categories
3. **Frontend Components**: `frontend/src/components/` for UI extensions
4. **Configuration**: Environment-based plugin discovery
5. **Security**: Unified key management for plugin authentication

### Plugin Loading Strategy:
- **Service Discovery**: Automatic detection of plugin services
- **Route Registration**: Dynamic API endpoint registration
- **Component Registration**: Frontend component discovery
- **Configuration Injection**: Plugin-specific settings management

## Container Integration

### Volume Mappings:
```yaml
volumes:
  - ./security/keys:/app/security/keys     # Unified security
  - ./security/certs:/app/security/certs   # TLS certificates  
  - app_logs:/app/logs                     # Unified logging
  - app_data:/app/data                     # Application data
```

### Path Conventions:
- **Host Development**: Relative paths (`./security/keys/`)
- **Container Runtime**: Absolute paths (`/app/security/keys/`)
- **Configuration**: Environment-aware path resolution

## Epic 1.1 Alignment

### OW-001 (Repository Separation):
✅ **Clean Structure**: No duplicate files, clear organization
✅ **OSS Ready**: Professional directory layout for public release
✅ **Documentation**: Complete architectural documentation

### OW-004 (Plugin Architecture Foundation):
✅ **Extension Points**: Clear interfaces for plugin integration
✅ **Modular Design**: Core/extension separation established
✅ **Service Discovery**: Framework for plugin loading

### OW-005 (Container Deployment):
✅ **Container Paths**: All paths container-compatible
✅ **Volume Strategy**: Persistent data properly mapped
✅ **Multi-Runtime**: Docker/Podman support maintained

## Validation Results

### Functionality Preserved:
- ✅ Audit logging operational (`/logs/audit.log`)
- ✅ Container volume mappings intact
- ✅ Security key access maintained
- ✅ All service dependencies preserved

### Architecture Quality:
- ✅ Zero empty directories in core structure
- ✅ Clear separation of concerns
- ✅ Plugin-ready interfaces established
- ✅ Professional organization standards met

---

**Architecture Status**: ✅ OPTIMIZED FOR EPIC 1.1  
**Plugin Readiness**: ✅ FOUNDATION ESTABLISHED  
**Repository Status**: ✅ READY FOR SEPARATION