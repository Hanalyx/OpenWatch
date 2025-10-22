# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Structure

This is the **Hanalyx monorepo** containing multiple projects:

- **`/openwatch/`** - Main SCAP compliance scanner application (primary focus)
- **`/website/`** - Marketing/documentation website
- **`/ai_workflow/`** - AI automation tooling and workflows

**Default working directory:** Always operate in `/home/rracine/hanalyx/openwatch/` unless explicitly working on website or AI workflows.

## OpenWatch Development Commands

### Container Operations (Docker/Podman)
```bash
cd openwatch/

# Start all services (auto-detects runtime)
./start-openwatch.sh --runtime docker --build    # Docker
./start-openwatch.sh --runtime podman --build    # Podman (rootless)

# Stop services (SAFE - preserves data by default)
./stop-openwatch.sh

# Dangerous: Delete ALL data
OPENWATCH_CLEAN_STOP=true ./stop-openwatch.sh

# Container logs
docker logs openwatch-backend --tail 100
docker logs openwatch-frontend
docker logs openwatch-worker
```

### Frontend Development
```bash
cd openwatch/frontend/

npm run dev              # Start Vite dev server (port 3001)
npm run build           # Production build
npm run lint            # ESLint check
npm run lint:fix        # Auto-fix ESLint issues
npm run test:e2e        # Run Playwright E2E tests
npm run test:e2e:ui     # Interactive test UI
npm run test:e2e:debug  # Debug mode with browser
```

### Backend Development
```bash
cd openwatch/backend/

# Run linting/security checks
black --check app/                    # Format checking (line-length: 100)
black app/                           # Auto-format
flake8 app/                          # Linting
mypy app/                            # Type checking
bandit -r app/                       # Security scanning

# Run tests (from repository root)
pytest -v                            # All tests
pytest -m unit                       # Unit tests only
pytest -m "not slow"                 # Exclude slow tests
pytest --cov=app --cov-report=html   # Coverage report

# Hot-reload backend code changes (backend doesn't auto-reload)
docker cp backend/app/file.py openwatch-backend:/app/backend/app/file.py
docker restart openwatch-backend
```

### Database Operations
```bash
# PostgreSQL migrations
cd openwatch/backend/
alembic revision --autogenerate -m "Description"
alembic upgrade head
alembic current

# Access database console
docker exec -it openwatch-db psql -U openwatch -d openwatch

# MongoDB console
docker exec -it openwatch-mongodb mongosh
```

## Critical Architecture Patterns

### Database Schema - UUID Strategy
**CRITICAL:** Primary keys use native PostgreSQL UUIDs, NOT integers.

```python
# CORRECT - UUID primary keys
class Host(Base):
    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)

class Scan(Base):
    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    host_id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("hosts.id"))
```

**Key UUID relationships:**
- `hosts.id` → `UUID`
- `scans.host_id` → `UUID` (foreign key to `hosts.id`)
- `host_group_memberships.host_id` → `UUID`

### Dual Database Architecture
1. **PostgreSQL** (SQLAlchemy ORM) - Relational data
   - Users, hosts, scans, credentials, groups, webhooks
   - Location: `backend/app/database.py`

2. **MongoDB** (Beanie ODM) - Document store
   - Compliance rules, detailed scan results, health monitoring
   - Location: `backend/app/models/mongo_models.py`

### Repository Pattern (MongoDB)
All MongoDB access uses repository pattern:

```python
from backend.app.repositories.base_repository import BaseRepository

class ComplianceRuleRepository(BaseRepository[ComplianceRule]):
    async def find_by_framework(self, framework: str) -> List[ComplianceRule]:
        # Framework-specific queries
```

**Base repository features:**
- Generic CRUD with type safety
- Pagination support (`find_with_pagination`)
- Performance monitoring (logs slow queries >1s)
- Aggregation pipeline support

### Authentication Flow
```
1. Login → FastAPI endpoint
2. Argon2id password verification (64MB memory, FIPS-compliant)
3. RS256 JWT signed with RSA-2048 key pair
4. Frontend: localStorage.getItem('auth_token')  ← NOT 'token'
5. API requests: Authorization: Bearer <token>
6. Backend validates with public key
```

**IMPORTANT:** Frontend uses `localStorage.getItem('auth_token')` NOT `'token'`.

### SCAP Scanning Workflow
```
1. API Request → /api/scans validates parameters
2. Celery Task → execute_scan_task queued to Redis
3. Credential Resolution → AuthService resolves host/system credentials
4. SSH Validation → UnifiedSSHService tests connectivity
5. SCAP Execution:
   - Local: oscap xccdf eval
   - Remote: oscap-ssh wrapper
6. Progress Tracking → Database updates (5%, 10%, 20%...100%)
7. Result Parsing → XML → PostgreSQL metadata + MongoDB details
8. File Storage → /app/data/results/ (XML, ARF, HTML)
9. Webhook Callbacks → AEGIS integration
```

### Service Layer Patterns

**Centralized SSH Management:**
```python
# ALWAYS use UnifiedSSHService for SSH operations
from backend.app.services.unified_ssh_service import UnifiedSSHService

ssh_service = UnifiedSSHService()
result = await ssh_service.test_connection(host, credentials)
```

**Centralized Credential Resolution:**
```python
# ALWAYS use AuthService for credentials
from backend.app.services.auth_service import AuthService

auth_service = AuthService()
credentials = await auth_service.resolve_credentials(host_id)
```

### Security - FIPS Compliance
- **Encryption:** AES-256-GCM only
- **Password Hashing:** Argon2id (64MB memory cost)
- **JWT Signing:** RS256 with RSA-2048 keys
- **SSH Credentials:** Encrypted in `Host.encrypted_credentials` field
- **System Credentials:** Stored in `SystemCredentials` table with fingerprinting

### Async Task Processing (Celery)
Background tasks execute via Celery workers:
- **Scans:** `backend/app/tasks/scan_tasks.py`
- **Monitoring:** `backend/app/tasks/monitoring_tasks.py`
- **Webhooks:** `backend/app/tasks/webhook_tasks.py`
- **Message Broker:** Redis
- **Worker Command:** `celery -A app.tasks worker --loglevel=info`

## Frontend Architecture

### Technology Stack
- **React 18** + **TypeScript**
- **Material-UI v5** (Material Design 3)
- **State Management:**
  - Redux Toolkit + Redux Persist (auth state)
  - TanStack React Query (server state, 5min stale time)
- **Routing:** React Router v6
- **HTTP:** Axios with interceptors
- **Charts:** Recharts + Chart.js
- **Terminal:** XTerm.js
- **Testing:** Playwright (E2E)

### Component Organization
```
frontend/src/
├── components/      # Reusable UI components
│   ├── auth/       # Login, Register, MFA
│   ├── hosts/      # Host management
│   ├── scans/      # Scan execution
│   ├── dashboard/  # Widgets
│   └── layout/     # Navigation, sidebar
├── pages/          # Route-level components
├── services/       # API client
├── store/slices/   # Redux state
├── hooks/          # Custom hooks
└── types/          # TypeScript definitions
```

### API Client Pattern
```typescript
// Axios instance automatically injects JWT token
import api from '@/services/api';

// Token retrieved from: localStorage.getItem('auth_token')
const response = await api.get('/api/v1/hosts');
```

## File System Locations

### Container Volumes
- **SCAP Content:** `/app/data/scap/` (XML data-streams)
- **Scan Results:** `/app/data/results/` (XML, ARF, HTML)
- **Application Logs:** `/app/logs/`
- **TLS Certificates:** `/app/security/certs/`
- **Encryption Keys:** `/app/security/keys/`

### Local Development
- **Backend Config:** `openwatch/backend/.env` (copy from `.env.example`)
- **Frontend Config:** Environment variables in Vite config
- **Database Data:** Docker volumes (preserved across restarts)

## Common Issues & Solutions

### Backend Code Changes Not Reflecting
Backend container doesn't auto-reload. Copy files manually:
```bash
docker cp backend/app/file.py openwatch-backend:/app/backend/app/file.py
docker restart openwatch-backend openwatch-worker
```

### Authentication Failures
Verify correct localStorage key:
```typescript
localStorage.getItem('auth_token')  // CORRECT
localStorage.getItem('token')       // WRONG
```

### Database Connection Issues
```bash
# Check PostgreSQL health
docker-compose ps
docker-compose logs db

# Verify SSL certificates exist (if SSL mode enabled)
ls openwatch/security/certs/
```

### UUID vs Integer Confusion
```python
# WRONG - treating UUID as integer
host = db.query(Host).filter(Host.id == 12345).first()

# CORRECT - UUID as string
from uuid import UUID
host_uuid = UUID("550e8400-e29b-41d4-a716-446655440000")
host = db.query(Host).filter(Host.id == host_uuid).first()
```

### SCAP Scan Performance
Enhanced parsing is disabled by default for performance. Enable only when needed:
```python
# In scan configuration
enable_enhanced_parsing = False  # Default
```

## Testing Standards

### Pytest Configuration
```bash
# Run with markers
pytest -m unit              # Unit tests only
pytest -m integration       # Integration tests
pytest -m "not slow"       # Exclude slow tests
pytest -m scap             # SCAP-specific tests

# Coverage requirements
pytest --cov=app --cov-fail-under=80
```

### Code Quality Standards
- **Line Length:** 100 characters (Black, Flake8)
- **Type Checking:** MyPy strict mode enabled
- **Import Sorting:** isort with Black profile
- **Security:** Bandit scanning required

### Frontend Testing
```bash
# Playwright E2E tests
npm run test:e2e                    # Headless
npm run test:e2e:ui                 # Interactive UI
npm run test:e2e:debug              # Debug with browser
npm run test:e2e:headed             # Watch tests run
```

## Git Workflow

### Branch Naming
- `feature/descriptive-name`
- `fix/issue-description`
- `refactor/component-name`
- `docs/documentation-update`

### Commit Standards
All commits include Claude Code attribution:
```
feat: Add feature description

Detailed explanation of changes.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>
```

### Pull Requests
PRs automatically run CI checks:
- Backend CI (pytest, Black, Flake8, MyPy, Bandit)
- Frontend CI (ESLint, TypeScript, Playwright)
- Security scans (CodeQL, Trivy, Grype, SonarCloud)

**Dependency conflict fix:** FastAPI 0.119.1+ required for Starlette 0.47.2 compatibility.

## Automated Triage System

**Location:** `.github/workflows/automated-triage.yml`

**Purpose:** Automatically processes 8,756+ security alerts using risk-based triage.

**Risk Matrix:** `(Complexity + Severity + Disruption) / 3`
- **LOW (1.0-1.6):** Auto-merge Dependabot PRs
- **MEDIUM (1.7-2.3):** Create issues tagged `claude-assist`
- **HIGH (2.4-3.0):** Create urgent issues for human review

**Schedule:** Runs every 6 hours (0, 6, 12, 18 UTC)

**Manual trigger:**
```bash
# Via GitHub Actions UI or API
gh workflow run automated-triage.yml
```

## Environment Variables

### Required Variables
```bash
# Backend (.env)
SECRET_KEY=$(openssl rand -hex 32)
MASTER_KEY=$(openssl rand -hex 32)
DATABASE_URL=postgresql://user:pass@db:5432/openwatch
MONGODB_URI=mongodb://mongodb:27017
REDIS_URL=redis://redis:6379

# Optional
OPENWATCH_DEBUG=false
OPENWATCH_REQUIRE_HTTPS=true
OPENWATCH_FIPS_MODE=true
```

### Security Keys Generation
```bash
# Generate encryption keys
openssl rand -hex 32  # SECRET_KEY
openssl rand -hex 32  # MASTER_KEY

# Generate RSA key pair (JWT signing)
openssl genrsa -out private_key.pem 2048
openssl rsa -in private_key.pem -pubout -out public_key.pem
```

## Documentation Reference

- **Main README:** `/openwatch/README.md`
- **API Docs:** Auto-generated at `/api/docs` (Swagger UI)
- **Architecture Docs:** `/openwatch/docs/`
- **Automated Triage:** `/openwatch/docs/AUTOMATED_TRIAGE_SYSTEM.md`
- **Claude Code Automation:** `/openwatch/docs/CLAUDE_CODE_AUTOMATION.md`

## Key Design Principles

1. **UUID Primary Keys** - All distributed entities use native PostgreSQL UUIDs
2. **Repository Pattern** - MongoDB access abstracted through repositories
3. **Centralized Services** - SSH and credential logic consolidated
4. **Async by Default** - Long-running tasks via Celery, async/await in FastAPI
5. **FIPS Compliance** - AES-256-GCM, Argon2id, RSA-2048, no MD5/SHA1
6. **Defense in Depth** - Rate limiting → security headers → audit logs → size limits
7. **Fail Fast** - Validate early (SSH test before scan, credential check before connection)
8. **Type Safety** - MyPy strict mode, TypeScript strict mode enabled
