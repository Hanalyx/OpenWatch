# OpenWatch Docker Configuration

Docker configurations for containerized deployment of OpenWatch services.

## Directory Structure

```
docker/
├── Dockerfile.backend       # Production Docker backend image
├── Dockerfile.backend.dev   # Development Docker backend image  
├── Dockerfile.frontend      # Production Docker frontend image
├── Dockerfile.frontend.dev  # Development Docker frontend image
├── Containerfile.backend    # Production Podman backend image
├── Containerfile.frontend   # Production Podman frontend image
├── database/                # Database initialization
│   └── init.sql            # Initial schema and roles
└── frontend/                # Nginx configurations
    ├── default.conf        # Production HTTPS config
    ├── default-simple.conf # Simple HTTP config  
    ├── default.dev.conf    # Development config
    └── nginx.conf          # Base Nginx config
```

## Container Images

### Runtime Support
- **Docker**: Standard container runtime (`Dockerfile.*`)
- **Podman**: Rootless container runtime (`Containerfile.*`)
- **Auto-detection**: owadm CLI detects available runtime

### Backend Images

**Production (Dockerfile.backend)**
- Multi-stage build with Python 3.9
- FIPS-compliant cryptography
- Includes all production dependencies
- Runs as non-root user
- Health check included

**Development (Dockerfile.backend.dev)**
- Simpler build for faster iteration
- Includes development tools
- Volume mounts for code changes

### Frontend Images

**Production (Dockerfile.frontend)**
- Multi-stage build process
- Node.js build stage + Nginx serve stage
- Optimized static asset serving
- HTTPS with strong security headers

**Development (Dockerfile.frontend.dev)**
- Pre-built assets expected
- Simple Nginx configuration
- HTTP only for local development

## Nginx Configurations

### default.conf (Production)
- HTTPS on port 443 with HTTP->HTTPS redirect
- Strong SSL/TLS configuration
- Security headers (CSP, HSTS, etc.)
- API proxy to backend service
- Gzip compression enabled

### default-simple.conf
- HTTP only on port 80
- Extended timeouts for long scans (600s)
- Basic proxy configuration
- No SSL/security headers

### default.dev.conf
- Minimal configuration for development
- WebSocket support for HMR
- Relaxed security for local testing

## Usage

### Production Deployment
```bash
# Build all images
docker compose build

# Start all services
docker compose up -d

# View logs
docker compose logs -f
```

### Development Mode
```bash
# Use development compose file
docker compose -f docker-compose.dev.yml up -d

# Rebuild specific service
docker compose build backend
docker compose up -d backend
```

## Service Dependencies

1. **database**: PostgreSQL 15
2. **redis**: Redis 7 for Celery
3. **backend**: FastAPI application
4. **worker**: Celery worker
5. **frontend**: Nginx + React app

## Security Considerations

- SSL certificates required for production
- Strong cipher suites configured
- Security headers prevent common attacks
- Non-root user execution
- Network isolation between services

## Health Checks

All services include health checks:
- Backend: HTTP endpoint check
- Worker: Celery ping check
- Frontend: HTTP response check
- Database: PostgreSQL ready check
- Redis: Connection test

## Container Management Commands

### With owadm (Recommended)
```bash
# Automatic runtime detection
owadm start                    # Start all services
owadm status                   # Check service status
owadm logs backend --follow    # View logs
owadm stop                     # Stop all services

# Specific runtime
owadm start --runtime docker   # Force Docker
owadm start --runtime podman   # Force Podman
```

### Direct Compose Commands
```bash
# Docker Compose
docker-compose up -d                    # Production
docker-compose -f docker-compose.dev.yml up -d  # Development

# Podman Compose (rootless)
podman-compose up -d                    # Production
```

## Migration from Legacy Scripts

The following legacy scripts have been replaced by owadm:
- `start-openwatch.sh` → `owadm start`
- `stop-openwatch.sh` → `owadm stop`
- `install.sh` → `owadm start` (with auto-setup)

---
*Last updated: 2025-08-19*