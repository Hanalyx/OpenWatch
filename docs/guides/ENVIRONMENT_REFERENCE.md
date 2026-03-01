# Environment Variable Reference

Complete reference for all OpenWatch environment variables. Variables use the `OPENWATCH_` prefix and are validated by Pydantic Settings on startup.

Configuration source: `backend/app/config.py`

## Required Variables

These variables must be set for the application to start.

| Variable | Description | Format |
|----------|-------------|--------|
| `OPENWATCH_SECRET_KEY` | Application signing key for JWT tokens | String, min 32 characters |
| `OPENWATCH_MASTER_KEY` | Master encryption key for credential storage (AES-256-GCM) | String, min 32 characters |
| `OPENWATCH_DATABASE_URL` | PostgreSQL connection string | `postgresql://user:pass@host:port/db` | <!-- pragma: allowlist secret -->
| `OPENWATCH_ENCRYPTION_KEY` | Data encryption key | String |
| `POSTGRES_PASSWORD` | PostgreSQL password (used in compose) | String |
| `REDIS_PASSWORD` | Redis authentication password (used in compose) | String |

## Database

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENWATCH_DATABASE_URL` | (required) | PostgreSQL connection string |
| `OPENWATCH_DATABASE_SSL_MODE` | `require` | SSL mode: `disable`, `require`, `verify-ca`, `verify-full` |
| `OPENWATCH_DATABASE_SSL_CERT` | `None` | Path to client SSL certificate |
| `OPENWATCH_DATABASE_SSL_KEY` | `None` | Path to client SSL key |
| `OPENWATCH_DATABASE_SSL_CA` | `None` | Path to CA certificate |
| `POSTGRES_HOST` | `database` | PostgreSQL hostname (compose) |
| `POSTGRES_PORT` | `5432` | PostgreSQL port (compose) |
| `POSTGRES_DB` | `openwatch` | Database name (compose) |
| `POSTGRES_USER` | `openwatch` | Database user (compose) |
| `POSTGRES_PASSWORD` | (required) | Database password (compose) |

In docker-compose, the backend receives the full connection string:
```
OPENWATCH_DATABASE_URL=postgresql://openwatch:${POSTGRES_PASSWORD}@database:5432/openwatch
```

## Redis and Celery

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENWATCH_REDIS_URL` | `redis://localhost:6379` | Redis connection string with password |
| `OPENWATCH_REDIS_HOST` | `redis` | Redis hostname |
| `OPENWATCH_REDIS_PORT` | `6379` | Redis port |
| `OPENWATCH_REDIS_DB` | `0` | Redis database number |
| `OPENWATCH_REDIS_SSL` | `false` | Enable Redis TLS |
| `OPENWATCH_REDIS_SSL_CERT` | `None` | Redis client certificate path |
| `OPENWATCH_REDIS_SSL_KEY` | `None` | Redis client key path |
| `OPENWATCH_REDIS_SSL_CA` | `None` | Redis CA certificate path |
| `REDIS_PASSWORD` | (required) | Redis password (compose) |

In docker-compose:
```
OPENWATCH_REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379
```

## Application

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENWATCH_DEBUG` | `false` | Enable debug mode (never in production) |
| `OPENWATCH_APP_NAME` | `OpenWatch` | Application name |
| `OPENWATCH_APP_VERSION` | `1.2.0` | Application version string |
| `OPENWATCH_MAX_UPLOAD_SIZE` | `104857600` | Max file upload size in bytes (100MB) |
| `OPENWATCH_ALLOWED_FILE_TYPES` | `.xml,.zip,.bz2,.gz` | Allowed upload file extensions |
| `OPENWATCH_LICENSE_TIER` | `community` | License tier: `community` or `openwatch_plus` |

## Security and JWT

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENWATCH_SECRET_KEY` | (required) | JWT signing key, min 32 characters |
| `OPENWATCH_ALGORITHM` | `RS256` | JWT algorithm (FIPS-approved RSA) |
| `OPENWATCH_ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | Access token lifetime in minutes |
| `OPENWATCH_REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Refresh token lifetime in days |
| `OPENWATCH_MASTER_KEY` | (required) | AES-256-GCM encryption master key, min 32 chars |

Security note: Both `SECRET_KEY` and `MASTER_KEY` are validated on startup. The application will fail to start if either is shorter than 32 characters.

## FIPS and TLS

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENWATCH_FIPS_MODE` | `true` | Enable FIPS 140-2 compliant cryptography |
| `OPENWATCH_REQUIRE_HTTPS` | `true` | Require HTTPS for all connections |
| `OPENWATCH_TLS_CERT_FILE` | `None` | Backend TLS certificate path |
| `OPENWATCH_TLS_KEY_FILE` | `None` | Backend TLS private key path |
| `OPENWATCH_TLS_CA_FILE` | `None` | Backend TLS CA certificate path |

When `FIPS_MODE` is enabled, only FIPS-approved cipher suites are used:
- TLS_AES_256_GCM_SHA384
- TLS_AES_128_GCM_SHA256
- ECDHE-RSA-AES256-GCM-SHA384
- ECDHE-RSA-AES128-GCM-SHA256
- DHE-RSA-AES256-GCM-SHA384
- DHE-RSA-AES128-GCM-SHA256

## CORS

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENWATCH_ALLOWED_ORIGINS` | `https://localhost:3001` | Comma-separated list of allowed CORS origins |

All origins must use HTTPS except `http://localhost`. Validated on startup.

Example:
```
OPENWATCH_ALLOWED_ORIGINS=https://openwatch.example.com,https://admin.example.com
```

## SSH Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENWATCH_SSH_STRICT_MODE` | `false` | Enable strict SSH host key verification |

Docker-compose also supports (commented out by default):
- `OPENWATCH_STRICT_SSH` - Force RejectPolicy for unknown hosts
- `OPENWATCH_PERMISSIVE_SSH` - Force AutoAddPolicy for unknown hosts

## Scanning

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENWATCH_OPENSCAP_TIMEOUT` | `3600` | Maximum scan time in seconds (1 hour) |
| `OPENWATCH_MAX_CONCURRENT_SCANS` | `5` | Maximum simultaneous scans |
| `SCAP_CONTENT_DIR` | `/openwatch/data/scap` | SCAP content storage directory |
| `SCAN_RESULTS_DIR` | `/openwatch/data/results` | Scan results storage directory |
| `KENSA_RULES_PATH` | (auto-detected) | Path to Kensa YAML rules directory (set in Docker) |

> **Note**: `OPENWATCH_OPENSCAP_TIMEOUT` and `SCAP_CONTENT_DIR` are legacy variables from the OpenSCAP era. Kensa scans use SSH-based checks with their own timeout handling. These variables are retained for backward compatibility but have no effect on Kensa scans.

## Container Runtime

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENWATCH_CONTAINER_RUNTIME` | `auto` | Runtime: `docker`, `podman`, or `auto` |
| `OPENWATCH_CONTAINER_SOCKET` | `None` | Custom container socket path |
| `COMPOSE_PROJECT_NAME` | `openwatch` | Docker compose project name |
| `CONTAINER_RUNTIME` | `podman` | Container runtime for compose (compose-level) |

## Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENWATCH_LOG_LEVEL` | `INFO` | Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL |
| `OPENWATCH_LOG_FILE` | `None` | Application log file path |
| `OPENWATCH_AUDIT_LOG_FILE` | `/openwatch/logs/audit.log` | Audit log file path |

## External Integrations

### SMTP (Email Notifications)

| Variable | Default | Description |
|----------|---------|-------------|
| `SMTP_SERVER` | - | SMTP server hostname |
| `SMTP_PORT` | `587` | SMTP port (587 for TLS) |
| `SMTP_USERNAME` | - | SMTP authentication username |
| `SMTP_PASSWORD` | - | SMTP authentication password |
| `SMTP_USE_TLS` | `true` | Enable STARTTLS |

### LDAP (Directory Authentication)

| Variable | Default | Description |
|----------|---------|-------------|
| `LDAP_SERVER` | - | LDAP server URL (`ldap://host:389`) |
| `LDAP_BIND_DN` | - | Bind distinguished name |
| `LDAP_BIND_PASSWORD` | - | Bind password |
| `LDAP_USER_SEARCH_BASE` | - | User search base DN |

## TLS Certificate Paths

These paths are configured in `docker-compose.yml` volume mounts:

| Path | Purpose | Mount |
|------|---------|-------|
| `/openwatch/security/certs/` | TLS certificates | `./security/certs:ro` |
| `/openwatch/security/keys/` | TLS/SSH private keys | `./security/keys` |
| `/openwatch/security/known_hosts/` | SSH known hosts DB | Named volume |
| `/etc/ssl/certs/frontend.crt` | Frontend TLS cert | `./security/certs/frontend.crt:ro` |
| `/etc/ssl/private/frontend.key` | Frontend TLS key | `./security/keys/frontend.key:ro` |

## Monitoring Stack

These variables are used by `monitoring/docker-compose.monitoring.yml`:

| Variable | Default | Description |
|----------|---------|-------------|
| `GRAFANA_ADMIN_PASSWORD` | `secureops_grafana` | Grafana admin password |
| `REDIS_PASSWORD` | (shared) | Used by Redis exporter |
| `POSTGRES_PASSWORD` | (shared) | Used by Postgres exporter |

## Deprecated Variables

These variables exist for backward compatibility but are no longer functional:

| Variable | Status | Notes |
|----------|--------|-------|
| `OPENWATCH_MONGODB_URL` | Deprecated | MongoDB removed, using PostgreSQL |
| `OPENWATCH_MONGODB_DATABASE` | Deprecated | MongoDB removed |
| `OPENWATCH_USE_QUERY_BUILDER` | Removed | QueryBuilder is now the only option |
| `OPENWATCH_USE_REPOSITORY_PATTERN` | Removed | Repository pattern refactoring complete |

## Generating a Production .env File

```bash
cat > .env << 'ENVEOF'
# Database
POSTGRES_PASSWORD=$(openssl rand -base64 32)

# Redis
REDIS_PASSWORD=$(openssl rand -base64 32)

# Application
OPENWATCH_DEBUG=false
OPENWATCH_SECRET_KEY=$(openssl rand -base64 48)
OPENWATCH_MASTER_KEY=$(openssl rand -base64 48)
OPENWATCH_ENCRYPTION_KEY=$(openssl rand -base64 48)
OPENWATCH_FIPS_MODE=true
OPENWATCH_REQUIRE_HTTPS=true

# CORS (update with your domain)
OPENWATCH_ALLOWED_ORIGINS=https://openwatch.yourdomain.com

# Logging
OPENWATCH_LOG_LEVEL=INFO
ENVEOF
```

Security note: Never commit the `.env` file to version control. The `.gitignore` already excludes it.
