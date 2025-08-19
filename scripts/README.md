# OpenWatch Scripts

Utility scripts for OpenWatch setup, deployment, and maintenance.

## Directory Structure

```
scripts/
├── setup.sh              # Initial setup script
├── setup-dev.sh          # Development environment setup
├── setup-local-db.sh     # Local database initialization
├── generate-certs.sh     # SSL certificate generation
├── create-admin.sh       # Create admin user
├── check-environment.sh  # Verify environment setup
├── run-local.sh          # Run services locally
└── verify-setup.sh       # Validate installation
```

## Script Descriptions

### setup.sh
Main setup script that:
- Checks system requirements
- Installs dependencies
- Initializes database
- Generates certificates
- Creates initial admin user

Usage:
```bash
./setup.sh
```

### setup-dev.sh
Development environment setup:
- Installs development dependencies
- Configures local environment variables
- Sets up pre-commit hooks
- Initializes test database

Usage:
```bash
./setup-dev.sh
```

### setup-local-db.sh
Database initialization for local development:
- Creates PostgreSQL database
- Runs initial migrations
- Sets up test data (optional)
- Configures database permissions

Usage:
```bash
./setup-local-db.sh [--with-test-data]
```

### generate-certs.sh
SSL certificate generation:
- Creates self-signed certificates for development
- Generates CA, server, and client certificates
- Creates Diffie-Hellman parameters
- Sets appropriate file permissions

Usage:
```bash
./generate-certs.sh [--production]
```

### create-admin.sh
Creates administrative user:
- Prompts for username and password
- Assigns super_admin role
- Configures MFA (optional)
- Adds to audit log

Usage:
```bash
./create-admin.sh
```

### check-environment.sh
Environment validation:
- Verifies required environment variables
- Checks service connectivity
- Validates certificate configuration
- Tests database access

Usage:
```bash
./check-environment.sh
```

### run-local.sh
Local service launcher:
- Starts backend services
- Launches frontend development server
- Configures logging
- Sets up debugging if requested

Usage:
```bash
./run-local.sh [--debug] [--services backend,frontend,worker]
```

### verify-setup.sh
Installation verification:
- Tests all service endpoints
- Validates authentication flow
- Checks scan functionality
- Verifies integrations

Usage:
```bash
./verify-setup.sh [--comprehensive]
```

## Common Tasks

### First Time Setup
```bash
./setup.sh
./generate-certs.sh
./create-admin.sh
```

### Development Setup
```bash
./setup-dev.sh
./setup-local-db.sh --with-test-data
./run-local.sh --debug
```

### Production Deployment
```bash
./check-environment.sh
./generate-certs.sh --production
./verify-setup.sh --comprehensive
```

## Environment Variables

Scripts expect these variables:
- `OPENWATCH_DATABASE_URL`: PostgreSQL connection
- `OPENWATCH_REDIS_URL`: Redis connection
- `OPENWATCH_SECRET_KEY`: Application secret
- `OPENWATCH_ADMIN_EMAIL`: Initial admin email

## Best Practices

1. Always run `check-environment.sh` before deployment
2. Use `--production` flag for production certificates
3. Store script logs for troubleshooting
4. Run scripts from the OpenWatch root directory
5. Review script output for warnings/errors

## Troubleshooting

### Permission Issues
```bash
chmod +x scripts/*.sh
```

### Database Connection
Check PostgreSQL service and credentials in environment

### Certificate Errors
Regenerate certificates and restart services

---
*Last updated: 2025-01-12*