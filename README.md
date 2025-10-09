# OpenWatch - Open Source SCAP Compliance Scanner

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Container Support](https://img.shields.io/badge/Container-Docker%20%7C%20Podman-green)](https://podman.io/)

OpenWatch is an open-source SCAP (Security Content Automation Protocol) compliance scanner for automated security assessments. Scan your infrastructure against STIG, CIS, and custom security profiles.

## Quick Start

### Prerequisites
- Docker or Podman
- Linux system (RHEL/Ubuntu recommended)
- 4GB RAM, 2 CPU cores minimum

### Installation

```bash
# Clone and start
git clone https://github.com/hanalyx/openwatch.git
cd openwatch
./start-openwatch.sh --runtime docker --build

# Wait 60-90 seconds for services to start
# Access web interface at http://localhost:3000
# Default credentials: admin / admin
```

**Important**: Change the default admin password immediately after first login.

### First Scan

1. **Add SSH credentials** (Settings → System Credentials)
   - Name: `default-ssh`
   - Username: Your SSH user
   - Authentication: Password or SSH key

2. **Add a host** (Hosts → Add Host)
   - Hostname/IP: Your target system
   - SSH Port: 22 (default)
   - Credentials: Select `default-ssh`

3. **Upload SCAP content** (Content → Upload)
   - Download SCAP content from [NIST NCP](https://ncp.nist.gov/repository)
   - Upload the `.xml` data-stream file

4. **Run a scan** (Scanning → New Scan)
   - Select host and SCAP profile
   - Click "Start Scan"
   - View results in real-time

## Architecture

```
┌─────────────┬─────────────┬─────────────┐
│  Frontend   │   Backend   │   Scanner   │
│   (React)   │  (FastAPI)  │  (OpenSCAP) │
└──────┬──────┴──────┬──────┴──────┬──────┘
       │             │             │
   ┌───▼───┬────────▼────────┬────▼────┐
   │ NGINX │   PostgreSQL    │  Redis  │
   └───────┴─────────────────┴─────────┘
```

**Components:**
- **Frontend**: React with Material Design 3
- **Backend**: FastAPI with OpenSCAP integration
- **Database**: PostgreSQL for compliance data
- **Task Queue**: Celery with Redis
- **Web Server**: NGINX with TLS

## Features

- **Multi-host scanning**: Scan 100+ hosts in parallel
- **STIG/CIS profiles**: Pre-configured security baselines
- **Real-time results**: Live scan progress and results
- **SSH authentication**: Password and key-based auth
- **Container deployment**: Docker/Podman ready
- **REST API**: Full automation support

## Configuration

### Environment Variables

Create `backend/.env` with required settings:

```bash
# Generate secure keys
SECRET_KEY=$(openssl rand -hex 32)
MASTER_KEY=$(openssl rand -hex 32)

# Database connection
DATABASE_URL=postgresql://openwatch:password@db:5432/openwatch

# Optional settings
OPENWATCH_DEBUG=false
OPENWATCH_REQUIRE_HTTPS=true
```

See [`backend/.env.example`](backend/.env.example) for complete configuration options.

### Container Runtime

**Docker:**
```bash
./start-openwatch.sh --runtime docker
./stop-openwatch.sh                # Safe stop (preserves data)
```

**Podman (rootless):**
```bash
./start-openwatch.sh --runtime podman
./stop-openwatch.sh                # Safe stop (preserves data)
```

**⚠️ IMPORTANT:** By default, `./stop-openwatch.sh` preserves all data. Use `OPENWATCH_CLEAN_STOP=true ./stop-openwatch.sh` only when you want to delete all data.

## Troubleshooting

### Services won't start
```bash
# Check container logs
docker logs openwatch-backend
docker logs openwatch-frontend

# Restart services (preserves data)
./stop-openwatch.sh
./start-openwatch.sh --runtime docker --build
```

### Data disappeared after restart
```bash
# This is caused by running old versions of stop-openwatch.sh
# Update to latest version (safe by default):
git pull origin main

# Data is lost and must be re-entered
# Future restarts will preserve data
```

### Database connection errors
```bash
# Verify database is running
docker-compose ps

# Check database logs
docker-compose logs db
```

### Scan failures
- Verify SSH credentials are correct
- Ensure target host is reachable
- Check target host has `oscap` installed (for remote scans)
- Review scan logs in Scanning → Scan History

See [docs/FIRST_RUN_SETUP.md](docs/FIRST_RUN_SETUP.md) for detailed troubleshooting.

## Development

### Backend Development
```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Set environment variables
export SECRET_KEY="your-secret-key"
export MASTER_KEY="your-master-key"

# Start backend
uvicorn app.main:app --reload --port 8000
```

### Frontend Development
```bash
cd frontend
npm install
npm run dev  # Runs on port 3001
```

### Running Tests
```bash
# Backend tests
cd backend
pip install pytest pytest-asyncio pytest-cov
pytest tests/ -v

# Frontend tests
cd frontend
npm test
```

**Important:** Always run tests before committing. See [docs/STOP_BREAKING_THINGS.md](docs/STOP_BREAKING_THINGS.md) for testing strategy.

## Security

- **Encryption**: AES-256-GCM for credentials, TLS for transport
- **Authentication**: JWT with RS256 signing
- **FIPS compliance**: FIPS 140-2 Level 1 cryptography
- **Audit logging**: All security events logged

**Report vulnerabilities**: security@hanalyx.com

## License

Apache License 2.0 - see [LICENSE](LICENSE)

## Acknowledgments

Built with:
- [OpenSCAP](https://www.open-scap.org/) - SCAP scanning engine
- [FastAPI](https://fastapi.tiangolo.com/) - Python web framework
- [React](https://reactjs.org/) - Frontend framework
- [Material-UI](https://mui.com/) - UI components
- [Podman](https://podman.io/) - Container runtime
