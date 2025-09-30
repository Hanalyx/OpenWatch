# OpenWatch - Open Source SCAP Compliance Scanner

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Container Support](https://img.shields.io/badge/Container-Docker%20%7C%20Podman-green)](https://podman.io/)
[![Kubernetes Ready](https://img.shields.io/badge/Kubernetes-Ready-326ce5)](https://kubernetes.io/)

OpenWatch is a modern, open-source SCAP (Security Content Automation Protocol) compliance scanner designed for enterprise environments. Built with a plugin-first architecture, OpenWatch provides comprehensive security compliance assessment capabilities with support for STIG, CIS, and custom security profiles.

## 🚀 Quick Start

### Prerequisites
- **Container Runtime**: Docker or Podman
- **System**: Linux (RHEL/Ubuntu recommended)
- **Resources**: 4GB RAM, 2CPU cores minimum

### Installation

```bash
# Clone the repository
git clone https://github.com/hanalyx/openwatch.git
cd openwatch

# Quick start (automatic runtime detection)
./start-openwatch.sh

# Or use container compose directly
podman-compose -f podman-compose-fixed.yml up -d  # Rootless Podman (recommended)
# OR
docker-compose up -d  # Standard Docker

# To stop services
./stop-openwatch.sh
```

### First Scan
```bash
# Access the web interface
open https://localhost:3000

# Or use CLI scanning
owadm exec backend python -m app.cli scan --profile stig-rhel8 --target 192.168.1.100
```

## 🏗️ Architecture

OpenWatch follows a modern, cloud-native architecture with plugin extensibility:

```
┌─────────────────┬─────────────────┬─────────────────┐
│   Frontend      │    Backend      │   Extensions    │
│   (React)       │   (FastAPI)     │   (Plugins)     │
├─────────────────┼─────────────────┼─────────────────┤
│ • Scan Results  │ • SCAP Engine   │ • Custom Rules  │
│ • Dashboard     │ • Host Mgmt     │ • Integrations  │
│ • Reports       │ • API Gateway   │ • Remediation   │
└─────────────────┴─────────────────┴─────────────────┘
         │                 │                 │
    ┌────▼────┬───────────▼──────────┬──────▼──────┐
    │ NGINX   │    PostgreSQL        │    Redis    │
    │ (TLS)   │    (Compliance       │  (Tasks)    │
    │         │     Data)            │             │
    └─────────┴──────────────────────┴─────────────┘
```

### Core Components

- **SCAP Scanning Engine**: OpenSCAP integration with parallel processing
- **Web Interface**: Modern React frontend with Material Design 3
- **API Gateway**: FastAPI backend with comprehensive REST API
- **Plugin System**: Extensible architecture for custom functionality
- **Container-First**: Docker/Podman ready with Kubernetes support

## 📋 Features

### ✅ Current Capabilities
- **Multi-Host Scanning**: Parallel SCAP scanning for 100+ hosts
- **STIG/CIS Support**: Built-in security profiles and baselines
- **Web Dashboard**: Interactive compliance reporting and visualization
- **Container Deployment**: Docker/Podman with health monitoring
- **REST API**: Complete API for automation and integration
- **Audit Logging**: Comprehensive security event tracking

### 🚧 Roadmap (Community Contributions Welcome)
- **Plugin Marketplace**: Community-driven extension ecosystem
- **Advanced Analytics**: ML-powered compliance insights
- **Multi-Cloud Support**: AWS/Azure/GCP native integrations
- **Kubernetes Operator**: Native K8s deployment and scaling
- **SIEM Integration**: Splunk, QRadar, Sentinel connectors

## 🛠️ Development

### Development Setup

#### Required Environment Variables
Before starting OpenWatch, you **must** configure these critical environment variables:

```bash
# 1. Copy the example environment file
cp backend/.env.example backend/.env

# 2. Generate secure keys
SECRET_KEY=$(openssl rand -hex 32)
MASTER_KEY=$(openssl rand -hex 32)

# 3. Edit backend/.env with your values
SECRET_KEY=your-generated-secret-key-here
MASTER_KEY=your-generated-master-key-here
DATABASE_URL=postgresql://openwatch:password@localhost:5432/openwatch
```

#### Backend Development
```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Ensure environment variables are set
export SECRET_KEY="your-secret-key"
export MASTER_KEY="your-master-key"

uvicorn app.main:app --reload --port 8000
```

#### Frontend Development  
```bash
cd frontend
npm install
npm run dev  # Runs on port 3001
```

#### Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECRET_KEY` | **Yes** | None | JWT signing key (min 32 chars) |
| `MASTER_KEY` | **Yes** | None | Data encryption key (min 32 chars) |
| `DATABASE_URL` | **Yes** | None | PostgreSQL connection string |
| `SCAP_CONTENT_DIR` | No | `/app/data/scap` | SCAP content files location |
| `SCAN_RESULTS_DIR` | No | `/app/data/results` | Scan results storage location |
| `OPENWATCH_DEBUG` | No | `false` | Enable debug mode |
| `OPENWATCH_REQUIRE_HTTPS` | No | `true` | Enforce HTTPS connections |

For complete environment configuration, see [`backend/.env.example`](backend/.env.example).

### Architecture Documentation
- [Directory Structure](DIRECTORY_ARCHITECTURE.md) - Project organization and rationale
- [Kubernetes Migration](KUBERNETES_READINESS.md) - Container orchestration strategy
- [API Documentation](http://localhost:8000/docs) - Interactive API explorer (when running)

### Infrastructure Documentation
- [SSH Troubleshooting Guide](docs/SSH_TROUBLESHOOTING_GUIDE.md) - Comprehensive SSH connectivity troubleshooting
- [FIPS Compliance Validation](docs/FIPS_COMPLIANCE_VALIDATION.md) - Federal security standards compliance report
- [SSH Infrastructure Completion Report](docs/SSH_INFRASTRUCTURE_COMPLETION_REPORT.md) - Complete infrastructure improvement documentation

### Contributing
We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details on:
- Development workflow and standards
- Plugin development guidelines
- Security review process
- Community communication

## 📊 Performance & Scale

### Benchmarks
- **Scanning Performance**: 100+ hosts in parallel
- **SCAP Processing**: <30s for standard STIG profiles
- **Resource Usage**: <2GB RAM for standard deployments
- **Container Startup**: <30s cold start time

### Enterprise Scale
OpenWatch is designed for enterprise environments:
- **High Availability**: Multi-instance deployment support
- **Horizontal Scaling**: Stateless backend architecture
- **Data Persistence**: PostgreSQL with backup automation
- **Security**: FIPS-compliant cryptography and audit logging

## 🔒 Security

### Security Features
- **FIPS Compliance**: FIPS 140-2 Level 1 cryptographic modules
- **JWT Authentication**: RS256 with key rotation support
- **TLS Encryption**: End-to-end encrypted communications
- **Audit Logging**: Complete security event tracking
- **Rootless Containers**: Enhanced container security posture

### Security Reporting
- **Vulnerability Reports**: Email security@hanalyx.com
- **Security Advisories**: Published via GitHub Security Advisories
- **Response Time**: <48 hours for critical vulnerabilities

## 📄 License

OpenWatch is licensed under the [Apache License 2.0](LICENSE).

## 🤝 Community & Support

### Community Resources
- **Documentation**: [docs.openwatch.io](https://docs.openwatch.io)
- **Discussions**: [GitHub Discussions](https://github.com/hanalyx/openwatch/discussions)
- **Issues**: [GitHub Issues](https://github.com/hanalyx/openwatch/issues)
- **Discord**: [OpenWatch Community](https://discord.gg/openwatch)

### Commercial Support
Enterprise support and services available through [Hanalyx](https://hanalyx.com):
- Professional services and consulting
- Custom plugin development
- Enterprise deployment assistance
- 24/7 technical support options

---

## 🙏 Acknowledgments

OpenWatch is built on excellent open-source foundations:
- [OpenSCAP](https://www.open-scap.org/) - SCAP toolkit and scanner
- [FastAPI](https://fastapi.tiangolo.com/) - Modern Python web framework
- [React](https://reactjs.org/) - User interface library
- [Material-UI](https://mui.com/) - React component library
- [Podman](https://podman.io/) - Rootless container runtime

**Made with ❤️ by the Hanalyx team and OpenWatch community**