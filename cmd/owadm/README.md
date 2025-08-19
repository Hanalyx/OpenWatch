# OpenWatch Admin (owadm)

**owadm** is a fast, intuitive command-line utility for managing OpenWatch containers. It replaces multiple scattered shell scripts with a single, professional CLI tool that supports both Docker and Podman runtimes with automatic detection.

## 🚀 Quick Start

```bash
# Install owadm
make install

# Start OpenWatch
owadm start

# Check status
owadm status

# View logs
owadm logs backend --follow

# Stop services
owadm stop
```

## 📦 Installation

### From Source
```bash
# Clone and build
git clone https://github.com/hanalyx/openwatch
cd openwatch
make install
```

### Quick Install Script (Coming Soon)
```bash
curl -sSL https://get.openwatch.io/owadm | bash
```

### Manual Download (Coming Soon)
```bash
# Download binary for your platform
wget https://releases.openwatch.io/owadm-linux-amd64
chmod +x owadm-linux-amd64
sudo mv owadm-linux-amd64 /usr/local/bin/owadm
```

## 🎯 Commands

### Container Management
```bash
owadm start                    # Start OpenWatch containers
owadm start --runtime podman   # Start with specific runtime
owadm start --env dev          # Start development environment
owadm start --build            # Rebuild images before starting

owadm stop                     # Stop containers
owadm stop --force             # Force stop containers
owadm stop --remove-volumes    # Stop and remove volumes

owadm status                   # Show container status
owadm restart                  # Restart containers (stop + start)
```

### Service Operations
```bash
owadm logs backend             # View backend logs
owadm logs frontend --follow   # Follow frontend logs in real-time
owadm logs database --tail 100 # Show last 100 lines

owadm exec backend bash        # Open shell in backend container
owadm exec database psql -U openwatch # Connect to database
```

### System Information
```bash
owadm version                  # Show version information
owadm help                     # Show help
owadm help start              # Show help for specific command
```

## ⚙️ Configuration

### Global Flags
```bash
--runtime docker|podman       # Specify container runtime (auto-detected)
--env dev|prod                # Environment mode (default: prod)
--verbose                     # Enable verbose output
--no-color                   # Disable colored output
```

### Environment Variables
```bash
OWADM_RUNTIME=podman          # Default runtime
OWADM_ENVIRONMENT=dev         # Default environment
OWADM_VERBOSE=true           # Enable verbose mode
```

### Configuration File
Create `.owadm.yaml` in your project directory:
```yaml
runtime: podman
environment: dev
verbose: false
```

## 🔧 Development

### Building
```bash
make build                    # Build for current platform
make build-all               # Build for all platforms
make build-dev               # Build with race detection
```

### Testing
```bash
make test                    # Run tests
make test-coverage           # Run tests with coverage
make lint                    # Lint code
```

### Development Workflow
```bash
make dev                     # Format, lint, test, and build
```

## 📋 Features

### Runtime Support
- **Docker**: Supports both `docker-compose` and `docker compose` plugin
- **Podman**: Full rootless container support with `podman-compose`
- **Auto-detection**: Automatically detects available runtime
- **Fallback**: Gracefully handles missing runtimes

### Environment Management
- **Development**: Optimized for local development
- **Production**: Production-ready configurations
- **Auto-setup**: Creates required directories and keys
- **Environment Files**: Automatic `.env` generation with secure defaults

### User Experience
- **Fast**: Written in Go for instant startup
- **Intuitive**: Consistent command structure
- **Colored Output**: Beautiful, readable output
- **Progress Indicators**: Visual feedback for long operations
- **Error Handling**: Clear error messages with suggestions

### Security
- **Secure Defaults**: Automatic JWT key generation
- **Permission Management**: Proper file permissions
- **Environment Isolation**: Separate dev/prod configurations

## 🏗️ Architecture

### Runtime Abstraction
owadm uses a pluggable runtime system that abstracts Docker and Podman operations:

```go
type Runtime interface {
    Start(ctx context.Context, options StartOptions) error
    Stop(ctx context.Context, options StopOptions) error
    Status(ctx context.Context) (*StatusInfo, error)
    Logs(ctx context.Context, service string, options LogOptions) error
    Exec(ctx context.Context, service string, command []string) error
}
```

### Command Structure
Built with Cobra for professional CLI experience:
- Automatic help generation
- Command aliases
- Flag inheritance
- Shell completion support

## 🚦 Migration from Scripts

owadm replaces these OpenWatch scripts:

| Old Script | New Command |
|------------|-------------|
| `start-podman.sh` | `owadm start` |
| `podman-start.sh` | `owadm start --runtime podman` |
| `stop-podman.sh` | `owadm stop` |
| `install.sh` | `owadm start` (with auto-setup) |
| `scripts/setup.sh` | `owadm start` (with auto-setup) |
| `scripts/check-environment.sh` | `owadm status --verbose` |

### Migration Benefits
- **Single Binary**: No dependency management
- **Consistent Interface**: Same command structure across all operations
- **Better Error Handling**: Clear messages and recovery suggestions
- **Cross-Platform**: Works on Linux, macOS, and Windows

## 🆘 Troubleshooting

### Common Issues

**"No container runtime found"**
```bash
# Install Docker or Podman
sudo apt install docker.io docker-compose  # Ubuntu
# or
sudo apt install podman podman-compose     # Ubuntu

# Verify installation
owadm status --verbose
```

**"Permission denied"**
```bash
# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Or use rootless Podman
owadm start --runtime podman
```

**"Port already in use"**
```bash
# Check what's using the ports
owadm status
sudo netstat -tlnp | grep :3001

# Stop conflicting services
owadm stop
```

### Debug Mode
```bash
# Enable verbose output for troubleshooting
owadm start --verbose
owadm status --verbose
```

## 🤝 Contributing

### Development Setup
```bash
git clone https://github.com/hanalyx/openwatch
cd openwatch
make dev        # Set up development environment
```

### Testing
```bash
make test              # Run unit tests
make test-coverage     # Generate coverage report
```

## 📄 License

OpenWatch Admin (owadm) is part of the OpenWatch project.

---

**Made with ❤️ by the Hanalyx team**