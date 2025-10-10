# Podman Testing and Resource Analysis Plan

## Executive Summary

This document outlines a comprehensive plan to:
1. Test OpenWatch deployment with Podman and podman-compose
2. Analyze resource usage differences between Podman and Docker
3. Update the OpenWatch command utility (owadm) for full container runtime support
4. Fix naming conventions and ensure production-ready Podman deployment

## Current State Assessment

### Existing Infrastructure
- **Dual Runtime Support**: Both Docker and Podman configurations exist
- **Auto-detection Scripts**: `start-podman.sh` and `stop-podman.sh` support both runtimes
- **Naming Issue**: Script references non-existent `podman-compose-fixed.yml` (should use `podman-compose.yml` or `podman-compose.dev.yml`)
- **Missing Components**: 
  - `owadm` CLI tool planned but not implemented
  - MongoDB missing from Podman configurations

### Correct Compose File Structure
```
Production:
- docker-compose.yml      # Production Docker configuration
- podman-compose.yml      # Production Podman configuration

Development:
- docker-compose.dev.yml  # Development Docker configuration  
- podman-compose.dev.yml  # Development Podman configuration

Overrides:
- docker-compose.override.yml  # Local overrides for Docker
```

## Phase 1: Fix Configuration and Initial Testing (Week 1)

### 1.1 Fix Naming Convention
```bash
# Update start-podman.sh to use correct file names
Tasks:
- [ ] Change line 46: COMPOSE_FILE="podman-compose.yml"  # for production
- [ ] Add environment detection for dev vs production
- [ ] Support --dev flag to use podman-compose.dev.yml
- [ ] Update fallback logic to be cleaner
```

### 1.2 Environment-Based Compose File Selection
```bash
# Proposed logic for start-podman.sh
if [ "$1" = "--dev" ] || [ "$OPENWATCH_ENV" = "development" ]; then
    if [ "$RUNTIME" = "podman-compose" ]; then
        COMPOSE_FILE="podman-compose.dev.yml"
    else
        COMPOSE_FILE="docker-compose.dev.yml"
    fi
else
    if [ "$RUNTIME" = "podman-compose" ]; then
        COMPOSE_FILE="podman-compose.yml"
    else
        COMPOSE_FILE="docker-compose.yml"
    fi
fi
```

### 1.3 Basic Functionality Testing
```yaml
Test Cases:
  Production Mode:
    - [ ] ./start-podman.sh (uses podman-compose.yml)
    - [ ] Verify FIPS mode enabled
    - [ ] Check ports 8080/8443
    - [ ] Validate rootless operation
    
  Development Mode:
    - [ ] ./start-podman.sh --dev (uses podman-compose.dev.yml)
    - [ ] Verify development settings
    - [ ] Check debug mode enabled
    - [ ] Validate hot reload working
    
  Service Connectivity:
    - [ ] Frontend accessible on configured ports
    - [ ] Backend API health checks
    - [ ] Database connectivity
    - [ ] Redis cache operations
```

## Phase 2: Resource Usage Analysis (Week 2)

### 2.1 Monitoring Setup
```yaml
Metrics Collection Tools:
  Podman Native:
    - podman stats --format json
    - podman system df
    - podman pod stats (if using pods)
    
  Docker Native:
    - docker stats --format json
    - docker system df
    - docker container stats
    
  System Level:
    - /proc/meminfo monitoring
    - cgroup statistics
    - systemd-cgtop (for systemd systems)
```

### 2.2 Resource Comparison Test Matrix
```yaml
Test Scenarios:
  1. Startup Resources:
     - Time to ready state
     - Initial memory allocation
     - CPU usage during startup
     
  2. Idle State (5 min after startup):
     - Memory usage per container
     - CPU usage baseline
     - Network connections
     
  3. Single User Operations:
     - Login and browse
     - Run a SCAP scan
     - Generate reports
     
  4. Concurrent Load (10/50/100 users):
     - Resource scaling behavior
     - Memory growth patterns
     - CPU utilization curves
```

### 2.3 Key Metrics to Compare
```markdown
| Metric | Docker | Podman | Notes |
|--------|--------|--------|-------|
| Startup Time | | | Time until health checks pass |
| Base Memory (Idle) | | | After 5 min idle |
| Memory per User | | | Additional memory per concurrent user |
| CPU Usage (Idle) | | | Percentage of allocated CPU |
| CPU per Request | | | CPU time per API request |
| Storage Overhead | | | Container layer sizes |
| Network Latency | | | API response times |
```

## Phase 3: OpenWatch Admin CLI (owadm) Implementation (Week 3)

### 3.1 Core Architecture
```go
// cmd/owadm/pkg/runtime/interface.go
package runtime

type Runtime interface {
    Name() string
    IsAvailable() bool
    ComposeCommand() []string
    Start(composeFile string, opts StartOptions) error
    Stop(opts StopOptions) error
    Status() ([]Container, error)
    Logs(container string, opts LogOptions) (io.ReadCloser, error)
}

// Implementations
type PodmanRuntime struct {
    usePodmanCompose bool  // vs podman-compose
}

type DockerRuntime struct {
    useComposePlugin bool  // vs docker-compose
}
```

### 3.2 Command Structure
```bash
# Basic Commands
owadm start [--dev] [--runtime=auto|docker|podman]
owadm stop [--clean] [--timeout=30]
owadm status [--format=table|json|yaml]
owadm logs <service> [--follow] [--tail=100]

# Advanced Commands
owadm exec <service> <command>
owadm config validate
owadm config generate
owadm backup [--include-uploads]
owadm restore <backup-file>

# Development Commands
owadm dev reload <service>
owadm dev shell <service>
```

### 3.3 Runtime Auto-Detection Logic
```go
func DetectRuntime() Runtime {
    // Priority order:
    // 1. Environment variable OPENWATCH_RUNTIME
    // 2. Podman (if available)
    // 3. Docker (fallback)
    
    if override := os.Getenv("OPENWATCH_RUNTIME"); override != "" {
        return GetRuntime(override)
    }
    
    if runtime.CommandExists("podman") {
        if runtime.CommandExists("podman-compose") {
            return &PodmanRuntime{usePodmanCompose: true}
        }
        // Check for podman compose plugin
        if runtime.CheckPodmanPlugin() {
            return &PodmanRuntime{usePodmanCompose: false}
        }
    }
    
    if runtime.CommandExists("docker") {
        return &DockerRuntime{
            useComposePlugin: runtime.CheckDockerPlugin(),
        }
    }
    
    return nil
}
```

## Phase 4: Podman-Specific Optimizations (Week 4)

### 4.1 Security Enhancements
```yaml
Podman Security Features:
  - [ ] Validate rootless operation
  - [ ] Configure user namespaces properly
  - [ ] Set up proper SELinux contexts
  - [ ] Enable seccomp profiles
  - [ ] Configure AppArmor (if available)
```

### 4.2 Performance Optimizations
```yaml
Optimization Areas:
  Storage:
    - [ ] Use native overlay storage driver
    - [ ] Configure proper volume mount options
    - [ ] Optimize image layer sharing
    
  Networking:
    - [ ] Use slirp4netns for rootless
    - [ ] Configure CNI plugins properly
    - [ ] Optimize DNS resolution
    
  Resource Limits:
    - [ ] Set appropriate CPU limits
    - [ ] Configure memory limits with swap
    - [ ] Set up proper cgroup controllers
```

### 4.3 Systemd Integration
```ini
# /etc/systemd/system/openwatch-podman.service
[Unit]
Description=OpenWatch Podman Application
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/openwatch
ExecStart=/usr/local/bin/owadm start --runtime=podman
ExecStop=/usr/local/bin/owadm stop --timeout=30
Restart=always
RestartSec=10
User=openwatch
Group=openwatch

[Install]
WantedBy=multi-user.target
```

## Phase 5: Production Deployment Guide

### 5.1 Pre-Production Checklist
```yaml
Infrastructure:
  - [ ] Dedicated user for rootless containers
  - [ ] Sufficient storage for container images
  - [ ] Network configuration validated
  - [ ] Firewall rules configured
  - [ ] SELinux policies in place

Application:
  - [ ] Environment variables configured
  - [ ] TLS certificates installed
  - [ ] Database migrations completed
  - [ ] Initial admin user created

Monitoring:
  - [ ] Logging configured
  - [ ] Metrics collection enabled
  - [ ] Alerts configured
  - [ ] Backup automation tested
```

### 5.2 Deployment Steps
```bash
# 1. Install Prerequisites
sudo dnf install -y podman podman-compose

# 2. Create dedicated user
sudo useradd -r -s /bin/bash openwatch
sudo loginctl enable-linger openwatch

# 3. Deploy application
sudo -u openwatch git clone https://github.com/Hanalyx/OpenWatch.git
cd OpenWatch
sudo -u openwatch ./start-podman.sh

# 4. Verify deployment
owadm status
curl -k https://localhost:8443/api/health

# 5. Enable systemd service
sudo systemctl enable --now openwatch-podman.service
```

## Testing Automation

### Automated Test Suite
```yaml
tests/podman/:
  - startup_test.sh      # Verify all services start
  - connectivity_test.sh # Check service connectivity
  - security_test.sh     # Validate security settings
  - performance_test.sh  # Run performance benchmarks
  - cleanup_test.sh      # Verify clean shutdown

tests/comparison/:
  - docker_vs_podman.sh  # Automated comparison tests
  - resource_monitor.sh  # Continuous resource monitoring
  - report_generator.py  # Generate comparison reports
```

### CI/CD Integration
```yaml
# .github/workflows/podman-test.yml
name: Podman Testing

on:
  push:
    paths:
      - 'podman-compose*.yml'
      - 'start-podman.sh'
      - 'cmd/owadm/**'

jobs:
  test-podman:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install Podman
        run: |
          sudo apt-get update
          sudo apt-get install -y podman podman-compose
          
      - name: Run Podman Tests
        run: |
          ./tests/podman/startup_test.sh
          ./tests/podman/connectivity_test.sh
          
      - name: Generate Report
        run: |
          ./tests/comparison/resource_monitor.sh
          python tests/comparison/report_generator.py
```

## Success Metrics

### Performance Targets
- Startup time: < 60 seconds to all services healthy
- Memory usage: < 10% overhead vs Docker
- CPU efficiency: Within 5% of Docker performance
- Network latency: < 5ms additional overhead

### Feature Parity
- ✅ All services functional
- ✅ Data persistence working
- ✅ Security features enabled
- ✅ Monitoring operational
- ✅ Backup/restore functional

## Risk Mitigation

### Known Issues and Solutions

1. **Rootless Networking Limitations**
   - Issue: Cannot bind to ports < 1024
   - Solution: Use high ports (8080/8443) or port forwarding

2. **Storage Driver Compatibility**
   - Issue: Different behavior between overlay/overlay2
   - Solution: Explicitly specify storage driver

3. **Systemd Cgroup Version**
   - Issue: cgroup v1 vs v2 compatibility
   - Solution: Detect and configure appropriately

4. **User Namespace Mapping**
   - Issue: UID/GID mapping for volumes
   - Solution: Use podman unshare or proper ownership

## Documentation Updates Required

1. **README.md**
   - Add Podman installation instructions
   - Update ports for Podman deployment
   - Add troubleshooting section

2. **docs/deployment/**
   - Create podman-deployment.md
   - Update security-hardening.md
   - Add resource-requirements.md

3. **cmd/owadm/README.md**
   - Full command reference
   - Runtime-specific features
   - Troubleshooting guide

## Timeline Summary

- **Week 1**: Fix configurations, basic testing
- **Week 2**: Resource analysis, performance comparison  
- **Week 3**: owadm implementation
- **Week 4**: Production optimizations, documentation

## Next Steps

1. Fix `start-podman.sh` to use correct compose file names
2. Set up Podman test environment
3. Begin automated testing implementation
4. Start owadm development in cmd/owadm/