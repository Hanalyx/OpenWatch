# OpenWatch Development Workflow

## Quick Development Cycle

For fast development iteration with immediate change reflection:

```bash
# Stop everything cleanly (removes containers, volumes, orphans)
./stop-openwatch.sh

# Start fresh environment  
./start-openwatch.sh

# For frontend development with backend in containers
cd frontend && npm run dev  # Runs on port 3001
```

## Stop Script Options

### Default Behavior (Recommended for Development)
```bash
./stop-openwatch.sh
```
- **Development-optimized**: Removes containers, volumes, and orphans
- **Clean state**: Next startup reflects all code changes immediately
- **Fast iteration**: No stale data or cached configurations

### Other Options
```bash
./stop-openwatch.sh --simple     # Quick stop, preserve volumes (faster but may cache issues)
./stop-openwatch.sh --deep-clean # Nuclear option: remove EVERYTHING
./stop-openwatch.sh --help       # Show all options
```

### Environment Control
```bash
OPENWATCH_CLEAN_STOP=false ./stop-openwatch.sh  # Disable clean mode once
export OPENWATCH_CLEAN_STOP=false               # Disable clean mode permanently
```

## Runtime Detection

The script automatically detects and uses the correct container runtime:

- **Smart Detection**: Identifies if Docker or Podman containers are running
- **Multi-Runtime Support**: Cleans up both Docker and Podman resources
- **Compose Integration**: Uses appropriate compose files (docker-compose.yml or podman-compose.yml)

## Development Benefits

### ✅ **Clean State Between Runs**
- No stale database data affecting tests
- No cached configurations masking issues
- Code changes reflect immediately on restart

### ✅ **Fast Error Detection**
- Import errors surface immediately
- Dependency issues caught early
- Configuration problems visible on startup

### ✅ **Consistent Environment**
- Every startup is "production-like"
- No accumulated development artifacts
- Predictable container behavior

## Workflow Examples

### Frontend Development
```bash
./stop-openwatch.sh              # Clean stop
./start-openwatch.sh             # Start backend services
cd frontend && npm run dev       # Start frontend dev server
# Edit frontend code - hot reload active
# Edit backend code - restart needed:
./stop-openwatch.sh && ./start-openwatch.sh
```

### Backend Development
```bash
./stop-openwatch.sh              # Clean stop
./start-openwatch.sh             # Start all services
# Edit backend code
./stop-openwatch.sh && ./start-openwatch.sh  # See changes
```

### Full Stack Development
```bash
./stop-openwatch.sh              # Clean stop
./start-openwatch.sh             # Start all services
# Make changes to backend, frontend, or config
./stop-openwatch.sh && ./start-openwatch.sh  # Fresh environment
```

## Troubleshooting

### Containers Won't Stop
```bash
./stop-openwatch.sh --deep-clean  # Force cleanup everything
```

### Stale Data Issues
```bash
./stop-openwatch.sh               # Default clean stop removes volumes
./start-openwatch.sh              # Fresh database state
```

### Mixed Runtime Issues
```bash
./stop-openwatch.sh --deep-clean  # Cleans both Docker and Podman
```

### Permission Issues
```bash
docker system prune -f           # If Docker cleanup needed
podman system prune -f           # If Podman cleanup needed
```

## Next Steps

After running `./stop-openwatch.sh`, you'll see:

```
Next steps:
  ./start-openwatch.sh    # Start fresh OpenWatch stack
  docker system df        # Check disk space usage
```

The clean development workflow ensures:
- **Immediate feedback** on code changes
- **Consistent behavior** across development environments  
- **Early detection** of configuration and dependency issues
- **Production-like testing** with fresh state every time