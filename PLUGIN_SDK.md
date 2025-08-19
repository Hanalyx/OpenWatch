# OpenWatch Plugin SDK Documentation

## Overview

OpenWatch provides a comprehensive plugin architecture that allows developers to extend the core SCAP scanning functionality with custom implementations. This SDK documentation covers everything needed to develop, deploy, and maintain OpenWatch plugins.

## Plugin Architecture

### Plugin Types

OpenWatch supports several types of plugins:

1. **Scanner Plugins** - Custom scanning engines
2. **Reporter Plugins** - Custom report generation 
3. **Remediation Plugins** - Automated remediation providers
4. **Integration Plugins** - External system integrations
5. **Content Plugins** - SCAP content providers
6. **Authentication Plugins** - Custom authentication providers
7. **Notification Plugins** - Custom notification services

### Plugin Interface

All plugins must implement the base `PluginInterface` class and provide:

- **Metadata** - Plugin information and capabilities
- **Lifecycle Management** - Initialize and cleanup methods
- **Health Checks** - Status monitoring capabilities
- **Configuration Support** - JSON-based configuration

## Getting Started

### Prerequisites

- Python 3.8+
- OpenWatch backend development environment
- Basic understanding of SCAP concepts (for scanner plugins)

### Plugin Directory Structure

```
plugins/
├── my_plugin/
│   ├── plugin.py          # Main plugin implementation
│   ├── config.json        # Plugin configuration
│   ├── requirements.txt   # Plugin dependencies (optional)
│   └── README.md          # Plugin documentation
```

### Basic Plugin Template

```python
from plugins.interface import (
    PluginInterface, PluginMetadata, PluginType,
    create_plugin_metadata
)

class MyPlugin(PluginInterface):
    def __init__(self, config: Dict = None):
        super().__init__(config)
    
    def get_metadata(self) -> PluginMetadata:
        return create_plugin_metadata(
            name="my_plugin",
            version="1.0.0",
            description="My custom plugin",
            author="Your Name",
            plugin_type=PluginType.SCANNER  # or other type
        )
    
    async def initialize(self) -> bool:
        # Plugin initialization logic
        return True
    
    async def cleanup(self) -> bool:
        # Plugin cleanup logic
        return True

# Plugin entry point
plugin_class = MyPlugin
```

## Scanner Plugin Development

Scanner plugins extend SCAP scanning capabilities with custom scanning engines.

### Interface Implementation

```python
from plugins.interface import ScannerPlugin, ScanContext, ScanResult

class CustomScannerPlugin(ScannerPlugin):
    async def can_scan_host(self, host_config: Dict) -> bool:
        """Check if this plugin can scan the specified host"""
        # Implementation here
        return True
    
    async def execute_scan(self, context: ScanContext) -> ScanResult:
        """Execute a scan using this plugin"""
        # Implementation here
        return scan_result
    
    async def validate_content(self, content_path: str) -> bool:
        """Validate SCAP content compatibility"""
        # Implementation here
        return True
```

### Scan Context

The `ScanContext` provides all information needed for scanning:

```python
@dataclass
class ScanContext:
    scan_id: str           # Unique scan identifier
    profile_id: str        # SCAP profile to use
    content_path: str      # Path to SCAP content file
    target_host: str       # Target hostname/IP
    scan_type: str         # 'local' or 'remote'
    rule_id: Optional[str] # Specific rule (optional)
    user_id: Optional[str] # User requesting scan
    scan_parameters: Dict  # Additional parameters
```

### Scan Result

Return standardized scan results:

```python
@dataclass
class ScanResult:
    scan_id: str           # Scan identifier
    hostname: str          # Target hostname
    status: str            # 'completed', 'failed', 'error'
    timestamp: str         # ISO timestamp
    rules_total: int       # Total rules checked
    rules_passed: int      # Rules that passed
    rules_failed: int      # Rules that failed
    rules_error: int       # Rules with errors
    score: float           # Compliance score (0-100)
    failed_rules: List[Dict]    # Failed rule details
    rule_details: List[Dict]    # All rule details
    metadata: Dict         # Plugin-specific data
```

## Reporter Plugin Development

Reporter plugins generate custom reports from scan results.

### Interface Implementation

```python
from plugins.interface import ReporterPlugin

class CustomReporterPlugin(ReporterPlugin):
    async def generate_report(self, scan_results: List[ScanResult], 
                            format_type: str = "html") -> bytes:
        """Generate a report from scan results"""
        # Implementation here
        return report_bytes
    
    def get_supported_formats(self) -> List[str]:
        """Get list of supported report formats"""
        return ["html", "pdf", "json", "csv"]
```

## Plugin Configuration

### Configuration Schema

Define configuration schema in plugin metadata:

```python
def get_metadata(self) -> PluginMetadata:
    return create_plugin_metadata(
        name="my_plugin",
        version="1.0.0",
        description="My plugin",
        author="Your Name",
        plugin_type=PluginType.SCANNER,
        config_schema={
            "timeout": {
                "type": "integer",
                "description": "Scan timeout in seconds",
                "default": 300,
                "minimum": 60,
                "maximum": 3600
            },
            "enabled_features": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of enabled features"
            }
        }
    )
```

### Configuration File

Create a `config.json` file for your plugin:

```json
{
  "timeout": 600,
  "enabled_features": ["feature1", "feature2"],
  "api_endpoint": "https://api.example.com",
  "credentials": {
    "username": "user",
    "password": "pass"
  },
  "enabled": true
}
```

## Plugin Hooks

Plugins can register for system events using hooks:

```python
from plugins.interface import HookablePlugin, PluginHooks, PluginHookContext

class MyHookablePlugin(HookablePlugin):
    def __init__(self, config: Dict = None):
        super().__init__(config)
        # Register for hooks
        self.register_hook(PluginHooks.BEFORE_SCAN)
        self.register_hook(PluginHooks.AFTER_SCAN)
    
    async def handle_hook(self, context: PluginHookContext) -> Optional[Dict]:
        """Handle a plugin hook"""
        if context.hook_name == PluginHooks.BEFORE_SCAN:
            # Pre-scan processing
            return {"processed": True}
        elif context.hook_name == PluginHooks.AFTER_SCAN:
            # Post-scan processing
            return {"notified": True}
        return None
```

### Available Hooks

- `BEFORE_SCAN` - Called before scan execution
- `AFTER_SCAN` - Called after scan completion
- `SCAN_FAILED` - Called when scan fails
- `BEFORE_REPORT` - Called before report generation
- `AFTER_REPORT` - Called after report generation
- `HOST_ADDED` - Called when host is added
- `HOST_REMOVED` - Called when host is removed
- `SYSTEM_STARTUP` - Called on system startup
- `SYSTEM_SHUTDOWN` - Called on system shutdown
- `LOGIN_SUCCESS` - Called on successful login
- `LOGIN_FAILED` - Called on failed login

## Error Handling

### Exception Handling

Always wrap plugin operations in try-catch blocks:

```python
async def execute_scan(self, context: ScanContext) -> ScanResult:
    try:
        # Scan implementation
        result = await self._perform_scan(context)
        return result
    except Exception as e:
        self.logger.error(f"Scan failed: {e}")
        return create_scan_result(
            scan_id=context.scan_id,
            hostname=context.target_host,
            status="error",
            timestamp=datetime.now().isoformat(),
            metadata={"error": str(e)}
        )
```

### Logging

Use the plugin logger for consistent logging:

```python
class MyPlugin(PluginInterface):
    def __init__(self, config: Dict = None):
        super().__init__(config)
        # self.logger is available automatically
    
    async def some_method(self):
        self.logger.info("Plugin operation started")
        self.logger.debug("Debug information")
        self.logger.error("Error occurred")
```

## Testing Plugins

### Unit Testing

```python
import pytest
from my_plugin.plugin import MyPlugin

@pytest.mark.asyncio
async def test_plugin_initialization():
    plugin = MyPlugin()
    assert await plugin.initialize() == True

@pytest.mark.asyncio
async def test_scan_execution():
    plugin = MyPlugin()
    await plugin.initialize()
    
    context = create_scan_context(
        scan_id="test-scan",
        profile_id="test-profile",
        content_path="/path/to/content.xml",
        target_host="localhost",
        scan_type="local"
    )
    
    result = await plugin.execute_scan(context)
    assert result.status in ["completed", "failed", "error"]
```

### Integration Testing

Test plugins with the OpenWatch plugin manager:

```python
from plugins.manager import PluginManager

@pytest.mark.asyncio
async def test_plugin_loading():
    manager = PluginManager()
    success = await manager.load_plugin("plugins/my_plugin/plugin.py", "my_plugin")
    assert success == True
    
    plugin = manager.get_plugin("my_plugin")
    assert plugin is not None
    assert plugin.is_enabled() == True
```

## Deployment

### Plugin Installation

1. Copy plugin directory to `/app/plugins/`
2. Ensure plugin configuration is in `/app/config/plugins/`
3. Restart OpenWatch backend to load the plugin

### Plugin Distribution

Package plugins for distribution:

```bash
# Create plugin package
tar -czf my_plugin-1.0.0.tar.gz my_plugin/

# Include in distribution
- plugin.py (required)
- config.json (optional)
- requirements.txt (optional)
- README.md (recommended)
```

## Best Practices

### Performance

- Use async/await for I/O operations
- Implement proper timeouts
- Cache expensive operations
- Use connection pooling for external services

### Security

- Validate all inputs
- Use secure communication protocols
- Store credentials securely
- Implement proper authentication
- Log security events

### Reliability

- Implement comprehensive error handling
- Provide meaningful error messages
- Support graceful degradation
- Include health checks
- Monitor plugin performance

### Maintainability

- Follow Python coding standards
- Document all public methods
- Use type hints
- Write comprehensive tests
- Version your plugins

## Plugin Examples

### Example Scanner Plugin

See `plugins/example_scanner/plugin.py` for a complete scanner plugin implementation.

### Example Configuration

```json
{
  "enabled": true,
  "scan_timeout": 300,
  "supported_os": ["linux", "rhel", "ubuntu"],
  "max_parallel_scans": 10,
  "retry_attempts": 3,
  "log_level": "INFO"
}
```

## API Reference

### Core Interfaces

- `PluginInterface` - Base plugin interface
- `ScannerPlugin` - Scanner plugin interface
- `ReporterPlugin` - Reporter plugin interface
- `RemediationPlugin` - Remediation plugin interface
- `IntegrationPlugin` - Integration plugin interface
- `ContentPlugin` - Content plugin interface
- `AuthenticationPlugin` - Authentication plugin interface
- `NotificationPlugin` - Notification plugin interface

### Data Classes

- `PluginMetadata` - Plugin metadata
- `ScanContext` - Scan execution context
- `ScanResult` - Scan result data
- `PluginHookContext` - Hook execution context

### Utility Functions

- `create_plugin_metadata()` - Create plugin metadata
- `create_scan_context()` - Create scan context
- `create_scan_result()` - Create scan result

## Support

### Resources

- OpenWatch Documentation: [docs.openwatch.io](https://docs.openwatch.io)
- Plugin API Reference: [api.openwatch.io](https://api.openwatch.io)
- Community Forum: [community.openwatch.io](https://community.openwatch.io)
- Source Code: [github.com/hanalyx/openwatch](https://github.com/hanalyx/openwatch)

### Getting Help

- GitHub Issues: Report bugs and request features
- Community Discussions: Ask questions and share ideas
- Discord: Real-time community support

---

**Happy Plugin Development!**

*The OpenWatch team is committed to supporting the plugin developer community. We welcome contributions and feedback to make the plugin system even better.*