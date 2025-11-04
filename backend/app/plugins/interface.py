"""
OpenWatch Plugin Interface Specification
Defines the core plugin architecture for extensible SCAP scanning functionality
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, AsyncGenerator, Dict, List, Optional

logger = logging.getLogger(__name__)


class PluginType(Enum):
    """Plugin types supported by OpenWatch"""

    SCANNER = "scanner"  # Custom scanning engines
    REPORTER = "reporter"  # Custom report generation
    REMEDIATION = "remediation"  # Automated remediation providers
    INTEGRATION = "integration"  # External system integrations
    CONTENT = "content"  # SCAP content providers
    AUTH = "auth"  # Authentication providers
    NOTIFICATION = "notification"  # Notification services


@dataclass
class PluginMetadata:
    """Plugin metadata information"""

    name: str
    version: str
    description: str
    author: str
    plugin_type: PluginType
    supported_api_version: str = "1.0.0"
    dependencies: List[str] = None
    config_schema: Dict = None

    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []
        if self.config_schema is None:
            self.config_schema = {}


@dataclass
class ScanContext:
    """Context information for scan operations"""

    scan_id: str
    profile_id: str
    content_path: str
    target_host: str
    scan_type: str  # 'local' or 'remote'
    rule_id: Optional[str] = None
    user_id: Optional[str] = None
    scan_parameters: Dict = None

    def __post_init__(self):
        if self.scan_parameters is None:
            self.scan_parameters = {}


@dataclass
class ScanResult:
    """Standardized scan result format"""

    scan_id: str
    hostname: str
    status: str  # 'completed', 'failed', 'error'
    timestamp: str
    rules_total: int = 0
    rules_passed: int = 0
    rules_failed: int = 0
    rules_error: int = 0
    score: float = 0.0
    failed_rules: List[Dict] = None
    rule_details: List[Dict] = None
    metadata: Dict = None

    def __post_init__(self):
        if self.failed_rules is None:
            self.failed_rules = []
        if self.rule_details is None:
            self.rule_details = []
        if self.metadata is None:
            self.metadata = {}


class PluginInterface(ABC):
    """Base interface for all OpenWatch plugins"""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.metadata: Optional[PluginMetadata] = None
        self.enabled = True
        self.logger = logging.getLogger(f"plugin.{self.__class__.__name__}")

    @abstractmethod
    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata"""
        pass

    @abstractmethod
    async def initialize(self) -> bool:
        """Initialize the plugin. Return True if successful."""
        pass

    @abstractmethod
    async def cleanup(self) -> bool:
        """Cleanup plugin resources. Return True if successful."""
        pass

    def health_check(self) -> Dict:
        """Perform plugin health check"""
        return {
            "status": "healthy" if self.enabled else "disabled",
            "plugin": self.get_metadata().name,
            "version": self.get_metadata().version,
        }

    def is_enabled(self) -> bool:
        """Check if plugin is enabled"""
        return self.enabled

    def set_enabled(self, enabled: bool):
        """Enable or disable the plugin"""
        self.enabled = enabled


class ScannerPlugin(PluginInterface):
    """Interface for custom scanning engine plugins"""

    @abstractmethod
    async def can_scan_host(self, host_config: Dict) -> bool:
        """Check if this plugin can scan the specified host"""
        pass

    @abstractmethod
    async def execute_scan(self, context: ScanContext) -> ScanResult:
        """Execute a scan using this plugin"""
        pass

    @abstractmethod
    async def validate_content(self, content_path: str) -> bool:
        """Validate SCAP content compatibility with this scanner"""
        pass

    def get_supported_profiles(self, content_path: str) -> List[Dict]:
        """Get profiles supported by this scanner"""
        return []


class ReporterPlugin(PluginInterface):
    """Interface for custom report generation plugins"""

    @abstractmethod
    async def generate_report(
        self, scan_results: List[ScanResult], format_type: str = "html"
    ) -> bytes:
        """Generate a report from scan results"""
        pass

    @abstractmethod
    def get_supported_formats(self) -> List[str]:
        """Get list of supported report formats"""
        pass

    def get_report_template(self, format_type: str) -> Optional[str]:
        """Get report template for the specified format"""
        return None


class RemediationPlugin(PluginInterface):
    """Interface for automated remediation plugins"""

    @abstractmethod
    async def can_remediate_rule(self, rule_id: str, host_config: Dict) -> bool:
        """Check if this plugin can remediate the specified rule"""
        pass

    @abstractmethod
    async def execute_remediation(
        self, rule_id: str, host_config: Dict, scan_result: ScanResult
    ) -> Dict:
        """Execute remediation for a failed rule"""
        pass

    @abstractmethod
    async def get_remediation_plan(self, failed_rules: List[str], host_config: Dict) -> Dict:
        """Get remediation plan for multiple failed rules"""
        pass

    def validate_remediation(self, rule_id: str, host_config: Dict) -> Dict:
        """Validate that remediation was successful"""
        return {"status": "unknown", "validated": False}


class IntegrationPlugin(PluginInterface):
    """Interface for external system integration plugins"""

    @abstractmethod
    async def export_results(
        self, scan_results: List[ScanResult], destination_config: Dict
    ) -> bool:
        """Export scan results to external system"""
        pass

    @abstractmethod
    async def import_content(self, source_config: Dict) -> Optional[str]:
        """Import SCAP content from external source"""
        pass

    def sync_hosts(self, source_config: Dict) -> List[Dict]:
        """Synchronize host inventory from external system"""
        return []


class ContentPlugin(PluginInterface):
    """Interface for SCAP content provider plugins"""

    @abstractmethod
    async def fetch_content(self, content_id: str, version: str = "latest") -> str:
        """Fetch SCAP content by identifier"""
        pass

    @abstractmethod
    async def list_available_content(self) -> List[Dict]:
        """List available SCAP content from this provider"""
        pass

    @abstractmethod
    async def validate_content_integrity(self, content_path: str) -> bool:
        """Validate content integrity and authenticity"""
        pass

    def get_content_metadata(self, content_id: str) -> Dict:
        """Get metadata for specific content"""
        return {}


class AuthenticationPlugin(PluginInterface):
    """Interface for authentication provider plugins"""

    @abstractmethod
    async def authenticate_user(self, credentials: Dict) -> Optional[Dict]:
        """Authenticate user and return user info if successful"""
        pass

    @abstractmethod
    async def authorize_action(self, user_info: Dict, action: str, resource: str) -> bool:
        """Check if user is authorized for specific action on resource"""
        pass

    def get_user_groups(self, user_info: Dict) -> List[str]:
        """Get list of groups for authenticated user"""
        return []


class NotificationPlugin(PluginInterface):
    """Interface for notification service plugins"""

    @abstractmethod
    async def send_notification(
        self, message: str, recipients: List[str], notification_type: str = "info"
    ) -> bool:
        """Send notification message"""
        pass

    @abstractmethod
    def get_supported_types(self) -> List[str]:
        """Get supported notification types"""
        pass

    def validate_recipients(self, recipients: List[str]) -> List[str]:
        """Validate and return valid recipients"""
        return recipients


# Plugin Hook Definitions
class PluginHooks:
    """Defines available plugin hooks in the OpenWatch system"""

    # Scan lifecycle hooks
    BEFORE_SCAN = "before_scan"
    AFTER_SCAN = "after_scan"
    SCAN_FAILED = "scan_failed"

    # Report generation hooks
    BEFORE_REPORT = "before_report"
    AFTER_REPORT = "after_report"

    # Host management hooks
    HOST_ADDED = "host_added"
    HOST_REMOVED = "host_removed"
    HOST_UPDATED = "host_updated"

    # System hooks
    SYSTEM_STARTUP = "system_startup"
    SYSTEM_SHUTDOWN = "system_shutdown"

    # Security hooks
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    UNAUTHORIZED_ACCESS = "unauthorized_access"


@dataclass
class PluginHookContext:
    """Context passed to plugin hooks"""

    hook_name: str
    timestamp: str
    data: Dict
    user_id: Optional[str] = None
    session_id: Optional[str] = None

    def __post_init__(self):
        if self.data is None:
            self.data = {}


class HookablePlugin(PluginInterface):
    """Base class for plugins that can register hooks"""

    def __init__(self, config: Dict = None):
        super().__init__(config)
        self.registered_hooks: List[str] = []

    @abstractmethod
    async def handle_hook(self, context: PluginHookContext) -> Optional[Dict]:
        """Handle a plugin hook"""
        pass

    def register_hook(self, hook_name: str):
        """Register interest in a specific hook"""
        if hook_name not in self.registered_hooks:
            self.registered_hooks.append(hook_name)

    def get_registered_hooks(self) -> List[str]:
        """Get list of registered hooks"""
        return self.registered_hooks.copy()


# Utility functions for plugin development
def create_plugin_metadata(
    name: str,
    version: str,
    description: str,
    author: str,
    plugin_type: PluginType,
    **kwargs,
) -> PluginMetadata:
    """Utility function to create plugin metadata"""
    return PluginMetadata(
        name=name,
        version=version,
        description=description,
        author=author,
        plugin_type=plugin_type,
        **kwargs,
    )


def create_scan_context(
    scan_id: str,
    profile_id: str,
    content_path: str,
    target_host: str,
    scan_type: str,
    **kwargs,
) -> ScanContext:
    """Utility function to create scan context"""
    return ScanContext(
        scan_id=scan_id,
        profile_id=profile_id,
        content_path=content_path,
        target_host=target_host,
        scan_type=scan_type,
        **kwargs,
    )


def create_scan_result(
    scan_id: str, hostname: str, status: str, timestamp: str, **kwargs
) -> ScanResult:
    """Utility function to create scan result"""
    return ScanResult(
        scan_id=scan_id, hostname=hostname, status=status, timestamp=timestamp, **kwargs
    )
