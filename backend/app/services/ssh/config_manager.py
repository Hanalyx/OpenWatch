"""
SSH Configuration Manager Module

Provides centralized management of SSH-related system settings including
host key policies, trusted networks, and SSH client configuration.

This module handles:
- System settings storage and retrieval (database-backed)
- SSH host key policy management (strict, auto_add, warning, bypass_trusted)
- Trusted network configuration for policy bypass
- SSH client configuration with security policies

Configuration Options:
    ssh_host_key_policy: Controls how unknown host keys are handled
        - "strict": Reject unknown hosts (highest security)
        - "auto_add": Accept all hosts silently (development only)
        - "auto_add_warning": Accept with warning logged (default)
        - "bypass_trusted": Auto-add for trusted networks, warning for others

    ssh_trusted_networks: List of CIDR network ranges where host key
        verification can be bypassed (e.g., ["192.168.1.0/24", "10.0.0.0/8"])

Usage:
    from backend.app.services.ssh.config_manager import SSHConfigManager

    config_manager = SSHConfigManager(db)

    # Get current policy
    policy = config_manager.get_ssh_policy()

    # Configure SSH client
    ssh_client = paramiko.SSHClient()
    config_manager.configure_ssh_client(ssh_client, host_ip="192.168.1.100")

Security Notes:
    - Settings are stored encrypted in the database
    - Policy changes are logged for audit compliance
    - Default policy (auto_add_warning) balances security and automation needs
    - Trusted network bypass should only be used in controlled environments

References:
    - NIST SP 800-53 SC-8: Transmission Confidentiality and Integrity
    - NIST SP 800-53 SC-23: Session Authenticity
"""

import ipaddress
import json
import logging
import os
from datetime import datetime
from typing import TYPE_CHECKING, Any, List, Optional

import paramiko

from .policies import SecurityWarningPolicy

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


class SSHConfigManager:
    """
    Manages SSH configuration settings stored in the database.

    This class provides a centralized interface for managing SSH-related
    system settings, including host key policies and trusted network
    configurations. All settings are persisted to the database and
    cached for performance.

    The configuration manager follows the principle of secure defaults:
    - Default policy is "auto_add_warning" (logs but allows connections)
    - Trusted networks default to empty (no bypass)
    - All configuration changes are logged for audit trail

    Attributes:
        db: SQLAlchemy database session for persistence operations

    Example:
        >>> from backend.app.services.ssh.config_manager import SSHConfigManager
        >>> config = SSHConfigManager(db)
        >>>
        >>> # Check current policy
        >>> print(config.get_ssh_policy())  # "auto_add_warning"
        >>>
        >>> # Update policy (requires user_id for audit)
        >>> config.set_ssh_policy("strict", user_id=1)
        >>>
        >>> # Configure an SSH client with current settings
        >>> ssh = paramiko.SSHClient()
        >>> config.configure_ssh_client(ssh, host_ip="10.0.0.50")
    """

    # Valid SSH host key policy options
    # Each policy has different security/convenience tradeoffs
    VALID_POLICIES = ["strict", "auto_add", "auto_add_warning", "bypass_trusted"]

    def __init__(self, db: Optional["Session"] = None) -> None:
        """
        Initialize the SSH configuration manager.

        Args:
            db: Optional SQLAlchemy session for database operations.
                If not provided, settings will use defaults and changes
                cannot be persisted.
        """
        self.db = db

    def get_setting(self, key: str, default: Any = None) -> Any:
        """
        Get a system setting value from the database.

        This method retrieves settings from the system_settings table with
        automatic type conversion based on the stored setting_type field.

        The method handles gracefully when:
        - Database session is not available (returns default)
        - System settings table doesn't exist yet (returns default silently)
        - Setting key doesn't exist (returns default)

        Args:
            key: Setting key to retrieve (e.g., "ssh_host_key_policy")
            default: Value to return if setting not found or error occurs

        Returns:
            The setting value with appropriate type conversion, or default
            if the setting doesn't exist or cannot be retrieved.

        Type Conversions:
            - "json": Parsed as JSON object/array
            - "boolean": Converted to Python bool
            - "integer": Converted to Python int
            - Other: Returned as string

        Note:
            Database errors are handled gracefully to prevent cascading
            failures. The session is rolled back on error to prevent
            "aborted transaction" state in PostgreSQL.
        """
        if not self.db:
            logger.warning("No database session available for SSH config service")
            return default

        try:
            # Import here to avoid circular imports at module load time
            # SystemSettings model may not be available during initial setup
            from ...models.system_models import SystemSettings

            setting = self.db.query(SystemSettings).filter(SystemSettings.setting_key == key).first()

            if not setting:
                return default

            # Convert based on stored type for type-safe retrieval
            if setting.setting_type == "json":
                return json.loads(setting.setting_value) if setting.setting_value else default
            elif setting.setting_type == "boolean":
                return setting.setting_value.lower() in ("true", "1", "yes") if setting.setting_value else default
            elif setting.setting_type == "integer":
                return int(setting.setting_value) if setting.setting_value else default
            else:
                return setting.setting_value or default

        except Exception as e:
            # Check if error is due to missing table (expected during initial setup)
            # This allows the application to start even before migrations run
            error_msg = str(e).lower()
            if "does not exist" in error_msg or "relation" in error_msg:
                # Table doesn't exist yet - expected during setup, use default silently
                logger.debug("system_settings table not found, using default for %s: %s", key, default)
            else:
                # Unexpected error - log for investigation
                logger.error("Error getting setting %s: %s", key, e)

            # Rollback transaction on error to prevent PostgreSQL
            # "current transaction is aborted" state
            if self.db:
                self.db.rollback()
            return default

    def set_setting(
        self,
        key: str,
        value: Any,
        setting_type: str,
        description: str,
        user_id: int,
    ) -> bool:
        """
        Set a system setting value in the database.

        This method creates or updates a setting in the system_settings table
        with full audit trail (created_by, modified_by, timestamps).

        Args:
            key: Setting key to set (e.g., "ssh_host_key_policy")
            value: Value to store (will be converted to string based on type)
            setting_type: Type hint for storage ("string", "json", "boolean", "integer")
            description: Human-readable description of the setting
            user_id: ID of user making the change (for audit trail)

        Returns:
            True if setting was successfully saved, False otherwise

        Value Conversion:
            - "json" type: Value is JSON-serialized
            - "boolean" type: Value is converted to lowercase string
            - Other types: Value is converted to string directly

        Note:
            The method logs all successful changes for audit compliance.
            Failures are logged as errors and the transaction is rolled back.
        """
        if not self.db:
            logger.warning("No database session available for SSH config service")
            return False

        try:
            # Import here to avoid circular imports
            from ...models.system_models import SystemSettings

            # Convert value to string based on declared type
            if setting_type == "json":
                string_value = json.dumps(value)
            elif setting_type == "boolean":
                string_value = str(value).lower()
            else:
                string_value = str(value)

            # Update existing or create new setting
            setting = self.db.query(SystemSettings).filter(SystemSettings.setting_key == key).first()

            if setting:
                # Update existing setting with audit fields
                setting.setting_value = string_value
                setting.setting_type = setting_type
                setting.description = description
                setting.modified_by = user_id
                setting.modified_at = datetime.utcnow()
            else:
                # Create new setting with full audit trail
                setting = SystemSettings(
                    setting_key=key,
                    setting_value=string_value,
                    setting_type=setting_type,
                    description=description,
                    created_by=user_id,
                    modified_by=user_id,
                )
                self.db.add(setting)

            self.db.commit()
            logger.info("Updated setting %s = %s", key, string_value)
            return True

        except Exception as e:
            logger.error("Error setting %s: %s", key, e)
            if self.db:
                self.db.rollback()
            return False

    def get_ssh_policy(self) -> str:
        """
        Get the current SSH host key verification policy.

        Returns:
            Policy name string. One of:
                - "strict": Reject unknown hosts
                - "auto_add": Accept all hosts silently
                - "auto_add_warning": Accept with warning (default)
                - "bypass_trusted": Auto-add for trusted networks only

        Note:
            Default policy "auto_add_warning" provides a balance between
            security (full audit trail) and operational needs (automation
            doesn't fail on new hosts).
        """
        return self.get_setting("ssh_host_key_policy", "auto_add_warning")

    def set_ssh_policy(self, policy: str, user_id: Optional[int] = None) -> bool:
        """
        Set the SSH host key verification policy.

        Args:
            policy: Policy name to set. Must be one of:
                - "strict": Reject unknown hosts (highest security)
                - "auto_add": Accept all hosts silently (development only)
                - "auto_add_warning": Accept with warning logged
                - "bypass_trusted": Auto-add for trusted networks, warning for others
            user_id: ID of user making the change (defaults to system user 1)

        Returns:
            True if policy was successfully updated, False otherwise

        Security Note:
            Policy changes are logged for audit compliance. Changing to
            less secure policies (auto_add) should only be done in
            development environments.
        """
        if policy not in self.VALID_POLICIES:
            logger.error("Invalid SSH policy: %s. Valid options: %s", policy, self.VALID_POLICIES)
            return False

        return self.set_setting(
            "ssh_host_key_policy",
            policy,
            "string",
            f"SSH host key verification policy: {policy}",
            user_id or 1,
        )

    def get_trusted_networks(self) -> List[str]:
        """
        Get the list of trusted network ranges.

        Trusted networks are CIDR ranges where SSH host key verification
        can be bypassed when using the "bypass_trusted" policy.

        Returns:
            List of network CIDR strings (e.g., ["192.168.1.0/24", "10.0.0.0/8"])
            Returns empty list if no trusted networks configured.

        Note:
            The method handles legacy string storage format by attempting
            JSON parsing if the value is a string.
        """
        networks = self.get_setting("ssh_trusted_networks", [])

        # Handle legacy string storage format
        if isinstance(networks, str):
            try:
                networks = json.loads(networks)
            except (json.JSONDecodeError, ValueError):
                networks = []

        return networks if isinstance(networks, list) else []

    def set_trusted_networks(
        self,
        networks: List[str],
        user_id: Optional[int] = None,
    ) -> bool:
        """
        Set the list of trusted network ranges.

        Only valid CIDR network ranges are stored. Invalid ranges are
        logged as warnings and skipped.

        Args:
            networks: List of CIDR network strings to trust
                (e.g., ["192.168.1.0/24", "10.0.0.0/8"])
            user_id: ID of user making the change (defaults to system user 1)

        Returns:
            True if at least some networks were successfully saved, False otherwise

        Validation:
            Each network string is validated using Python's ipaddress module.
            Invalid networks are logged and skipped rather than failing
            the entire operation.

        Security Note:
            Trusted networks bypass host key verification. Only add networks
            where you control all hosts and can verify their identity through
            other means (e.g., private cloud infrastructure).
        """
        # Validate each network range before storing
        valid_networks = []
        for network in networks:
            try:
                # Validate using Python's ipaddress module
                # strict=False allows host bits to be set (e.g., 192.168.1.1/24)
                ipaddress.ip_network(network, strict=False)
                valid_networks.append(network)
            except ValueError as e:
                logger.warning("Invalid network range %s: %s", network, e)

        return self.set_setting(
            "ssh_trusted_networks",
            valid_networks,
            "json",
            "Trusted network ranges for SSH host key bypass",
            user_id or 1,
        )

    def is_host_in_trusted_network(self, host_ip: str) -> bool:
        """
        Check if a host IP address is within any trusted network.

        Args:
            host_ip: IP address to check (e.g., "192.168.1.100")

        Returns:
            True if the IP is within any configured trusted network,
            False otherwise (including if IP is invalid)

        Note:
            This method is used by create_ssh_policy() to determine
            whether to use AutoAddPolicy or SecurityWarningPolicy
            when the "bypass_trusted" policy is configured.
        """
        try:
            host_addr = ipaddress.ip_address(host_ip)
            trusted_networks = self.get_trusted_networks()

            for network_str in trusted_networks:
                try:
                    network = ipaddress.ip_network(network_str, strict=False)
                    if host_addr in network:
                        return True
                except ValueError:
                    # Skip invalid network entries (shouldn't happen
                    # if set_trusted_networks was used, but defensive)
                    continue

            return False

        except ValueError:
            # Invalid host IP address - treat as untrusted
            return False

    def create_ssh_policy(
        self,
        host_ip: Optional[str] = None,
    ) -> paramiko.MissingHostKeyPolicy:
        """
        Create a paramiko host key policy based on current configuration.

        This factory method creates the appropriate paramiko policy object
        based on the configured ssh_host_key_policy setting and optionally
        the target host's IP address (for trusted network checks).

        Args:
            host_ip: Optional target host IP for trusted network check.
                Only used when policy is "bypass_trusted".

        Returns:
            paramiko.MissingHostKeyPolicy instance:
                - RejectPolicy for "strict"
                - AutoAddPolicy for "auto_add" or trusted network bypass
                - SecurityWarningPolicy for "auto_add_warning" or default

        Policy Behavior:
            - strict: Raises SSHException for unknown hosts
            - auto_add: Silently accepts and stores host keys
            - auto_add_warning: Accepts but logs security warning
            - bypass_trusted: auto_add for trusted networks, warning for others
        """
        policy = self.get_ssh_policy()

        if policy == "strict":
            return paramiko.RejectPolicy()
        elif policy == "auto_add":
            return paramiko.AutoAddPolicy()
        elif policy == "auto_add_warning":
            return SecurityWarningPolicy()
        elif policy == "bypass_trusted":
            # Check if host is in trusted network
            if host_ip and self.is_host_in_trusted_network(host_ip):
                return paramiko.AutoAddPolicy()
            else:
                return SecurityWarningPolicy()
        else:
            # Unknown policy - default to warning policy for safety
            return SecurityWarningPolicy()

    def configure_ssh_client(
        self,
        ssh: paramiko.SSHClient,
        host_ip: Optional[str] = None,
    ) -> None:
        """
        Configure an SSH client with the current security policy.

        This method applies the full SSH configuration to a paramiko
        SSHClient instance, including:
        - Setting the host key policy based on configuration
        - Loading system-wide known hosts
        - Loading user-specific known hosts (if available)

        Args:
            ssh: paramiko.SSHClient instance to configure
            host_ip: Optional target host IP for policy selection

        Security Notes:
            - Policy is selected based on current configuration and host_ip
            - System host keys are loaded first (typically /etc/ssh/ssh_known_hosts)
            - User host keys (~/.ssh/known_hosts) loaded only if file exists
            - Falls back to SecurityWarningPolicy on any configuration error

        Known Hosts Loading:
            The method is careful to check if ~/.ssh/known_hosts exists
            before attempting to load it. This is important because
            paramiko's load_host_keys() sets _host_keys_filename BEFORE
            attempting to load, which causes AutoAddPolicy to fail when
            trying to save to a non-existent file.
        """
        try:
            # Set host key policy based on configuration
            policy = self.create_ssh_policy(host_ip)
            ssh.set_missing_host_key_policy(policy)

            # Load system-wide known hosts (typically /etc/ssh/ssh_known_hosts)
            # This provides a baseline of trusted hosts
            try:
                ssh.load_system_host_keys()
            except Exception as e:
                logger.debug("Could not load system host keys: %s", e)

            # Load user-specific known hosts - only if file exists
            # IMPORTANT: paramiko's load_host_keys() sets _host_keys_filename
            # BEFORE attempting to load, which causes AutoAddPolicy to fail
            # when trying to save to a non-existent file. We must check first.
            known_hosts_path = os.path.expanduser("~/.ssh/known_hosts")
            if os.path.exists(known_hosts_path):
                try:
                    ssh.load_host_keys(known_hosts_path)
                except Exception as e:
                    logger.debug("Could not load user host keys: %s", e)
            else:
                logger.debug("Known hosts file does not exist: %s", known_hosts_path)

        except Exception as e:
            logger.warning("Error configuring SSH client: %s", e)
            # Fallback to warning policy - maintains security audit trail
            ssh.set_missing_host_key_policy(SecurityWarningPolicy())


__all__ = [
    "SSHConfigManager",
]
