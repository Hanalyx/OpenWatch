"""
Kensa Plugin Configuration

Configuration settings for the Kensa compliance plugin integration.
Settings can be overridden via environment variables with KENSA_ prefix.
"""

from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings

# Default paths - use runner.paths for rule discovery
DEFAULT_BACKUP_PATH = "/tmp/kensa_backups"


class KensaConfig(BaseSettings):
    """
    Kensa plugin configuration.

    All settings can be overridden via environment variables with the
    KENSA_ prefix (e.g., KENSA_CHECK_TIMEOUT, KENSA_MAX_CONCURRENT_CHECKS).
    """

    # ==========================================================================
    # Execution Settings
    # ==========================================================================

    max_concurrent_checks: int = Field(
        default=10,
        description="Maximum concurrent rule checks per host",
        ge=1,
        le=50,
    )

    check_timeout: int = Field(
        default=60,
        description="Timeout for individual rule checks in seconds",
        ge=5,
        le=300,
    )

    remediation_timeout: int = Field(
        default=300,
        description="Timeout for remediation operations in seconds",
        ge=30,
        le=1800,
    )

    dry_run_default: bool = Field(
        default=True,
        description="Default to dry-run mode for remediations",
    )

    # ==========================================================================
    # SSH Settings
    # ==========================================================================

    ssh_connect_timeout: int = Field(
        default=30,
        description="SSH connection timeout in seconds",
        ge=5,
        le=120,
    )

    ssh_command_timeout: int = Field(
        default=60,
        description="SSH command execution timeout in seconds",
        ge=10,
        le=300,
    )

    # ==========================================================================
    # Update Settings
    # ==========================================================================

    update_registry_url: str = Field(
        default="https://registry.openwatch.io/kensa",
        description="URL for Kensa update registry",
    )

    update_check_interval: int = Field(
        default=86400,
        description="Update check interval in seconds (24 hours)",
        ge=3600,
        le=604800,
    )

    auto_update: bool = Field(
        default=False,
        description="Enable automatic updates (manual by default)",
    )

    offline_mode: bool = Field(
        default=False,
        description="Disable online update checks (air-gapped environments)",
    )

    # ==========================================================================
    # Paths
    # ==========================================================================

    rules_path: Optional[str] = Field(
        default=None,
        description="Path to Kensa rules directory (auto-discovered via runner.paths if not set)",
    )

    backup_path: str = Field(
        default=DEFAULT_BACKUP_PATH,
        description="Path for backup storage during updates",
    )

    # ==========================================================================
    # Signing Key (Ed25519 public key for package verification)
    # ==========================================================================

    signing_public_key: str = Field(
        default="",
        description="Ed25519 public key for verifying package signatures (base64)",
    )

    # ==========================================================================
    # Logging
    # ==========================================================================

    log_check_commands: bool = Field(
        default=False,
        description="Log check commands (verbose, disable in production)",
    )

    log_remediation_commands: bool = Field(
        default=True,
        description="Log remediation commands for audit trail",
    )

    class Config:
        """Pydantic settings configuration."""

        env_prefix = "KENSA_"
        env_file = ".env"
        extra = "ignore"


# Global config instance (lazy loaded)
_config: Optional[KensaConfig] = None


def get_kensa_config() -> KensaConfig:
    """
    Get the Kensa configuration singleton.

    Returns:
        KensaConfig instance with settings from environment.
    """
    global _config
    if _config is None:
        _config = KensaConfig()
    return _config
