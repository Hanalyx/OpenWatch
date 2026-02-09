"""
Aegis Plugin Configuration

Configuration settings for the Aegis compliance plugin integration.
Settings can be overridden via environment variables with AEGIS_ prefix.

Part of Phase 5: Control Plane (Aegis Integration Plan)
"""

from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings

# Default paths relative to backend directory
DEFAULT_AEGIS_PATH = Path(__file__).parent.parent.parent.parent / "aegis"
DEFAULT_RULES_PATH = DEFAULT_AEGIS_PATH / "rules"
DEFAULT_BACKUP_PATH = Path("/tmp/aegis_backups")


class AegisConfig(BaseSettings):
    """
    Aegis plugin configuration.

    All settings can be overridden via environment variables with the
    AEGIS_ prefix (e.g., AEGIS_CHECK_TIMEOUT, AEGIS_MAX_CONCURRENT_CHECKS).
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
        default="https://registry.openwatch.io/aegis",
        description="URL for Aegis update registry",
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

    aegis_path: Path = Field(
        default=DEFAULT_AEGIS_PATH,
        description="Path to Aegis installation directory",
    )

    rules_path: Path = Field(
        default=DEFAULT_RULES_PATH,
        description="Path to Aegis rules directory",
    )

    backup_path: Path = Field(
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

        env_prefix = "AEGIS_"
        env_file = ".env"
        extra = "ignore"


# Global config instance (lazy loaded)
_config: Optional[AegisConfig] = None


def get_aegis_config() -> AegisConfig:
    """
    Get the Aegis configuration singleton.

    Returns:
        AegisConfig instance with settings from environment.
    """
    global _config
    if _config is None:
        _config = AegisConfig()
    return _config
