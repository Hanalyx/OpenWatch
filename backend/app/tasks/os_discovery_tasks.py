"""
OS Discovery Celery Tasks

Provides asynchronous host operating system detection capabilities.
Integrates with the Host OS Detection feature to auto-populate os_family,
os_version, and architecture fields on hosts.

This module supports:
- Single host OS discovery via trigger_os_discovery task
- Batch OS discovery for multiple hosts
- Integration with host creation workflow for automatic discovery

Security Considerations:
- Uses SSHConnectionManager for secure credential handling
- Credentials are decrypted only during SSH connection (not logged)
- Discovery results are validated before database persistence

Usage:
    # Trigger OS discovery for a single host
    from backend.app.tasks.os_discovery_tasks import trigger_os_discovery
    trigger_os_discovery.delay(str(host_id))

    # Trigger batch discovery
    from backend.app.tasks.os_discovery_tasks import batch_os_discovery
    batch_os_discovery.delay([str(host_id) for host_id in host_ids])

See: docs/plans/HOST_OS_DETECTION_AND_OVAL_ALIGNMENT_PLAN.md
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy import text

from backend.app.celery_app import celery_app
from backend.app.config import get_settings
from backend.app.database import get_db_session
from backend.app.encryption import EncryptionConfig, create_encryption_service
from backend.app.services.host_discovery_service import HostBasicDiscoveryService

# SSHConnectionManager provides modular SSH connection handling with better testability
from backend.app.services.ssh import SSHConnectionManager

logger = logging.getLogger(__name__)


def _normalize_platform_identifier(os_family: str, os_version: str) -> Optional[str]:
    """
    Normalize OS family and version into a platform identifier for OVAL selection.

    This function converts discovered OS information into standardized platform
    identifiers that match the compliance rules bundle structure.

    Args:
        os_family: Detected OS family (e.g., "rhel", "ubuntu", "debian")
        os_version: Detected OS version (e.g., "9.3", "22.04", "12")

    Returns:
        Normalized platform identifier (e.g., "rhel9", "ubuntu2204") or None if
        OS information is insufficient for normalization.

    Examples:
        >>> _normalize_platform_identifier("rhel", "9.3")
        'rhel9'
        >>> _normalize_platform_identifier("ubuntu", "22.04")
        'ubuntu2204'
        >>> _normalize_platform_identifier("debian", "12")
        'debian12'
    """
    if not os_family or os_family.lower() == "unknown":
        return None

    if not os_version or os_version.lower() == "unknown":
        return None

    os_family_lower = os_family.lower()

    # Extract major version (handles "9.3", "22.04", "12", etc.)
    try:
        # For versions like "22.04", keep both parts for Ubuntu
        if os_family_lower == "ubuntu":
            # Ubuntu uses YY.MM format - keep both parts without dot
            version_parts = os_version.split(".")
            if len(version_parts) >= 2:
                major = version_parts[0]
                minor = version_parts[1]
                return f"ubuntu{major}{minor}"
            else:
                return f"ubuntu{version_parts[0]}"

        # For RHEL-compatible distros, use major version only
        elif os_family_lower in ["rhel", "centos", "rocky", "alma", "oracle"]:
            major_version = os_version.split(".")[0]
            return f"rhel{major_version}"

        # For other distros, use major version only
        else:
            major_version = os_version.split(".")[0]
            return f"{os_family_lower}{major_version}"

    except (IndexError, ValueError) as e:
        logger.warning(f"Failed to normalize platform identifier for {os_family} {os_version}: {e}")
        return None


def _record_discovery_failure(host_id: str, error_message: str) -> None:
    """
    Record a permanent discovery failure for notification purposes.

    This function is called when all retry attempts for OS discovery have been
    exhausted. It stores the failure in the system_settings table as a JSON
    array of failed hosts, which can be polled by the frontend for notification.

    Args:
        host_id: UUID of the host that failed discovery
        error_message: Error message from the final failure
    """
    try:
        import json

        with get_db_session() as db:
            # Get current failures list
            query = text(
                "SELECT setting_value FROM system_settings WHERE setting_key = 'os_discovery_failures'"
            )
            result = db.execute(query).fetchone()

            if result and result[0]:
                try:
                    failures = json.loads(result[0])
                except json.JSONDecodeError:
                    failures = []
            else:
                failures = []

            # Add new failure (limit to last 50 failures)
            failure_entry = {
                "host_id": host_id,
                "error": error_message[:500],  # Truncate long errors
                "failed_at": datetime.utcnow().isoformat(),
            }
            failures.append(failure_entry)
            failures = failures[-50:]  # Keep only last 50

            # Upsert the failures list
            upsert_query = text("""
                INSERT INTO system_settings (setting_key, setting_value, setting_type, description, created_at, modified_at)
                VALUES ('os_discovery_failures', :value, 'json', 'Failed OS discovery attempts', :now, :now)
                ON CONFLICT (setting_key)
                DO UPDATE SET setting_value = :value, modified_at = :now
            """)
            db.execute(upsert_query, {"value": json.dumps(failures), "now": datetime.utcnow()})
            db.commit()

            logger.info(f"Recorded OS discovery failure for host {host_id}")

    except Exception as e:
        # Don't fail silently but also don't propagate - this is best-effort
        logger.warning(f"Failed to record OS discovery failure for {host_id}: {e}")


@celery_app.task(bind=True, name="backend.app.tasks.trigger_os_discovery")
def trigger_os_discovery(self, host_id: str) -> Dict[str, Any]:
    """
    Asynchronously discover and update OS information for a single host.

    This Celery task performs SSH-based OS detection and updates the host
    record with discovered os_family, os_version, architecture, and
    last_os_detection timestamp.

    Args:
        host_id: UUID string of the host to discover OS information for.

    Returns:
        Dictionary containing discovery results:
        - host_id: The host UUID
        - success: Whether discovery completed successfully
        - os_family: Detected OS family (e.g., "rhel", "ubuntu")
        - os_version: Detected OS version (e.g., "9.3", "22.04")
        - platform_identifier: Normalized platform ID (e.g., "rhel9")
        - architecture: Detected architecture (e.g., "x86_64")
        - error: Error message if discovery failed

    Raises:
        Retries up to 3 times with exponential backoff on transient failures.

    Example:
        >>> # Trigger async discovery
        >>> result = trigger_os_discovery.delay("550e8400-e29b-41d4-a716-446655440000")
        >>> # Later, check result
        >>> result.get(timeout=60)
        {'host_id': '550e8400-...', 'success': True, 'os_family': 'rhel', ...}
    """
    logger.info(f"Starting OS discovery for host {host_id}")

    result = {
        "host_id": host_id,
        "success": False,
        "os_family": None,
        "os_version": None,
        "platform_identifier": None,
        "architecture": None,
        "error": None,
        "discovered_at": datetime.utcnow().isoformat(),
    }

    try:
        with get_db_session() as db:
            # Fetch host details including credentials
            host_query = text("""
                SELECT id, hostname, ip_address, port, username, auth_method,
                       encrypted_credentials, status, os_family, os_version
                FROM hosts
                WHERE id = :host_id AND is_active = true
            """)
            host_row = db.execute(host_query, {"host_id": host_id}).fetchone()

            if not host_row:
                result["error"] = f"Host {host_id} not found or inactive"
                logger.warning(result["error"])
                return result

            # Check if host has credentials for SSH discovery
            if not host_row.encrypted_credentials:
                result["error"] = "Host has no credentials configured for SSH discovery"
                logger.warning(f"Host {host_id} ({host_row.hostname}): {result['error']}")
                return result

            # Create encryption service for credential decryption
            settings = get_settings()
            encryption_service = create_encryption_service(
                master_key=settings.master_key, config=EncryptionConfig()
            )

            # Create a Host-like object for the discovery service
            # HostBasicDiscoveryService expects a Host model instance
            class HostProxy:
                """Proxy object providing Host-like interface for discovery service."""

                def __init__(self, row: Any, enc_service: Any) -> None:
                    self.id = row.id
                    self.hostname = row.hostname
                    self.ip_address = row.ip_address
                    self.port = row.port or 22
                    self.username = row.username
                    self.auth_method = row.auth_method
                    self.encrypted_credentials = row.encrypted_credentials
                    self.os_family = row.os_family
                    self.os_version = row.os_version
                    self.architecture = None
                    self.operating_system = None
                    self.last_os_detection = None
                    self._encryption_service = enc_service

            host_proxy = HostProxy(host_row, encryption_service)

            # SSHConnectionManager handles SSH connections with configurable policies
            ssh_service = SSHConnectionManager()
            discovery_service = HostBasicDiscoveryService(ssh_service=ssh_service)

            # Perform OS discovery
            discovery_results = discovery_service.discover_basic_system_info(host_proxy)

            if not discovery_results.get("discovery_success", False):
                errors = discovery_results.get("discovery_errors", ["Unknown error"])
                result["error"] = "; ".join(errors)
                logger.warning(
                    f"OS discovery failed for host {host_id} ({host_row.hostname}): {result['error']}"
                )
                return result

            # Extract discovered values
            discovered_os_family = discovery_results.get("os_family", "Unknown")
            discovered_os_version = discovery_results.get("os_version", "Unknown")
            discovered_architecture = discovery_results.get("architecture", "Unknown")
            discovered_os_name = discovery_results.get("os_name", "Unknown")

            # Normalize to platform identifier for OVAL selection
            platform_identifier = _normalize_platform_identifier(
                discovered_os_family, discovered_os_version
            )

            # Update host record in database
            # Phase 4: Include platform_identifier for OVAL selection during scans
            update_query = text("""
                UPDATE hosts
                SET os_family = :os_family,
                    os_version = :os_version,
                    architecture = :architecture,
                    operating_system = :operating_system,
                    platform_identifier = :platform_identifier,
                    last_os_detection = :last_os_detection,
                    updated_at = :updated_at
                WHERE id = :host_id
            """)
            db.execute(
                update_query,
                {
                    "host_id": host_id,
                    "os_family": (
                        discovered_os_family if discovered_os_family != "Unknown" else None
                    ),
                    "os_version": (
                        discovered_os_version if discovered_os_version != "Unknown" else None
                    ),
                    "architecture": (
                        discovered_architecture if discovered_architecture != "Unknown" else None
                    ),
                    "operating_system": (
                        discovered_os_name if discovered_os_name != "Unknown" else None
                    ),
                    "platform_identifier": platform_identifier,  # Phase 4: Persisted for scan OVAL selection
                    "last_os_detection": datetime.utcnow(),
                    "updated_at": datetime.utcnow(),
                },
            )
            db.commit()

            # Populate result
            result["success"] = True
            result["os_family"] = discovered_os_family
            result["os_version"] = discovered_os_version
            result["platform_identifier"] = platform_identifier
            result["architecture"] = discovered_architecture

            logger.info(
                f"OS discovery completed for host {host_id} ({host_row.hostname}): "
                f"{discovered_os_family} {discovered_os_version} ({platform_identifier}), "
                f"arch={discovered_architecture}"
            )

            return result

    except Exception as exc:
        logger.error(f"Critical error in OS discovery for host {host_id}: {exc}")
        result["error"] = str(exc)

        # Check if we've exhausted all retries
        if self.request.retries >= 3:
            # All retries exhausted - record failure for notification
            logger.error(
                f"OS discovery permanently failed for host {host_id} after "
                f"{self.request.retries + 1} attempts: {exc}"
            )
            _record_discovery_failure(host_id, str(exc))
            return result

        # Retry with exponential backoff on transient failures
        # Max 3 retries: 60s, 120s, 240s delays
        raise self.retry(
            exc=exc,
            countdown=min(2**self.request.retries * 60, 300),
            max_retries=3,
        )


@celery_app.task(bind=True, name="backend.app.tasks.batch_os_discovery")
def batch_os_discovery(self, host_ids: List[str]) -> Dict[str, Any]:
    """
    Trigger OS discovery for multiple hosts in batch.

    This task dispatches individual trigger_os_discovery tasks for each host,
    allowing parallel discovery across multiple hosts.

    Args:
        host_ids: List of host UUID strings to discover OS information for.

    Returns:
        Dictionary containing batch dispatch results:
        - total_hosts: Number of hosts in the batch
        - dispatched: Number of tasks successfully dispatched
        - failed: Number of tasks that failed to dispatch
        - dispatch_errors: List of errors for failed dispatches

    Example:
        >>> host_ids = ["uuid-1", "uuid-2", "uuid-3"]
        >>> batch_os_discovery.delay(host_ids)
    """
    logger.info(f"Starting batch OS discovery for {len(host_ids)} hosts")

    result = {
        "total_hosts": len(host_ids),
        "dispatched": 0,
        "failed": 0,
        "dispatch_errors": [],
        "dispatched_at": datetime.utcnow().isoformat(),
    }

    for host_id in host_ids:
        try:
            # Validate UUID format before dispatching
            try:
                UUID(host_id)
            except ValueError:
                result["failed"] += 1
                result["dispatch_errors"].append(
                    {"host_id": host_id, "error": "Invalid UUID format"}
                )
                continue

            # Dispatch individual discovery task
            trigger_os_discovery.apply_async(
                args=[host_id],
                queue="default",  # Use default queue for OS discovery
            )
            result["dispatched"] += 1

        except Exception as e:
            result["failed"] += 1
            result["dispatch_errors"].append({"host_id": host_id, "error": str(e)})
            logger.error(f"Failed to dispatch OS discovery for host {host_id}: {e}")

    logger.info(
        f"Batch OS discovery dispatch complete: "
        f"{result['dispatched']}/{result['total_hosts']} dispatched, "
        f"{result['failed']} failed"
    )

    return result


@celery_app.task(bind=True, name="backend.app.tasks.discover_all_hosts_os")
def discover_all_hosts_os(self, force: bool = False) -> Dict[str, Any]:
    """
    Discover OS information for all active hosts.

    This task queries all active hosts and dispatches OS discovery tasks
    for hosts that either have no OS information or when force=True.

    The task respects the system_settings.os_discovery_enabled setting.
    If disabled, the task will skip execution (unless force=True).

    Args:
        force: If True, rediscover OS for all hosts regardless of existing data
               and ignore the os_discovery_enabled setting.
               If False (default), only discover for hosts with missing OS info.

    Returns:
        Dictionary containing:
        - total_active_hosts: Total number of active hosts
        - hosts_needing_discovery: Number of hosts that need OS discovery
        - dispatched: Number of discovery tasks dispatched
        - skipped: Number of hosts skipped (already have OS info)
        - disabled: True if task was skipped due to system setting

    Example:
        >>> # Discover OS for hosts with missing info only
        >>> discover_all_hosts_os.delay()
        >>> # Force rediscovery for all hosts
        >>> discover_all_hosts_os.delay(force=True)
    """
    logger.info(f"Starting OS discovery for all active hosts (force={force})")

    result = {
        "total_active_hosts": 0,
        "hosts_needing_discovery": 0,
        "dispatched": 0,
        "skipped": 0,
        "disabled": False,
        "started_at": datetime.utcnow().isoformat(),
    }

    try:
        with get_db_session() as db:
            # Check system setting (unless force=True)
            if not force:
                setting_query = text(
                    "SELECT setting_value FROM system_settings WHERE setting_key = 'os_discovery_enabled'"
                )
                setting_result = db.execute(setting_query).fetchone()

                # Default to enabled if setting doesn't exist
                if setting_result:
                    is_enabled = setting_result[0].lower() in ("true", "1", "yes", "enabled")
                    if not is_enabled:
                        logger.info(
                            "Scheduled OS discovery is disabled via system_settings. "
                            "Use force=True to override."
                        )
                        result["disabled"] = True
                        return result
            # Build query based on force flag
            if force:
                # Get all active hosts with credentials
                query = text("""
                    SELECT id, hostname, os_family, os_version
                    FROM hosts
                    WHERE is_active = true
                      AND encrypted_credentials IS NOT NULL
                """)
            else:
                # Get only hosts missing OS information
                query = text("""
                    SELECT id, hostname, os_family, os_version
                    FROM hosts
                    WHERE is_active = true
                      AND encrypted_credentials IS NOT NULL
                      AND (os_family IS NULL OR os_version IS NULL)
                """)

            hosts = db.execute(query).fetchall()
            result["total_active_hosts"] = len(hosts)

            if not hosts:
                logger.info("No hosts need OS discovery")
                return result

            # Collect host IDs for batch dispatch
            host_ids_to_discover = []
            for host in hosts:
                if force or not host.os_family or not host.os_version:
                    host_ids_to_discover.append(str(host.id))
                else:
                    result["skipped"] += 1

            result["hosts_needing_discovery"] = len(host_ids_to_discover)

            # Dispatch batch discovery if there are hosts to process
            if host_ids_to_discover:
                batch_os_discovery.apply_async(
                    args=[host_ids_to_discover],
                    queue="default",
                )
                result["dispatched"] = len(host_ids_to_discover)

            logger.info(
                f"OS discovery dispatch complete: "
                f"{result['dispatched']} hosts queued, "
                f"{result['skipped']} skipped"
            )

            return result

    except Exception as exc:
        logger.error(f"Failed to initiate full OS discovery: {exc}")
        raise self.retry(exc=exc, countdown=120, max_retries=2)
