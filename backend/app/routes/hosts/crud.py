"""
Host CRUD API Endpoints

This module provides endpoints for host management operations including
create, read, update, delete, and SSH key management.

Endpoints:
    POST /validate-credentials         - Validate SSH credentials
    GET  /                             - List all hosts
    POST /                             - Create new host
    GET  /capabilities                 - Get host management capabilities
    GET  /summary                      - Get hosts summary statistics
    GET  /{host_id}                    - Get host details
    PUT  /{host_id}                    - Update host
    DELETE /{host_id}                  - Delete host
    DELETE /{host_id}/ssh-key          - Delete host SSH key
    POST /{host_id}/discover-os        - Trigger async OS discovery (Celery task)
    GET  /{host_id}/os-info            - Get OS information
    POST /{host_id}/detect-platform    - Synchronous JIT platform detection (scan wizard)

Architecture Notes:
    - Uses SQLAlchemy for database operations
    - Uses QueryBuilder for parameterized queries where applicable
    - Uses unified_credentials table for credential storage
    - Follows CLAUDE.md coding standards
"""

import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer
from sqlalchemy import text
from sqlalchemy.orm import Session

from ...auth import get_current_user
from ...database import get_db
from ...services.ssh import validate_ssh_key
from ...utils.logging_security import sanitize_id_for_log
from ...utils.query_builder import QueryBuilder
from .helpers import validate_host_uuid
from .models import Host, HostCreate, HostUpdate, OSDiscoveryResponse

logger = logging.getLogger(__name__)
security = HTTPBearer(auto_error=False)

router = APIRouter(tags=["Host Management"])


# =============================================================================
# CREDENTIAL VALIDATION
# =============================================================================


@router.post("/validate-credentials")
async def validate_credentials(
    validation_data: Dict[str, Any],
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Validate SSH credentials without creating a host.

    This endpoint allows the Add Host frontend to validate SSH keys
    before submission, providing immediate feedback to users.

    Request body:
    {
        "auth_method": "ssh_key" | "password",  # pragma: allowlist secret
        "ssh_key": "string (optional)",
        "credential": "string (optional)"
    }

    Returns:
    {
        "is_valid": boolean,
        "auth_method": string,
        "key_type": string (for SSH keys),
        "key_bits": integer (for SSH keys),
        "security_level": string (for SSH keys),
        "error_message": string (if invalid),
        "warnings": list (if any),
        "recommendations": list (if any)
    }
    """
    try:
        auth_method = validation_data.get("auth_method")
        ssh_key = validation_data.get("ssh_key")
        password = validation_data.get("password")

        # Validate SSH key
        if auth_method == "ssh_key" and ssh_key:
            logger.info("Validating SSH key credentials via validate-credentials endpoint")
            validation_result = validate_ssh_key(ssh_key)

            return {
                "is_valid": validation_result.is_valid,
                "auth_method": "ssh_key",
                "key_type": (validation_result.key_type.value if validation_result.key_type else None),
                "key_bits": validation_result.key_size,
                "security_level": (
                    validation_result.security_level.value if validation_result.security_level else None
                ),
                "error_message": validation_result.error_message,
                "warnings": validation_result.warnings,
                "recommendations": validation_result.recommendations,
            }

        # Password validation (basic check)
        elif auth_method == "password" and password:
            # Basic password validation - just check it's not empty
            if len(password.strip()) == 0:
                return {
                    "is_valid": False,
                    "auth_method": "password",
                    "error_message": "Password cannot be empty",
                    "warnings": [],
                    "recommendations": ["Use a strong password with at least 12 characters"],
                }

            return {
                "is_valid": True,
                "auth_method": "password",
                "error_message": None,
                "warnings": ([] if len(password) >= 12 else ["Password should be at least 12 characters for security"]),
                "recommendations": [
                    "Use a password manager",
                    "Consider using SSH key authentication instead",
                ],
            }

        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing credentials: provide either ssh_key or password based on auth_method",
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Credential validation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Validation failed: {str(e)}",
        )


# =============================================================================
# LIST AND CREATE HOSTS
# =============================================================================


@router.get("/", response_model=List[Host])
async def list_hosts(
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> List[Host]:
    """List all managed hosts"""
    try:
        # Try to get hosts from database with latest scan information and group details
        # NOTE: This query uses LATERAL JOIN which is PostgreSQL-specific and complex
        # OW-REFACTOR-001B: Keeping original SQL due to LATERAL JOIN complexity
        result = db.execute(
            text(
                """
            SELECT h.id, h.hostname, h.ip_address, h.display_name, h.operating_system,
                   h.os_family, h.os_version, h.platform_identifier,
                   h.status, h.port, h.username, h.auth_method, h.created_at, h.updated_at, h.description,
                   h.last_check, h.response_time_ms, h.check_priority,
                   h.ping_consecutive_failures, h.ssh_consecutive_failures, h.privilege_consecutive_failures,
                   h.ping_consecutive_successes, h.ssh_consecutive_successes, h.privilege_consecutive_successes,
                   s.id as latest_scan_id, s.name as latest_scan_name, s.status as scan_status,
                   s.progress as scan_progress, s.started_at as scan_started_at, s.completed_at as scan_completed_at,
                   sr.score as compliance_score, sr.failed_rules as failed_rules, sr.passed_rules as passed_rules,
                   sr.severity_critical as critical_issues, sr.severity_high as high_issues,
                   sr.severity_medium as medium_issues, sr.severity_low as low_issues, sr.total_rules,
                   sr.severity_critical_passed, sr.severity_critical_failed,
                   sr.severity_high_passed, sr.severity_high_failed,
                   sr.severity_medium_passed, sr.severity_medium_failed,
                   sr.severity_low_passed, sr.severity_low_failed,
                   hg.id as group_id, hg.name as group_name,
                   hg.description as group_description, hg.color as group_color
            FROM hosts h
            LEFT JOIN LATERAL (
                SELECT s2.id, s2.name, s2.status, s2.progress, s2.started_at, s2.completed_at
                FROM scans s2
                WHERE s2.host_id = h.id
                ORDER BY s2.started_at DESC
                LIMIT 1
            ) s ON true
            LEFT JOIN scan_results sr ON sr.scan_id = s.id
            LEFT JOIN host_group_memberships hgm ON hgm.host_id = h.id
            LEFT JOIN host_groups hg ON hg.id = hgm.group_id
            ORDER BY h.created_at DESC
        """
            )
        )

        hosts = []
        for row in result:
            # Parse compliance score
            compliance_score = None
            if row.compliance_score:
                try:
                    # Remove % sign if present and convert to float
                    score_str = str(row.compliance_score).replace("%", "")
                    compliance_score = float(score_str)
                except (ValueError, TypeError):
                    pass

            host_data = Host(
                id=str(row.id),
                hostname=row.hostname,
                ip_address=str(row.ip_address),
                display_name=row.display_name,
                operating_system=row.operating_system,
                # OS detection fields for platform auto-detection in scan wizard
                os_family=row.os_family,
                os_version=row.os_version,
                platform_identifier=row.platform_identifier,
                status=row.status,
                port=row.port,
                username=row.username,
                auth_method=row.auth_method,
                created_at=row.created_at.isoformat() + "Z" if row.created_at else None,
                updated_at=row.updated_at.isoformat() + "Z" if row.updated_at else None,
                last_check=row.last_check.isoformat() + "Z" if row.last_check else None,
                response_time_ms=row.response_time_ms,
                check_priority=row.check_priority,
                ping_consecutive_failures=row.ping_consecutive_failures,
                ssh_consecutive_failures=row.ssh_consecutive_failures,
                privilege_consecutive_failures=row.privilege_consecutive_failures,
                ping_consecutive_successes=row.ping_consecutive_successes,
                ssh_consecutive_successes=row.ssh_consecutive_successes,
                privilege_consecutive_successes=row.privilege_consecutive_successes,
                ssh_key_fingerprint=None,  # Not in database schema
                ssh_key_type=None,  # Not in database schema
                ssh_key_bits=None,  # Not in database schema
                ssh_key_comment=None,  # Not in database schema
                group_id=row.group_id,
                group_name=row.group_name,
                group_description=row.group_description,
                group_color=row.group_color,
            )

            # Add scan information as additional fields
            if row.latest_scan_id:
                host_data.latest_scan_id = str(row.latest_scan_id)
                host_data.latest_scan_name = row.latest_scan_name
                host_data.scan_status = row.scan_status
                host_data.scan_progress = row.scan_progress
                host_data.last_scan = (
                    row.scan_completed_at.isoformat() + "Z"
                    if row.scan_completed_at
                    else (row.scan_started_at.isoformat() + "Z" if row.scan_started_at else None)
                )
                host_data.compliance_score = compliance_score
                host_data.failed_rules = row.failed_rules or 0
                host_data.passed_rules = row.passed_rules or 0

                # NIST SP 800-30 severity tracking (CVSS-based)
                host_data.critical_issues = row.critical_issues or 0  # CVSS >= 9.0
                host_data.high_issues = row.high_issues or 0
                host_data.medium_issues = row.medium_issues or 0
                host_data.low_issues = row.low_issues or 0
                host_data.total_rules = row.total_rules or 0

                # NIST SP 800-137 per-severity pass/fail breakdown
                # Enables accurate ComplianceRing visualization with real data
                host_data.critical_passed = row.severity_critical_passed or 0
                host_data.critical_failed = row.severity_critical_failed or 0
                host_data.high_passed = row.severity_high_passed or 0
                host_data.high_failed = row.severity_high_failed or 0
                host_data.medium_passed = row.severity_medium_passed or 0
                host_data.medium_failed = row.severity_medium_failed or 0
                host_data.low_passed = row.severity_low_passed or 0
                host_data.low_failed = row.severity_low_failed or 0

            hosts.append(host_data)

        return hosts

    except Exception as e:
        logger.error(f"Database error in host listing: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve hosts from database",
        )


@router.post("/", response_model=Host)
async def create_host(
    host: HostCreate,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Host:
    """Add a new host to management"""
    try:
        # Insert into database
        host_id = str(uuid.uuid4())
        current_time = datetime.utcnow()

        # Use display_name if provided, otherwise use hostname
        display_name = host.display_name or host.hostname

        # Phase 2: Use HostCredentialHandler service for credential validation
        from ...services.auth.credential_handler import HostCredentialHandler

        credential_handler = HostCredentialHandler(db)
        host_uuid = uuid.UUID(host_id)

        # Validate and prepare credentials (if provided)
        credential_info = credential_handler.validate_and_prepare_credential(
            hostname=host.hostname,
            auth_method=host.auth_method or "ssh_key",
            username=host.username or "",
            password=host.password,
            ssh_key=host.ssh_key,
            host_id=host_uuid,
        )

        # Keep NULL in hosts.encrypted_credentials (unified system uses unified_credentials table)
        encrypted_creds = None

        # NOTE: QueryBuilder is for SELECT queries only (OW-REFACTOR-001B)
        # For INSERT/UPDATE/DELETE, use raw SQL with parameterized queries
        insert_query = text(
            """
            INSERT INTO hosts (
                id, hostname, ip_address, display_name, operating_system,
                status, port, username, auth_method, encrypted_credentials,
                is_active, created_at, updated_at
            )
            VALUES (
                :id, :hostname, :ip_address, :display_name, :operating_system,
                :status, :port, :username, :auth_method, :encrypted_credentials,
                :is_active, :created_at, :updated_at
            )
        """
        )

        db.execute(
            insert_query,
            {
                "id": host_id,
                "hostname": host.hostname,
                "ip_address": host.ip_address,
                "display_name": display_name,
                "operating_system": host.operating_system,
                "status": "offline",
                "port": int(host.port) if host.port else 22,
                "username": host.username,
                "auth_method": host.auth_method or "ssh_key",
                "encrypted_credentials": encrypted_creds,
                "is_active": True,
                "created_at": current_time,
                "updated_at": current_time,
            },
        )

        db.commit()

        # Phase 2: Store credential in unified_credentials using service
        if credential_info:
            # Get user UUID for audit trail (QueryBuilder for consistent parameterization)
            user_query_builder = (
                QueryBuilder("users").select("id").where("id = :user_id", current_user.get("id"), "user_id")
            )
            user_query, user_params = user_query_builder.build()
            user_id_result = db.execute(text(user_query), user_params)
            user_row = user_id_result.fetchone()
            user_uuid = str(user_row[0]) if user_row else None

            # Store credential (gracefully handles failures)
            credential_handler.store_host_credential(
                credential_data=credential_info["credential_data"],
                metadata=credential_info["metadata"],
                created_by=user_uuid,
                hostname=host.hostname,
            )

        new_host = Host(
            id=host_id,
            hostname=host.hostname,
            ip_address=host.ip_address,
            display_name=display_name,
            operating_system=host.operating_system,
            status="offline",
            created_at=current_time.isoformat() + "Z",
            updated_at=current_time.isoformat() + "Z",
        )

        logger.info(f"Created new host in database: {host.hostname}")

        # Trigger async OS discovery if credentials were provided
        # This populates os_family, os_version, architecture fields
        # for accurate platform-specific OVAL selection during scanning
        if credential_info:
            try:
                from ...tasks.os_discovery_tasks import trigger_os_discovery

                trigger_os_discovery.apply_async(
                    args=[host_id],
                    countdown=5,  # Delay 5 seconds to ensure credential is stored
                    queue="default",
                )
                logger.info(f"Queued OS discovery task for new host {host.hostname} ({host_id})")
            except Exception as e:
                # Non-blocking: Log warning but don't fail host creation
                # OS discovery can be triggered manually later via /hosts/{id}/discover-os
                logger.warning(
                    f"Failed to queue OS discovery for host {host.hostname}: {e}. "
                    f"OS detection can be triggered manually via API."
                )

        return new_host

    except Exception as e:
        logger.error(f"Failed to create host in database: {e}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create host",
        )


# =============================================================================
# CAPABILITIES AND SUMMARY
# =============================================================================


@router.get("/capabilities")
async def get_host_management_capabilities(
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get host management capabilities

    Returns information about available host management features,
    limits, and supported operations.
    """
    return {
        "features": {
            "bulk_import": True,
            "csv_import": True,
            "host_groups": True,
            "ssh_key_management": True,
            "remote_scanning": True,
            "monitoring": True,
        },
        "limits": {
            "max_hosts_per_request": 100,
            "bulk_import_max_size": 10000,
            "supported_os": ["linux", "unix", "rhel", "ubuntu", "debian", "centos"],
        },
        "endpoints": {
            "list_hosts": "GET /api/hosts",
            "create_host": "POST /api/hosts",
            "get_host": "GET /api/hosts/{host_id}",
            "update_host": "PUT /api/hosts/{host_id}",
            "delete_host": "DELETE /api/hosts/{host_id}",
            "bulk_import": "POST /api/hosts/bulk",
            "capabilities": "GET /api/hosts/capabilities",
            "discover_os": "POST /api/hosts/{host_id}/discover-os",
            "get_os_info": "GET /api/hosts/{host_id}/os-info",
            # Discovery endpoints (Phase 3)
            "discovery_basic": "POST /api/hosts/{host_id}/discovery/basic",
            "discovery_network": "POST /api/hosts/{host_id}/discovery/network",
            "discovery_security": "POST /api/hosts/{host_id}/discovery/security",
            "discovery_compliance": "POST /api/hosts/{host_id}/discovery/compliance",
        },
    }


@router.get("/summary")
async def get_hosts_summary(
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get summary statistics for host management

    Returns aggregate information about hosts, groups, and management status.
    """
    # This would typically query the database for actual statistics
    return {
        "total_hosts": 0,
        "active_hosts": 0,
        "groups": 0,
        "last_scan": None,
        "compliance_summary": {"compliant": 0, "non_compliant": 0, "unknown": 0},
        "os_distribution": {},
        "scan_status": {"never_scanned": 0, "recently_scanned": 0, "outdated_scans": 0},
    }


# =============================================================================
# SINGLE HOST OPERATIONS
# =============================================================================


@router.get("/{host_id}", response_model=Host)
async def get_host(
    host_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Host:
    """Get host details by ID"""
    try:
        # Use centralized UUID validation (eliminates duplication)
        host_uuid = validate_host_uuid(host_id)

        # Use QueryBuilder for parameterized SELECT with JOINs
        logger.info(f"Using QueryBuilder for get_host endpoint (host_id: {sanitize_id_for_log(host_id)})")
        builder = (
            QueryBuilder("hosts h")
            .select(
                "h.id",
                "h.hostname",
                "h.ip_address",
                "h.display_name",
                "h.operating_system",
                "h.status",
                "h.port",
                "h.username",
                "h.auth_method",
                "h.created_at",
                "h.updated_at",
                "h.description",
                "hg.id as group_id",
                "hg.name as group_name",
                "hg.description as group_description",
                "hg.color as group_color",
            )
            .join("host_group_memberships hgm", "hgm.host_id = h.id", "LEFT")
            .join("host_groups hg", "hg.id = hgm.group_id", "LEFT")
            .where("h.id = :id", host_uuid, "id")
        )
        query, params = builder.build()
        result = db.execute(text(query), params)

        row = result.fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Host not found")

        return Host(
            id=str(row.id),
            hostname=row.hostname,
            ip_address=str(row.ip_address),
            display_name=row.display_name,
            operating_system=row.operating_system,
            status=row.status,
            port=row.port,
            username=row.username,
            auth_method=row.auth_method,
            created_at=row.created_at.isoformat() + "Z" if row.created_at else None,
            updated_at=row.updated_at.isoformat() + "Z" if row.updated_at else None,
            ssh_key_fingerprint=None,  # Not in database schema
            ssh_key_type=None,  # Not in database schema
            ssh_key_bits=None,  # Not in database schema
            ssh_key_comment=None,  # Not in database schema
            group_id=row.group_id,
            group_name=row.group_name,
            group_description=row.group_description,
            group_color=row.group_color,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get host: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve host",
        )


@router.put("/{host_id}", response_model=Host)
async def update_host(
    host_id: str,
    host_update: HostUpdate,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Host:
    """Update host information"""
    try:
        # Use centralized UUID validation (eliminates duplication)
        host_uuid = validate_host_uuid(host_id)

        # Verify host exists before updating (QueryBuilder for parameterization)
        check_query_builder = QueryBuilder("hosts").select("id").where("id = :id", host_uuid, "id")
        check_query, check_params = check_query_builder.build()
        result = db.execute(text(check_query), check_params)

        if not result.fetchone():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Host not found")

        # Get current host data for partial update logic
        current_host_builder = (
            QueryBuilder("hosts")
            .select(
                "hostname",
                "ip_address",
                "display_name",
                "operating_system",
                "port",
                "username",
                "auth_method",
                "description",
            )
            .where("id = :id", host_uuid, "id")
        )
        current_host_query, current_host_params = current_host_builder.build()
        current_host_result = db.execute(text(current_host_query), current_host_params)

        current_host = current_host_result.fetchone()
        if not current_host:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Host not found")

        # Update host - use existing values if new ones not provided
        current_time = datetime.utcnow()

        # Handle display_name logic properly
        new_hostname = host_update.hostname if host_update.hostname is not None else current_host.hostname
        new_display_name = (
            host_update.display_name
            if host_update.display_name is not None
            else current_host.display_name or new_hostname
        )

        # Handle credential updates using unified_credentials system
        encrypted_creds = None  # Always NULL for unified system
        if host_update.auth_method:
            from ...services.auth import (
                AuthMethod,
                CredentialData,
                CredentialMetadata,
                CredentialScope,
                get_auth_service,
            )

            auth_service = get_auth_service(db)  # type: ignore[call-arg]

            if host_update.auth_method == "system_default":
                # Delete host-specific credentials when switching to system default
                try:
                    existing_creds = auth_service.list_credentials(scope=CredentialScope.HOST, target_id=str(host_uuid))
                    for cred in existing_creds:
                        auth_service.delete_credential(cred["id"])
                    logger.info(f"Deleted host-specific credentials for system default on host {host_id}")
                except Exception as e:
                    logger.error(f"Failed to delete host-specific credentials: {e}")

            elif host_update.password or host_update.ssh_key:
                # Validate SSH key if provided
                if host_update.ssh_key:
                    logger.info(f"Validating SSH key for host update '{host_id}'")
                    validation_result = validate_ssh_key(host_update.ssh_key)

                    if not validation_result.is_valid:
                        logger.error(
                            f"SSH key validation failed for host update '{host_id}': "
                            f"{validation_result.error_message}"
                        )
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Invalid SSH key: {validation_result.error_message}",
                        )

                    if validation_result.warnings:
                        logger.warning(
                            f"SSH key warnings for host update '{host_id}': " f"{'; '.join(validation_result.warnings)}"
                        )

                # Create credential data
                credential_data = CredentialData(
                    username=host_update.username or current_host.username,
                    auth_method=AuthMethod(host_update.auth_method),
                    password=(host_update.password if host_update.auth_method in ["password", "both"] else None),
                    private_key=(host_update.ssh_key if host_update.auth_method in ["ssh_key", "both"] else None),
                    private_key_passphrase=None,
                )

                # Create metadata
                metadata = CredentialMetadata(
                    name=f"{current_host.hostname} credential",
                    description=f"Host-specific credential for {current_host.hostname}",
                    scope=CredentialScope.HOST,
                    target_id=str(host_uuid),
                    is_default=False,
                )

                # Check if host-specific credential already exists
                try:
                    existing_creds = auth_service.list_credentials(scope=CredentialScope.HOST, target_id=str(host_uuid))

                    # Get user UUID for created_by field (QueryBuilder for parameterization)
                    user_query_builder = (
                        QueryBuilder("users").select("id").where("id = :user_id", current_user.get("id"), "user_id")
                    )
                    user_query, user_params = user_query_builder.build()
                    user_id_result = db.execute(text(user_query), user_params)
                    user_row = user_id_result.fetchone()
                    user_uuid = str(user_row[0]) if user_row else None

                    if existing_creds:
                        # Delete old credential and create new one (simpler than update)
                        for cred in existing_creds:
                            auth_service.delete_credential(cred["id"])
                        logger.info(f"Deleted old host-specific credential for {current_host.hostname}")

                    # Store new credential
                    cred_id = auth_service.store_credential(
                        credential_data=credential_data,
                        metadata=metadata,
                        created_by=user_uuid or "",
                    )
                    logger.info(
                        f"Stored updated host-specific credential for " f"{current_host.hostname} (id: {cred_id})"
                    )

                except Exception as e:
                    logger.error(f"Failed to update host-specific credential: {e}")
                    # Continue with host update even if credential storage fails

        # Update all fields including encrypted credentials
        update_params = {
            "id": host_uuid,
            "hostname": new_hostname,
            "ip_address": (host_update.ip_address if host_update.ip_address is not None else current_host.ip_address),
            "display_name": new_display_name,
            "operating_system": (
                host_update.operating_system
                if host_update.operating_system is not None
                else current_host.operating_system
            ),
            "port": (host_update.port if host_update.port is not None else current_host.port),
            "username": (host_update.username if host_update.username is not None else current_host.username),
            "auth_method": (
                host_update.auth_method if host_update.auth_method is not None else current_host.auth_method
            ),
            "description": (
                host_update.description if host_update.description is not None else current_host.description
            ),
            "updated_at": current_time,
        }

        # Build UPDATE query with conditional encrypted_credentials field
        if encrypted_creds is not None or (host_update.auth_method == "system_default"):
            update_params["encrypted_credentials"] = encrypted_creds

        # NOTE: QueryBuilder is for SELECT queries only (OW-REFACTOR-001B)
        # For INSERT/UPDATE/DELETE, use raw SQL with parameterized queries
        update_query = text(
            """
            UPDATE hosts
            SET hostname = :hostname,
                ip_address = :ip_address,
                display_name = :display_name,
                operating_system = :operating_system,
                port = :port,
                username = :username,
                auth_method = :auth_method,
                description = :description,
                encrypted_credentials = :encrypted_credentials,
                updated_at = :updated_at
            WHERE id = :id
        """
        )

        db.execute(update_query, update_params)

        db.commit()

        # Retrieve updated host with group information for response
        select_query_builder = (
            QueryBuilder("hosts h")
            .select(
                "h.id",
                "h.hostname",
                "h.ip_address",
                "h.display_name",
                "h.operating_system",
                "h.status",
                "h.port",
                "h.username",
                "h.auth_method",
                "h.created_at",
                "h.updated_at",
                "h.description",
                "hg.id as group_id",
                "hg.name as group_name",
                "hg.description as group_description",
                "hg.color as group_color",
            )
            .join("host_group_memberships hgm", "hgm.host_id = h.id", "LEFT")
            .join("host_groups hg", "hg.id = hgm.group_id", "LEFT")
            .where("h.id = :id", host_uuid, "id")
        )
        select_query, select_params = select_query_builder.build()
        result = db.execute(text(select_query), select_params)

        row = result.fetchone()

        # Null guard: fetchone() returns Optional[Row], validate before accessing attributes
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve updated host data",
            )

        updated_host = Host(
            id=str(row.id),
            hostname=row.hostname,
            ip_address=str(row.ip_address),
            display_name=row.display_name,
            operating_system=row.operating_system,
            status=row.status,
            port=row.port,
            username=row.username,
            auth_method=row.auth_method,
            created_at=row.created_at.isoformat() + "Z" if row.created_at else None,
            updated_at=row.updated_at.isoformat() + "Z" if row.updated_at else None,
            ssh_key_fingerprint=None,  # Not in database schema
            ssh_key_type=None,  # Not in database schema
            ssh_key_bits=None,  # Not in database schema
            ssh_key_comment=None,  # Not in database schema
            group_id=row.group_id,
            group_name=row.group_name,
            group_description=row.group_description,
            group_color=row.group_color,
        )

        logger.info(f"Updated host {host_id}")
        return updated_host

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update host: {e}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update host",
        )


@router.delete("/{host_id}")
async def delete_host(
    host_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, str]:
    """Remove host from management"""
    try:
        # Use centralized UUID validation (eliminates duplication)
        host_uuid = validate_host_uuid(host_id)

        # Verify host exists before deleting (QueryBuilder for parameterization)
        check_query_builder = QueryBuilder("hosts").select("id").where("id = :id", host_uuid, "id")
        check_query, check_params = check_query_builder.build()
        result = db.execute(text(check_query), check_params)

        if not result.fetchone():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Host not found")

        # Check if host has scans (for cascade delete)
        count_query_builder = (
            QueryBuilder("scans").select("COUNT(*) as count").where("host_id = :host_id", host_uuid, "host_id")
        )
        count_query, count_params = count_query_builder.build()
        scan_result = db.execute(text(count_query), count_params)

        # Null guard: fetchone() returns Optional[Row], default to 0 if no result
        # Note: Using getattr for type safety since Row.count attribute has complex type
        scan_count_row = scan_result.fetchone()
        scan_count: int = int(getattr(scan_count_row, "count", 0)) if scan_count_row else 0
        if scan_count > 0:
            # Cascade delete: Remove scan_results first (foreign key constraint)
            # Why: Must delete child records before parent to avoid FK violation
            # NOTE: QueryBuilder is for SELECT queries only (OW-REFACTOR-001B)
            # For INSERT/UPDATE/DELETE, use raw SQL with parameterized queries
            delete_results_query = text(
                """
                DELETE FROM scan_results
                WHERE scan_id IN (SELECT id FROM scans WHERE host_id = :host_id)
            """
            )
            db.execute(delete_results_query, {"host_id": host_uuid})

            # Then delete scans
            delete_scans_query = text(
                """
                DELETE FROM scans
                WHERE host_id = :host_id
            """
            )
            db.execute(delete_scans_query, {"host_id": host_uuid})

            logger.info(f"Deleted {scan_count} scans for host {host_id}")

        # Delete the host record
        delete_host_query = text(
            """
            DELETE FROM hosts
            WHERE id = :id
        """
        )
        db.execute(delete_host_query, {"id": host_uuid})

        db.commit()

        logger.info(f"Deleted host {host_id}")
        return {"message": "Host deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete host: {e}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete host",
        )


@router.delete("/{host_id}/ssh-key")
async def delete_host_ssh_key(
    host_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, str]:
    """Delete SSH key from host"""
    try:
        # Use centralized UUID validation (eliminates duplication)
        host_uuid = validate_host_uuid(host_id)

        # Verify host exists and has SSH key to delete
        select_query_builder = (
            QueryBuilder("hosts").select("id", "auth_method", "ssh_key_fingerprint").where("id = :id", host_uuid, "id")
        )
        select_query, select_params = select_query_builder.build()
        result = db.execute(text(select_query), select_params)

        row = result.fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Host not found")

        if not row.ssh_key_fingerprint:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No SSH key found to delete",
            )

        # Clear SSH key fields (set to NULL)
        # NOTE: QueryBuilder is for SELECT queries only (OW-REFACTOR-001B)
        # For INSERT/UPDATE/DELETE, use raw SQL with parameterized queries
        update_query = text(
            """
            UPDATE hosts
            SET ssh_key_fingerprint = NULL,
                ssh_key_type = NULL,
                ssh_key_bits = NULL,
                ssh_key_comment = NULL,
                updated_at = :updated_at
            WHERE id = :id
        """
        )
        db.execute(update_query, {"id": host_uuid, "updated_at": datetime.utcnow()})

        db.commit()

        logger.info(f"Deleted SSH key from host {host_id}")
        return {"message": "SSH key deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete SSH key from host: {e}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete SSH key",
        )


# =============================================================================
# OS DISCOVERY ENDPOINTS
# =============================================================================


@router.post("/{host_id}/discover-os", response_model=OSDiscoveryResponse)
async def trigger_host_os_discovery(
    host_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> OSDiscoveryResponse:
    """
    Trigger OS discovery for a specific host.

    This endpoint queues an asynchronous Celery task to discover the host's
    operating system information via SSH. The discovered os_family, os_version,
    and architecture are used for platform-specific OVAL selection during
    compliance scanning.

    The task performs:
    1. SSH connection to the host using configured credentials
    2. Detection of OS family (rhel, ubuntu, debian, etc.)
    3. Detection of OS version (9.3, 22.04, 12, etc.)
    4. Detection of CPU architecture (x86_64, aarch64)
    5. Normalization to platform identifier (rhel9, ubuntu2204)
    6. Database update with discovered values

    Args:
        host_id: UUID of the host to discover OS information for

    Returns:
        OSDiscoveryResponse with task_id for status tracking

    Raises:
        HTTPException 400: Invalid host ID format
        HTTPException 404: Host not found
        HTTPException 400: Host has no credentials configured
        HTTPException 500: Failed to queue discovery task
    """
    try:
        # Validate host UUID format
        host_uuid = validate_host_uuid(host_id)

        # Verify host exists and check for credentials
        # QueryBuilder for consistent parameterized SELECT
        host_query_builder = (
            QueryBuilder("hosts h")
            .select(
                "h.id",
                "h.hostname",
                "h.ip_address",
                "h.status",
                "h.os_family",
                "h.os_version",
                "h.architecture",
            )
            .where("h.id = :id", host_uuid, "id")
            .where("h.is_active = :is_active", True, "is_active")
        )
        host_query, host_params = host_query_builder.build()
        result = db.execute(text(host_query), host_params)
        host_row = result.fetchone()

        if not host_row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Host not found or inactive",
            )

        # Check if host has credentials configured (unified_credentials table)
        # Must have credentials to perform SSH-based OS discovery
        cred_query_builder = (
            QueryBuilder("unified_credentials")
            .select("id")
            .where("target_id = :target_id", str(host_uuid), "target_id")
            .where("scope = :scope", "host", "scope")
        )
        cred_query, cred_params = cred_query_builder.build()
        cred_result = db.execute(text(cred_query), cred_params)
        cred_row = cred_result.fetchone()

        # Also check for system default credentials as fallback
        if not cred_row:
            system_cred_query_builder = (
                QueryBuilder("unified_credentials")
                .select("id")
                .where("scope = :scope", "system", "scope")
                .where("is_default = :is_default", True, "is_default")
            )
            system_cred_query, system_cred_params = system_cred_query_builder.build()
            system_cred_result = db.execute(text(system_cred_query), system_cred_params)
            cred_row = system_cred_result.fetchone()

        if not cred_row:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No credentials configured for this host. "
                "Configure host-specific or system default credentials first.",
            )

        # Queue OS discovery Celery task
        try:
            from ...tasks.os_discovery_tasks import trigger_os_discovery

            task = trigger_os_discovery.apply_async(
                args=[host_id],
                queue="default",
            )

            logger.info(
                f"Queued OS discovery task {task.id} for host {host_row.hostname} ({host_id}) "
                f"by user {current_user.get('username', 'unknown')}"
            )

            return OSDiscoveryResponse(
                host_id=host_id,
                task_id=task.id,
                status="queued",
                os_family=None,
                os_version=None,
                platform_identifier=None,
                architecture=None,
                discovered_at=None,
                error=None,
            )

        except Exception as task_error:
            logger.error(f"Failed to queue OS discovery task for host {host_id}: {task_error}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to queue OS discovery task. Check Celery worker status.",
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in OS discovery for host {host_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to initiate OS discovery",
        )


@router.get("/{host_id}/os-info", response_model=OSDiscoveryResponse)
async def get_host_os_info(
    host_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> OSDiscoveryResponse:
    """
    Get current OS information for a host.

    Returns the currently stored OS information for a host, including
    os_family, os_version, architecture, and the last discovery timestamp.
    This endpoint does NOT trigger a new discovery - use POST /discover-os
    for that.

    Args:
        host_id: UUID of the host to get OS information for

    Returns:
        OSDiscoveryResponse with current OS information

    Raises:
        HTTPException 400: Invalid host ID format
        HTTPException 404: Host not found
    """
    try:
        # Validate host UUID format
        host_uuid = validate_host_uuid(host_id)

        # Query host OS information
        # Phase 4: Include platform_identifier from database (persisted during OS discovery)
        # QueryBuilder for consistent parameterized SELECT
        host_query_builder = (
            QueryBuilder("hosts")
            .select(
                "id",
                "hostname",
                "os_family",
                "os_version",
                "architecture",
                "platform_identifier",
                "last_os_detection",
            )
            .where("id = :id", host_uuid, "id")
        )
        host_query, host_params = host_query_builder.build()
        result = db.execute(text(host_query), host_params)
        host_row = result.fetchone()

        if not host_row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Host not found",
            )

        # Phase 4: Use platform_identifier from database if available,
        # otherwise compute it on-the-fly for backward compatibility
        platform_identifier = host_row.platform_identifier
        if not platform_identifier and host_row.os_family and host_row.os_version:
            from ...tasks.os_discovery_tasks import _normalize_platform_identifier

            platform_identifier = _normalize_platform_identifier(host_row.os_family, host_row.os_version)

        # Determine status based on whether OS info exists
        if host_row.os_family and host_row.os_version:
            discovery_status = "completed"
        elif host_row.last_os_detection:
            discovery_status = "failed"  # Had detection but no valid OS info
        else:
            discovery_status = "pending"  # Never discovered

        return OSDiscoveryResponse(
            host_id=host_id,
            task_id=None,
            status=discovery_status,
            os_family=host_row.os_family,
            os_version=host_row.os_version,
            platform_identifier=platform_identifier,
            architecture=host_row.architecture,
            discovered_at=(host_row.last_os_detection.isoformat() + "Z" if host_row.last_os_detection else None),
            error=None,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get OS info for host {host_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve host OS information",
        )


@router.post("/{host_id}/detect-platform", response_model=OSDiscoveryResponse)
async def detect_platform_jit(
    host_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> OSDiscoveryResponse:
    """
    Synchronous Just-In-Time platform detection for scan wizard.

    This endpoint performs SYNCHRONOUS platform detection via SSH when
    OS Discovery scheduled task hasn't populated the host's platform data.
    Used by the frontend scan wizard Step 2 for auto-detection.

    Strategy:
    1. Check database for existing os_family/os_version (from OS Discovery)
    2. If found, return immediately (no SSH needed)
    3. If not found, perform JIT detection via SSH using platform_detector.py
    4. Persist results to database for future use
    5. Return detected platform info

    Args:
        host_id: UUID of the host to detect platform for

    Returns:
        OSDiscoveryResponse with platform detection results

    Raises:
        HTTPException 400: Invalid host ID format
        HTTPException 404: Host not found
        HTTPException 400: No credentials configured
        HTTPException 500: Detection failed
    """
    from datetime import datetime

    from ...config import get_settings
    from ...encryption import EncryptionConfig, create_encryption_service
    from ...services.auth import CentralizedAuthService, CredentialNotFoundError
    from ...services.engine.discovery import PlatformDetector
    from ...tasks.os_discovery_tasks import _normalize_platform_identifier

    try:
        # Validate host UUID format
        host_uuid = validate_host_uuid(host_id)

        # Check database for existing platform data first
        host_query_builder = (
            QueryBuilder("hosts h")
            .select(
                "h.id",
                "h.hostname",
                "h.ip_address",
                "h.port",
                "h.username",
                "h.os_family",
                "h.os_version",
                "h.platform_identifier",
                "h.architecture",
                "h.last_os_detection",
            )
            .where("h.id = :id", host_uuid, "id")
            .where("h.is_active = :is_active", True, "is_active")
        )
        host_query, host_params = host_query_builder.build()
        result = db.execute(text(host_query), host_params)
        host_row = result.fetchone()

        if not host_row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Host not found or inactive",
            )

        # If OS Discovery data exists, return it immediately (no SSH needed)
        if host_row.os_family and host_row.os_version:
            platform_id = host_row.platform_identifier
            if not platform_id:
                platform_id = _normalize_platform_identifier(host_row.os_family, host_row.os_version)

            logger.info(
                f"Platform data exists for host {host_id}: "
                f"{host_row.os_family} {host_row.os_version} ({platform_id})"
            )

            return OSDiscoveryResponse(
                host_id=host_id,
                task_id=None,
                status="completed",
                os_family=host_row.os_family,
                os_version=host_row.os_version,
                platform_identifier=platform_id,
                architecture=host_row.architecture,
                discovered_at=(host_row.last_os_detection.isoformat() + "Z" if host_row.last_os_detection else None),
                error=None,
            )

        # No OS Discovery data - perform JIT detection via SSH
        logger.info(f"Performing JIT platform detection for host {host_id}")

        # Resolve credentials using CentralizedAuthService
        # This follows the SSH Connection Best Practices from CLAUDE.md:
        # Credentials are resolved at the API endpoint and passed as CredentialData
        settings = get_settings()
        encryption_service = create_encryption_service(master_key=settings.master_key, config=EncryptionConfig())

        auth_service = CentralizedAuthService(db, encryption_service)
        try:
            credential_data = auth_service.resolve_credential(target_id=str(host_uuid))
        except CredentialNotFoundError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No credentials configured for this host. "
                "Configure host-specific or system default credentials first.",
            )

        if credential_data is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No credentials configured for this host. "
                "Configure host-specific or system default credentials first.",
            )

        # Perform JIT platform detection with pre-resolved CredentialData
        detector = PlatformDetector(db)
        platform_info = await detector.detect(
            hostname=host_row.ip_address or host_row.hostname,
            port=host_row.port or 22,
            credential_data=credential_data,
        )

        if not platform_info.detection_success:
            logger.warning(f"JIT platform detection failed for host {host_id}: " f"{platform_info.detection_error}")
            return OSDiscoveryResponse(
                host_id=host_id,
                task_id=None,
                status="failed",
                os_family=None,
                os_version=None,
                platform_identifier=None,
                architecture=None,
                discovered_at=datetime.utcnow().isoformat() + "Z",
                error=platform_info.detection_error,
            )

        # Persist detected platform to database for future use
        update_query = text(
            """
            UPDATE hosts
            SET os_family = :os_family,
                os_version = :os_version,
                platform_identifier = :platform_identifier,
                architecture = :architecture,
                operating_system = :operating_system,
                last_os_detection = :last_os_detection,
                updated_at = :updated_at
            WHERE id = :host_id
        """
        )
        now = datetime.utcnow()
        db.execute(
            update_query,
            {
                "host_id": host_uuid,
                "os_family": platform_info.platform,
                "os_version": platform_info.platform_version,
                "platform_identifier": platform_info.platform_identifier,
                "architecture": platform_info.architecture,
                "operating_system": platform_info.os_name,
                "last_os_detection": now,
                "updated_at": now,
            },
        )
        db.commit()

        logger.info(
            f"JIT platform detection completed for host {host_id}: "
            f"{platform_info.platform} {platform_info.platform_version} "
            f"({platform_info.platform_identifier})"
        )

        return OSDiscoveryResponse(
            host_id=host_id,
            task_id=None,
            status="completed",
            os_family=platform_info.platform,
            os_version=platform_info.platform_version,
            platform_identifier=platform_info.platform_identifier,
            architecture=platform_info.architecture,
            discovered_at=now.isoformat() + "Z",
            error=None,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"JIT platform detection failed for host {host_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Platform detection failed: {str(e)}",
        )
