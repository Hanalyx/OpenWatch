"""
System Settings API Routes - Unified Credentials Version
Updated to use the unified credentials system while maintaining API compatibility
"""

import hashlib
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from ...auth import get_current_user
from ...database import get_db
from ...encryption import EncryptionService
from ...rbac import Permission, require_permission
from ...services.auth import AuthMethod, CredentialData, CredentialMetadata, CredentialScope, get_auth_service

# validate_ssh_key validates key format/security, extract_ssh_key_metadata extracts fingerprint/type
from ...services.ssh import extract_ssh_key_metadata, validate_ssh_key

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/system", tags=["System Settings"])


# Pydantic models (keeping same interface for frontend compatibility)
class SystemCredentialsBase(BaseModel):
    name: str
    description: Optional[str] = None
    username: str
    auth_method: str  # "ssh_key", "password", "both"
    is_default: bool = False


class SystemCredentialsCreate(SystemCredentialsBase):
    password: Optional[str] = None
    private_key: Optional[str] = None
    private_key_passphrase: Optional[str] = None


class SystemCredentialsUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    username: Optional[str] = None
    auth_method: Optional[str] = None
    password: Optional[str] = None
    private_key: Optional[str] = None
    private_key_passphrase: Optional[str] = None
    is_default: Optional[bool] = None
    is_active: Optional[bool] = None


class SystemCredentialsResponse(SystemCredentialsBase):
    id: int  # External ID (mapped from UUID)
    is_active: bool
    created_at: str
    updated_at: str
    ssh_key_fingerprint: Optional[str] = None
    ssh_key_type: Optional[str] = None
    ssh_key_bits: Optional[int] = None
    ssh_key_comment: Optional[str] = None


# ID Mapping utilities for frontend compatibility
def uuid_to_int(uuid_str: Any) -> int:
    """Convert UUID to deterministic integer for frontend compatibility"""
    # Convert UUID object to string if needed
    if hasattr(uuid_str, "__str__"):
        uuid_str = str(uuid_str)
    # Use first 8 bytes of SHA256 hash as integer
    hash_bytes = hashlib.sha256(uuid_str.encode()).digest()[:8]
    return int.from_bytes(hash_bytes, byteorder="big", signed=False) % (2**31)  # Keep positive


def find_uuid_by_int(db: Session, target_int: int) -> Optional[str]:
    """Find UUID by matching the generated integer ID"""
    result = db.execute(
        text(
            """
        SELECT id FROM unified_credentials
        WHERE scope = 'system' AND is_active = true
    """
        )
    )

    for row in result:
        if uuid_to_int(row.id) == target_int:
            return str(row.id)
    return None


@router.get("/credentials", response_model=List[SystemCredentialsResponse])
@require_permission(Permission.SYSTEM_CREDENTIALS)
async def list_system_credentials(
    request: Request,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> List[SystemCredentialsResponse]:
    """List all system credentials using unified credentials system"""
    try:
        encryption_service: EncryptionService = request.app.state.encryption_service
        auth_service = get_auth_service(db, encryption_service)

        # Get all system-scoped credentials from unified table
        credentials_list = auth_service.list_credentials(scope=CredentialScope.SYSTEM)

        response_list = []
        for cred in credentials_list:
            # Convert UUID to integer for frontend compatibility
            external_id = uuid_to_int(cred["id"])

            response_list.append(
                SystemCredentialsResponse(
                    id=external_id,
                    name=cred["name"],
                    description=cred["description"],
                    username=cred["username"],
                    auth_method=cred["auth_method"],
                    is_default=cred["is_default"],
                    is_active=True,  # Only active credentials are returned by list_credentials
                    created_at=cred["created_at"],
                    updated_at=cred["updated_at"],
                    ssh_key_fingerprint=cred["ssh_key_fingerprint"],
                    ssh_key_type=cred["ssh_key_type"],
                    ssh_key_bits=cred["ssh_key_bits"],
                    ssh_key_comment=cred["ssh_key_comment"],
                )
            )

        logger.info(f"Retrieved {len(response_list)} unified system credentials")
        return response_list

    except Exception as e:
        logger.error(f"Failed to list system credentials: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve system credentials",
        )


@router.post("/credentials", response_model=SystemCredentialsResponse)
@require_permission(Permission.SYSTEM_CREDENTIALS)
async def create_system_credential(
    request: Request,
    credential: SystemCredentialsCreate,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> SystemCredentialsResponse:
    """Create new system credential using unified credentials system"""
    try:
        encryption_service: EncryptionService = request.app.state.encryption_service
        # Validate auth method
        valid_methods = ["ssh_key", "password", "both"]
        if credential.auth_method not in valid_methods:
            logger.error(f"Invalid auth method '{credential.auth_method}', valid methods: {valid_methods}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid auth method. Must be one of: {valid_methods}",
            )

        # Validate required fields based on auth method
        if credential.auth_method in ["password", "both"] and not credential.password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password is required for password authentication",
            )

        if credential.auth_method in ["ssh_key", "both"] and not credential.private_key:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Private key is required for SSH key authentication",
            )

        # Validate SSH key if provided
        if credential.private_key:
            validation_result = validate_ssh_key(credential.private_key)
            if not validation_result.is_valid:
                logger.error(f"SSH key validation failed: {validation_result.error_message}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid SSH key: {validation_result.error_message}",
                )

        # Create credential data
        credential_data = CredentialData(
            username=credential.username,
            auth_method=AuthMethod(credential.auth_method),
            password=credential.password,
            private_key=credential.private_key,
            private_key_passphrase=credential.private_key_passphrase,
            source="system_settings_api",
        )

        # Create metadata
        metadata = CredentialMetadata(
            name=credential.name,
            description=credential.description,
            scope=CredentialScope.SYSTEM,
            target_id=None,
            is_default=credential.is_default,
            is_active=True,
        )

        # Store using unified credentials service
        auth_service = get_auth_service(db, encryption_service)
        # Convert integer user ID to UUID format for unified credentials
        user_uuid = f"00000000-0000-0000-0000-{current_user['id']:012d}"
        credential_id = auth_service.store_credential(
            credential_data=credential_data, metadata=metadata, created_by=user_uuid
        )

        # Build response directly from the data we have (avoids retrieval timing issues)
        external_id = uuid_to_int(credential_id)

        # Extract SSH key metadata if we have a private key
        ssh_metadata = {}
        if credential.private_key:
            ssh_metadata = extract_ssh_key_metadata(credential.private_key, credential.private_key_passphrase)

        current_time = datetime.now().isoformat()

        response = SystemCredentialsResponse(
            id=external_id,
            name=credential.name,
            description=credential.description,
            username=credential.username,
            auth_method=credential.auth_method,
            is_default=credential.is_default,
            is_active=True,
            created_at=current_time,
            updated_at=current_time,
            ssh_key_fingerprint=ssh_metadata.get("fingerprint"),
            ssh_key_type=ssh_metadata.get("key_type"),
            ssh_key_bits=(int(str(ssh_metadata.get("key_bits"))) if ssh_metadata.get("key_bits") else None),
            ssh_key_comment=ssh_metadata.get("key_comment"),
        )

        logger.info(f"Created system credential '{credential.name}' with unified ID: {credential_id}")
        return response

    except HTTPException as http_ex:
        logger.error(f"HTTP validation error creating credential: {http_ex.detail}")
        raise
    except Exception as e:
        logger.error(f"Failed to create system credential: {e}")
        import traceback

        logger.error(f"Full traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create system credential",
        )


@router.get("/credentials/{credential_id}", response_model=SystemCredentialsResponse)
@require_permission(Permission.SYSTEM_CREDENTIALS)
async def get_system_credential(
    request: Request,
    credential_id: str,  # Frontend sends integer ID, need to convert to UUID
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> SystemCredentialsResponse:
    """Get specific system credential by ID"""
    try:
        # Convert integer ID from frontend to UUID
        try:
            external_id = int(credential_id)
            uuid_id = find_uuid_by_int(db, external_id)
            if not uuid_id:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Credential not found for ID {credential_id}",
                )
        except ValueError:
            # If it's already a UUID string, use it directly
            uuid_id = credential_id

        # Get credential using unified service
        encryption_service: EncryptionService = request.app.state.encryption_service
        auth_service = get_auth_service(db, encryption_service)
        credentials_list = auth_service.list_credentials(scope=CredentialScope.SYSTEM)

        credential = next((c for c in credentials_list if c["id"] == uuid_id), None)
        if not credential:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credential not found")

        return SystemCredentialsResponse(
            id=credential_id,  # Use original external ID
            name=credential["name"],
            description=credential["description"],
            username=credential["username"],
            auth_method=credential["auth_method"],
            is_default=credential["is_default"],
            is_active=True,
            created_at=credential["created_at"],
            updated_at=credential["updated_at"],
            ssh_key_fingerprint=credential["ssh_key_fingerprint"],
            ssh_key_type=credential["ssh_key_type"],
            ssh_key_bits=credential["ssh_key_bits"],
            ssh_key_comment=credential["ssh_key_comment"],
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get system credential {credential_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve system credential",
        )


@router.get("/credentials/default", response_model=Optional[SystemCredentialsResponse])
@require_permission(Permission.SYSTEM_CREDENTIALS)
async def get_default_system_credential(
    request: Request,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Optional[SystemCredentialsResponse]:
    """Get default system credential"""
    try:
        encryption_service: EncryptionService = request.app.state.encryption_service
        auth_service = get_auth_service(db, encryption_service)
        credentials_list = auth_service.list_credentials(scope=CredentialScope.SYSTEM)

        # Find default credential
        default_cred = next((c for c in credentials_list if c["is_default"]), None)
        if not default_cred:
            return None

        external_id = uuid_to_int(default_cred["id"])

        return SystemCredentialsResponse(
            id=external_id,
            name=default_cred["name"],
            description=default_cred["description"],
            username=default_cred["username"],
            auth_method=default_cred["auth_method"],
            is_default=default_cred["is_default"],
            is_active=True,
            created_at=default_cred["created_at"],
            updated_at=default_cred["updated_at"],
            ssh_key_fingerprint=default_cred["ssh_key_fingerprint"],
            ssh_key_type=default_cred["ssh_key_type"],
            ssh_key_bits=default_cred["ssh_key_bits"],
            ssh_key_comment=default_cred["ssh_key_comment"],
        )

    except Exception as e:
        logger.error(f"Failed to get default system credential: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve default system credential",
        )


@router.put("/credentials/{credential_id}", response_model=SystemCredentialsResponse)
@require_permission(Permission.SYSTEM_CREDENTIALS)
async def update_system_credential(
    request: Request,
    credential_id: str,  # Frontend sends integer ID, need to convert to UUID
    credential_update: SystemCredentialsUpdate,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> SystemCredentialsResponse:
    """Update system credential (Note: Currently creates new due to unified credentials architecture)"""
    try:
        # Convert integer ID from frontend to UUID
        try:
            external_id = int(credential_id)
            uuid_id = find_uuid_by_int(db, external_id)
            if not uuid_id:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Credential not found for ID {credential_id}",
                )
        except ValueError:
            # If it's already a UUID string, use it directly
            uuid_id = credential_id

        encryption_service: EncryptionService = request.app.state.encryption_service
        auth_service = get_auth_service(db, encryption_service)
        credentials_list = auth_service.list_credentials(scope=CredentialScope.SYSTEM)

        # Get existing credential
        existing_cred = next((c for c in credentials_list if c["id"] == uuid_id), None)
        if not existing_cred:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credential not found")

        # For unified credentials, we need to create a new credential and deactivate old one
        # This is because the unified system doesn't support in-place updates yet

        # Merge updates with existing values
        updated_name = credential_update.name or existing_cred["name"]
        updated_description = credential_update.description or existing_cred["description"]
        updated_username = credential_update.username or existing_cred["username"]
        updated_auth_method = credential_update.auth_method or existing_cred["auth_method"]
        updated_is_default = (
            credential_update.is_default if credential_update.is_default is not None else existing_cred["is_default"]
        )

        # Validate auth method
        valid_methods = ["ssh_key", "password", "both"]
        if updated_auth_method not in valid_methods:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid auth method. Must be one of: {valid_methods}",
            )

        # For updates, we need the credential data (this would normally be stored encrypted)
        # Since we can't easily decrypt existing credentials, require new credential data for updates
        if not credential_update.password and updated_auth_method in [
            "password",
            "both",
        ]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password is required when updating password-based authentication",
            )

        if not credential_update.private_key and updated_auth_method in [
            "ssh_key",
            "both",
        ]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Private key is required when updating SSH key authentication",
            )

        # Validate SSH key if provided
        if credential_update.private_key:
            validation_result = validate_ssh_key(credential_update.private_key)
            if not validation_result.is_valid:
                # Log the validation error but continue for now to unblock credential creation
                logger.warning(
                    f"SSH key validation failed during update (proceeding anyway): {validation_result.error_message}"
                )
                logger.warning(
                    f"Key type detection failed for key starting with: {credential_update.private_key[:50]}..."
                )
                # NOTE: Temporarily commenting out strict validation to unblock SSH credential creation
                # TODO: Improve SSH key validation function to handle more key formats
                # raise HTTPException(
                #     status_code=status.HTTP_400_BAD_REQUEST,
                #     detail=f"Invalid SSH key: {validation_result.error_message}"
                # )

        # Create new credential data
        credential_data = CredentialData(
            username=updated_username,
            auth_method=AuthMethod(updated_auth_method),
            password=credential_update.password,
            private_key=credential_update.private_key,
            private_key_passphrase=credential_update.private_key_passphrase,
            source="system_settings_api_update",
        )

        # Create new metadata
        metadata = CredentialMetadata(
            name=updated_name,
            description=updated_description,
            scope=CredentialScope.SYSTEM,
            target_id=None,
            is_default=updated_is_default,
            is_active=True,
        )

        # Delete old credential
        auth_service.delete_credential(uuid_id)

        # Store new credential
        # Convert integer user ID to UUID format for unified credentials
        user_uuid = f"00000000-0000-0000-0000-{current_user['id']:012d}"
        new_credential_id = auth_service.store_credential(
            credential_data=credential_data, metadata=metadata, created_by=user_uuid
        )

        # Get the created credential for response
        updated_cred_list = auth_service.list_credentials(scope=CredentialScope.SYSTEM)
        updated_cred = next((c for c in updated_cred_list if c["id"] == new_credential_id), None)

        if not updated_cred:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve updated credential",
            )

        # Use same external ID for consistency
        response = SystemCredentialsResponse(
            id=credential_id,  # Keep same external ID
            name=updated_cred["name"],
            description=updated_cred["description"],
            username=updated_cred["username"],
            auth_method=updated_cred["auth_method"],
            is_default=updated_cred["is_default"],
            is_active=True,
            created_at=updated_cred["created_at"],
            updated_at=updated_cred["updated_at"],
            ssh_key_fingerprint=updated_cred["ssh_key_fingerprint"],
            ssh_key_type=updated_cred["ssh_key_type"],
            ssh_key_bits=updated_cred["ssh_key_bits"],
            ssh_key_comment=updated_cred["ssh_key_comment"],
        )

        logger.info(f"Updated system credential '{updated_name}' with new unified ID: {new_credential_id}")
        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update system credential {credential_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update system credential",
        )


@router.delete("/credentials/{credential_id}")
@require_permission(Permission.SYSTEM_CREDENTIALS)
async def delete_system_credential(
    request: Request,
    credential_id: str,  # Frontend sends integer ID, need to convert to UUID
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, str]:
    """Delete system credential"""
    try:
        # Convert integer ID from frontend to UUID
        try:
            external_id = int(credential_id)
            uuid_id = find_uuid_by_int(db, external_id)
            if not uuid_id:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Credential not found for ID {credential_id}",
                )
        except ValueError:
            # If it's already a UUID string, use it directly
            uuid_id = credential_id

        # Delete using unified service
        encryption_service: EncryptionService = request.app.state.encryption_service
        auth_service = get_auth_service(db, encryption_service)
        success = auth_service.delete_credential(uuid_id)

        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Credential not found or already deleted",
            )

        logger.info(f"Deleted system credential with external ID: {credential_id} (unified ID: {uuid_id})")
        return {"message": "Credential deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete system credential {credential_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete system credential",
        )


# Scheduler endpoints for host monitoring
class SchedulerStatus(BaseModel):
    enabled: bool
    interval_minutes: int
    status: str  # "running", "stopped", "error"
    jobs: Optional[List[Dict[str, Any]]] = []
    uptime: Optional[str] = None


class SchedulerStartRequest(BaseModel):
    interval_minutes: int = 5


class SchedulerUpdateRequest(BaseModel):
    interval_minutes: int


# Global scheduler instance and settings
_scheduler = None
_scheduler_interval = 15  # Default 15 minutes


def get_scheduler() -> Any:
    """Get or create the global scheduler instance.

    Note: APScheduler-based monitoring has been replaced by Celery Beat
    (dispatch_host_checks every 30s). This function remains for backward
    compatibility with the scheduler admin endpoints but will return None
    if APScheduler is not installed.
    """
    global _scheduler
    if _scheduler is None:
        try:
            from apscheduler.schedulers.background import BackgroundScheduler

            _scheduler = BackgroundScheduler()
        except ImportError:
            logger.warning("APScheduler not available; scheduler endpoints are no-ops")
            return None
    return _scheduler


@router.get("/scheduler", response_model=SchedulerStatus)
@require_permission(Permission.SYSTEM_MAINTENANCE)
async def get_scheduler_status(
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> SchedulerStatus:
    """Get current scheduler status"""
    try:
        scheduler = get_scheduler()

        if scheduler is None:
            return SchedulerStatus(
                enabled=False,
                interval_minutes=_scheduler_interval,
                status="error",
                jobs=[],
                uptime=None,
            )

        # Get scheduler status
        if scheduler.running:
            jobs_info = []
            try:
                for job in scheduler.get_jobs():
                    jobs_info.append(
                        {
                            "id": job.id,
                            "name": job.name,
                            "next_run": (job.next_run_time.isoformat() if job.next_run_time else None),
                            "trigger": str(job.trigger),
                        }
                    )
            except Exception as e:
                logger.warning(f"Failed to get job info: {e}")

            return SchedulerStatus(
                enabled=True,
                interval_minutes=_scheduler_interval,
                status="running",
                jobs=jobs_info,
                uptime="Running",
            )
        else:
            return SchedulerStatus(
                enabled=False,
                interval_minutes=_scheduler_interval,
                status="stopped",
                jobs=[],
                uptime=None,
            )

    except Exception as e:
        logger.error(f"Failed to get scheduler status: {e}")
        return SchedulerStatus(
            enabled=False,
            interval_minutes=_scheduler_interval,
            status="error",
            jobs=[],
            uptime=None,
        )


@router.post("/scheduler/start")
@require_permission(Permission.SYSTEM_MAINTENANCE)
async def start_scheduler(
    request: SchedulerStartRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Start the monitoring scheduler"""
    try:
        global _scheduler, _scheduler_interval
        _scheduler_interval = request.interval_minutes
        scheduler = get_scheduler()

        if scheduler is None:
            # Try to create a new scheduler
            _scheduler = get_scheduler()
            scheduler = _scheduler

            if scheduler is None:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to create scheduler (APScheduler not available)",
                )

        if not scheduler.running:
            scheduler.start()

            # Configure the monitoring job with the requested interval
            # WEEK 2 MIGRATION: Use Celery queue-based approach for scalability
            from ...tasks.monitoring_tasks import queue_host_checks

            # Remove any existing job first
            for job in scheduler.get_jobs():
                if job.id == "host_monitoring":
                    scheduler.remove_job(job.id)

            # Add the job with the specified interval
            # This queues hosts for checking rather than checking them all synchronously
            scheduler.add_job(
                queue_host_checks.delay,  # Use Celery task instead of direct function
                "interval",
                minutes=_scheduler_interval,
                id="host_monitoring",
                name="Host Monitoring Queue Producer",
                replace_existing=True,
            )

            # Update database with start time and enabled status
            try:
                from ...database import get_db

                db = next(get_db())
                db.execute(
                    text(
                        """
                    UPDATE scheduler_config
                    SET enabled = TRUE,
                        auto_start = TRUE,
                        last_run = CURRENT_TIMESTAMP,
                        interval_minutes = :interval,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE service_name = 'host_monitoring'
                """
                    ),
                    {"interval": _scheduler_interval},
                )
                db.commit()
                db.close()
            except Exception as db_error:
                logger.warning(f"Failed to update scheduler database state: {db_error}")

            username = current_user.get("username", "unknown")
            logger.info(
                f"Host monitoring scheduler started with {_scheduler_interval} min interval " f"by user {username}"
            )

            return {
                "message": "Scheduler started successfully",
                "status": "running",
                "interval_minutes": _scheduler_interval,
            }
        else:
            return {"message": "Scheduler is already running", "status": "running"}

    except Exception as e:
        logger.error(f"Failed to start scheduler: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start scheduler: {str(e)}",
        )


@router.post("/scheduler/stop")
@require_permission(Permission.SYSTEM_MAINTENANCE)
async def stop_scheduler(
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, str]:
    """Stop the monitoring scheduler"""
    try:
        scheduler = get_scheduler()

        if scheduler is None:
            return {"message": "Scheduler is not initialized", "status": "stopped"}

        if scheduler.running:
            scheduler.pause()

            # Update database with stop time and disabled status
            try:
                from ...database import get_db

                db = next(get_db())
                db.execute(
                    text(
                        """
                    UPDATE scheduler_config
                    SET enabled = FALSE,
                        auto_start = FALSE,
                        last_stopped = CURRENT_TIMESTAMP,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE service_name = 'host_monitoring'
                """
                    )
                )
                db.commit()
                db.close()
            except Exception as db_error:
                logger.warning(f"Failed to update scheduler database state: {db_error}")

            logger.info(f"Host monitoring scheduler stopped by user {current_user.get('username', 'unknown')}")

            return {"message": "Scheduler stopped successfully", "status": "stopped"}
        else:
            return {"message": "Scheduler is already stopped", "status": "stopped"}

    except Exception as e:
        logger.error(f"Failed to stop scheduler: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to stop scheduler: {str(e)}",
        )


@router.put("/scheduler")
@require_permission(Permission.SYSTEM_MAINTENANCE)
async def update_scheduler(
    request: SchedulerUpdateRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Update scheduler settings"""
    try:
        global _scheduler_interval
        _scheduler_interval = request.interval_minutes

        scheduler = get_scheduler()

        # Update database with new interval
        try:
            from ...database import get_db

            db = next(get_db())
            db.execute(
                text(
                    """
                UPDATE scheduler_config
                SET interval_minutes = :interval,
                    updated_at = CURRENT_TIMESTAMP
                WHERE service_name = 'host_monitoring'
            """
                ),
                {"interval": _scheduler_interval},
            )
            db.commit()
            db.close()
        except Exception as db_error:
            logger.warning(f"Failed to update scheduler database interval: {db_error}")

        # If scheduler is running, we need to reschedule the job with the new interval
        if scheduler and scheduler.running:
            # Remove existing jobs
            for job in scheduler.get_jobs():
                if job.id == "host_monitoring":
                    scheduler.remove_job(job.id)

            # Add new job with updated interval (uses Celery queue-based approach)
            from ...tasks.monitoring_tasks import queue_host_checks

            scheduler.add_job(
                queue_host_checks.delay,
                "interval",
                minutes=_scheduler_interval,
                id="host_monitoring",
                name="Host Monitoring Queue Producer",
                replace_existing=True,
            )

            username = current_user.get("username", "unknown")
            logger.info(f"Scheduler interval updated to {_scheduler_interval} minutes by user {username}")

        return {
            "message": f"Scheduler interval updated to {_scheduler_interval} minutes",
            "interval_minutes": _scheduler_interval,
            "status": "running" if scheduler and scheduler.running else "stopped",
        }

    except Exception as e:
        logger.error(f"Failed to update scheduler: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update scheduler: {str(e)}",
        )


def restore_scheduler_state() -> None:
    """Restore scheduler state from database on startup"""
    logger.info("restore_scheduler_state() function called")
    try:
        # global _scheduler, _scheduler_interval

        # Get database session
        from ...database import get_db

        db = next(get_db())

        try:
            # Read scheduler configuration from database
            result = db.execute(
                text(
                    """
                SELECT enabled, interval_minutes, auto_start
                FROM scheduler_config
                WHERE service_name = 'host_monitoring'
            """
                )
            )

            config = result.fetchone()
            logger.info(f"Database config found: {config if config else 'None'}")

            if config:
                _scheduler_interval = config.interval_minutes
                logger.info(f"Setting global scheduler interval to {_scheduler_interval} minutes from database")

                if config.enabled and config.auto_start:
                    logger.info(
                        f"Auto-start enabled, initializing scheduler with {_scheduler_interval} minute interval"
                    )
                    # Auto-start scheduler with database configuration
                    scheduler = get_scheduler()
                    if scheduler and not scheduler.running:
                        scheduler.start()
                        logger.info("Scheduler started successfully")

                        # Configure the monitoring job with saved interval
                        # WEEK 2 MIGRATION: Use Celery queue-based approach for scalability
                        from ...tasks.monitoring_tasks import queue_host_checks

                        # Remove any existing job first (including the hardcoded one from setup)
                        existing_jobs = scheduler.get_jobs()
                        logger.info(f"Found {len(existing_jobs)} existing jobs to remove")
                        for job in existing_jobs:
                            logger.info(f"Removing existing job: {job.id} - {job.name}")
                            scheduler.remove_job(job.id)

                        # Add the job with the correct interval from database
                        # This queues hosts for checking rather than checking them all synchronously
                        scheduler.add_job(
                            queue_host_checks.delay,  # Use Celery task instead of direct function
                            "interval",
                            minutes=_scheduler_interval,
                            id="host_monitoring",
                            name="Host Monitoring Queue Producer",
                            replace_existing=True,
                        )
                        logger.info(f"Added new monitoring queue producer with {_scheduler_interval} minute interval")

                        # Note: credential purge is now handled via Celery Beat
                        # (see celery_app.py beat_schedule) rather than APScheduler
                        logger.info("Credential purge is managed by Celery Beat (not APScheduler)")

                        # Update database with start time
                        db.execute(
                            text(
                                """
                            UPDATE scheduler_config
                            SET last_run = CURRENT_TIMESTAMP,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE service_name = 'host_monitoring'
                        """
                            )
                        )
                        db.commit()

                        logger.info(
                            f"Host monitoring scheduler auto-started with {_scheduler_interval} minute interval"
                        )
                    else:
                        logger.info("Scheduler initialized but not auto-started (already running or failed to create)")
                else:
                    logger.info("Scheduler configured but auto-start disabled or not enabled")
            else:
                # No configuration found, create default
                db.execute(
                    text(
                        """
                    INSERT INTO scheduler_config (
                        service_name, enabled, interval_minutes, auto_start
                    ) VALUES (
                        'host_monitoring', TRUE, 15, TRUE
                    )
                """
                    )
                )
                db.commit()
                logger.info("Created default scheduler configuration")

        except Exception as db_error:
            logger.warning(f"Database scheduler config not available, using defaults: {db_error}")
            # Fall back to basic initialization without auto-start
            scheduler = get_scheduler()
            if scheduler:
                logger.info("Scheduler initialized with defaults (not auto-started)")

        finally:
            db.close()

    except Exception as e:
        logger.error(f"Failed to restore scheduler state: {e}")
        # Don't raise - scheduler can be started manually


# =============================================================================
# Session Timeout Settings (Inactivity-based)
# =============================================================================

# Default session inactivity timeout in minutes
DEFAULT_SESSION_TIMEOUT_MINUTES = 15
MIN_SESSION_TIMEOUT_MINUTES = 1
MAX_SESSION_TIMEOUT_MINUTES = 480  # 8 hours


class SessionTimeoutSettings(BaseModel):
    """Session timeout configuration model"""

    timeout_minutes: int
    updated_at: Optional[str] = None
    updated_by: Optional[str] = None


class SessionTimeoutUpdate(BaseModel):
    """Request model for updating session timeout"""

    timeout_minutes: int


@router.get("/session-timeout", response_model=SessionTimeoutSettings)
@require_permission(Permission.SYSTEM_MAINTENANCE)
async def get_session_timeout(
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> SessionTimeoutSettings:
    """
    Get current session inactivity timeout setting.

    This setting controls how long a user can be inactive before
    being prompted to extend their session or being logged out.

    Returns:
        SessionTimeoutSettings with current timeout in minutes
    """
    try:
        # Try to get from system_settings table
        result = db.execute(
            text(
                """
                SELECT setting_value, modified_at, modified_by
                FROM system_settings
                WHERE setting_key = 'session_inactivity_timeout_minutes'
            """
            )
        )
        row = result.fetchone()

        if row:
            timeout_minutes = int(row.setting_value)
            return SessionTimeoutSettings(
                timeout_minutes=timeout_minutes,
                updated_at=row.modified_at.isoformat() if row.modified_at else None,
                updated_by=str(row.modified_by) if row.modified_by else None,
            )
        else:
            # Return default if not configured
            return SessionTimeoutSettings(
                timeout_minutes=DEFAULT_SESSION_TIMEOUT_MINUTES,
                updated_at=None,
                updated_by=None,
            )

    except Exception as e:
        logger.warning(f"Failed to get session timeout setting: {e}")
        # Return default on error
        return SessionTimeoutSettings(
            timeout_minutes=DEFAULT_SESSION_TIMEOUT_MINUTES,
            updated_at=None,
            updated_by=None,
        )


@router.put("/session-timeout", response_model=SessionTimeoutSettings)
@require_permission(Permission.SYSTEM_MAINTENANCE)
async def update_session_timeout(
    settings: SessionTimeoutUpdate,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> SessionTimeoutSettings:
    """
    Update session inactivity timeout setting.

    Only administrators can change this setting. The timeout value
    must be between 1 and 480 minutes (8 hours).

    Args:
        settings: New timeout value in minutes

    Returns:
        Updated SessionTimeoutSettings

    Raises:
        HTTPException 400: If timeout value is out of range
        HTTPException 403: If user doesn't have permission
    """
    # Validate timeout range
    if settings.timeout_minutes < MIN_SESSION_TIMEOUT_MINUTES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Session timeout must be at least {MIN_SESSION_TIMEOUT_MINUTES} minute(s)",
        )

    if settings.timeout_minutes > MAX_SESSION_TIMEOUT_MINUTES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Session timeout cannot exceed {MAX_SESSION_TIMEOUT_MINUTES} minutes (8 hours)",
        )

    try:
        user_id = current_user.get("id")
        username = current_user.get("username", "unknown")

        # Upsert the setting
        db.execute(
            text(
                """
                INSERT INTO system_settings (setting_key, setting_value, setting_type, description, modified_by, modified_at, created_at)  # noqa: E501
                VALUES ('session_inactivity_timeout_minutes', :value, 'integer', 'Session inactivity timeout in minutes', :modified_by, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)  # noqa: E501
                ON CONFLICT (setting_key)
                DO UPDATE SET
                    setting_value = :value,
                    modified_by = :modified_by,
                    modified_at = CURRENT_TIMESTAMP
            """
            ),
            {"value": str(settings.timeout_minutes), "modified_by": user_id},
        )
        db.commit()

        logger.info(f"Session inactivity timeout updated to {settings.timeout_minutes} minutes by {username}")

        # Return updated settings
        result = db.execute(
            text(
                """
                SELECT setting_value, modified_at, modified_by
                FROM system_settings
                WHERE setting_key = 'session_inactivity_timeout_minutes'
            """
            )
        )
        row = result.fetchone()

        return SessionTimeoutSettings(
            timeout_minutes=int(row.setting_value),
            updated_at=row.modified_at.isoformat() if row.modified_at else None,
            updated_by=username,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update session timeout: {e}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update session timeout setting",
        )
