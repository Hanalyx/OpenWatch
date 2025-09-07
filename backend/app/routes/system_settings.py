"""
System Settings API Routes
Handles system-wide configuration including SSH credentials
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import List, Optional
from pydantic import BaseModel
import logging
from datetime import datetime

from ..database import get_db
from ..auth import get_current_user
from ..rbac import require_permission, Permission
from ..services.encryption import encrypt_data, decrypt_data
from ..services.ssh_utils import validate_ssh_key, format_validation_message
from ..services.ssh_key_service import extract_ssh_key_metadata
from ..tasks.monitoring_tasks import setup_host_monitoring_scheduler

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/system", tags=["System Settings"])


# Pydantic models
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
    id: int
    is_active: bool
    created_at: str
    updated_at: str
    ssh_key_fingerprint: Optional[str] = None
    ssh_key_type: Optional[str] = None
    ssh_key_bits: Optional[int] = None
    ssh_key_comment: Optional[str] = None


@router.get("/credentials", response_model=List[SystemCredentialsResponse])
@require_permission(Permission.SYSTEM_CREDENTIALS)
async def list_system_credentials(
    db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)
):
    """List all system credentials (admin only)"""
    try:

        result = db.execute(
            text(
                """
            SELECT id, name, description, username, auth_method, is_default, 
                   is_active, created_at, updated_at, ssh_key_fingerprint,
                   ssh_key_type, ssh_key_bits, ssh_key_comment
            FROM system_credentials 
            WHERE is_active = true
            ORDER BY is_default DESC, name ASC
        """
            )
        )

        credentials = []
        for row in result:
            credentials.append(
                SystemCredentialsResponse(
                    id=row.id,
                    name=row.name,
                    description=row.description,
                    username=row.username,
                    auth_method=row.auth_method,
                    is_default=row.is_default,
                    is_active=row.is_active,
                    created_at=row.created_at.isoformat(),
                    updated_at=row.updated_at.isoformat(),
                    ssh_key_fingerprint=row.ssh_key_fingerprint,
                    ssh_key_type=row.ssh_key_type,
                    ssh_key_bits=row.ssh_key_bits,
                    ssh_key_comment=row.ssh_key_comment,
                )
            )

        return credentials

    except Exception as e:
        logger.error(f"Error listing system credentials: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve system credentials")


@router.post("/credentials", response_model=SystemCredentialsResponse)
@require_permission(Permission.SYSTEM_CREDENTIALS)
async def create_system_credentials(
    credentials: SystemCredentialsCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Create new system credentials (admin only)"""
    try:

        # If setting as default, unset other defaults
        if credentials.is_default:
            db.execute(
                text(
                    """
                UPDATE system_credentials SET is_default = false WHERE is_default = true
            """
                )
            )

        # Validate SSH key if provided
        if credentials.private_key and credentials.auth_method in ["ssh_key", "both"]:
            logger.info(f"Validating SSH key for system credentials '{credentials.name}'")
            validation_result = validate_ssh_key(credentials.private_key)

            if not validation_result.is_valid:
                logger.error(
                    f"SSH key validation failed for system credentials '{credentials.name}': {validation_result.error_message}"
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid SSH key: {validation_result.error_message}",
                )

            # Log warnings if any
            if validation_result.warnings:
                logger.warning(
                    f"SSH key warnings for system credentials '{credentials.name}': {'; '.join(validation_result.warnings)}"
                )

            # Log recommendations
            if validation_result.recommendations:
                logger.info(
                    f"SSH key recommendations for system credentials '{credentials.name}': {'; '.join(validation_result.recommendations)}"
                )

        # Extract SSH key metadata for storage and display
        ssh_key_fingerprint = None
        ssh_key_type = None
        ssh_key_bits = None
        ssh_key_comment = None

        if credentials.private_key:
            metadata = extract_ssh_key_metadata(
                credentials.private_key, credentials.private_key_passphrase
            )
            ssh_key_fingerprint = metadata.get("fingerprint")
            ssh_key_type = metadata.get("key_type")
            ssh_key_bits = int(metadata.get("key_bits")) if metadata.get("key_bits") else None
            ssh_key_comment = metadata.get("key_comment")

            if metadata.get("error"):
                logger.warning(
                    f"Failed to extract SSH key metadata for '{credentials.name}': {metadata.get('error')}"
                )

        # Encrypt sensitive data
        encrypted_password = None
        encrypted_private_key = None
        encrypted_passphrase = None

        if credentials.password:
            encrypted_password = encrypt_data(credentials.password.encode())
        if credentials.private_key:
            encrypted_private_key = encrypt_data(credentials.private_key.encode())
        if credentials.private_key_passphrase:
            encrypted_passphrase = encrypt_data(credentials.private_key_passphrase.encode())

        current_time = datetime.utcnow()

        # Insert credentials
        result = db.execute(
            text(
                """
            INSERT INTO system_credentials 
            (name, description, username, auth_method, encrypted_password, 
             encrypted_private_key, private_key_passphrase, ssh_key_fingerprint,
             ssh_key_type, ssh_key_bits, ssh_key_comment, is_default, is_active, 
             created_by, created_at, updated_at)
            VALUES (:name, :description, :username, :auth_method, :encrypted_password,
                    :encrypted_private_key, :private_key_passphrase, :ssh_key_fingerprint,
                    :ssh_key_type, :ssh_key_bits, :ssh_key_comment, :is_default, :is_active,
                    :created_by, :created_at, :updated_at)
            RETURNING id
        """
            ),
            {
                "name": credentials.name,
                "description": credentials.description,
                "username": credentials.username,
                "auth_method": credentials.auth_method,
                "encrypted_password": encrypted_password,
                "encrypted_private_key": encrypted_private_key,
                "private_key_passphrase": encrypted_passphrase,
                "ssh_key_fingerprint": ssh_key_fingerprint,
                "ssh_key_type": ssh_key_type,
                "ssh_key_bits": ssh_key_bits,
                "ssh_key_comment": ssh_key_comment,
                "is_default": credentials.is_default,
                "is_active": True,
                "created_by": current_user.get("id"),
                "created_at": current_time,
                "updated_at": current_time,
            },
        )

        credential_id = result.fetchone().id
        db.commit()

        logger.info(f"Created system credentials '{credentials.name}' (ID: {credential_id})")

        return SystemCredentialsResponse(
            id=credential_id,
            name=credentials.name,
            description=credentials.description,
            username=credentials.username,
            auth_method=credentials.auth_method,
            is_default=credentials.is_default,
            is_active=True,
            created_at=current_time.isoformat(),
            updated_at=current_time.isoformat(),
            ssh_key_fingerprint=ssh_key_fingerprint,
            ssh_key_type=ssh_key_type,
            ssh_key_bits=ssh_key_bits,
            ssh_key_comment=ssh_key_comment,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating system credentials: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create system credentials")


@router.get("/credentials/default")
async def get_default_credentials(
    db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)
):
    """Get default system credentials for internal use"""
    try:
        result = db.execute(
            text(
                """
            SELECT id, name, username, auth_method, encrypted_password, 
                   encrypted_private_key, private_key_passphrase
            FROM system_credentials 
            WHERE is_default = true AND is_active = true
            LIMIT 1
        """
            )
        )

        row = result.fetchone()
        if not row:
            return None

        # Decrypt credentials for internal use
        password = None
        private_key = None
        passphrase = None

        if row.encrypted_password:
            encrypted_pw = row.encrypted_password
            if isinstance(encrypted_pw, memoryview):
                encrypted_pw = encrypted_pw.tobytes().decode("utf-8")
            password = decrypt_data(encrypted_pw).decode()
        if row.encrypted_private_key:
            encrypted_key = row.encrypted_private_key
            if isinstance(encrypted_key, memoryview):
                encrypted_key = encrypted_key.tobytes().decode("utf-8")
            private_key = decrypt_data(encrypted_key).decode()
        if row.private_key_passphrase:
            encrypted_phrase = row.private_key_passphrase
            if isinstance(encrypted_phrase, memoryview):
                encrypted_phrase = encrypted_phrase.tobytes().decode("utf-8")
            passphrase = decrypt_data(encrypted_phrase).decode()

        return {
            "id": row.id,
            "name": row.name,
            "username": row.username,
            "auth_method": row.auth_method,
            "password": password,
            "private_key": private_key,
            "private_key_passphrase": passphrase,
        }

    except Exception as e:
        logger.error(f"Error getting default credentials: {e}")
        return None


@router.put("/credentials/{credential_id}", response_model=SystemCredentialsResponse)
@require_permission(Permission.SYSTEM_CREDENTIALS)
async def update_system_credentials(
    credential_id: int,
    credentials: SystemCredentialsUpdate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Update system credentials (admin only)"""
    try:

        # Check if credentials exist
        result = db.execute(
            text(
                """
            SELECT id FROM system_credentials WHERE id = :id
        """
            ),
            {"id": credential_id},
        )

        if not result.fetchone():
            raise HTTPException(status_code=404, detail="Credentials not found")

        # If setting as default, unset other defaults
        if credentials.is_default:
            db.execute(
                text(
                    """
                UPDATE system_credentials SET is_default = false WHERE is_default = true
            """
                )
            )

        # Validate SSH key if provided
        if credentials.private_key and credentials.auth_method in ["ssh_key", "both"]:
            logger.info(f"Validating SSH key for system credentials update (ID: {credential_id})")
            validation_result = validate_ssh_key(credentials.private_key)

            if not validation_result.is_valid:
                logger.error(
                    f"SSH key validation failed for system credentials update (ID: {credential_id}): {validation_result.error_message}"
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid SSH key: {validation_result.error_message}",
                )

            # Log warnings if any
            if validation_result.warnings:
                logger.warning(
                    f"SSH key warnings for system credentials update (ID: {credential_id}): {'; '.join(validation_result.warnings)}"
                )

            # Log recommendations
            if validation_result.recommendations:
                logger.info(
                    f"SSH key recommendations for system credentials update (ID: {credential_id}): {'; '.join(validation_result.recommendations)}"
                )

        # Extract SSH key metadata if private key is being updated
        ssh_key_fingerprint = None
        ssh_key_type = None
        ssh_key_bits = None
        ssh_key_comment = None

        if credentials.private_key:
            metadata = extract_ssh_key_metadata(
                credentials.private_key, credentials.private_key_passphrase
            )
            ssh_key_fingerprint = metadata.get("fingerprint")
            ssh_key_type = metadata.get("key_type")
            ssh_key_bits = int(metadata.get("key_bits")) if metadata.get("key_bits") else None
            ssh_key_comment = metadata.get("key_comment")

            if metadata.get("error"):
                logger.warning(
                    f"Failed to extract SSH key metadata for update (ID: {credential_id}): {metadata.get('error')}"
                )

        # Build update query dynamically
        updates = []
        params = {"id": credential_id, "updated_at": datetime.utcnow()}

        if credentials.name is not None:
            updates.append("name = :name")
            params["name"] = credentials.name
        if credentials.description is not None:
            updates.append("description = :description")
            params["description"] = credentials.description
        if credentials.username is not None:
            updates.append("username = :username")
            params["username"] = credentials.username
        if credentials.auth_method is not None:
            updates.append("auth_method = :auth_method")
            params["auth_method"] = credentials.auth_method
        if credentials.is_default is not None:
            updates.append("is_default = :is_default")
            params["is_default"] = credentials.is_default
        if credentials.is_active is not None:
            updates.append("is_active = :is_active")
            params["is_active"] = credentials.is_active

        # Handle encrypted fields
        if credentials.password is not None:
            updates.append("encrypted_password = :encrypted_password")
            params["encrypted_password"] = (
                encrypt_data(credentials.password.encode()) if credentials.password else None
            )
        if credentials.private_key is not None:
            updates.append("encrypted_private_key = :encrypted_private_key")
            params["encrypted_private_key"] = (
                encrypt_data(credentials.private_key.encode()) if credentials.private_key else None
            )
            # Update SSH key metadata when private key changes
            updates.append("ssh_key_fingerprint = :ssh_key_fingerprint")
            params["ssh_key_fingerprint"] = ssh_key_fingerprint if credentials.private_key else None
            updates.append("ssh_key_type = :ssh_key_type")
            params["ssh_key_type"] = ssh_key_type if credentials.private_key else None
            updates.append("ssh_key_bits = :ssh_key_bits")
            params["ssh_key_bits"] = ssh_key_bits if credentials.private_key else None
            updates.append("ssh_key_comment = :ssh_key_comment")
            params["ssh_key_comment"] = ssh_key_comment if credentials.private_key else None
        if credentials.private_key_passphrase is not None:
            updates.append("private_key_passphrase = :private_key_passphrase")
            params["private_key_passphrase"] = (
                encrypt_data(credentials.private_key_passphrase.encode())
                if credentials.private_key_passphrase
                else None
            )

        if updates:
            updates.append("updated_at = :updated_at")
            # Security Fix: Use safe string concatenation instead of f-string
            query = "UPDATE system_credentials SET " + ", ".join(updates) + " WHERE id = :id"
            db.execute(text(query), params)
            db.commit()

        # Return updated credentials
        result = db.execute(
            text(
                """
            SELECT id, name, description, username, auth_method, is_default, 
                   is_active, created_at, updated_at, ssh_key_fingerprint,
                   ssh_key_type, ssh_key_bits, ssh_key_comment
            FROM system_credentials WHERE id = :id
        """
            ),
            {"id": credential_id},
        )

        row = result.fetchone()
        return SystemCredentialsResponse(
            id=row.id,
            name=row.name,
            description=row.description,
            username=row.username,
            auth_method=row.auth_method,
            is_default=row.is_default,
            is_active=row.is_active,
            created_at=row.created_at.isoformat(),
            updated_at=row.updated_at.isoformat(),
            ssh_key_fingerprint=row.ssh_key_fingerprint,
            ssh_key_type=row.ssh_key_type,
            ssh_key_bits=row.ssh_key_bits,
            ssh_key_comment=row.ssh_key_comment,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating system credentials: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to update system credentials")


@router.delete("/credentials/{credential_id}")
@require_permission(Permission.SYSTEM_CREDENTIALS)
async def delete_system_credentials(
    credential_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Delete system credentials (admin only)"""
    try:

        # Check if credentials exist
        result = db.execute(
            text(
                """
            SELECT id, is_default FROM system_credentials WHERE id = :id
        """
            ),
            {"id": credential_id},
        )

        row = result.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Credentials not found")

        # Prevent deletion of default credentials if it's the only one
        if row.is_default:
            count_result = db.execute(
                text(
                    """
                SELECT COUNT(*) as count FROM system_credentials WHERE is_active = true
            """
                )
            )
            if count_result.fetchone().count <= 1:
                raise HTTPException(
                    status_code=400, detail="Cannot delete the last active credential set"
                )

        # Soft delete (mark as inactive)
        db.execute(
            text(
                """
            UPDATE system_credentials SET is_active = false, updated_at = :updated_at 
            WHERE id = :id
        """
            ),
            {"id": credential_id, "updated_at": datetime.utcnow()},
        )

        db.commit()

        logger.info(f"Deleted system credentials ID: {credential_id}")
        return {"message": "Credentials deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting system credentials: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to delete system credentials")


@router.delete("/credentials/{credential_id}/ssh-key")
@require_permission(Permission.SYSTEM_CREDENTIALS)
async def delete_ssh_key_from_credentials(
    credential_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Delete SSH key from system credentials (admin only)"""
    try:

        # Check if credentials exist and have SSH key
        result = db.execute(
            text(
                """
            SELECT id, auth_method, ssh_key_fingerprint FROM system_credentials 
            WHERE id = :id AND is_active = true
        """
            ),
            {"id": credential_id},
        )

        row = result.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Credentials not found")

        if not row.ssh_key_fingerprint:
            raise HTTPException(status_code=400, detail="No SSH key found to delete")

        # Check if this would leave the credential with no authentication method
        if row.auth_method == "ssh_key":
            raise HTTPException(
                status_code=400,
                detail="Cannot delete SSH key - it's the only authentication method. Update to use password authentication first.",
            )

        # Remove SSH key and update auth method if necessary
        new_auth_method = "password" if row.auth_method == "both" else row.auth_method

        db.execute(
            text(
                """
            UPDATE system_credentials SET 
                encrypted_private_key = NULL,
                private_key_passphrase = NULL,
                ssh_key_fingerprint = NULL,
                ssh_key_type = NULL,
                ssh_key_bits = NULL,
                ssh_key_comment = NULL,
                auth_method = :auth_method,
                updated_at = :updated_at
            WHERE id = :id
        """
            ),
            {"id": credential_id, "auth_method": new_auth_method, "updated_at": datetime.utcnow()},
        )

        db.commit()

        logger.info(f"Deleted SSH key from system credentials ID: {credential_id}")
        return {"message": "SSH key deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting SSH key from credentials: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to delete SSH key")


# Global scheduler instance
scheduler_instance = None


def restore_scheduler_state():
    """
    Restore scheduler state from database on application startup
    """
    global scheduler_instance

    try:
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy import text
        from ..database import engine

        # Create a session to check scheduler state
        SessionLocal = sessionmaker(bind=engine)
        db = SessionLocal()

        try:
            # Check if scheduler was previously enabled
            result = db.execute(
                text(
                    """
                SELECT setting_value FROM system_settings 
                WHERE setting_key = 'scheduler_enabled' AND setting_value = 'true'
            """
                )
            )

            was_enabled = result.fetchone() is not None

            if was_enabled:
                # Get the interval setting
                result = db.execute(
                    text(
                        """
                    SELECT setting_value FROM system_settings 
                    WHERE setting_key = 'scheduler_interval_minutes'
                """
                    )
                )
                row = result.fetchone()
                interval_minutes = int(row.setting_value) if row else 5

                # Start the scheduler
                from apscheduler.schedulers.background import BackgroundScheduler
                from ..tasks.monitoring_tasks import periodic_host_monitoring
                import atexit

                scheduler_instance = BackgroundScheduler()
                scheduler_instance.add_job(
                    func=periodic_host_monitoring,
                    trigger="interval",
                    minutes=interval_minutes,
                    id="host_monitoring",
                    name="Monitor host availability",
                )
                scheduler_instance.start()

                # Shut down the scheduler when exiting the app
                atexit.register(
                    lambda: scheduler_instance.shutdown() if scheduler_instance else None
                )

                logger.info(
                    f"Host monitoring scheduler restored (every {interval_minutes} minutes)"
                )
            else:
                logger.info("Scheduler was not previously enabled, staying stopped")

        finally:
            db.close()

    except Exception as e:
        logger.warning(f"Failed to restore scheduler state: {e}")
        # Don't raise - this is optional initialization


# Scheduler models
class SchedulerSettings(BaseModel):
    enabled: bool
    interval_minutes: int
    status: str


class SchedulerUpdateRequest(BaseModel):
    interval_minutes: int


class SchedulerStartRequest(BaseModel):
    interval_minutes: int


# Alert Settings models
class AlertSettingsBase(BaseModel):
    alert_type: str
    enabled: bool = True
    email_enabled: bool = False
    email_addresses: List[str] = []
    webhook_url: Optional[str] = None
    webhook_enabled: bool = False


class AlertSettingsCreate(AlertSettingsBase):
    pass


class AlertSettingsUpdate(BaseModel):
    enabled: Optional[bool] = None
    email_enabled: Optional[bool] = None
    email_addresses: Optional[List[str]] = None
    webhook_url: Optional[str] = None
    webhook_enabled: Optional[bool] = None


class AlertSettingsResponse(AlertSettingsBase):
    id: int
    user_id: int
    created_at: str
    updated_at: str


@router.get("/scheduler", response_model=SchedulerSettings)
async def get_scheduler_settings(
    db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)
):
    """Get current scheduler settings"""
    try:
        global scheduler_instance

        # Check if scheduler is running
        is_running = scheduler_instance is not None and scheduler_instance.running

        # Get enabled state from database (fallback to runtime state)
        enabled_from_db = False
        try:
            result = db.execute(
                text(
                    """
                SELECT setting_value FROM system_settings 
                WHERE setting_key = 'scheduler_enabled'
            """
                )
            )
            row = result.fetchone()
            enabled_from_db = row and row.setting_value == "true"
        except:
            pass

        # Use database state if available, otherwise fall back to runtime state
        is_enabled = enabled_from_db if enabled_from_db is not None else is_running

        # Get settings from database or use defaults
        try:
            result = db.execute(
                text(
                    """
                SELECT setting_value FROM system_settings 
                WHERE setting_key = 'scheduler_interval_minutes'
            """
                )
            )
            row = result.fetchone()
            interval_minutes = int(row.setting_value) if row else 5
        except:
            interval_minutes = 5

        return SchedulerSettings(
            enabled=is_enabled,
            interval_minutes=interval_minutes,
            status="running" if is_running else "stopped",
        )

    except Exception as e:
        logger.error(f"Error getting scheduler settings: {e}")
        raise HTTPException(status_code=500, detail="Failed to get scheduler settings")


@router.post("/scheduler/start")
@require_permission(Permission.SYSTEM_CONFIG)
async def start_scheduler(
    request: SchedulerStartRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Start the host monitoring scheduler"""
    try:
        global scheduler_instance

        # Stop existing scheduler if running
        if scheduler_instance and scheduler_instance.running:
            scheduler_instance.shutdown()
            scheduler_instance = None

        # Save interval setting to database
        try:
            # Create system_settings table if it doesn't exist
            db.execute(
                text(
                    """
                CREATE TABLE IF NOT EXISTS system_settings (
                    id SERIAL PRIMARY KEY,
                    setting_key VARCHAR(255) UNIQUE NOT NULL,
                    setting_value TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
                )
            )

            # Insert or update the interval setting
            db.execute(
                text(
                    """
                INSERT INTO system_settings (setting_key, setting_value, updated_at)
                VALUES ('scheduler_interval_minutes', :interval, :updated_at)
                ON CONFLICT (setting_key) 
                DO UPDATE SET setting_value = :interval, updated_at = :updated_at
            """
                ),
                {"interval": str(request.interval_minutes), "updated_at": datetime.utcnow()},
            )

            # Save enabled state
            db.execute(
                text(
                    """
                INSERT INTO system_settings (setting_key, setting_value, updated_at)
                VALUES ('scheduler_enabled', 'true', :updated_at)
                ON CONFLICT (setting_key) 
                DO UPDATE SET setting_value = 'true', updated_at = :updated_at
            """
                ),
                {"updated_at": datetime.utcnow()},
            )
            db.commit()
        except Exception as db_error:
            logger.warning(f"Failed to save scheduler settings to database: {db_error}")

        # Start new scheduler with custom interval
        from apscheduler.schedulers.background import BackgroundScheduler
        from ..tasks.monitoring_tasks import periodic_host_monitoring
        import atexit

        scheduler_instance = BackgroundScheduler()
        scheduler_instance.add_job(
            func=periodic_host_monitoring,
            trigger="interval",
            minutes=request.interval_minutes,
            id="host_monitoring",
            name="Monitor host availability",
        )
        scheduler_instance.start()

        # Shut down the scheduler when exiting the app
        atexit.register(lambda: scheduler_instance.shutdown() if scheduler_instance else None)

        logger.info(f"Host monitoring scheduler started (every {request.interval_minutes} minutes)")
        return {
            "message": f"Scheduler started successfully (every {request.interval_minutes} minutes)"
        }

    except Exception as e:
        logger.error(f"Error starting scheduler: {e}")
        raise HTTPException(status_code=500, detail="Failed to start scheduler")


@router.post("/scheduler/stop")
@require_permission(Permission.SYSTEM_CONFIG)
async def stop_scheduler(
    db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)
):
    """Stop the host monitoring scheduler"""
    try:
        global scheduler_instance

        # Save disabled state to database
        try:
            db.execute(
                text(
                    """
                INSERT INTO system_settings (setting_key, setting_value, updated_at)
                VALUES ('scheduler_enabled', 'false', :updated_at)
                ON CONFLICT (setting_key) 
                DO UPDATE SET setting_value = 'false', updated_at = :updated_at
            """
                ),
                {"updated_at": datetime.utcnow()},
            )
            db.commit()
        except Exception as db_error:
            logger.warning(f"Failed to save scheduler disabled state to database: {db_error}")

        if scheduler_instance and scheduler_instance.running:
            scheduler_instance.shutdown()
            scheduler_instance = None
            logger.info("Host monitoring scheduler stopped")
            return {"message": "Scheduler stopped successfully"}
        else:
            return {"message": "Scheduler was not running"}

    except Exception as e:
        logger.error(f"Error stopping scheduler: {e}")
        raise HTTPException(status_code=500, detail="Failed to stop scheduler")


@router.put("/scheduler", response_model=SchedulerSettings)
@require_permission(Permission.SYSTEM_CONFIG)
async def update_scheduler_settings(
    request: SchedulerUpdateRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Update scheduler settings"""
    try:
        global scheduler_instance

        # Save new interval to database
        try:
            db.execute(
                text(
                    """
                INSERT INTO system_settings (setting_key, setting_value, updated_at)
                VALUES ('scheduler_interval_minutes', :interval, :updated_at)
                ON CONFLICT (setting_key) 
                DO UPDATE SET setting_value = :interval, updated_at = :updated_at
            """
                ),
                {"interval": str(request.interval_minutes), "updated_at": datetime.utcnow()},
            )
            db.commit()
        except Exception as db_error:
            logger.warning(f"Failed to save scheduler settings to database: {db_error}")

        # If scheduler is running, restart it with new interval
        was_running = scheduler_instance is not None and scheduler_instance.running

        if was_running:
            # Stop current scheduler
            scheduler_instance.shutdown()
            scheduler_instance = None

            # Start with new interval
            from apscheduler.schedulers.background import BackgroundScheduler
            from ..tasks.monitoring_tasks import periodic_host_monitoring
            import atexit

            scheduler_instance = BackgroundScheduler()
            scheduler_instance.add_job(
                func=periodic_host_monitoring,
                trigger="interval",
                minutes=request.interval_minutes,
                id="host_monitoring",
                name="Monitor host availability",
            )
            scheduler_instance.start()

            atexit.register(lambda: scheduler_instance.shutdown() if scheduler_instance else None)
            logger.info(
                f"Scheduler restarted with new interval: {request.interval_minutes} minutes"
            )

        return SchedulerSettings(
            enabled=was_running,
            interval_minutes=request.interval_minutes,
            status="running" if was_running else "stopped",
        )

    except Exception as e:
        logger.error(f"Error updating scheduler settings: {e}")
        raise HTTPException(status_code=500, detail="Failed to update scheduler settings")


# Alert Settings endpoints
@router.get("/alerts", response_model=List[AlertSettingsResponse])
@require_permission(Permission.SYSTEM_CONFIG)
async def list_alert_settings(
    db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)
):
    """List all alert settings for the current user"""
    try:
        user_id = current_user.get("id")
        result = db.execute(
            text(
                """
            SELECT id, user_id, alert_type, enabled, email_enabled, email_addresses,
                   webhook_url, webhook_enabled, created_at, updated_at
            FROM alert_settings 
            WHERE user_id = :user_id
            ORDER BY alert_type
        """
            ),
            {"user_id": user_id},
        )

        settings = []
        for row in result:
            settings.append(
                AlertSettingsResponse(
                    id=row.id,
                    user_id=row.user_id,
                    alert_type=row.alert_type,
                    enabled=row.enabled,
                    email_enabled=row.email_enabled,
                    email_addresses=row.email_addresses or [],
                    webhook_url=row.webhook_url,
                    webhook_enabled=row.webhook_enabled,
                    created_at=row.created_at.isoformat(),
                    updated_at=row.updated_at.isoformat(),
                )
            )

        return settings

    except Exception as e:
        logger.error(f"Error listing alert settings: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve alert settings")


@router.post("/alerts", response_model=AlertSettingsResponse)
@require_permission(Permission.SYSTEM_CONFIG)
async def create_alert_settings(
    alert_settings: AlertSettingsCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Create new alert settings"""
    try:
        user_id = current_user.get("id")
        current_time = datetime.utcnow()

        # Insert or update alert settings
        result = db.execute(
            text(
                """
            INSERT INTO alert_settings 
            (user_id, alert_type, enabled, email_enabled, email_addresses, 
             webhook_url, webhook_enabled, created_at, updated_at)
            VALUES (:user_id, :alert_type, :enabled, :email_enabled, :email_addresses,
                    :webhook_url, :webhook_enabled, :created_at, :updated_at)
            ON CONFLICT (user_id, alert_type) 
            DO UPDATE SET 
                enabled = :enabled,
                email_enabled = :email_enabled,
                email_addresses = :email_addresses,
                webhook_url = :webhook_url,
                webhook_enabled = :webhook_enabled,
                updated_at = :updated_at
            RETURNING id
        """
            ),
            {
                "user_id": user_id,
                "alert_type": alert_settings.alert_type,
                "enabled": alert_settings.enabled,
                "email_enabled": alert_settings.email_enabled,
                "email_addresses": alert_settings.email_addresses,
                "webhook_url": alert_settings.webhook_url,
                "webhook_enabled": alert_settings.webhook_enabled,
                "created_at": current_time,
                "updated_at": current_time,
            },
        )

        setting_id = result.fetchone().id
        db.commit()

        logger.info(
            f"Created/updated alert settings for {alert_settings.alert_type} (ID: {setting_id})"
        )

        return AlertSettingsResponse(
            id=setting_id,
            user_id=user_id,
            alert_type=alert_settings.alert_type,
            enabled=alert_settings.enabled,
            email_enabled=alert_settings.email_enabled,
            email_addresses=alert_settings.email_addresses,
            webhook_url=alert_settings.webhook_url,
            webhook_enabled=alert_settings.webhook_enabled,
            created_at=current_time.isoformat(),
            updated_at=current_time.isoformat(),
        )

    except Exception as e:
        logger.error(f"Error creating alert settings: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create alert settings")


@router.put("/alerts/{alert_id}", response_model=AlertSettingsResponse)
@require_permission(Permission.SYSTEM_CONFIG)
async def update_alert_settings(
    alert_id: int,
    alert_settings: AlertSettingsUpdate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Update existing alert settings"""
    try:
        user_id = current_user.get("id")

        # Check if alert settings exist and belong to user
        result = db.execute(
            text(
                """
            SELECT id FROM alert_settings 
            WHERE id = :id AND user_id = :user_id
        """
            ),
            {"id": alert_id, "user_id": user_id},
        )

        if not result.fetchone():
            raise HTTPException(status_code=404, detail="Alert settings not found")

        # Build update query dynamically
        updates = []
        params = {"id": alert_id, "updated_at": datetime.utcnow()}

        if alert_settings.enabled is not None:
            updates.append("enabled = :enabled")
            params["enabled"] = alert_settings.enabled
        if alert_settings.email_enabled is not None:
            updates.append("email_enabled = :email_enabled")
            params["email_enabled"] = alert_settings.email_enabled
        if alert_settings.email_addresses is not None:
            updates.append("email_addresses = :email_addresses")
            params["email_addresses"] = alert_settings.email_addresses
        if alert_settings.webhook_url is not None:
            updates.append("webhook_url = :webhook_url")
            params["webhook_url"] = alert_settings.webhook_url
        if alert_settings.webhook_enabled is not None:
            updates.append("webhook_enabled = :webhook_enabled")
            params["webhook_enabled"] = alert_settings.webhook_enabled

        if updates:
            updates.append("updated_at = :updated_at")
            # Security Fix: Use safe string concatenation instead of f-string
            query = "UPDATE alert_settings SET " + ", ".join(updates) + " WHERE id = :id"
            db.execute(text(query), params)
            db.commit()

        # Return updated settings
        result = db.execute(
            text(
                """
            SELECT id, user_id, alert_type, enabled, email_enabled, email_addresses,
                   webhook_url, webhook_enabled, created_at, updated_at
            FROM alert_settings WHERE id = :id
        """
            ),
            {"id": alert_id},
        )

        row = result.fetchone()
        return AlertSettingsResponse(
            id=row.id,
            user_id=row.user_id,
            alert_type=row.alert_type,
            enabled=row.enabled,
            email_enabled=row.email_enabled,
            email_addresses=row.email_addresses or [],
            webhook_url=row.webhook_url,
            webhook_enabled=row.webhook_enabled,
            created_at=row.created_at.isoformat(),
            updated_at=row.updated_at.isoformat(),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating alert settings: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to update alert settings")
