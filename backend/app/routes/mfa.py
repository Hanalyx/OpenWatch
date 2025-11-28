"""
MFA (Multi-Factor Authentication) Routes for OpenWatch
FIPS-compliant TOTP and backup code management
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, validator
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..auth import audit_logger, get_current_user
from ..database import MFAAuditLog, MFAUsedCodes, get_db
from ..services.mfa_service import get_mfa_service

logger = logging.getLogger(__name__)
router = APIRouter()
mfa_service = get_mfa_service()


def get_client_ip(request: Request) -> str:
    """Extract client IP address from request"""
    if "x-forwarded-for" in request.headers:
        ip: str = request.headers["x-forwarded-for"].split(",")[0].strip()
        return ip
    return request.client.host if request.client else "unknown"


# Request/Response Models
class MFAEnrollmentRequest(BaseModel):
    """Request to enroll in MFA"""

    verify_password: str


class MFAEnrollmentResponse(BaseModel):
    """Response for MFA enrollment"""

    success: bool
    qr_code: Optional[str] = None
    backup_codes: Optional[List[str]] = None
    error_message: Optional[str] = None

    @validator("backup_codes")
    def mask_sensitive_data(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        # In production, consider not returning backup codes in API response
        # Instead, display them once and require user to save them
        return v


class MFAValidationRequest(BaseModel):
    """Request to validate MFA code"""

    code: str

    @validator("code")
    def validate_code_format(cls, v: str) -> str:
        # Remove spaces and validate format
        code = v.strip().replace(" ", "")
        if not code:
            raise ValueError("MFA code cannot be empty")
        if not (len(code) == 6 and code.isdigit()) and not (len(code) == 8 and code.isalnum()):
            raise ValueError("Invalid MFA code format")
        return code


class MFAStatusResponse(BaseModel):
    """MFA status for user"""

    mfa_enabled: bool
    totp_enabled: bool
    backup_codes_available: int
    last_mfa_use: Optional[datetime] = None
    enrollment_date: Optional[datetime] = None
    supported_methods: List[str]


class BackupCodesRegenerateResponse(BaseModel):
    """Response for backup code regeneration"""

    success: bool
    backup_codes: Optional[List[str]] = None
    error_message: Optional[str] = None


class MFADisableRequest(BaseModel):
    """Request to disable MFA"""

    verify_password: str
    confirm_disable: bool = False


# Audit Logging
def log_mfa_action(
    db: Session,
    user_id: int,
    action: str,
    success: bool,
    ip_address: str,
    user_agent: str,
    method: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """Log MFA action to audit table"""
    try:
        audit_entry = MFAAuditLog(
            user_id=user_id,
            action=action,
            method=method,
            success=success,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details or {},
        )
        db.add(audit_entry)
        db.commit()

        # Also log to security audit logger
        status_text = "SUCCESS" if success else "FAILED"
        audit_logger.log_security_event(
            f"MFA_{action.upper()}_{status_text}",
            f"User {user_id} {action} MFA - Method: {method or 'N/A'}",
            ip_address,
        )
    except Exception as e:
        logger.error(f"Failed to log MFA action: {e}")


@router.get("/status", response_model=MFAStatusResponse)
async def get_mfa_status(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> MFAStatusResponse:
    """Get user's MFA status"""
    try:
        # Get user MFA data from database
        result = db.execute(
            text(
                """
            SELECT mfa_enabled, mfa_secret, backup_codes, last_mfa_use, mfa_enrolled_at
            FROM users WHERE id = :user_id
        """
            ),
            {"user_id": current_user["id"]},
        )

        user_data = result.fetchone()
        if not user_data:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        backup_codes_count = len(user_data.backup_codes) if user_data.backup_codes else 0

        return MFAStatusResponse(
            mfa_enabled=bool(user_data.mfa_enabled),
            totp_enabled=bool(user_data.mfa_secret),
            backup_codes_available=backup_codes_count,
            last_mfa_use=user_data.last_mfa_use,
            enrollment_date=user_data.mfa_enrolled_at,
            supported_methods=["totp", "backup_codes"],
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get MFA status for user {current_user['id']}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve MFA status",
        )


@router.post("/enroll", response_model=MFAEnrollmentResponse)
async def enroll_mfa(
    request: MFAEnrollmentRequest,
    http_request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> MFAEnrollmentResponse:
    """Enroll user in MFA with TOTP and backup codes"""
    client_ip = get_client_ip(http_request)
    user_agent = http_request.headers.get("user-agent", "")

    try:
        # Verify user's password first
        from ..auth import pwd_context

        result = db.execute(
            text(
                """
            SELECT hashed_password, mfa_enabled
            FROM users WHERE id = :user_id
        """
            ),
            {"user_id": current_user["id"]},
        )

        user_data = result.fetchone()
        if not user_data:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        if not pwd_context.verify(request.verify_password, user_data.hashed_password):
            log_mfa_action(
                db,
                current_user["id"],
                "enroll_attempt",
                False,
                client_ip,
                user_agent,
                details={"reason": "invalid_password"},
            )
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password")

        if user_data.mfa_enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA is already enabled for this user",
            )

        # Enroll user in MFA
        enrollment_result = mfa_service.enroll_user_mfa(current_user["username"])

        if not enrollment_result.success:
            log_mfa_action(
                db,
                current_user["id"],
                "enroll",
                False,
                client_ip,
                user_agent,
                details={"error": enrollment_result.error_message},
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=enrollment_result.error_message,
            )

        # Encrypt and store MFA secret
        if enrollment_result.secret_key is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="MFA enrollment failed: no secret key generated",
            )
        encrypted_secret = mfa_service.encrypt_mfa_secret(enrollment_result.secret_key)

        # Hash backup codes for storage
        if enrollment_result.backup_codes is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="MFA enrollment failed: no backup codes generated",
            )
        hashed_backup_codes = [
            mfa_service.hash_backup_code(code) for code in enrollment_result.backup_codes
        ]

        # Update user record
        db.execute(
            text(
                """
            UPDATE users
            SET mfa_secret = :encrypted_secret,
                backup_codes = :backup_codes,
                mfa_enrolled_at = CURRENT_TIMESTAMP,
                mfa_recovery_codes_generated_at = CURRENT_TIMESTAMP
            WHERE id = :user_id
        """
            ),
            {
                "encrypted_secret": encrypted_secret,
                "backup_codes": hashed_backup_codes,
                "user_id": current_user["id"],
            },
        )
        db.commit()

        log_mfa_action(db, current_user["id"], "enroll", True, client_ip, user_agent, method="totp")

        return MFAEnrollmentResponse(
            success=True,
            qr_code=enrollment_result.qr_code_data,
            backup_codes=enrollment_result.backup_codes,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"MFA enrollment failed for user {current_user['id']}: {e}")
        log_mfa_action(
            db,
            current_user["id"],
            "enroll",
            False,
            client_ip,
            user_agent,
            details={"error": str(e)},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="MFA enrollment failed",
        )


@router.post("/validate")
async def validate_mfa_code(
    request: MFAValidationRequest,
    http_request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Validate MFA code for already enrolled user"""
    client_ip = get_client_ip(http_request)
    user_agent = http_request.headers.get("user-agent", "")

    try:
        # Get user MFA data
        result = db.execute(
            text(
                """
            SELECT mfa_enabled, mfa_secret, backup_codes
            FROM users WHERE id = :user_id
        """
            ),
            {"user_id": current_user["id"]},
        )

        user_data = result.fetchone()
        if not user_data or not user_data.mfa_enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA is not enabled for this user",
            )

        # Get recently used codes for replay protection
        recent_codes = db.execute(
            text(
                """
            SELECT code_hash FROM mfa_used_codes
            WHERE user_id = :user_id AND used_at > NOW() - INTERVAL '5 minutes'
        """
            ),
            {"user_id": current_user["id"]},
        ).fetchall()

        used_codes_cache = {row.code_hash for row in recent_codes}

        # Validate MFA code
        validation_result = mfa_service.validate_mfa_code(
            user_data.mfa_secret,
            user_data.backup_codes or [],
            request.code,
            used_codes_cache,
        )

        if validation_result.valid:
            # Update last MFA use
            db.execute(
                text(
                    """
                UPDATE users SET last_mfa_use = CURRENT_TIMESTAMP
                WHERE id = :user_id
            """
                ),
                {"user_id": current_user["id"]},
            )

            # Record used code for replay protection (TOTP only)
            # Null guard: method_used is Optional[MFAMethod], access .value safely
            method_used_value = (
                validation_result.method_used.value if validation_result.method_used else None
            )
            if method_used_value == "totp":
                import hashlib

                code_hash = hashlib.sha256(
                    f"{request.code}_{int(datetime.now().timestamp() // 30)}".encode()
                ).hexdigest()
                used_code = MFAUsedCodes(user_id=current_user["id"], code_hash=code_hash)
                db.add(used_code)

            # Remove used backup code if applicable
            if validation_result.backup_code_used:
                updated_codes = [
                    code
                    for code in user_data.backup_codes
                    if code != validation_result.backup_code_used
                ]
                db.execute(
                    text(
                        """
                    UPDATE users SET backup_codes = :backup_codes
                    WHERE id = :user_id
                """
                    ),
                    {"backup_codes": updated_codes, "user_id": current_user["id"]},
                )

            db.commit()

            log_mfa_action(
                db,
                current_user["id"],
                "validate",
                True,
                client_ip,
                user_agent,
                method=method_used_value,
            )

            return {"success": True, "method": method_used_value}
        else:
            log_mfa_action(
                db,
                current_user["id"],
                "validate",
                False,
                client_ip,
                user_agent,
                details={"error": validation_result.error_message},
            )

            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA code")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"MFA validation failed for user {current_user['id']}: {e}")
        log_mfa_action(
            db,
            current_user["id"],
            "validate",
            False,
            client_ip,
            user_agent,
            details={"error": str(e)},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="MFA validation failed",
        )


@router.post("/enable")
async def enable_mfa(
    request: MFAValidationRequest,
    http_request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Enable MFA after successful enrollment verification"""
    client_ip = get_client_ip(http_request)
    user_agent = http_request.headers.get("user-agent", "")

    try:
        # Verify the TOTP code to confirm enrollment
        result = db.execute(
            text(
                """
            SELECT mfa_enabled, mfa_secret, backup_codes
            FROM users WHERE id = :user_id
        """
            ),
            {"user_id": current_user["id"]},
        )

        user_data = result.fetchone()
        if not user_data or not user_data.mfa_secret:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA enrollment not found. Please enroll first.",
            )

        if user_data.mfa_enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="MFA is already enabled"
            )

        # Validate the provided code
        validation_result = mfa_service.validate_mfa_code(
            user_data.mfa_secret, user_data.backup_codes or [], request.code
        )

        if not validation_result.valid:
            log_mfa_action(
                db,
                current_user["id"],
                "enable_attempt",
                False,
                client_ip,
                user_agent,
                details={"reason": "invalid_code"},
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid MFA code. Please try again.",
            )

        # Enable MFA
        db.execute(
            text(
                """
            UPDATE users
            SET mfa_enabled = true, last_mfa_use = CURRENT_TIMESTAMP
            WHERE id = :user_id
        """
            ),
            {"user_id": current_user["id"]},
        )
        db.commit()

        log_mfa_action(db, current_user["id"], "enable", True, client_ip, user_agent, method="totp")

        return {"success": True, "message": "MFA enabled successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"MFA enable failed for user {current_user['id']}: {e}")
        log_mfa_action(
            db,
            current_user["id"],
            "enable",
            False,
            client_ip,
            user_agent,
            details={"error": str(e)},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to enable MFA",
        )


@router.post("/regenerate-backup-codes", response_model=BackupCodesRegenerateResponse)
async def regenerate_backup_codes(
    request: MFAValidationRequest,
    http_request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> BackupCodesRegenerateResponse:
    """Regenerate backup codes after MFA validation"""
    client_ip = get_client_ip(http_request)
    user_agent = http_request.headers.get("user-agent", "")

    try:
        # Verify user has MFA enabled
        result = db.execute(
            text(
                """
            SELECT mfa_enabled, mfa_secret, backup_codes
            FROM users WHERE id = :user_id
        """
            ),
            {"user_id": current_user["id"]},
        )

        user_data = result.fetchone()
        if not user_data or not user_data.mfa_enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="MFA is not enabled"
            )

        # Validate MFA code first
        validation_result = mfa_service.validate_mfa_code(
            user_data.mfa_secret, user_data.backup_codes or [], request.code
        )

        if not validation_result.valid:
            log_mfa_action(
                db,
                current_user["id"],
                "regenerate_backup_codes",
                False,
                client_ip,
                user_agent,
                details={"reason": "invalid_mfa_code"},
            )
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA code")

        # Generate new backup codes
        new_backup_codes = mfa_service.regenerate_backup_codes(current_user["username"])
        hashed_backup_codes = [mfa_service.hash_backup_code(code) for code in new_backup_codes]

        # Update database
        db.execute(
            text(
                """
            UPDATE users
            SET backup_codes = :backup_codes,
                mfa_recovery_codes_generated_at = CURRENT_TIMESTAMP
            WHERE id = :user_id
        """
            ),
            {"backup_codes": hashed_backup_codes, "user_id": current_user["id"]},
        )
        db.commit()

        log_mfa_action(
            db,
            current_user["id"],
            "regenerate_backup_codes",
            True,
            client_ip,
            user_agent,
            method="backup_codes",
        )

        return BackupCodesRegenerateResponse(success=True, backup_codes=new_backup_codes)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Backup code regeneration failed for user {current_user['id']}: {e}")
        log_mfa_action(
            db,
            current_user["id"],
            "regenerate_backup_codes",
            False,
            client_ip,
            user_agent,
            details={"error": str(e)},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to regenerate backup codes",
        )


@router.post("/disable")
async def disable_mfa(
    request: MFADisableRequest,
    http_request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Disable MFA for user (requires password confirmation)"""
    client_ip = get_client_ip(http_request)
    user_agent = http_request.headers.get("user-agent", "")

    try:
        if not request.confirm_disable:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Must confirm MFA disable action",
            )

        # Verify password
        from ..auth import pwd_context

        result = db.execute(
            text(
                """
            SELECT hashed_password, mfa_enabled
            FROM users WHERE id = :user_id
        """
            ),
            {"user_id": current_user["id"]},
        )

        user_data = result.fetchone()
        if not user_data:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        if not pwd_context.verify(request.verify_password, user_data.hashed_password):
            log_mfa_action(
                db,
                current_user["id"],
                "disable_attempt",
                False,
                client_ip,
                user_agent,
                details={"reason": "invalid_password"},
            )
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password")

        if not user_data.mfa_enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="MFA is not enabled"
            )

        # Disable MFA and clear secrets
        db.execute(
            text(
                """
            UPDATE users
            SET mfa_enabled = false,
                mfa_secret = NULL,
                backup_codes = NULL,
                last_mfa_use = NULL
            WHERE id = :user_id
        """
            ),
            {"user_id": current_user["id"]},
        )

        # Clear used codes
        db.execute(
            text(
                """
            DELETE FROM mfa_used_codes WHERE user_id = :user_id
        """
            ),
            {"user_id": current_user["id"]},
        )

        db.commit()

        log_mfa_action(db, current_user["id"], "disable", True, client_ip, user_agent)

        return {"success": True, "message": "MFA disabled successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"MFA disable failed for user {current_user['id']}: {e}")
        log_mfa_action(
            db,
            current_user["id"],
            "disable",
            False,
            client_ip,
            user_agent,
            details={"error": str(e)},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to disable MFA",
        )
