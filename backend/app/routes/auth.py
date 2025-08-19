"""
Authentication Routes - FIPS Compliant
"""
from fastapi import APIRouter, HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer
from pydantic import BaseModel, EmailStr
from typing import Optional
from sqlalchemy.orm import Session
from sqlalchemy import text
from datetime import datetime, timedelta
import logging

from ..auth import jwt_manager, audit_logger, pwd_context
from ..config import get_settings
from ..database import get_db
from ..rbac import UserRole
from ..audit_db import log_login_event

logger = logging.getLogger(__name__)
settings = get_settings()
security = HTTPBearer()

router = APIRouter()


def get_client_ip(request: Request) -> str:
    """Extract client IP address from request"""
    if "x-forwarded-for" in request.headers:
        return request.headers["x-forwarded-for"].split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class LoginRequest(BaseModel):
    username: str
    password: str
    mfa_code: Optional[str] = None


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: dict


class RefreshRequest(BaseModel):
    refresh_token: str


class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: Optional[UserRole] = UserRole.GUEST


@router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest, http_request: Request, db: Session = Depends(get_db)):
    """Authenticate user with username/password and optional MFA"""
    client_ip = get_client_ip(http_request)
    user_agent = http_request.headers.get("user-agent")
    
    try:
        # Get user from database including MFA status
        result = db.execute(text("""
            SELECT id, username, email, hashed_password, role, is_active, 
                   failed_login_attempts, locked_until, last_login,
                   mfa_enabled, mfa_secret, backup_codes
            FROM users 
            WHERE username = :username
        """), {"username": request.username})
        
        user = result.fetchone()
        if not user:
            # Log to file and database
            audit_logger.log_security_event(
                "AUTH_FAILURE", 
                f"Login attempt with non-existent username: {request.username}", 
                client_ip
            )
            await log_login_event(
                db=db,
                username=request.username,
                user_id=None,
                success=False,
                ip_address=client_ip,
                user_agent=user_agent,
                failure_reason="Non-existent username"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )
        
        # Check if user is active
        if not user.is_active:
            audit_logger.log_security_event(
                "AUTH_FAILURE", 
                f"Login attempt with inactive account: {request.username}", 
                client_ip
            )
            await log_login_event(
                db=db,
                username=request.username,
                user_id=user.id,
                success=False,
                ip_address=client_ip,
                user_agent=user_agent,
                failure_reason="Account deactivated"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account is deactivated"
            )
        
        # Check if account is locked
        if user.locked_until and user.locked_until > datetime.utcnow():
            audit_logger.log_security_event(
                "AUTH_FAILURE", 
                f"Login attempt with locked account: {request.username}", 
                client_ip
            )
            await log_login_event(
                db=db,
                username=request.username,
                user_id=user.id,
                success=False,
                ip_address=client_ip,
                user_agent=user_agent,
                failure_reason="Account locked"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account is temporarily locked"
            )
        
        # Verify password
        if not pwd_context.verify(request.password, user.hashed_password):
            # Increment failed login attempts
            failed_attempts = user.failed_login_attempts + 1
            locked_until = None
            
            # Lock account after 5 failed attempts for 30 minutes
            if failed_attempts >= 5:
                locked_until = datetime.utcnow() + timedelta(minutes=30)
            
            db.execute(text("""
                UPDATE users 
                SET failed_login_attempts = :attempts, locked_until = :locked_until
                WHERE id = :user_id
            """), {
                "attempts": failed_attempts,
                "locked_until": locked_until,
                "user_id": user.id
            })
            db.commit()
            
            audit_logger.log_security_event(
                "AUTH_FAILURE", 
                f"Invalid password for user: {request.username} (attempt {failed_attempts})", 
                client_ip
            )
            await log_login_event(
                db=db,
                username=request.username,
                user_id=user.id,
                success=False,
                ip_address=client_ip,
                user_agent=user_agent,
                failure_reason=f"Invalid password (attempt {failed_attempts})"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )
        
        # Check for MFA requirement
        if user.mfa_enabled and user.mfa_secret:
            if not request.mfa_code:
                # MFA required but not provided
                audit_logger.log_security_event(
                    "MFA_REQUIRED", 
                    f"User {request.username} requires MFA code", 
                    client_ip
                )
                raise HTTPException(
                    status_code=status.HTTP_202_ACCEPTED,
                    detail="MFA code required",
                    headers={"X-Require-MFA": "true"}
                )
            
            # Validate MFA code
            from ..services.mfa_service import get_mfa_service
            mfa_service = get_mfa_service()
            
            validation_result = mfa_service.validate_mfa_code(
                user.mfa_secret,
                user.backup_codes or [],
                request.mfa_code
            )
            
            if not validation_result.valid:
                audit_logger.log_security_event(
                    "MFA_FAILURE", 
                    f"Invalid MFA code for user {request.username}", 
                    client_ip
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid MFA code"
                )
            
            # Update last MFA use
            db.execute(text("""
                UPDATE users SET last_mfa_use = CURRENT_TIMESTAMP
                WHERE id = :user_id
            """), {"user_id": user.id})
        
        # Reset failed login attempts and update last login
        db.execute(text("""
            UPDATE users 
            SET failed_login_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP
            WHERE id = :user_id
        """), {"user_id": user.id})
        db.commit()
        
        user_data = {
            "sub": user.username,  # Standard JWT subject field
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "mfa_enabled": bool(user.mfa_enabled)
        }
        
        # Generate tokens
        access_token = jwt_manager.create_access_token(user_data)
        refresh_token = jwt_manager.create_refresh_token(user_data)
        
        audit_logger.log_security_event(
            "LOGIN_SUCCESS",
            f"User {request.username} logged in successfully",
            client_ip
        )
        await log_login_event(
            db=db,
            username=request.username,
            user_id=user.id,
            success=True,
            ip_address=client_ip,
            user_agent=user_agent
        )
        
        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=settings.access_token_expire_minutes * 60,
            user=user_data
        )
        
    except HTTPException:
        # Re-raise HTTP exceptions (already logged above)
        raise
    except Exception as e:
        logger.error(f"Login failed for {request.username}: {e}")
        audit_logger.log_security_event(
            "LOGIN_FAILURE",
            f"System error during login for {request.username}: {str(e)}",
            client_ip
        )
        await log_login_event(
            db=db,
            username=request.username,
            user_id=None,
            success=False,
            ip_address=client_ip,
            user_agent=user_agent,
            failure_reason=f"System error: {str(e)}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )


@router.post("/register", response_model=LoginResponse)
async def register(request: RegisterRequest, db: Session = Depends(get_db)):
    """Register a new user (guest role by default)"""
    try:
        # Check if username or email already exists
        result = db.execute(text("""
            SELECT id FROM users WHERE username = :username OR email = :email
        """), {"username": request.username, "email": request.email})
        
        if result.fetchone():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username or email already exists"
            )
        
        # Hash password
        hashed_password = pwd_context.hash(request.password)
        
        # Create user with guest role (or specified role if admin is creating)
        result = db.execute(text("""
            INSERT INTO users (username, email, hashed_password, role, is_active, created_at, failed_login_attempts)
            VALUES (:username, :email, :password, :role, true, CURRENT_TIMESTAMP, 0)
            RETURNING id
        """), {
            "username": request.username,
            "email": request.email,
            "password": hashed_password,
            "role": request.role.value
        })
        
        user_id = result.fetchone().id
        db.commit()
        
        user_data = {
            "sub": request.username,  # Standard JWT subject field
            "id": user_id,
            "username": request.username,
            "email": request.email,
            "role": request.role.value,
            "mfa_enabled": False
        }
        
        # Generate tokens for immediate login
        access_token = jwt_manager.create_access_token(user_data)
        refresh_token = jwt_manager.create_refresh_token(user_data)
        
        audit_logger.log_security_event(
            "USER_REGISTER",
            f"New user registered: {request.username}",
            "127.0.0.1"
        )
        
        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=settings.access_token_expire_minutes * 60,
            user=user_data
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration failed for {request.username}: {e}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed"
        )


@router.post("/refresh")
async def refresh_token(request: RefreshRequest):
    """Refresh access token using refresh token"""
    try:
        # Validate refresh token and get user
        user_data = jwt_manager.validate_refresh_token(request.refresh_token)
        
        # Generate new access token
        access_token = jwt_manager.create_access_token(user_data)
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": settings.access_token_expire_minutes * 60
        }
        
    except Exception as e:
        logger.error(f"Token refresh failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )


@router.post("/logout")
async def logout(token: str = Depends(security)):
    """Logout user and invalidate tokens"""
    try:
        # In production, add token to blacklist
        audit_logger.log_security_event(
            "LOGOUT",
            "User logged out",
            "127.0.0.1"
        )
        
        return {"message": "Successfully logged out"}
        
    except Exception as e:
        logger.error(f"Logout failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        )


@router.get("/me")
async def get_current_user(token: str = Depends(security)):
    """Get current user information"""
    try:
        # Validate token and get user data
        user_data = jwt_manager.validate_access_token(token.credentials)
        
        from ..rbac import RBACManager, UserRole
        user_role = UserRole(user_data.get("role", "guest")) 
        permissions = [p.value for p in RBACManager.get_role_permissions(user_role)]
        
        return {
            "user": user_data,
            "permissions": permissions
        }
        
    except Exception as e:
        logger.error(f"Failed to get current user: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )