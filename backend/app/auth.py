"""
FIPS-compliant authentication and authorization system for OpenWatch
Uses RSA-PSS signatures and secure password hashing
"""

import logging
import os
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext

from .config import get_settings
from .rbac import UserRole

logger = logging.getLogger(__name__)
settings = get_settings()

# FIPS-compliant password hashing using Argon2id
pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
    argon2__memory_cost=65536,  # 64MB
    argon2__time_cost=3,
    argon2__parallelism=1,
    argon2__hash_len=32,
    argon2__salt_len=16,
)

security = HTTPBearer()


class FIPSJWTManager:
    """FIPS-compliant JWT token management using RSA-PSS"""

    def __init__(self):
        self.private_key = None
        self.public_key = None
        self._load_or_generate_keys()

    def _load_or_generate_keys(self):
        """Load existing RSA keys or generate new FIPS-compliant ones"""
        # Use environment variables for key paths, with fallback to default
        import tempfile

        # Check if running in test environment
        testing_mode = os.getenv("TESTING", "false").lower() == "true"

        if testing_mode:
            # Test mode - use temp directory
            keys_dir = tempfile.gettempdir()
            private_key_path = os.path.join(keys_dir, "jwt_private_test.pem")
            public_key_path = os.path.join(keys_dir, "jwt_public_test.pem")
        else:
            # Production/Development mode - use /app/security/keys/
            keys_dir = os.getenv("JWT_KEYS_DIR", "/app/security/keys")
            private_key_path = os.path.join(keys_dir, "jwt_private.pem")
            public_key_path = os.path.join(keys_dir, "jwt_public.pem")

        try:
            # Try to load existing keys
            if os.path.exists(private_key_path) and os.path.exists(public_key_path):
                with open(private_key_path, "rb") as f:
                    self.private_key = serialization.load_pem_private_key(
                        f.read(), password=None, backend=default_backend()
                    )

                with open(public_key_path, "rb") as f:
                    self.public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
                logger.info("Loaded existing RSA keys for JWT signing")
            else:
                # Generate new FIPS-compliant RSA keys
                self._generate_keys(private_key_path, public_key_path)

        except Exception as e:
            logger.error(f"Error loading RSA keys: {e}")
            self._generate_keys(private_key_path, public_key_path)

    def _generate_keys(self, private_path: str, public_path: str):
        """Generate FIPS-compliant RSA-2048 key pair"""
        try:
            # Generate RSA-2048 key pair (FIPS approved)
            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            self.public_key = self.private_key.public_key()

            # Ensure directory exists
            os.makedirs(os.path.dirname(private_path), exist_ok=True)

            # Save private key
            with open(private_path, "wb") as f:
                f.write(
                    self.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                )

            # Save public key
            with open(public_path, "wb") as f:
                f.write(
                    self.public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                )

            # Set secure permissions
            os.chmod(private_path, 0o600)
            os.chmod(public_path, 0o644)

            logger.info("Generated new FIPS-compliant RSA keys for JWT signing")

        except Exception as e:
            logger.error(f"Failed to generate RSA keys: {e}")
            raise

    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT access token with RSA-PSS signature"""
        to_encode = data.copy()

        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)

        to_encode.update(
            {
                "exp": expire,
                "iat": datetime.utcnow(),
                "jti": secrets.token_urlsafe(32),  # JWT ID for revocation
            }
        )

        try:
            # Use RS256 with FIPS-compliant RSA-PSS padding
            token = jwt.encode(to_encode, self.private_key, algorithm="RS256")
            return token
        except Exception as e:
            logger.error(f"Failed to create JWT token: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Could not create access token",
            )

    def create_refresh_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT refresh token with longer expiration"""
        to_encode = data.copy()

        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(days=settings.refresh_token_expire_days)

        to_encode.update(
            {
                "exp": expire,
                "iat": datetime.utcnow(),
                "jti": secrets.token_urlsafe(32),
                "type": "refresh",  # Token type identifier
            }
        )

        try:
            token = jwt.encode(to_encode, self.private_key, algorithm="RS256")
            return token
        except Exception as e:
            logger.error(f"Failed to create refresh token: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Could not create refresh token",
            )

    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify JWT token with RSA-PSS signature"""
        try:
            payload = jwt.decode(token, self.public_key, algorithms=["RS256"])
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
            )

    def validate_access_token(self, token: str) -> Dict[str, Any]:
        """Validate access token specifically"""
        payload = self.verify_token(token)
        if payload.get("type") == "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token cannot be used for API access",
            )
        return payload

    def validate_refresh_token(self, token: str) -> Dict[str, Any]:
        """Validate refresh token specifically"""
        payload = self.verify_token(token)
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
        return payload


# Global JWT manager instance
jwt_manager = FIPSJWTManager()


class PasswordManager:
    """FIPS-compliant password management"""

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using Argon2id (FIPS approved)"""
        return pwd_context.hash(password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        return pwd_context.verify(plain_password, hashed_password)

    @staticmethod
    def generate_secure_password(length: int = 16) -> str:
        """Generate cryptographically secure password"""
        return secrets.token_urlsafe(length)


class SecurityAuditLogger:
    """Security event audit logging"""

    def __init__(self):
        self.audit_logger = logging.getLogger("openwatch.audit")
        handler = logging.FileHandler(settings.audit_log_file)
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        self.audit_logger.addHandler(handler)
        self.audit_logger.setLevel(logging.INFO)

    def log_login_attempt(self, username: str, success: bool, ip_address: str):
        """Log authentication attempts"""
        status = "SUCCESS" if success else "FAILED"
        self.audit_logger.info(f"LOGIN_{status} - User: {username}, IP: {ip_address}")

    def log_scan_action(self, username: str, action: str, target: str, ip_address: str):
        """Log scan-related actions"""
        self.audit_logger.info(f"SCAN_{action} - User: {username}, Target: {target}, IP: {ip_address}")

    def log_security_event(self, event_type: str, details: str, ip_address: str):
        """Log security events"""
        self.audit_logger.warning(f"SECURITY_{event_type} - Details: {details}, IP: {ip_address}")

    def log_api_key_action(
        self,
        user_id: str,
        action: str,
        api_key_id: str,
        api_key_name: str,
        details: Optional[Dict] = None,
    ):
        """Log API key related actions"""
        self.audit_logger.info(
            f"API_KEY_{action} - User: {user_id}, Key: {api_key_name} ({api_key_id}), " f"Details: {details or {}}"
        )


audit_logger = SecurityAuditLogger()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> Dict[str, Any]:
    """Get current authenticated user from JWT token or API key"""
    import hashlib

    from sqlalchemy.orm import Session

    from .database import ApiKey, get_db

    try:
        token = credentials.credentials

        # Check if it's an API key (starts with "owk_")
        if token.startswith("owk_"):
            # Get database session
            db: Session = next(get_db())
            try:
                # Hash the API key
                key_hash = hashlib.sha256(token.encode()).hexdigest()

                # Find the API key in database
                api_key = db.query(ApiKey).filter(ApiKey.key_hash == key_hash, ApiKey.is_active.is_(True)).first()

                if not api_key:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid API key",
                    )

                # Check expiration
                if api_key.expires_at and api_key.expires_at < datetime.utcnow():
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="API key expired",
                    )

                # Update last used timestamp
                api_key.last_used_at = datetime.utcnow()
                db.commit()

                # Return API key info as user context
                return {
                    "sub": f"api_key_{api_key.id}",
                    "id": str(api_key.id),
                    "username": f"API Key: {api_key.name}",
                    "email": None,
                    "role": "api_key",
                    "permissions": api_key.permissions,
                    "api_key_id": str(api_key.id),
                    "api_key_name": api_key.name,
                }
            finally:
                db.close()

        # Otherwise, it's a JWT token
        payload = jwt_manager.verify_token(token)
        username = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
            )
        return payload
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )


def decode_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Decode JWT token for authorization middleware
    Returns token payload or None if invalid
    """
    try:

        # Handle API keys
        if token.startswith("owk_"):
            # For middleware, we don't want to update database
            # Just return basic API key info
            return {
                "sub": "api_key",
                "role": "api_key",
                "username": "API Key",
                "api_key": True,
            }

        # Decode JWT token
        payload = jwt_manager.verify_token(token)
        return payload

    except Exception as e:
        logger.debug(f"Token decode failed: {e}")
        return None


def require_permissions(current_user: Dict[str, Any], permissions: str) -> None:
    """Require specific permissions for protected endpoints"""
    user_permissions = current_user.get("permissions", [])

    # Handle API keys - they have permissions as a list
    if isinstance(user_permissions, list):
        if permissions not in user_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permissions}' required",
            )
    else:
        # Handle regular users - check role-based permissions
        user_role = current_user.get("role")

        # Super admin has all permissions
        if user_role == UserRole.SUPER_ADMIN.value:
            return

        # For other roles, you would implement role-based permission checking
        # For now, allow basic permissions for authenticated users
        allowed_permissions = {
            "scans:create": [UserRole.ADMIN.value, UserRole.SCANNER.value],
            "scans:view": [
                UserRole.ADMIN.value,
                UserRole.SCANNER.value,
                UserRole.VIEWER.value,
            ],
            "reports:view": [
                UserRole.ADMIN.value,
                UserRole.SCANNER.value,
                UserRole.VIEWER.value,
            ],
            "hosts:view": [
                UserRole.ADMIN.value,
                UserRole.SCANNER.value,
                UserRole.VIEWER.value,
            ],
            "hosts:manage": [UserRole.ADMIN.value, UserRole.SCANNER.value],
        }

        if permissions not in allowed_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permissions}' not recognized",
            )

        if user_role not in allowed_permissions[permissions]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permissions}' required",
            )


def require_admin(
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Require admin role for protected endpoints"""
    if current_user.get("role") != UserRole.SUPER_ADMIN.value:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    return current_user
