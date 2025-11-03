"""
Multi-Factor Authentication (MFA) Service for OpenWatch
FIPS-compliant TOTP implementation with backup codes and FIDO2 support framework
"""

import os
import pyotp
import qrcode
import base64
import secrets
import hashlib
from io import BytesIO
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import logging

from .encryption import encrypt_data, decrypt_data
from ..config import get_settings
from ..utils.logging_security import sanitize_username_for_log

logger = logging.getLogger(__name__)
settings = get_settings()


class MFAMethod(Enum):
    """Supported MFA methods"""

    TOTP = "totp"
    BACKUP_CODES = "backup_codes"
    FIDO2 = "fido2"  # Framework ready for future implementation


@dataclass
class MFAEnrollmentResult:
    """Result of MFA enrollment process"""

    success: bool
    secret_key: Optional[str] = None
    qr_code_data: Optional[str] = None
    backup_codes: Optional[List[str]] = None
    error_message: Optional[str] = None


@dataclass
class MFAValidationResult:
    """Result of MFA validation"""

    valid: bool
    method_used: Optional[MFAMethod] = None
    backup_code_used: Optional[str] = None
    error_message: Optional[str] = None


class MFAService:
    """FIPS-compliant Multi-Factor Authentication service"""

    def __init__(self):
        self.issuer_name = "OpenWatch Security Platform"
        self.backup_code_length = 8
        self.backup_code_count = 10
        self.totp_window = 1  # Allow 1 time window before/after current

    def generate_totp_secret(self) -> str:
        """Generate a FIPS-compliant TOTP secret key"""
        # Generate 160-bit (20 bytes) secret for TOTP (FIPS recommended)
        secret_bytes = secrets.token_bytes(20)
        return base64.b32encode(secret_bytes).decode("utf-8")

    def generate_backup_codes(self) -> List[str]:
        """Generate cryptographically secure backup codes"""
        codes = []
        for _ in range(self.backup_code_count):
            # Generate 8-character alphanumeric backup codes
            code = "".join(
                secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
                for _ in range(self.backup_code_length)
            )
            codes.append(code)
        return codes

    def hash_backup_code(self, code: str) -> str:
        """Hash backup code for secure storage"""
        # Use SHA-256 for backup code hashing (FIPS approved)
        return hashlib.sha256(code.encode("utf-8")).hexdigest()

    def generate_qr_code(self, username: str, secret: str) -> str:
        """Generate QR code for TOTP setup"""
        try:
            # Create TOTP URI
            totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
                name=username, issuer_name=self.issuer_name
            )

            # Generate QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(totp_uri)
            qr.make(fit=True)

            # Create QR code image
            img = qr.make_image(fill_color="black", back_color="white")

            # Convert to base64 for embedding in HTML
            buffer = BytesIO()
            img.save(buffer, format="PNG")
            img_data = buffer.getvalue()

            return base64.b64encode(img_data).decode("utf-8")

        except Exception as e:
            logger.error(f"Failed to generate QR code: {e}")
            return None

    def encrypt_mfa_secret(self, secret: str) -> str:
        """Encrypt MFA secret for database storage"""
        try:
            encrypted = encrypt_data(secret.encode("utf-8"))
            return encrypted
        except Exception as e:
            logger.error(f"Failed to encrypt MFA secret: {e}")
            raise

    def decrypt_mfa_secret(self, encrypted_secret: str) -> str:
        """Decrypt MFA secret from database"""
        try:
            decrypted_bytes = decrypt_data(encrypted_secret)
            return decrypted_bytes.decode("utf-8")
        except Exception as e:
            logger.error(f"Failed to decrypt MFA secret: {e}")
            raise

    def validate_totp_code(self, secret: str, user_code: str, used_codes_cache: set = None) -> bool:
        """
        Validate TOTP code with replay protection

        Args:
            secret: User's TOTP secret
            user_code: Code provided by user
            used_codes_cache: Set of recently used codes to prevent replay

        Returns:
            True if code is valid and not replayed
        """
        try:
            totp = pyotp.TOTP(secret)

            # Check current time window and adjacent windows
            current_time = datetime.now()
            for i in range(-self.totp_window, self.totp_window + 1):
                test_time = current_time + timedelta(seconds=i * 30)
                expected_code = totp.at(test_time)

                if user_code == expected_code:
                    # Check for replay attack
                    code_key = f"{user_code}_{int(test_time.timestamp() // 30)}"
                    if used_codes_cache and code_key in used_codes_cache:
                        logger.warning(f"TOTP replay attack detected: {code_key}")
                        return False

                    # Add to used codes cache if provided
                    if used_codes_cache is not None:
                        used_codes_cache.add(code_key)

                    return True

            return False

        except Exception as e:
            logger.error(f"TOTP validation error: {e}")
            return False

    def validate_backup_code(
        self, hashed_backup_codes: List[str], user_code: str
    ) -> Tuple[bool, str]:
        """
        Validate backup code against stored hashes

        Args:
            hashed_backup_codes: List of hashed backup codes from database
            user_code: Code provided by user

        Returns:
            Tuple of (is_valid, code_hash_if_valid)
        """
        try:
            user_code_hash = self.hash_backup_code(user_code.upper())

            if user_code_hash in hashed_backup_codes:
                return True, user_code_hash

            return False, None

        except Exception as e:
            logger.error(f"Backup code validation error: {e}")
            return False, None

    def enroll_user_mfa(self, username: str) -> MFAEnrollmentResult:
        """
        Enroll user in MFA with TOTP and backup codes

        Args:
            username: Username for MFA enrollment

        Returns:
            MFAEnrollmentResult with secret, QR code, and backup codes
        """
        try:
            # Generate TOTP secret
            secret = self.generate_totp_secret()

            # Generate QR code
            qr_code_data = self.generate_qr_code(username, secret)
            if not qr_code_data:
                return MFAEnrollmentResult(
                    success=False, error_message="Failed to generate QR code"
                )

            # Generate backup codes
            backup_codes = self.generate_backup_codes()

            return MFAEnrollmentResult(
                success=True,
                secret_key=secret,
                qr_code_data=qr_code_data,
                backup_codes=backup_codes,
            )

        except Exception as e:
            logger.error(
                f"MFA enrollment failed for {sanitize_username_for_log(username)}: {type(e).__name__}"
            )
            return MFAEnrollmentResult(success=False, error_message=f"Enrollment failed: {str(e)}")

    def validate_mfa_code(
        self,
        encrypted_secret: str,
        hashed_backup_codes: List[str],
        user_code: str,
        used_codes_cache: set = None,
    ) -> MFAValidationResult:
        """
        Validate MFA code (TOTP or backup code)

        Args:
            encrypted_secret: Encrypted TOTP secret from database
            hashed_backup_codes: List of hashed backup codes
            user_code: Code provided by user
            used_codes_cache: Cache of recently used TOTP codes

        Returns:
            MFAValidationResult with validation status and method used
        """
        try:
            user_code = user_code.strip().replace(" ", "").upper()

            # First try TOTP validation
            if len(user_code) == 6 and user_code.isdigit():
                try:
                    secret = self.decrypt_mfa_secret(encrypted_secret)
                    if self.validate_totp_code(secret, user_code, used_codes_cache):
                        return MFAValidationResult(valid=True, method_used=MFAMethod.TOTP)
                except Exception as e:
                    logger.warning(f"TOTP validation failed: {e}")

            # Try backup code validation
            if len(user_code) == self.backup_code_length:
                is_valid, used_code_hash = self.validate_backup_code(hashed_backup_codes, user_code)
                if is_valid:
                    return MFAValidationResult(
                        valid=True,
                        method_used=MFAMethod.BACKUP_CODES,
                        backup_code_used=used_code_hash,
                    )

            return MFAValidationResult(
                valid=False, error_message="Invalid MFA code format or value"
            )

        except Exception as e:
            logger.error(f"MFA validation error: {e}")
            return MFAValidationResult(valid=False, error_message=f"Validation failed: {str(e)}")

    def regenerate_backup_codes(self, username: str) -> List[str]:
        """
        Generate new backup codes for a user

        Args:
            username: Username for backup code regeneration

        Returns:
            List of new backup codes
        """
        try:
            backup_codes = self.generate_backup_codes()
            logger.info(f"Regenerated backup codes for user: {sanitize_username_for_log(username)}")
            return backup_codes

        except Exception as e:
            logger.error(
                f"Failed to regenerate backup codes for {sanitize_username_for_log(username)}: {type(e).__name__}"
            )
            raise

    def get_mfa_status(self, user_data: Dict) -> Dict[str, any]:
        """
        Get user's MFA status and capabilities

        Args:
            user_data: User data from database

        Returns:
            Dictionary with MFA status information
        """
        return {
            "mfa_enabled": bool(user_data.get("mfa_secret")),
            "totp_enabled": bool(user_data.get("mfa_secret")),
            "backup_codes_available": len(user_data.get("backup_codes", [])),
            "fido2_enabled": False,  # Future implementation
            "last_mfa_use": user_data.get("last_mfa_use"),
            "supported_methods": [MFAMethod.TOTP.value, MFAMethod.BACKUP_CODES.value],
        }


# Global MFA service instance
_mfa_service = None


def get_mfa_service() -> MFAService:
    """Get global MFA service instance"""
    global _mfa_service
    if _mfa_service is None:
        _mfa_service = MFAService()
    return _mfa_service


# Convenience functions
def enroll_mfa(username: str) -> MFAEnrollmentResult:
    """Enroll user in MFA"""
    return get_mfa_service().enroll_user_mfa(username)


def validate_mfa(
    encrypted_secret: str, backup_codes: List[str], code: str, used_codes: set = None
) -> MFAValidationResult:
    """Validate MFA code"""
    return get_mfa_service().validate_mfa_code(encrypted_secret, backup_codes, code, used_codes)


def regenerate_backup_codes(username: str) -> List[str]:
    """Regenerate backup codes"""
    return get_mfa_service().regenerate_backup_codes(username)
