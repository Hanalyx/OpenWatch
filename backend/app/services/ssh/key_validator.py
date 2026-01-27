"""
SSH Key Validation Module

Provides comprehensive SSH key validation with security assessment following
NIST SP 800-57 key management guidelines and current cryptographic best
practices.

This module handles:
- SSH key format validation (RSA, Ed25519, ECDSA, DSA)
- Security level assessment based on key type and size
- Generation of security warnings and upgrade recommendations

Security Standards Applied:
- NIST SP 800-57: Recommendation for Key Management
- NIST SP 800-131A: Transitioning the Use of Cryptographic Algorithms
- OpenSSH security recommendations (Ed25519 preferred)

Key Security Assessment Criteria:
    SECURE:
        - Ed25519 (any size - always 256-bit equivalent to 3072-bit RSA)
        - RSA >= 4096 bits
        - ECDSA P-384 or P-521

    ACCEPTABLE:
        - RSA 2048-4095 bits
        - ECDSA P-256

    DEPRECATED:
        - RSA < 2048 bits
        - ECDSA < P-256

    REJECTED:
        - DSA (any size) - disabled in OpenSSH 7.0+

Usage:
    from app.services.ssh.key_validator import validate_ssh_key

    result = validate_ssh_key(key_content)
    if result.is_valid:
        if result.security_level == SSHKeySecurityLevel.REJECTED:
            raise ValueError("Key is insecure and must be replaced")
        print(f"Key type: {result.key_type.value}, Size: {result.key_size}")
    else:
        print(f"Invalid key: {result.error_message}")

References:
- NIST SP 800-57 Part 1 Rev 5: https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final
- OpenSSH Release Notes: https://www.openssh.com/releasenotes.html
"""

import io
import logging
from typing import List, Optional, Tuple, Union

import paramiko

from .models import KEY_TYPE_MAPPING, SSHKeySecurityLevel, SSHKeyType, SSHKeyValidationResult

logger = logging.getLogger(__name__)


def assess_key_security(
    key_type: SSHKeyType, key_size: Optional[int]
) -> Tuple[SSHKeySecurityLevel, List[str], List[str]]:
    """
    Assess the security level of an SSH key based on type and size.

    This function implements security assessment following NIST SP 800-57
    key management guidelines. It evaluates the cryptographic strength
    of SSH keys and provides actionable recommendations for upgrades.

    Args:
        key_type: Type of SSH key (RSA, Ed25519, ECDSA, DSA)
        key_size: Size of key in bits (None if size cannot be determined)

    Returns:
        Tuple containing:
            - security_level: SSHKeySecurityLevel enum value
            - warnings: List of security warnings about the key
            - recommendations: List of suggested improvements

    Security Assessment Logic:
        - Ed25519: Always SECURE (256-bit security, equivalent to RSA-3072)
        - RSA: SECURE >= 4096, ACCEPTABLE >= 2048, DEPRECATED < 2048
        - ECDSA: SECURE >= P-384, ACCEPTABLE >= P-256, DEPRECATED < P-256
        - DSA: Always REJECTED (vulnerable to attacks, disabled in OpenSSH 7.0+)

    Example:
        >>> level, warns, recs = assess_key_security(SSHKeyType.RSA, 2048)
        >>> print(level)
        SSHKeySecurityLevel.ACCEPTABLE
        >>> print(recs)
        ['Consider upgrading to 4096-bit RSA or Ed25519']
    """
    warnings: List[str] = []
    recommendations: List[str] = []

    if key_type == SSHKeyType.ED25519:
        # Ed25519 is always secure - provides 256-bit security level
        # Equivalent to RSA-3072 but faster and with smaller keys
        # No warnings or recommendations needed for this key type
        return SSHKeySecurityLevel.SECURE, warnings, recommendations

    elif key_type == SSHKeyType.RSA:
        if not key_size:
            # Cannot verify security without knowing key size
            # Conservative approach: mark as acceptable with verification warning
            warnings.append("Cannot determine RSA key size")
            return (
                SSHKeySecurityLevel.ACCEPTABLE,
                warnings,
                ["Verify key size is at least 2048 bits"],
            )
        elif key_size >= 4096:
            # RSA-4096 provides approximately 140-bit security
            # Meets NIST recommendations for long-term security
            return SSHKeySecurityLevel.SECURE, warnings, recommendations
        elif key_size >= 2048:
            # RSA-2048 provides approximately 112-bit security
            # Acceptable but should be upgraded when convenient
            return (
                SSHKeySecurityLevel.ACCEPTABLE,
                warnings,
                ["Consider upgrading to 4096-bit RSA or Ed25519"],
            )
        else:
            # RSA < 2048 is below NIST minimum recommendations
            # Should be replaced as soon as possible
            warnings.append(f"RSA key size {key_size} is below current security standards")
            recommendations.append("Replace with at least 2048-bit RSA or Ed25519 key")
            return SSHKeySecurityLevel.DEPRECATED, warnings, recommendations

    elif key_type == SSHKeyType.ECDSA:
        if not key_size:
            # Cannot verify curve without key size
            # ECDSA curve is encoded in key size (256=P-256, 384=P-384, 521=P-521)
            return (
                SSHKeySecurityLevel.ACCEPTABLE,
                warnings,
                ["Verify ECDSA curve is P-256 or higher"],
            )
        elif key_size >= 384:
            # P-384 provides 192-bit security, P-521 provides 256-bit security
            # Both meet high security requirements
            return SSHKeySecurityLevel.SECURE, warnings, recommendations
        elif key_size >= 256:
            # P-256 provides 128-bit security
            # Acceptable but Ed25519 offers better security-to-size ratio
            return (
                SSHKeySecurityLevel.ACCEPTABLE,
                warnings,
                ["Consider Ed25519 for better security"],
            )
        else:
            # Curves below P-256 are not recommended
            warnings.append(f"ECDSA key size {key_size} may be insecure")
            recommendations.append("Replace with P-256 ECDSA or Ed25519 key")
            return SSHKeySecurityLevel.DEPRECATED, warnings, recommendations

    elif key_type == SSHKeyType.DSA:
        # DSA has known vulnerabilities and is disabled in OpenSSH 7.0+
        # Should never be used for new deployments
        # Existing DSA keys should be replaced immediately
        warnings.append("DSA keys are deprecated due to security vulnerabilities")
        recommendations.append("Replace with Ed25519 or RSA key immediately")
        return SSHKeySecurityLevel.REJECTED, warnings, recommendations

    else:
        # Unknown key type - treat with caution
        # Log for investigation but allow connection
        warnings.append("Unknown key type")
        return SSHKeySecurityLevel.ACCEPTABLE, warnings, ["Use Ed25519 for new keys"]


def validate_ssh_key(
    key_content: Union[str, bytes, memoryview],
    passphrase: Optional[str] = None,
) -> SSHKeyValidationResult:
    """
    Validate SSH key with comprehensive security assessment.

    This function provides a simplified, robust SSH key validation using
    paramiko's built-in capabilities. It handles various key formats and
    provides detailed security assessment.

    The implementation uses paramiko's battle-tested key parsing rather
    than manual format detection, which fixes issues with modern OpenSSH
    key formats (e.g., OpenSSH format vs PEM format).

    Args:
        key_content: SSH private key content as string, bytes, or memoryview.
                    Accepts both PEM format and OpenSSH format keys.
        passphrase: Optional passphrase for encrypted private keys.
                   Required if the key is encrypted.

    Returns:
        SSHKeyValidationResult containing:
            - is_valid: True if key was parsed successfully
            - key_type: Detected key algorithm (RSA, Ed25519, etc.)
            - security_level: Security assessment result
            - key_size: Key size in bits
            - error_message: Description if validation failed
            - warnings: List of security warnings
            - recommendations: List of suggested improvements

    Error Handling:
        - Empty input: Returns invalid result with descriptive message
        - Encrypted key without passphrase: Returns invalid with passphrase request
        - Malformed key: Returns invalid with format error message
        - Unsupported format: Returns invalid with format details

    Security Notes:
        - Key content is never logged (sensitive data protection)
        - Error messages are sanitized to prevent information leakage
        - Passphrase is handled securely (not stored or logged)

    Example:
        >>> # Validate an unencrypted RSA key
        >>> result = validate_ssh_key(rsa_key_content)
        >>> if result.is_valid:
        ...     print(f"Valid {result.key_type.value} key, {result.key_size} bits")
        ...     if result.warnings:
        ...         print(f"Warnings: {result.warnings}")
        ... else:
        ...     print(f"Invalid: {result.error_message}")

        >>> # Validate an encrypted key
        >>> result = validate_ssh_key(encrypted_key, passphrase="secret")
    """
    try:
        # Handle empty input - defensive check before any processing
        if not key_content:
            return SSHKeyValidationResult(
                is_valid=False,
                error_message="Empty key content provided",
            )

        # Normalize input to string - database may return bytes or memoryview
        if isinstance(key_content, (bytes, memoryview)):
            try:
                key_content = key_content.decode("utf-8", errors="ignore")
            except Exception as decode_error:
                logger.debug("Failed to decode key content: %s", type(decode_error).__name__)
                return SSHKeyValidationResult(
                    is_valid=False,
                    error_message="Key content could not be decoded as UTF-8",
                )

        # Convert to string and strip whitespace
        key_content_str = str(key_content).strip()

        # Verify we have content after stripping
        if not key_content_str:
            return SSHKeyValidationResult(
                is_valid=False,
                error_message="Empty key content provided",
            )

        # Try each supported key type using paramiko's parsers
        # Order matters: Ed25519 first (most common modern key), then RSA (most common legacy)
        # Note: DSA keys are not supported (deprecated, insecure)
        key_classes = [
            (paramiko.Ed25519Key, "Ed25519"),
            (paramiko.RSAKey, "RSA"),
            (paramiko.ECDSAKey, "ECDSA"),
        ]

        pkey = None
        last_error = None

        for key_class, key_name in key_classes:
            try:
                # Create StringIO for each attempt (must be fresh for seek position)
                key_file = io.StringIO(key_content_str)
                pkey = key_class.from_private_key(key_file, passphrase)
                # Successfully parsed - break out of loop
                break
            except paramiko.PasswordRequiredException:
                # Key is encrypted but no passphrase provided
                # This is definitive - no need to try other key types
                return SSHKeyValidationResult(
                    is_valid=False,
                    error_message="SSH key is encrypted and requires a passphrase",
                )
            except paramiko.SSHException as e:
                # Key parsing failed for this type - try next type
                last_error = str(e)
                continue
            except Exception as e:
                # Unexpected error - log and try next type
                logger.debug(
                    "Unexpected error parsing %s key: %s",
                    key_name,
                    type(e).__name__,
                )
                last_error = str(e)
                continue

        # Check if we successfully parsed a key
        if pkey is None:
            error_msg = "Unable to parse SSH key - unsupported format or incorrect passphrase"
            if last_error:
                # Include sanitized error details for debugging
                # Truncate to prevent log injection
                sanitized_error = last_error[:200] if len(last_error) > 200 else last_error
                error_msg = f"Invalid SSH key format: {sanitized_error}"
            return SSHKeyValidationResult(
                is_valid=False,
                error_message=error_msg,
            )

        # Extract key information using paramiko's methods
        # get_name() returns SSH protocol name (e.g., 'ssh-rsa', 'ssh-ed25519')
        key_name = pkey.get_name()
        # get_bits() returns key size in bits
        key_size = pkey.get_bits()

        # Map paramiko key name to our enum type
        # Use KEY_TYPE_MAPPING from models.py for consistency
        key_type = KEY_TYPE_MAPPING.get(key_name, SSHKeyType.RSA)

        # Perform security assessment
        security_level, warnings, recommendations = assess_key_security(key_type, key_size)

        return SSHKeyValidationResult(
            is_valid=True,
            key_type=key_type,
            security_level=security_level,
            key_size=key_size,
            warnings=warnings,
            recommendations=recommendations,
        )

    except Exception as e:
        # Catch-all for unexpected errors
        # Log the error type but not the content (security)
        logger.error(
            "Unexpected error during SSH key validation: %s",
            type(e).__name__,
        )
        return SSHKeyValidationResult(
            is_valid=False,
            error_message=f"Validation error: {type(e).__name__}",
        )


def is_key_secure(
    key_content: Union[str, bytes, memoryview],
    passphrase: Optional[str] = None,
    minimum_level: SSHKeySecurityLevel = SSHKeySecurityLevel.ACCEPTABLE,
) -> bool:
    """
    Quick check if an SSH key meets minimum security requirements.

    This is a convenience function for cases where you only need a
    boolean security check rather than full validation details.

    Args:
        key_content: SSH private key content
        passphrase: Optional passphrase for encrypted keys
        minimum_level: Minimum acceptable security level (default: ACCEPTABLE)

    Returns:
        True if key is valid and meets minimum security level, False otherwise

    Example:
        >>> if is_key_secure(user_key, minimum_level=SSHKeySecurityLevel.SECURE):
        ...     print("Key meets high security requirements")
        ... else:
        ...     print("Key does not meet security requirements")
    """
    result = validate_ssh_key(key_content, passphrase)

    if not result.is_valid:
        return False

    if result.security_level is None:
        return False

    # Security levels in order of increasing security
    # REJECTED < DEPRECATED < ACCEPTABLE < SECURE
    security_order = {
        SSHKeySecurityLevel.REJECTED: 0,
        SSHKeySecurityLevel.DEPRECATED: 1,
        SSHKeySecurityLevel.ACCEPTABLE: 2,
        SSHKeySecurityLevel.SECURE: 3,
    }

    actual_level = security_order.get(result.security_level, 0)
    required_level = security_order.get(minimum_level, 2)

    return actual_level >= required_level


__all__ = [
    "assess_key_security",
    "validate_ssh_key",
    "is_key_secure",
]
