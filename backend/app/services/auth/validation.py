"""
Credential Security Validation

Provides FIPS-compliant, strict SSH key validation and credential security enforcement.
This module validates credentials against security policies before storage or use.
"""

import logging
import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

from backend.app.services.error_classification import SecurityContext, classify_authentication_error
from backend.app.services.ssh import SSHKeySecurityLevel, SSHKeyType, validate_ssh_key

logger = logging.getLogger(__name__)


class SecurityPolicyLevel(Enum):
    """Security policy enforcement levels."""

    STRICT = "strict"  # FIPS compliance, reject all non-secure keys
    MODERATE = "moderate"  # Reject weak/deprecated keys, warn on acceptable
    PERMISSIVE = "permissive"  # Allow all keys with warnings


class FIPSComplianceStatus(Enum):
    """FIPS 140-2 compliance status."""

    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    CONDITIONAL = "conditional"  # Compliant under certain conditions


@dataclass
class KeySecurityAssessment:
    """Comprehensive security assessment for SSH keys."""

    is_valid: bool
    is_secure: bool
    is_fips_compliant: bool
    security_level: SSHKeySecurityLevel
    fips_status: FIPSComplianceStatus
    key_type: Optional[SSHKeyType]
    key_size: Optional[int]
    error_message: Optional[str]
    warnings: List[str]
    recommendations: List[str]
    compliance_notes: List[str]


@dataclass
class SecurityPolicyConfig:
    """Configuration for security policy enforcement."""

    policy_level: SecurityPolicyLevel = SecurityPolicyLevel.STRICT

    # FIPS requirements
    enforce_fips: bool = True
    require_minimum_key_strength: bool = True

    # Key type policies
    allowed_key_types: Set[SSHKeyType] = None
    minimum_rsa_bits: int = 3072  # NIST recommends 3072+ for RSA
    minimum_ecdsa_bits: int = 256
    allow_dsa_keys: bool = False
    allow_deprecated_curves: bool = False

    # Password policies
    minimum_password_length: int = 12
    require_complex_passwords: bool = True

    def __post_init__(self):
        if self.allowed_key_types is None:
            if self.enforce_fips:
                # FIPS-approved algorithms only
                self.allowed_key_types = {
                    SSHKeyType.RSA,
                    SSHKeyType.ED25519,
                    SSHKeyType.ECDSA,
                }
            else:
                self.allowed_key_types = {
                    SSHKeyType.RSA,
                    SSHKeyType.ED25519,
                    SSHKeyType.ECDSA,
                }


class CredentialSecurityValidator:
    """
    Comprehensive credential validation with strict security policy enforcement.

    This validator provides FIPS-compliant validation and rejects credentials
    that don't meet security standards.
    """

    def __init__(self, policy_config: Optional[SecurityPolicyConfig] = None):
        self.policy = policy_config or SecurityPolicyConfig()
        logger.info(f"Initialized credential validator with {self.policy.policy_level.value} policy")

    def validate_ssh_key_strict(self, key_content: str, passphrase: Optional[str] = None) -> KeySecurityAssessment:
        """
        Perform strict SSH key validation with FIPS compliance checking.

        Args:
            key_content: SSH private key content
            passphrase: Optional key passphrase

        Returns:
            KeySecurityAssessment with comprehensive security analysis
        """
        # Start with basic validation
        basic_validation = validate_ssh_key(key_content, passphrase)

        if not basic_validation.is_valid:
            return KeySecurityAssessment(
                is_valid=False,
                is_secure=False,
                is_fips_compliant=False,
                security_level=SSHKeySecurityLevel.REJECTED,
                fips_status=FIPSComplianceStatus.NON_COMPLIANT,
                key_type=basic_validation.key_type,
                key_size=basic_validation.key_size,
                error_message=basic_validation.error_message,
                warnings=[],
                recommendations=[],
                compliance_notes=["Key failed basic validation"],
            )

        # Enhanced security assessment
        key_type = basic_validation.key_type
        key_size = basic_validation.key_size
        warnings = list(basic_validation.warnings)
        recommendations = list(basic_validation.recommendations)
        compliance_notes = []

        # FIPS compliance check
        fips_status, fips_notes = self._assess_fips_compliance(key_type, key_size)
        compliance_notes.extend(fips_notes)

        # Strict policy enforcement
        is_secure, is_valid, security_errors = self._enforce_security_policy(
            key_type, key_size, basic_validation.security_level
        )

        # Override basic validation if strict policy rejects
        if not is_valid:
            error_message = "; ".join(security_errors) if security_errors else "Key rejected by security policy"
        else:
            error_message = basic_validation.error_message

        # Add policy-specific recommendations
        policy_recommendations = self._get_policy_recommendations(key_type, key_size)
        recommendations.extend(policy_recommendations)

        return KeySecurityAssessment(
            is_valid=is_valid,
            is_secure=is_secure,
            is_fips_compliant=(fips_status == FIPSComplianceStatus.COMPLIANT),
            security_level=basic_validation.security_level,
            fips_status=fips_status,
            key_type=key_type,
            key_size=key_size,
            error_message=error_message,
            warnings=warnings,
            recommendations=recommendations,
            compliance_notes=compliance_notes,
        )

    def validate_password_strength(self, password: str) -> Tuple[bool, List[str], List[str]]:
        """
        Validate password strength according to security policy.

        Args:
            password: Password to validate

        Returns:
            Tuple of (is_valid, warnings, recommendations)
        """
        warnings = []
        recommendations = []
        is_valid = True

        if len(password) < self.policy.minimum_password_length:
            is_valid = False
            warnings.append(f"Password must be at least {self.policy.minimum_password_length} characters")

        if self.policy.require_complex_passwords:
            complexity_checks = [
                (r"[a-z]", "lowercase letter"),
                (r"[A-Z]", "uppercase letter"),
                (r"[0-9]", "digit"),
                (r"[^a-zA-Z0-9]", "special character"),
            ]

            missing_requirements = []
            for pattern, requirement in complexity_checks:
                if not re.search(pattern, password):
                    missing_requirements.append(requirement)

            if missing_requirements:
                is_valid = False
                warnings.append(f"Password must contain: {', '.join(missing_requirements)}")

        # Common password checks
        if self._is_common_password(password):
            is_valid = False
            warnings.append("Password is too common or predictable")

        if not warnings:
            recommendations.append("Password meets security requirements")
        else:
            recommendations.extend(
                [
                    "Use a unique, randomly generated password",
                    "Consider using a password manager",
                    "Avoid dictionary words and personal information",
                ]
            )

        return is_valid, warnings, recommendations

    def audit_credential_security(
        self,
        username: str,
        auth_method: str,
        private_key: Optional[str] = None,
        password: Optional[str] = None,
    ) -> Dict:
        """
        Perform comprehensive security audit of credentials.

        Args:
            username: SSH username
            auth_method: Authentication method
            private_key: SSH private key (if applicable)
            password: Password (if applicable)

        Returns:
            Dictionary with audit results
        """
        audit_results = {
            "timestamp": datetime.utcnow().isoformat(),
            "username": username,
            "auth_method": auth_method,
            "overall_security_level": "unknown",
            "is_compliant": False,
            "findings": [],
            "recommendations": [],
            "policy_level": self.policy.policy_level.value,
        }

        findings = []
        recommendations = []
        security_levels = []

        # Username validation
        if len(username) < 3:
            findings.append("Username is too short (security risk)")
            recommendations.append("Use descriptive, non-default usernames")

        if username in ["root", "admin", "administrator", "user", "guest"]:
            findings.append("Username is a common default account")
            recommendations.append("Avoid using default or common usernames")
            security_levels.append("deprecated")

        # SSH key validation
        if private_key:
            key_assessment = self.validate_ssh_key_strict(private_key)

            if not key_assessment.is_valid:
                findings.append(f"SSH key validation failed: {key_assessment.error_message}")
                security_levels.append("rejected")
            elif not key_assessment.is_secure:
                findings.append("SSH key does not meet security requirements")
                security_levels.append("deprecated")
            elif not key_assessment.is_fips_compliant:
                findings.append("SSH key is not FIPS compliant")
                security_levels.append("acceptable")
            else:
                security_levels.append("secure")

            findings.extend(key_assessment.warnings)
            recommendations.extend(key_assessment.recommendations)

        # Password validation
        if password:
            is_strong, pwd_warnings, pwd_recommendations = self.validate_password_strength(password)

            if not is_strong:
                findings.append("Password does not meet strength requirements")
                security_levels.append("deprecated")
            else:
                security_levels.append("acceptable")

            findings.extend(pwd_warnings)
            recommendations.extend(pwd_recommendations)

        # Determine overall security level
        if "rejected" in security_levels:
            overall_level = "rejected"
        elif "deprecated" in security_levels:
            overall_level = "deprecated"
        elif "acceptable" in security_levels:
            overall_level = "acceptable"
        else:
            overall_level = "secure"

        audit_results.update(
            {
                "overall_security_level": overall_level,
                "is_compliant": (overall_level in ["secure", "acceptable"]),
                "findings": findings,
                "recommendations": list(set(recommendations)),
            }
        )

        return audit_results

    def _assess_fips_compliance(
        self, key_type: Optional[SSHKeyType], key_size: Optional[int]
    ) -> Tuple[FIPSComplianceStatus, List[str]]:
        """Assess FIPS 140-2 compliance for SSH key."""
        compliance_notes = []

        if not key_type:
            return FIPSComplianceStatus.NON_COMPLIANT, ["Unknown key type"]

        if key_type == SSHKeyType.ED25519:
            compliance_notes.append("Ed25519 is FIPS 186-4 approved")
            return FIPSComplianceStatus.COMPLIANT, compliance_notes

        elif key_type == SSHKeyType.RSA:
            if not key_size:
                return FIPSComplianceStatus.NON_COMPLIANT, ["Cannot determine RSA key size"]

            if key_size >= 2048:
                if key_size >= 3072:
                    compliance_notes.append("RSA key meets NIST SP 800-57 recommendations")
                    return FIPSComplianceStatus.COMPLIANT, compliance_notes
                else:
                    compliance_notes.append("RSA-2048 is FIPS approved but NIST recommends 3072+")
                    return FIPSComplianceStatus.CONDITIONAL, compliance_notes
            else:
                compliance_notes.append("RSA keys < 2048 bits are not FIPS compliant")
                return FIPSComplianceStatus.NON_COMPLIANT, compliance_notes

        elif key_type == SSHKeyType.ECDSA:
            if key_size and key_size >= 256:
                compliance_notes.append("ECDSA P-256+ curves are FIPS approved")
                return FIPSComplianceStatus.COMPLIANT, compliance_notes
            else:
                compliance_notes.append("ECDSA curves < 256 bits are not FIPS compliant")
                return FIPSComplianceStatus.NON_COMPLIANT, compliance_notes

        elif key_type == SSHKeyType.DSA:
            compliance_notes.append("DSA is deprecated and not FIPS compliant for new applications")
            return FIPSComplianceStatus.NON_COMPLIANT, compliance_notes

        return FIPSComplianceStatus.NON_COMPLIANT, ["Unknown key type for FIPS assessment"]

    def _enforce_security_policy(
        self,
        key_type: Optional[SSHKeyType],
        key_size: Optional[int],
        security_level: SSHKeySecurityLevel,
    ) -> Tuple[bool, bool, List[str]]:
        """
        Enforce security policy - this is where strict rejection happens.

        Returns:
            Tuple of (is_secure, is_valid, error_messages)
        """
        errors = []

        # Key type policy enforcement
        if key_type and key_type not in self.policy.allowed_key_types:
            errors.append(f"{key_type.value.upper()} keys are not allowed by security policy")
            return False, False, errors

        # Strict policy enforcement based on level
        if self.policy.policy_level == SecurityPolicyLevel.STRICT:
            if security_level in [
                SSHKeySecurityLevel.REJECTED,
                SSHKeySecurityLevel.DEPRECATED,
            ]:
                errors.append("Key rejected by strict security policy")
                return False, False, errors
            elif security_level == SSHKeySecurityLevel.ACCEPTABLE and self.policy.enforce_fips:
                fips_status, _ = self._assess_fips_compliance(key_type, key_size)
                if fips_status != FIPSComplianceStatus.COMPLIANT:
                    errors.append("Key does not meet strict FIPS compliance requirements")
                    return False, False, errors

        elif self.policy.policy_level == SecurityPolicyLevel.MODERATE:
            if security_level == SSHKeySecurityLevel.REJECTED:
                errors.append("Key rejected by security policy")
                return False, False, errors

        # Additional strength checks
        if key_type == SSHKeyType.RSA and key_size:
            if key_size < self.policy.minimum_rsa_bits:
                errors.append(f"RSA key size {key_size} is below minimum required {self.policy.minimum_rsa_bits}")
                return False, False, errors

        if key_type == SSHKeyType.ECDSA and key_size:
            if key_size < self.policy.minimum_ecdsa_bits:
                errors.append(f"ECDSA key size {key_size} is below minimum required {self.policy.minimum_ecdsa_bits}")
                return False, False, errors

        if key_type == SSHKeyType.DSA and not self.policy.allow_dsa_keys:
            errors.append("DSA keys are prohibited by security policy")
            return False, False, errors

        is_secure = security_level in [
            SSHKeySecurityLevel.SECURE,
            SSHKeySecurityLevel.ACCEPTABLE,
        ]
        return is_secure, True, errors

    def _get_policy_recommendations(self, key_type: Optional[SSHKeyType], key_size: Optional[int]) -> List[str]:
        """Get policy-specific recommendations."""
        recommendations = []

        if self.policy.policy_level == SecurityPolicyLevel.STRICT:
            recommendations.extend(
                [
                    "Use Ed25519 keys for maximum security and performance",
                    "If RSA is required, use RSA-4096 or larger",
                    "Ensure all keys meet FIPS 140-2 compliance requirements",
                ]
            )

        if self.policy.enforce_fips:
            recommendations.append("Only FIPS-approved cryptographic algorithms are accepted")

        if key_type == SSHKeyType.RSA and key_size and key_size < 4096:
            recommendations.append("Consider upgrading to RSA-4096 for future-proofing")

        return recommendations

    def _is_common_password(self, password: str) -> bool:
        """Check if password is commonly used or predictable."""
        common_passwords = {
            "password",
            "123456",
            "password123",
            "admin",
            "root",
            "qwerty",
            "letmein",
            "welcome",
            "monkey",
            "dragon",
        }

        lower_password = password.lower()

        if lower_password in common_passwords:
            return True

        if re.match(r"^(.)\1{2,}$", password):  # Repeated characters
            return True

        if re.match(r"^(123|abc|qwe)", lower_password):  # Sequential patterns
            return True

        return False


# Factory function for service creation
def get_credential_validator(
    policy_level: SecurityPolicyLevel = SecurityPolicyLevel.STRICT,
    enforce_fips: bool = True,
) -> CredentialSecurityValidator:
    """
    Factory function to create CredentialSecurityValidator with specified policy.

    Args:
        policy_level: Security policy enforcement level
        enforce_fips: Whether to enforce FIPS compliance

    Returns:
        Configured CredentialSecurityValidator instance
    """
    config = SecurityPolicyConfig(policy_level=policy_level, enforce_fips=enforce_fips)
    return CredentialSecurityValidator(config)


# Integration function for existing validation
def validate_credential_with_strict_policy(
    username: str,
    auth_method: str,
    private_key: Optional[str] = None,
    password: Optional[str] = None,
    policy_level: SecurityPolicyLevel = SecurityPolicyLevel.STRICT,
) -> Tuple[bool, str]:
    """
    Validate credential with strict security policy enforcement.

    Args:
        username: SSH username
        auth_method: Authentication method
        private_key: SSH private key content
        password: Password
        policy_level: Security policy level to enforce

    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        validator = get_credential_validator(policy_level=policy_level)
        audit_result = validator.audit_credential_security(
            username=username,
            auth_method=auth_method,
            private_key=private_key,
            password=password,
        )

        is_valid = audit_result["is_compliant"]

        if not is_valid:
            error_context = SecurityContext(operation="credential_validation", severity="high", requires_admin=True)
            classified_error = classify_authentication_error(error_context)
            error_message = classified_error.user_guidance
        else:
            error_message = ""

        return is_valid, error_message

    except Exception as e:
        logger.error(f"Strict credential validation error: {e}")
        return False, f"Validation failed: {str(e)}"
