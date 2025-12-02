"""
Security Configuration API Routes

API endpoints for managing security policies, SSH key validation rules,
and FIPS compliance settings.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..rbac import Permission, require_permission
from ..services.credential_validation import SecurityPolicyConfig, SecurityPolicyLevel, get_credential_validator
from ..services.security_config import ConfigScope, get_security_config_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/security/config", tags=["Security Configuration"])


# Pydantic models
class SecurityPolicyRequest(BaseModel):
    """Request model for security policy configuration."""

    policy_level: SecurityPolicyLevel = Field(..., description="Security policy enforcement level")
    enforce_fips: bool = Field(True, description="Enforce FIPS 140-2 compliance")
    minimum_rsa_bits: int = Field(3072, description="Minimum RSA key size in bits")
    minimum_ecdsa_bits: int = Field(256, description="Minimum ECDSA key size in bits")
    allow_dsa_keys: bool = Field(False, description="Allow DSA keys (not recommended)")
    minimum_password_length: int = Field(12, description="Minimum password length")
    require_complex_passwords: bool = Field(True, description="Require complex passwords")


class SecurityConfigResponse(BaseModel):
    """Response model for security configuration."""

    scope: str
    target_id: Optional[str]
    effective_config: Dict[str, Any]
    inheritance_chain: List[Dict[str, Any]]
    compliance_level: str
    last_updated: str


class TemplateResponse(BaseModel):
    """Response model for security templates."""

    name: str
    description: str
    policy_level: str
    enforce_fips: bool
    recommended_for: str


class ValidationResponse(BaseModel):
    """Response model for SSH key validation."""

    is_valid: bool
    is_secure: bool
    is_fips_compliant: bool
    security_level: str
    key_type: Optional[str]
    key_size: Optional[int]
    error_message: Optional[str]
    warnings: List[str]
    recommendations: List[str]
    compliance_notes: List[str]


@router.get("/", response_model=SecurityConfigResponse)
@require_permission(Permission.SYSTEM_CONFIG)
async def get_security_config(
    target_id: Optional[str] = None,
    target_type: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> SecurityConfigResponse:
    """
    Get effective security configuration for a target.
    Uses hierarchical inheritance to resolve final configuration.
    """
    try:
        config_manager = get_security_config_manager(db)
        summary = config_manager.get_config_summary(target_id, target_type)

        if "error" in summary:
            raise HTTPException(status_code=500, detail=summary["error"])

        return SecurityConfigResponse(
            scope=target_type or "system",
            target_id=target_id,
            effective_config=summary["effective_config"],
            inheritance_chain=summary["inheritance_chain"],
            compliance_level=summary["compliance_level"],
            last_updated=datetime.utcnow().isoformat(),
        )

    except Exception as e:
        logger.error(f"Failed to get security config: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve security configuration")


@router.put("/")
@require_permission(Permission.SYSTEM_CONFIG)
async def update_security_config(
    policy: SecurityPolicyRequest,
    scope: ConfigScope,
    target_id: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, str]:
    """
    Update security configuration for a specific scope.
    """
    try:
        config_manager = get_security_config_manager(db)

        # Convert request to SecurityPolicyConfig
        config = SecurityPolicyConfig(
            policy_level=policy.policy_level,
            enforce_fips=policy.enforce_fips,
            minimum_rsa_bits=policy.minimum_rsa_bits,
            minimum_ecdsa_bits=policy.minimum_ecdsa_bits,
            allow_dsa_keys=policy.allow_dsa_keys,
            minimum_password_length=policy.minimum_password_length,
            require_complex_passwords=policy.require_complex_passwords,
        )

        # Validate configuration
        is_valid, validation_messages = config_manager.validate_config(config)
        if not is_valid:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid configuration: {'; '.join(validation_messages)}",
            )

        # Update configuration
        success = config_manager.set_config(
            scope=scope,
            config=config,
            target_id=target_id,
            created_by=current_user.get("id", "unknown"),
        )

        if success:
            logger.info(f"Security config updated by {current_user.get('username')} for {scope.value}:{target_id}")
            return {"message": "Security configuration updated successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to update security configuration")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update security config: {e}")
        raise HTTPException(status_code=500, detail="Failed to update security configuration")


@router.post("/template/{template_name}")
@require_permission(Permission.SYSTEM_CONFIG)
async def apply_security_template(
    template_name: str,
    scope: ConfigScope,
    target_id: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, str]:
    """
    Apply a predefined security configuration template.
    """
    try:
        config_manager = get_security_config_manager(db)

        success = config_manager.apply_template(
            template_name=template_name,
            scope=scope,
            target_id=target_id,
            created_by=current_user.get("id", "unknown"),
        )

        if success:
            logger.info(
                f"Applied template '{template_name}' by {current_user.get('username')} to {scope.value}:{target_id}"
            )
            return {"message": f"Template '{template_name}' applied successfully"}
        else:
            raise HTTPException(status_code=400, detail=f"Failed to apply template '{template_name}'")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to apply security template: {e}")
        raise HTTPException(status_code=500, detail="Failed to apply security template")


@router.get("/templates", response_model=List[TemplateResponse])
async def list_security_templates(
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> List[TemplateResponse]:
    """List all available security configuration templates."""
    try:
        config_manager = get_security_config_manager(db)
        templates = config_manager.list_templates()

        return [TemplateResponse(**template) for template in templates]

    except Exception as e:
        logger.error(f"Failed to list security templates: {e}")
        raise HTTPException(status_code=500, detail="Failed to list security templates")


class SSHKeyValidationRequest(BaseModel):
    """Request model for SSH key validation."""

    key_content: str = Field(..., description="SSH private key content")
    passphrase: Optional[str] = Field(None, description="SSH key passphrase")
    target_id: Optional[str] = Field(None, description="Target ID for policy resolution")
    target_type: Optional[str] = Field(None, description="Target type (host, group)")


@router.post("/validate/ssh-key", response_model=ValidationResponse)
async def validate_ssh_key(
    request: SSHKeyValidationRequest,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> ValidationResponse:
    """
    Validate SSH key against current security policies.
    Provides comprehensive security assessment and FIPS compliance check.
    """
    try:
        # Get effective configuration for the target
        config_manager = get_security_config_manager(db)
        effective_config = config_manager.get_effective_config(request.target_id, request.target_type)

        # Create validator with effective configuration
        validator = get_credential_validator(
            policy_level=effective_config.policy_level,
            enforce_fips=effective_config.enforce_fips,
        )

        # Perform strict validation
        assessment = validator.validate_ssh_key_strict(request.key_content, request.passphrase)

        return ValidationResponse(
            is_valid=assessment.is_valid,
            is_secure=assessment.is_secure,
            is_fips_compliant=assessment.is_fips_compliant,
            security_level=assessment.security_level.value,
            key_type=assessment.key_type.value if assessment.key_type else None,
            key_size=assessment.key_size,
            error_message=assessment.error_message,
            warnings=assessment.warnings,
            recommendations=assessment.recommendations,
            compliance_notes=assessment.compliance_notes,
        )

    except Exception as e:
        logger.error(f"SSH key validation error: {e}")
        raise HTTPException(status_code=500, detail="SSH key validation failed")


@router.post("/audit/credential")
@require_permission(Permission.AUDIT_READ)
async def audit_credential(
    username: str,
    auth_method: str,
    private_key: Optional[str] = None,
    password: Optional[str] = None,
    target_id: Optional[str] = None,
    target_type: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Perform comprehensive security audit of credentials.
    """
    try:
        # Get effective configuration
        config_manager = get_security_config_manager(db)
        effective_config = config_manager.get_effective_config(target_id, target_type)

        # Create validator with effective configuration
        validator = get_credential_validator(
            policy_level=effective_config.policy_level,
            enforce_fips=effective_config.enforce_fips,
        )

        # Perform audit
        audit_result = validator.audit_credential_security(
            username=username,
            auth_method=auth_method,
            private_key=private_key,
            password=password,
        )

        # Log audit activity
        logger.info(f"Credential audit performed by {current_user.get('username')} for {username}")

        return audit_result

    except Exception as e:
        logger.error(f"Credential audit error: {e}")
        raise HTTPException(status_code=500, detail="Credential audit failed")


@router.get("/compliance/summary")
@require_permission(Permission.AUDIT_READ)
async def get_compliance_summary(
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get system-wide compliance summary."""
    try:
        config_manager = get_security_config_manager(db)

        # Get system configuration
        system_summary = config_manager.get_config_summary()

        # TODO: Add credential compliance statistics
        # This would scan all stored credentials for compliance

        return {
            "system_config": system_summary,
            "compliance_level": system_summary.get("compliance_level", "unknown"),
            "last_updated": datetime.utcnow().isoformat(),
            "assessed_by": current_user.get("username"),
        }

    except Exception as e:
        logger.error(f"Compliance summary error: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate compliance summary")
