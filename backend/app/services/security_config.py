"""
Security Configuration Management Service

Provides centralized management of security policies and configuration
for SSH key validation, credential enforcement, and FIPS compliance.
"""

import json
import logging
import os
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import text
from sqlalchemy.orm import Session

from .credential_validation import SecurityPolicyConfig, SecurityPolicyLevel

logger = logging.getLogger(__name__)


class ConfigScope(str, Enum):
    """Configuration scope levels"""

    SYSTEM = "system"  # System-wide default
    ORGANIZATION = "org"  # Organization level
    HOST_GROUP = "group"  # Host group level
    HOST = "host"  # Individual host level


@dataclass
class SecurityConfigTemplate:
    """Predefined security configuration templates"""

    name: str
    description: str
    policy_level: SecurityPolicyLevel
    enforce_fips: bool
    minimum_rsa_bits: int
    allow_dsa_keys: bool
    minimum_password_length: int
    require_complex_passwords: bool


class SecurityConfigManager:
    """
    Manages security configuration policies with hierarchical inheritance.

    Configuration inheritance order:
    1. Host-specific config
    2. Host group config
    3. Organization config
    4. System default config
    """

    # Predefined security templates
    TEMPLATES = {
        "fips_strict": SecurityConfigTemplate(
            name="FIPS Strict",
            description="Maximum security with FIPS 140-2 compliance",
            policy_level=SecurityPolicyLevel.STRICT,
            enforce_fips=True,
            minimum_rsa_bits=3072,
            allow_dsa_keys=False,
            minimum_password_length=16,
            require_complex_passwords=True,
        ),
        "enterprise": SecurityConfigTemplate(
            name="Enterprise",
            description="Balanced security for enterprise environments",
            policy_level=SecurityPolicyLevel.MODERATE,
            enforce_fips=True,
            minimum_rsa_bits=2048,
            allow_dsa_keys=False,
            minimum_password_length=12,
            require_complex_passwords=True,
        ),
        "development": SecurityConfigTemplate(
            name="Development",
            description="Permissive settings for development environments",
            policy_level=SecurityPolicyLevel.PERMISSIVE,
            enforce_fips=False,
            minimum_rsa_bits=2048,
            allow_dsa_keys=True,
            minimum_password_length=8,
            require_complex_passwords=False,
        ),
    }

    def __init__(self, db: Session):
        self.db = db
        self._ensure_default_config()

    def get_effective_config(
        self, target_id: Optional[str] = None, target_type: Optional[str] = None
    ) -> SecurityPolicyConfig:
        """
        Get effective security configuration for a target using inheritance.

        Args:
            target_id: ID of the target (host, group, etc.)
            target_type: Type of target ('host', 'group', 'org')

        Returns:
            SecurityPolicyConfig with resolved settings
        """
        try:
            config_data = {}

            # Start with system default
            system_config = self._get_config_by_scope(ConfigScope.SYSTEM)
            if system_config:
                config_data.update(system_config)

            # Layer on organization config if available
            org_config = self._get_config_by_scope(ConfigScope.ORGANIZATION)
            if org_config:
                config_data.update(org_config)

            # Layer on group config if target is host or in a group
            if target_type == "host" and target_id:
                # Get host's group and apply group config
                group_id = self._get_host_group_id(target_id)
                if group_id:
                    group_config = self._get_config_by_scope(ConfigScope.HOST_GROUP, group_id)
                    if group_config:
                        config_data.update(group_config)
            elif target_type == "group" and target_id:
                group_config = self._get_config_by_scope(ConfigScope.HOST_GROUP, target_id)
                if group_config:
                    config_data.update(group_config)

            # Finally, apply target-specific config
            if target_type == "host" and target_id:
                host_config = self._get_config_by_scope(ConfigScope.HOST, target_id)
                if host_config:
                    config_data.update(host_config)

            # Convert to SecurityPolicyConfig
            return self._dict_to_policy_config(config_data)

        except Exception as e:
            logger.error(f"Failed to get effective config for {target_type}:{target_id}: {e}")
            # Return default strict config on error
            return SecurityPolicyConfig()

    def set_config(
        self,
        scope: ConfigScope,
        config: SecurityPolicyConfig,
        target_id: Optional[str] = None,
        created_by: str = "system",
    ) -> bool:
        """
        Set security configuration for a specific scope.

        Args:
            scope: Configuration scope
            config: Security policy configuration
            target_id: Target ID (required for host/group scope)
            created_by: User who created the config

        Returns:
            bool: Success status
        """
        try:
            config_data = self._policy_config_to_dict(config)

            # Validate scope-target relationship
            if scope in [ConfigScope.HOST, ConfigScope.HOST_GROUP] and not target_id:
                raise ValueError(f"target_id is required for {scope.value} scope")

            if scope in [ConfigScope.SYSTEM, ConfigScope.ORGANIZATION] and target_id:
                raise ValueError(f"target_id must be null for {scope.value} scope")

            current_time = datetime.utcnow()

            # Upsert configuration
            self.db.execute(
                text(
                    """
                INSERT INTO security_config
                (scope, target_id, config_data, created_by, created_at, updated_at)
                VALUES (:scope, :target_id, :config_data, :created_by, :created_at, :updated_at)
                ON CONFLICT (scope, target_id)
                DO UPDATE SET
                    config_data = :config_data,
                    updated_at = :updated_at
            """
                ),
                {
                    "scope": scope.value,
                    "target_id": target_id,
                    "config_data": json.dumps(config_data),
                    "created_by": created_by,
                    "created_at": current_time,
                    "updated_at": current_time,
                },
            )

            self.db.commit()

            logger.info(f"Updated security config for scope={scope.value}, target={target_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to set security config: {e}")
            self.db.rollback()
            return False

    def apply_template(
        self,
        template_name: str,
        scope: ConfigScope,
        target_id: Optional[str] = None,
        created_by: str = "system",
    ) -> bool:
        """
        Apply a predefined security template.

        Args:
            template_name: Name of the template to apply
            scope: Configuration scope
            target_id: Target ID (if applicable)
            created_by: User applying the template

        Returns:
            bool: Success status
        """
        if template_name not in self.TEMPLATES:
            logger.error(f"Unknown security template: {template_name}")
            return False

        template = self.TEMPLATES[template_name]

        # Convert template to SecurityPolicyConfig
        config = SecurityPolicyConfig(
            policy_level=template.policy_level,
            enforce_fips=template.enforce_fips,
            minimum_rsa_bits=template.minimum_rsa_bits,
            allow_dsa_keys=template.allow_dsa_keys,
            minimum_password_length=template.minimum_password_length,
            require_complex_passwords=template.require_complex_passwords,
        )

        success = self.set_config(scope, config, target_id, created_by)

        if success:
            logger.info(f"Applied template '{template_name}' to {scope.value}:{target_id}")

        return success

    def get_config_summary(
        self, target_id: Optional[str] = None, target_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get comprehensive configuration summary including inheritance chain.

        Args:
            target_id: Target ID
            target_type: Target type

        Returns:
            Dict with configuration summary and inheritance info
        """
        try:
            effective_config = self.get_effective_config(target_id, target_type)

            # Get inheritance chain
            inheritance_chain = []

            # System level
            system_config = self._get_config_by_scope(ConfigScope.SYSTEM)
            if system_config:
                inheritance_chain.append(
                    {
                        "level": "system",
                        "source": "System Default",
                        "settings_count": len(system_config),
                    }
                )

            # Organization level
            org_config = self._get_config_by_scope(ConfigScope.ORGANIZATION)
            if org_config:
                inheritance_chain.append(
                    {
                        "level": "organization",
                        "source": "Organization Policy",
                        "settings_count": len(org_config),
                    }
                )

            # Group level
            if target_type in ["host", "group"] and target_id:
                group_id = (
                    target_id if target_type == "group" else self._get_host_group_id(target_id)
                )
                if group_id:
                    group_config = self._get_config_by_scope(ConfigScope.HOST_GROUP, group_id)
                    if group_config:
                        inheritance_chain.append(
                            {
                                "level": "group",
                                "source": f"Group {group_id}",
                                "settings_count": len(group_config),
                            }
                        )

            # Host level
            if target_type == "host" and target_id:
                host_config = self._get_config_by_scope(ConfigScope.HOST, target_id)
                if host_config:
                    inheritance_chain.append(
                        {
                            "level": "host",
                            "source": f"Host {target_id}",
                            "settings_count": len(host_config),
                        }
                    )

            return {
                "effective_config": {
                    "policy_level": effective_config.policy_level.value,
                    "enforce_fips": effective_config.enforce_fips,
                    "minimum_rsa_bits": effective_config.minimum_rsa_bits,
                    "allow_dsa_keys": effective_config.allow_dsa_keys,
                    "minimum_password_length": effective_config.minimum_password_length,
                    "require_complex_passwords": effective_config.require_complex_passwords,
                    "allowed_key_types": [kt.value for kt in effective_config.allowed_key_types],
                },
                "inheritance_chain": inheritance_chain,
                "compliance_level": self._assess_compliance_level(effective_config),
            }

        except Exception as e:
            logger.error(f"Failed to get config summary: {e}")
            return {"error": str(e)}

    def list_templates(self) -> List[Dict[str, Any]]:
        """List all available security configuration templates"""
        return [
            {
                "name": name,
                "description": template.description,
                "policy_level": template.policy_level.value,
                "enforce_fips": template.enforce_fips,
                "recommended_for": self._get_template_recommendation(name),
            }
            for name, template in self.TEMPLATES.items()
        ]

    def validate_config(self, config: SecurityPolicyConfig) -> Tuple[bool, List[str]]:
        """
        Validate security configuration for consistency and best practices.

        Args:
            config: Configuration to validate

        Returns:
            Tuple of (is_valid, validation_messages)
        """
        messages = []
        is_valid = True

        # FIPS compliance validation
        if config.enforce_fips:
            if config.allow_dsa_keys:
                messages.append("DSA keys are not FIPS compliant and should be disabled")
                is_valid = False

            if config.minimum_rsa_bits < 2048:
                messages.append("FIPS requires minimum RSA key size of 2048 bits")
                is_valid = False

        # Security best practices
        if config.policy_level == SecurityPolicyLevel.STRICT:
            if config.minimum_rsa_bits < 3072:
                messages.append("Strict policy should require RSA keys of 3072+ bits")

            if config.minimum_password_length < 12:
                messages.append("Strict policy should require passwords of 12+ characters")

        # Consistency checks
        if not config.require_complex_passwords and config.minimum_password_length < 16:
            messages.append("Simple passwords should be at least 16 characters long")

        if not messages:
            messages.append("Configuration meets security requirements")

        return is_valid, messages

    def _ensure_default_config(self):
        """Ensure system has a default security configuration"""
        try:
            result = self.db.execute(
                text(
                    """
                SELECT id FROM security_config
                WHERE scope = 'system' AND target_id IS NULL
            """
                )
            )

            if not result.fetchone():
                # Create default strict configuration
                default_config = SecurityPolicyConfig()
                self.set_config(ConfigScope.SYSTEM, default_config, created_by="system")
                logger.info("Created default system security configuration")

        except Exception as e:
            logger.error(f"Failed to ensure default config: {e}")

    def _get_config_by_scope(
        self, scope: ConfigScope, target_id: Optional[str] = None
    ) -> Optional[Dict]:
        """Get configuration data for a specific scope"""
        try:
            result = self.db.execute(
                text(
                    """
                SELECT config_data FROM security_config
                WHERE scope = :scope AND target_id IS :target_id
            """
                ),
                {"scope": scope.value, "target_id": target_id},
            )

            row = result.fetchone()
            if row and row.config_data:
                return json.loads(row.config_data)

            return None

        except Exception as e:
            logger.error(f"Failed to get config for scope {scope.value}: {e}")
            return None

    def _get_host_group_id(self, host_id: str) -> Optional[str]:
        """Get the primary group ID for a host"""
        try:
            result = self.db.execute(
                text(
                    """
                SELECT hgm.host_group_id
                FROM host_group_memberships hgm
                WHERE hgm.host_id = :host_id
                LIMIT 1
            """
                ),
                {"host_id": host_id},
            )

            row = result.fetchone()
            return str(row.host_group_id) if row else None

        except Exception as e:
            logger.error(f"Failed to get host group for {host_id}: {e}")
            return None

    def _dict_to_policy_config(self, config_data: Dict) -> SecurityPolicyConfig:
        """Convert dictionary to SecurityPolicyConfig"""
        try:
            # Set defaults
            policy_config = SecurityPolicyConfig()

            # Override with provided values
            if "policy_level" in config_data:
                policy_config.policy_level = SecurityPolicyLevel(config_data["policy_level"])
            if "enforce_fips" in config_data:
                policy_config.enforce_fips = config_data["enforce_fips"]
            if "minimum_rsa_bits" in config_data:
                policy_config.minimum_rsa_bits = config_data["minimum_rsa_bits"]
            if "allow_dsa_keys" in config_data:
                policy_config.allow_dsa_keys = config_data["allow_dsa_keys"]
            if "minimum_password_length" in config_data:
                policy_config.minimum_password_length = config_data["minimum_password_length"]
            if "require_complex_passwords" in config_data:
                policy_config.require_complex_passwords = config_data["require_complex_passwords"]

            return policy_config

        except Exception as e:
            logger.error(f"Failed to convert dict to policy config: {e}")
            return SecurityPolicyConfig()  # Return default on error

    def _policy_config_to_dict(self, config: SecurityPolicyConfig) -> Dict:
        """Convert SecurityPolicyConfig to dictionary"""
        return {
            "policy_level": config.policy_level.value,
            "enforce_fips": config.enforce_fips,
            "minimum_rsa_bits": config.minimum_rsa_bits,
            "minimum_ecdsa_bits": config.minimum_ecdsa_bits,
            "allow_dsa_keys": config.allow_dsa_keys,
            "minimum_password_length": config.minimum_password_length,
            "require_complex_passwords": config.require_complex_passwords,
            "allowed_key_types": [kt.value for kt in config.allowed_key_types],
        }

    def _assess_compliance_level(self, config: SecurityPolicyConfig) -> str:
        """Assess overall compliance level of configuration"""
        if config.enforce_fips and config.policy_level == SecurityPolicyLevel.STRICT:
            return "high"
        elif config.enforce_fips or config.policy_level == SecurityPolicyLevel.MODERATE:
            return "medium"
        else:
            return "low"

    def _get_template_recommendation(self, template_name: str) -> str:
        """Get recommendation for when to use a template"""
        recommendations = {
            "fips_strict": "Compliance-critical, healthcare, financial services requiring FIPS 140-2",
            "enterprise": "Corporate environments with security requirements",
            "development": "Development and testing environments",
        }
        return recommendations.get(template_name, "General use")


# Factory function
def get_security_config_manager(db: Session) -> SecurityConfigManager:
    """Factory function to create SecurityConfigManager"""
    return SecurityConfigManager(db)
