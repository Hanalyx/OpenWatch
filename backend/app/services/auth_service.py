"""
Centralized Authentication Service
Provides unified credential storage, encryption, and validation for OpenWatch.
Replaces the dual-system approach with a single, consistent authentication layer.
"""
import uuid
import json
import logging
from typing import Dict, Optional, List, Tuple
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import text
from pydantic import BaseModel, Field
from enum import Enum

from .encryption import encrypt_data, decrypt_data
from .ssh_utils import validate_ssh_key, parse_ssh_key
from .ssh_key_service import extract_ssh_key_metadata
from .credential_validation import validate_credential_with_strict_policy, SecurityPolicyLevel

logger = logging.getLogger(__name__)


class CredentialScope(str, Enum):
    """Credential scope types"""
    SYSTEM = "system"
    HOST = "host"
    GROUP = "group"


class AuthMethod(str, Enum):
    """Authentication method types"""
    SSH_KEY = "ssh_key"
    PASSWORD = "password"
    BOTH = "both"


class CredentialData(BaseModel):
    """Unified credential data structure"""
    username: str
    auth_method: AuthMethod
    private_key: Optional[str] = None
    password: Optional[str] = None
    private_key_passphrase: Optional[str] = None
    source: str = "unknown"


class CredentialMetadata(BaseModel):
    """Credential metadata for storage"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: Optional[str] = None
    scope: CredentialScope
    target_id: Optional[str] = None
    is_default: bool = False
    is_active: bool = True


class CentralizedAuthService:
    """
    Centralized authentication service that provides unified credential management.
    Solves the issue where system credentials use AES encryption but host credentials only use base64.
    """
    
    def __init__(self, db: Session):
        self.db = db
        
    def store_credential(self, credential_data: CredentialData, metadata: CredentialMetadata, 
                        created_by: str) -> str:
        """
        Store credential with unified encryption and validation.
        All credentials use AES-256-GCM regardless of scope.
        
        Args:
            credential_data: The credential information to store
            metadata: Metadata about the credential (scope, target, etc.)
            created_by: User ID who is creating the credential
            
        Returns:
            str: The credential ID
            
        Raises:
            ValueError: If credential validation fails
            Exception: If storage fails
        """
        try:
            # Validate credential format and connectivity
            validation_result = self.validate_credential(credential_data)
            if not validation_result[0]:
                raise ValueError(f"Credential validation failed: {validation_result[1]}")
            
            # Extract SSH key metadata if provided
            ssh_metadata = {}
            if credential_data.private_key:
                ssh_metadata = self._extract_ssh_key_metadata(credential_data.private_key, 
                                                            credential_data.private_key_passphrase)
            
            # If setting as default, unset other defaults in same scope
            if metadata.is_default:
                self._unset_default_credentials(metadata.scope, metadata.target_id)
            
            # Encrypt sensitive data using unified AES-256-GCM
            encrypted_password = None
            encrypted_private_key = None
            encrypted_passphrase = None
            
            if credential_data.password:
                encrypted_password = encrypt_data(credential_data.password.encode())
            if credential_data.private_key:
                encrypted_private_key = encrypt_data(credential_data.private_key.encode())
            if credential_data.private_key_passphrase:
                encrypted_passphrase = encrypt_data(credential_data.private_key_passphrase.encode())
            
            # Store in unified credentials table
            current_time = datetime.utcnow()
            
            self.db.execute(text("""
                INSERT INTO unified_credentials 
                (id, name, description, scope, target_id, username, auth_method,
                 encrypted_password, encrypted_private_key, encrypted_passphrase,
                 ssh_key_fingerprint, ssh_key_type, ssh_key_bits, ssh_key_comment,
                 is_default, is_active, created_by, created_at, updated_at)
                VALUES (:id, :name, :description, :scope, :target_id, :username, :auth_method,
                        :encrypted_password, :encrypted_private_key, :encrypted_passphrase,
                        :ssh_key_fingerprint, :ssh_key_type, :ssh_key_bits, :ssh_key_comment,
                        :is_default, :is_active, :created_by, :created_at, :updated_at)
            """), {
                "id": metadata.id,
                "name": metadata.name,
                "description": metadata.description,
                "scope": metadata.scope.value,
                "target_id": metadata.target_id,
                "username": credential_data.username,
                "auth_method": credential_data.auth_method.value,
                "encrypted_password": encrypted_password,
                "encrypted_private_key": encrypted_private_key,
                "encrypted_passphrase": encrypted_passphrase,
                "ssh_key_fingerprint": ssh_metadata.get('fingerprint'),
                "ssh_key_type": ssh_metadata.get('key_type'),
                "ssh_key_bits": ssh_metadata.get('key_bits'),
                "ssh_key_comment": ssh_metadata.get('key_comment'),
                "is_default": metadata.is_default,
                "is_active": metadata.is_active,
                "created_by": created_by,
                "created_at": current_time,
                "updated_at": current_time
            })
            
            self.db.commit()
            
            logger.info(f"Stored {metadata.scope.value} credential '{metadata.name}' (ID: {metadata.id})")
            return metadata.id
            
        except Exception as e:
            logger.error(f"Failed to store credential: {e}")
            self.db.rollback()
            raise
    
    def get_credential(self, credential_id: str) -> Optional[CredentialData]:
        """
        Retrieve and decrypt a specific credential by ID.
        
        Args:
            credential_id: The credential ID to retrieve
            
        Returns:
            CredentialData: The decrypted credential data, or None if not found
        """
        try:
            result = self.db.execute(text("""
                SELECT username, auth_method, encrypted_password, encrypted_private_key, 
                       encrypted_passphrase, scope, target_id
                FROM unified_credentials 
                WHERE id = :id AND is_active = true
            """), {"id": credential_id})
            
            row = result.fetchone()
            if not row:
                return None
            
            # Decrypt credential data
            password = None
            private_key = None
            passphrase = None
            
            if row.encrypted_password:
                password = decrypt_data(row.encrypted_password).decode()
            if row.encrypted_private_key:
                private_key = decrypt_data(row.encrypted_private_key).decode()
            if row.encrypted_passphrase:
                passphrase = decrypt_data(row.encrypted_passphrase).decode()
            
            return CredentialData(
                username=row.username,
                auth_method=AuthMethod(row.auth_method),
                password=password,
                private_key=private_key,
                private_key_passphrase=passphrase,
                source=f"{row.scope}:{row.target_id}" if row.target_id else row.scope
            )
            
        except Exception as e:
            logger.error(f"Failed to get credential {credential_id}: {e}")
            return None
    
    def resolve_credential(self, target_id: str = None, use_default: bool = False) -> Optional[CredentialData]:
        """
        Resolve effective credentials using inheritance logic.
        This is the core method that fixes the authentication inconsistency.
        
        Resolution order:
        1. If use_default=True -> system default credential
        2. If target_id provided -> target-specific credential 
        3. If target has no credential -> fallback to system default
        4. Validate and normalize before return
        
        Args:
            target_id: Target ID (host_id, group_id) to resolve credentials for
            use_default: Force use of system default credentials
            
        Returns:
            CredentialData: Resolved credential, or None if none available
        """
        try:
            # Step 1: Check for forced default use
            if use_default:
                logger.debug(f"Resolving system default credential (forced)")
                return self._get_system_default()
            
            # Step 2: Try target-specific credential first
            if target_id:
                logger.debug(f"Looking for host-specific credential for {target_id}")
                result = self.db.execute(text("""
                    SELECT id FROM unified_credentials 
                    WHERE scope = 'host' AND target_id = :target_id AND is_active = true
                    ORDER BY is_default DESC, created_at DESC
                    LIMIT 1
                """), {"target_id": target_id})
                
                row = result.fetchone()
                if row:
                    credential = self.get_credential(row.id)
                    if credential:
                        credential.source = f"host:{target_id}"
                        logger.info(f"Resolved host-specific credential for {target_id}")
                        return credential
            
            # Step 3: Fallback to system default
            logger.debug(f"Falling back to system default credential")
            default_credential = self._get_system_default()
            if default_credential:
                default_credential.source = "system_default_fallback"
                logger.info(f"Resolved system default credential as fallback")
            
            return default_credential
            
        except Exception as e:
            logger.error(f"Failed to resolve credential: {e}")
            return None
    
    def _get_system_default(self) -> Optional[CredentialData]:
        """Get system default credential"""
        try:
            result = self.db.execute(text("""
                SELECT id FROM unified_credentials 
                WHERE scope = 'system' AND is_default = true AND is_active = true
                LIMIT 1
            """))
            
            row = result.fetchone()
            if not row:
                logger.warning("No system default credential found")
                return None
            
            credential = self.get_credential(row.id)
            if credential:
                credential.source = "system_default"
            
            return credential
            
        except Exception as e:
            logger.error(f"Failed to get system default credential: {e}")
            return None
    
    def validate_credential(self, credential_data: CredentialData, 
                          strict_mode: bool = True) -> Tuple[bool, str]:
        """
        Validate credential data with strict security policy enforcement.
        
        Args:
            credential_data: The credential to validate
            strict_mode: Whether to enforce strict security policies (default: True)
            
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        try:
            # Basic format validation
            if not credential_data.username:
                return False, "Username is required"
            
            if credential_data.auth_method in [AuthMethod.PASSWORD, AuthMethod.BOTH]:
                if not credential_data.password:
                    return False, "Password is required for password authentication"
            
            if credential_data.auth_method in [AuthMethod.SSH_KEY, AuthMethod.BOTH]:
                if not credential_data.private_key:
                    return False, "SSH private key is required for key authentication"
            
            # Use strict validation by default (Security Fix 4)
            if strict_mode:
                policy_level = SecurityPolicyLevel.STRICT
                is_valid, error_message = validate_credential_with_strict_policy(
                    username=credential_data.username,
                    auth_method=credential_data.auth_method.value,
                    private_key=credential_data.private_key,
                    password=credential_data.password,
                    policy_level=policy_level
                )
                
                if not is_valid:
                    logger.warning(f"Credential rejected by strict security policy: {error_message}")
                    return False, error_message
            else:
                # Legacy validation (only for compatibility)
                if credential_data.private_key:
                    validation_result = validate_ssh_key(credential_data.private_key)
                    if not validation_result.is_valid:
                        return False, f"Invalid SSH key: {validation_result.error_message}"
            
            return True, ""
            
        except Exception as e:
            logger.error(f"Credential validation error: {e}")
            return False, f"Validation error: {str(e)}"
    
    def _extract_ssh_key_metadata(self, private_key: str, passphrase: str = None) -> Dict:
        """Extract SSH key metadata for storage"""
        try:
            metadata = extract_ssh_key_metadata(private_key, passphrase)
            return {
                'fingerprint': metadata.get('fingerprint'),
                'key_type': metadata.get('key_type'),
                'key_bits': int(metadata.get('key_bits')) if metadata.get('key_bits') else None,
                'key_comment': metadata.get('key_comment')
            }
        except Exception as e:
            logger.warning(f"Failed to extract SSH key metadata: {e}")
            return {}
    
    def _unset_default_credentials(self, scope: CredentialScope, target_id: str = None):
        """Unset existing default credentials in the same scope"""
        try:
            if scope == CredentialScope.SYSTEM:
                self.db.execute(text("""
                    UPDATE unified_credentials 
                    SET is_default = false 
                    WHERE scope = 'system' AND is_default = true
                """))
            else:
                self.db.execute(text("""
                    UPDATE unified_credentials 
                    SET is_default = false 
                    WHERE scope = :scope AND target_id = :target_id AND is_default = true
                """), {"scope": scope.value, "target_id": target_id})
                
        except Exception as e:
            logger.error(f"Failed to unset default credentials: {e}")
    
    def list_credentials(self, scope: CredentialScope = None, target_id: str = None, 
                        user_id: str = None) -> List[Dict]:
        """
        List credentials with filtering options.
        
        Args:
            scope: Filter by credential scope
            target_id: Filter by target ID
            user_id: Filter by user (for access control)
            
        Returns:
            List[Dict]: List of credential metadata (no sensitive data)
        """
        try:
            conditions = ["is_active = true"]
            params = {}
            
            if scope:
                conditions.append("scope = :scope")
                params["scope"] = scope.value
                
            if target_id:
                conditions.append("target_id = :target_id")
                params["target_id"] = target_id
                
            if user_id:
                conditions.append("created_by = :user_id")
                params["user_id"] = user_id
            
            where_clause = " AND ".join(conditions)
            
            result = self.db.execute(text(f"""
                SELECT id, name, description, scope, target_id, username, auth_method,
                       ssh_key_fingerprint, ssh_key_type, ssh_key_bits, ssh_key_comment,
                       is_default, created_at, updated_at
                FROM unified_credentials 
                WHERE {where_clause}
                ORDER BY scope, is_default DESC, name
            """), params)
            
            credentials = []
            for row in result:
                credentials.append({
                    "id": row.id,
                    "name": row.name,
                    "description": row.description,
                    "scope": row.scope,
                    "target_id": row.target_id,
                    "username": row.username,
                    "auth_method": row.auth_method,
                    "ssh_key_fingerprint": row.ssh_key_fingerprint,
                    "ssh_key_type": row.ssh_key_type,
                    "ssh_key_bits": row.ssh_key_bits,
                    "ssh_key_comment": row.ssh_key_comment,
                    "is_default": row.is_default,
                    "created_at": row.created_at.isoformat(),
                    "updated_at": row.updated_at.isoformat()
                })
            
            return credentials
            
        except Exception as e:
            logger.error(f"Failed to list credentials: {e}")
            return []
    
    def delete_credential(self, credential_id: str) -> bool:
        """
        Soft delete a credential by marking it inactive.
        
        Args:
            credential_id: The credential ID to delete
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            result = self.db.execute(text("""
                UPDATE unified_credentials 
                SET is_active = false, updated_at = :updated_at
                WHERE id = :id
            """), {"id": credential_id, "updated_at": datetime.utcnow()})
            
            if result.rowcount > 0:
                self.db.commit()
                logger.info(f"Deleted credential {credential_id}")
                return True
            else:
                logger.warning(f"Credential {credential_id} not found for deletion")
                return False
                
        except Exception as e:
            logger.error(f"Failed to delete credential {credential_id}: {e}")
            self.db.rollback()
            return False


# Factory function for service creation
def get_auth_service(db: Session) -> CentralizedAuthService:
    """Factory function to create CentralizedAuthService instance"""
    return CentralizedAuthService(db)