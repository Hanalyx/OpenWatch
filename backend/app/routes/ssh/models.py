"""
SSH Management Pydantic Models

This module contains all Pydantic request/response models for SSH operations.
Models are organized by functionality: settings and debug.
"""

import ipaddress
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, validator

# =============================================================================
# SSH SETTINGS MODELS
# =============================================================================


class SSHPolicyRequest(BaseModel):
    """Request model for SSH policy configuration."""

    policy: str
    trusted_networks: Optional[List[str]] = []

    @validator("policy")
    def validate_policy(cls, v: str) -> str:
        """Validate that policy is one of the allowed values."""
        valid_policies = ["strict", "auto_add", "bypass_trusted"]
        if v not in valid_policies:
            raise ValueError(f"Policy must be one of: {valid_policies}")
        return v

    @validator("trusted_networks")
    def validate_networks(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        """Validate that all network addresses are valid CIDR ranges."""
        if v is None:
            return v
        for network in v:
            try:
                ipaddress.ip_network(network, strict=False)
            except ValueError as e:
                raise ValueError(f"Invalid network range '{network}': {e}")
        return v


class SSHPolicyResponse(BaseModel):
    """Response model for SSH policy configuration."""

    policy: str
    trusted_networks: List[str]
    description: str


class KnownHostRequest(BaseModel):
    """Request model for adding a known SSH host."""

    hostname: str
    ip_address: Optional[str] = None
    key_type: str
    public_key: str
    notes: Optional[str] = None

    @validator("key_type")
    def validate_key_type(cls, v: str) -> str:
        """Validate that key type is one of the allowed SSH key types."""
        valid_types = ["rsa", "ecdsa", "ed25519", "dsa"]
        if v not in valid_types:
            raise ValueError(f"Key type must be one of: {valid_types}")
        return v


class KnownHostResponse(BaseModel):
    """Response model for SSH known host information."""

    id: int
    hostname: str
    ip_address: Optional[str]
    key_type: str
    fingerprint: str
    first_seen: str
    last_verified: Optional[str]
    is_trusted: bool
    notes: Optional[str]


# =============================================================================
# SSH DEBUG MODELS
# =============================================================================


class SSHDebugRequest(BaseModel):
    """Request model for SSH debug authentication testing."""

    host_id: str
    enable_paramiko_debug: Optional[bool] = True
    test_host_credentials: Optional[bool] = True
    test_global_credentials: Optional[bool] = True


class SSHDebugResponse(BaseModel):
    """Response model for SSH debug authentication results."""

    host_info: Dict[str, Any]
    host_credentials_test: Optional[Dict[str, Any]]
    global_credentials_test: Optional[Dict[str, Any]]
    ssh_policy_info: Dict[str, Any]
    recommendations: List[str]
