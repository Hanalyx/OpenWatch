"""
Credential Utility Functions
Shared utilities for credential processing and decoding
"""

import base64
import json
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def decode_base64_credentials(encrypted_credentials: str) -> Dict[str, Any]:
    """
    Decode base64 encoded credential data

    This function was extracted from duplicate implementations in:
    - routes/credentials.py
    - services/credential_migration.py

    Args:
        encrypted_credentials: Base64 encoded JSON credential data

    Returns:
        Dict: Decoded credential data

    Raises:
        ValueError: If decoding fails
    """
    try:
        decoded_data = base64.b64decode(encrypted_credentials).decode("utf-8")
        credentials_data = json.loads(decoded_data)
        return credentials_data
    except (base64.binascii.Error, json.JSONDecodeError, UnicodeDecodeError) as e:
        logger.error(f"Failed to decode base64 credentials: {e}")
        raise ValueError(f"Invalid credential data format: {e}")


def extract_ssh_credentials(
    credentials_data: Dict[str, Any],
) -> Dict[str, Optional[str]]:
    """
    Extract SSH credential fields from decoded credential data

    Handles the different field naming conventions:
    - 'ssh_key' vs 'private_key'
    - 'password'
    - 'private_key_passphrase' vs 'passphrase'

    Args:
        credentials_data: Decoded credential dictionary

    Returns:
        Dict with normalized field names:
        - 'private_key': SSH private key content
        - 'password': Password if available
        - 'passphrase': Private key passphrase if available
    """
    # Handle different naming conventions
    private_key = credentials_data.get("private_key") or credentials_data.get("ssh_key")
    password = credentials_data.get("password")
    passphrase = credentials_data.get("private_key_passphrase") or credentials_data.get(
        "passphrase"
    )

    return {"private_key": private_key, "password": password, "passphrase": passphrase}


def normalize_auth_method(auth_method: str) -> str:
    """
    Normalize authentication method strings to consistent format

    Args:
        auth_method: Authentication method string

    Returns:
        str: Normalized auth method ('ssh_key', 'password', or 'both')
    """
    if not auth_method:
        return "ssh_key"  # Default

    auth_method = auth_method.lower().strip()

    # Handle variations
    if auth_method in ["key", "publickey", "private_key", "ssh_key"]:
        return "ssh_key"
    elif auth_method in ["pass", "password"]:
        return "password"
    elif auth_method in ["both", "key_and_password", "ssh_key_and_password"]:
        return "both"
    else:
        # Default to ssh_key for unknown values
        logger.warning(f"Unknown auth method '{auth_method}', defaulting to 'ssh_key'")
        return "ssh_key"


def validate_credential_completeness(
    credentials: Dict[str, Optional[str]], auth_method: str
) -> bool:
    """
    Validate that credential data is complete for the specified auth method

    Args:
        credentials: Credential data with 'private_key', 'password', 'passphrase'
        auth_method: Authentication method ('ssh_key', 'password', 'both')

    Returns:
        bool: True if credentials are complete for the auth method
    """
    auth_method = normalize_auth_method(auth_method)

    has_key = bool(credentials.get("private_key"))
    has_password = bool(credentials.get("password"))

    if auth_method == "ssh_key":
        return has_key
    elif auth_method == "password":
        return has_password
    elif auth_method == "both":
        return has_key and has_password

    return False
