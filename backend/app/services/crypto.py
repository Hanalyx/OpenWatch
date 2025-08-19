"""
Encryption/Decryption service for sensitive data
FIPS-compliant AES-256-GCM encryption
"""
import os
import base64
from typing import Union
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import logging

logger = logging.getLogger(__name__)

# Get encryption key from environment (should be set in production)
ENCRYPTION_KEY = os.getenv("OPENWATCH_ENCRYPTION_KEY", "dev-key-change-in-production")


def _derive_key(password: str, salt: bytes):
    """Derive encryption key from password using PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt_credentials(data: str):
    """
    Encrypt credentials using AES-256-GCM
    Returns encrypted data as bytes
    """
    try:
        # Generate random salt and nonce
        salt = os.urandom(16)
        nonce = os.urandom(12)
        
        # Derive key
        key = _derive_key(ENCRYPTION_KEY, salt)
        
        # Encrypt data
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
        
        # Combine salt + nonce + tag + ciphertext
        encrypted_data = salt + nonce + encryptor.tag + ciphertext
        
        return encrypted_data
        
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        raise ValueError("Failed to encrypt credentials")


def decrypt_credentials(encrypted_data):
    """
    Decrypt credentials using AES-256-GCM
    Returns decrypted data as string
    """
    try:
        if len(encrypted_data) < 44:  # 16 (salt) + 12 (nonce) + 16 (tag) minimum
            raise ValueError("Invalid encrypted data length")
        
        # Extract components
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:28]
        tag = encrypted_data[28:44]
        ciphertext = encrypted_data[44:]
        
        # Derive key
        key = _derive_key(ENCRYPTION_KEY, salt)
        
        # Decrypt data
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext.decode()
        
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        raise ValueError("Failed to decrypt credentials")


def encrypt_string(data: str) -> str:
    """
    Encrypt string and return base64 encoded result
    """
    encrypted_bytes = encrypt_credentials(data)
    return base64.b64encode(encrypted_bytes).decode()


def decrypt_string(encrypted_b64: str) -> str:
    """
    Decrypt base64 encoded encrypted string
    """
    encrypted_bytes = base64.b64decode(encrypted_b64.encode())
    return decrypt_credentials(encrypted_bytes)


def verify_encryption() -> bool:
    """
    Verify encryption/decryption is working correctly
    """
    try:
        test_data = "test-credential-data-12345"
        encrypted = encrypt_credentials(test_data)
        decrypted = decrypt_credentials(encrypted)
        return decrypted == test_data
    except Exception as e:
        logger.error(f"Encryption verification failed: {e}")
        return False