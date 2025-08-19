"""
Encryption service for sensitive data like SSH credentials
Uses AES-256-GCM for authenticated encryption
"""
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import logging

logger = logging.getLogger(__name__)

class EncryptionService:
    def __init__(self, master_key: str):
        """Initialize encryption service with master key"""
        self.master_key = master_key.encode()
        
    def _derive_key(self, salt: bytes) -> bytes:
        """Derive encryption key from master key and salt"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(self.master_key)
    
    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data using AES-256-GCM"""
        try:
            # Generate random salt and nonce
            salt = os.urandom(16)
            nonce = os.urandom(12)  # GCM recommended nonce size
            
            # Derive key from master key and salt
            key = self._derive_key(salt)
            
            # Encrypt data
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, data, None)
            
            # Combine salt + nonce + ciphertext
            encrypted_data = salt + nonce + ciphertext
            
            return encrypted_data
            
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            raise
    
    def decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using AES-256-GCM"""
        try:
            # Extract salt, nonce, and ciphertext
            salt = encrypted_data[:16]
            nonce = encrypted_data[16:28]
            ciphertext = encrypted_data[28:]
            
            # Derive key from master key and salt
            key = self._derive_key(salt)
            
            # Decrypt data
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            return plaintext
            
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            raise

# Global encryption service instance
_encryption_service = None

def get_encryption_service() -> EncryptionService:
    """Get global encryption service instance"""
    global _encryption_service
    if _encryption_service is None:
        from ..config import get_settings
        settings = get_settings()
        _encryption_service = EncryptionService(settings.master_key)
    return _encryption_service

def encrypt_data(data: bytes) -> str:
    """Encrypt data using global encryption service and return base64 string"""
    encrypted_bytes = get_encryption_service().encrypt(data)
    return base64.b64encode(encrypted_bytes).decode('ascii')

def decrypt_data(encrypted_data: str) -> bytes:
    """Decrypt base64-encoded data using global encryption service"""
    encrypted_bytes = base64.b64decode(encrypted_data.encode('ascii'))
    return get_encryption_service().decrypt(encrypted_bytes)