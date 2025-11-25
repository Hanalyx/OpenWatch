"""
RSA Key Lifecycle Management Service for OpenWatch
FIPS-compliant JWT signing key rotation and management
"""

import logging
import secrets
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ..config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class KeyStatus(Enum):
    """RSA key lifecycle status"""

    ACTIVE = "active"
    PENDING = "pending"
    DEPRECATED = "deprecated"
    REVOKED = "revoked"


@dataclass
class RSAKeyMetadata:
    """RSA key metadata for JWT signing"""

    key_id: str
    key_size: int
    status: KeyStatus
    created_at: datetime
    activated_at: Optional[datetime] = None
    deprecated_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    usage_count: int = 0
    last_used: Optional[datetime] = None
    fingerprint: str = ""

    def to_dict(self) -> Dict:
        """Convert to dictionary for storage"""
        data = asdict(self)
        data["status"] = self.status.value
        # Convert datetime objects to ISO strings
        for field in [
            "created_at",
            "activated_at",
            "deprecated_at",
            "expires_at",
            "last_used",
        ]:
            if data[field]:
                data[field] = data[field].isoformat()
        return data

    @classmethod
    def from_dict(cls, data: Dict) -> "RSAKeyMetadata":
        """Create from dictionary"""
        data["status"] = KeyStatus(data["status"])
        # Convert ISO strings back to datetime objects
        for field in [
            "created_at",
            "activated_at",
            "deprecated_at",
            "expires_at",
            "last_used",
        ]:
            if data[field]:
                data[field] = datetime.fromisoformat(data[field])
        return cls(**data)


class RSAKeyLifecycleManager:
    """FIPS-compliant RSA key lifecycle management"""

    def __init__(self):
        self.key_storage_path = Path("/app/security/keys")
        self.key_storage_path.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.key_size = 2048  # FIPS minimum
        self.key_lifetime_days = 365  # 1 year default
        self.rotation_overlap_days = 7  # 7 days overlap for smooth transition

    def generate_key_id(self) -> str:
        """Generate unique key identifier"""
        return f"jwt_key_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(8)}"

    def calculate_fingerprint(self, public_key) -> str:
        """Calculate SHA-256 fingerprint of RSA public key"""
        public_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(public_der)
        hash_bytes = digest.finalize()
        return hash_bytes.hex()[:32]

    def generate_rsa_key_pair(
        self, key_size: int = None
    ) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """
        Generate FIPS-compliant RSA key pair

        Args:
            key_size: RSA key size (default: 2048, recommended: 4096)

        Returns:
            Tuple of (private_key, public_key)
        """
        if key_size is None:
            key_size = self.key_size

        if key_size < 2048:
            raise ValueError("RSA key size must be at least 2048 bits for FIPS compliance")

        try:
            # Generate RSA private key with FIPS-approved parameters
            private_key = rsa.generate_private_key(
                public_exponent=65537,  # Standard public exponent
                key_size=key_size,
                backend=default_backend(),
            )

            public_key = private_key.public_key()

            logger.info(f"Generated RSA-{key_size} key pair successfully")
            return private_key, public_key

        except Exception as e:
            logger.error(f"Failed to generate RSA key pair: {e}")
            raise

    def store_key_pair(
        self,
        private_key: rsa.RSAPrivateKey,
        public_key: rsa.RSAPublicKey,
        key_id: str,
        metadata: RSAKeyMetadata,
    ) -> Tuple[Path, Path]:
        """
        Store RSA key pair securely with metadata

        Args:
            private_key: RSA private key
            public_key: RSA public key
            key_id: Unique key identifier
            metadata: Key metadata

        Returns:
            Tuple of (private_key_path, public_key_path)
        """
        try:
            # Create key-specific directory
            key_dir = self.key_storage_path / key_id
            key_dir.mkdir(mode=0o700, exist_ok=True)

            # Store private key
            private_key_path = key_dir / "jwt_private.pem"
            with open(private_key_path, "wb") as f:
                f.write(
                    private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                )
            private_key_path.chmod(0o600)

            # Store public key
            public_key_path = key_dir / "jwt_public.pem"
            with open(public_key_path, "wb") as f:
                f.write(
                    public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                )
            public_key_path.chmod(0o644)

            # Store metadata
            metadata_path = key_dir / "metadata.json"
            import json

            with open(metadata_path, "w") as f:
                json.dump(metadata.to_dict(), f, indent=2)
            metadata_path.chmod(0o600)

            logger.info(f"Stored key pair {key_id} securely")
            return private_key_path, public_key_path

        except Exception as e:
            logger.error(f"Failed to store key pair {key_id}: {e}")
            raise

    def load_key_metadata(self, key_id: str) -> Optional[RSAKeyMetadata]:
        """Load key metadata by ID"""
        try:
            metadata_path = self.key_storage_path / key_id / "metadata.json"
            if not metadata_path.exists():
                return None

            import json

            with open(metadata_path, "r") as f:
                metadata_dict = json.load(f)

            return RSAKeyMetadata.from_dict(metadata_dict)

        except Exception as e:
            logger.error(f"Failed to load metadata for key {key_id}: {e}")
            return None

    def update_key_metadata(self, key_id: str, metadata: RSAKeyMetadata):
        """Update key metadata"""
        try:
            metadata_path = self.key_storage_path / key_id / "metadata.json"
            if not metadata_path.parent.exists():
                raise ValueError(f"Key directory not found for {key_id}")

            import json

            with open(metadata_path, "w") as f:
                json.dump(metadata.to_dict(), f, indent=2)

        except Exception as e:
            logger.error(f"Failed to update metadata for key {key_id}: {e}")
            raise

    def load_private_key(self, key_id: str) -> Optional[rsa.RSAPrivateKey]:
        """Load RSA private key by ID"""
        try:
            private_key_path = self.key_storage_path / key_id / "jwt_private.pem"
            if not private_key_path.exists():
                return None

            with open(private_key_path, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )

            return private_key

        except Exception as e:
            logger.error(f"Failed to load private key {key_id}: {e}")
            return None

    def load_public_key(self, key_id: str) -> Optional[rsa.RSAPublicKey]:
        """Load RSA public key by ID"""
        try:
            public_key_path = self.key_storage_path / key_id / "jwt_public.pem"
            if not public_key_path.exists():
                return None

            with open(public_key_path, "rb") as f:
                public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

            return public_key

        except Exception as e:
            logger.error(f"Failed to load public key {key_id}: {e}")
            return None

    def get_active_key_id(self) -> Optional[str]:
        """Get the current active key ID"""
        try:
            for key_dir in self.key_storage_path.iterdir():
                if key_dir.is_dir():
                    metadata = self.load_key_metadata(key_dir.name)
                    if metadata and metadata.status == KeyStatus.ACTIVE:
                        return key_dir.name
            return None

        except Exception as e:
            logger.error(f"Failed to get active key: {e}")
            return None

    def create_new_key(self, key_size: int = None) -> str:
        """
        Create new RSA key pair and store it

        Args:
            key_size: RSA key size (default from settings)

        Returns:
            New key ID
        """
        try:
            # Generate key pair
            private_key, public_key = self.generate_rsa_key_pair(key_size)

            # Create metadata
            key_id = self.generate_key_id()
            fingerprint = self.calculate_fingerprint(public_key)

            metadata = RSAKeyMetadata(
                key_id=key_id,
                key_size=key_size or self.key_size,
                status=KeyStatus.PENDING,
                created_at=datetime.utcnow(),
                fingerprint=fingerprint,
            )

            # Store key pair
            self.store_key_pair(private_key, public_key, key_id, metadata)

            logger.info(f"Created new RSA key: {key_id}")
            return key_id

        except Exception as e:
            logger.error(f"Failed to create new key: {e}")
            raise

    def activate_key(self, key_id: str):
        """
        Activate a pending key and deprecate the current active key

        Args:
            key_id: ID of key to activate
        """
        try:
            # Load key metadata
            metadata = self.load_key_metadata(key_id)
            if not metadata:
                raise ValueError(f"Key {key_id} not found")

            if metadata.status != KeyStatus.PENDING:
                raise ValueError(f"Key {key_id} is not in pending status")

            # Deprecate current active key
            current_active = self.get_active_key_id()
            if current_active:
                self.deprecate_key(current_active)

            # Activate new key
            metadata.status = KeyStatus.ACTIVE
            metadata.activated_at = datetime.utcnow()
            metadata.expires_at = datetime.utcnow() + timedelta(days=self.key_lifetime_days)

            self.update_key_metadata(key_id, metadata)

            # Update symlinks for current active key
            self.update_current_key_symlinks(key_id)

            logger.info(f"Activated RSA key: {key_id}")

        except Exception as e:
            logger.error(f"Failed to activate key {key_id}: {e}")
            raise

    def deprecate_key(self, key_id: str):
        """Mark key as deprecated"""
        try:
            metadata = self.load_key_metadata(key_id)
            if not metadata:
                raise ValueError(f"Key {key_id} not found")

            metadata.status = KeyStatus.DEPRECATED
            metadata.deprecated_at = datetime.utcnow()

            self.update_key_metadata(key_id, metadata)

            logger.info(f"Deprecated RSA key: {key_id}")

        except Exception as e:
            logger.error(f"Failed to deprecate key {key_id}: {e}")
            raise

    def revoke_key(self, key_id: str, reason: str = None):
        """Revoke a key immediately"""
        try:
            metadata = self.load_key_metadata(key_id)
            if not metadata:
                raise ValueError(f"Key {key_id} not found")

            metadata.status = KeyStatus.REVOKED

            self.update_key_metadata(key_id, metadata)

            logger.warning(f"Revoked RSA key: {key_id}. Reason: {reason or 'Not specified'}")

        except Exception as e:
            logger.error(f"Failed to revoke key {key_id}: {e}")
            raise

    def update_current_key_symlinks(self, key_id: str):
        """Update symlinks to point to current active key"""
        try:
            # Create symlinks for current active key
            current_private_link = self.key_storage_path / "jwt_private.pem"
            current_public_link = self.key_storage_path / "jwt_public.pem"

            # Remove existing symlinks
            if current_private_link.is_symlink():
                current_private_link.unlink()
            if current_public_link.is_symlink():
                current_public_link.unlink()

            # Create new symlinks
            private_target = self.key_storage_path / key_id / "jwt_private.pem"
            public_target = self.key_storage_path / key_id / "jwt_public.pem"

            current_private_link.symlink_to(private_target)
            current_public_link.symlink_to(public_target)

            logger.info(f"Updated symlinks to point to key {key_id}")

        except Exception as e:
            logger.error(f"Failed to update symlinks for key {key_id}: {e}")
            raise

    def rotate_keys(self, new_key_size: int = None) -> str:
        """
        Perform key rotation with overlap period

        Args:
            new_key_size: Size for new key (default: current key size)

        Returns:
            New key ID
        """
        try:
            # Create new key
            new_key_id = self.create_new_key(new_key_size)

            # Activate immediately (deprecates old key)
            self.activate_key(new_key_id)

            logger.info(f"Key rotation completed: New active key {new_key_id}")
            return new_key_id

        except Exception as e:
            logger.error(f"Failed to rotate keys: {e}")
            raise

    def get_keys_needing_rotation(self) -> List[str]:
        """Get list of keys that need rotation based on expiration"""
        keys_needing_rotation = []
        now = datetime.utcnow()
        warning_threshold = now + timedelta(days=self.rotation_overlap_days)

        try:
            for key_dir in self.key_storage_path.iterdir():
                if key_dir.is_dir():
                    metadata = self.load_key_metadata(key_dir.name)
                    if (
                        metadata
                        and metadata.status == KeyStatus.ACTIVE
                        and metadata.expires_at
                        and metadata.expires_at <= warning_threshold
                    ):
                        keys_needing_rotation.append(key_dir.name)

            return keys_needing_rotation

        except Exception as e:
            logger.error(f"Failed to check keys for rotation: {e}")
            return []

    def cleanup_old_keys(self, retention_days: int = 90):
        """Clean up deprecated/revoked keys older than retention period"""
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        cleaned_count = 0

        try:
            for key_dir in self.key_storage_path.iterdir():
                if key_dir.is_dir():
                    metadata = self.load_key_metadata(key_dir.name)
                    if (
                        metadata
                        and metadata.status in [KeyStatus.DEPRECATED, KeyStatus.REVOKED]
                        and metadata.created_at < cutoff_date
                    ):

                        # Remove key directory
                        import shutil

                        shutil.rmtree(key_dir)
                        cleaned_count += 1
                        logger.info(f"Cleaned up old key: {key_dir.name}")

            if cleaned_count > 0:
                logger.info(f"Cleaned up {cleaned_count} old keys")

        except Exception as e:
            logger.error(f"Failed during key cleanup: {e}")

    def record_key_usage(self, key_id: str):
        """Record key usage for analytics"""
        try:
            metadata = self.load_key_metadata(key_id)
            if metadata:
                metadata.usage_count += 1
                metadata.last_used = datetime.utcnow()
                self.update_key_metadata(key_id, metadata)

        except Exception as e:
            logger.debug(f"Failed to record key usage for {key_id}: {e}")

    def get_key_statistics(self) -> Dict:
        """Get key lifecycle statistics"""
        stats = {
            "total_keys": 0,
            "active_keys": 0,
            "pending_keys": 0,
            "deprecated_keys": 0,
            "revoked_keys": 0,
            "keys_needing_rotation": 0,
            "oldest_active_key_age_days": 0,
            "average_key_usage": 0,
        }

        try:
            usage_counts = []
            now = datetime.utcnow()
            oldest_active_age = 0

            for key_dir in self.key_storage_path.iterdir():
                if key_dir.is_dir():
                    metadata = self.load_key_metadata(key_dir.name)
                    if metadata:
                        stats["total_keys"] += 1
                        usage_counts.append(metadata.usage_count)

                        if metadata.status == KeyStatus.ACTIVE:
                            stats["active_keys"] += 1
                            age_days = (now - metadata.created_at).days
                            oldest_active_age = max(oldest_active_age, age_days)
                        elif metadata.status == KeyStatus.PENDING:
                            stats["pending_keys"] += 1
                        elif metadata.status == KeyStatus.DEPRECATED:
                            stats["deprecated_keys"] += 1
                        elif metadata.status == KeyStatus.REVOKED:
                            stats["revoked_keys"] += 1

            stats["keys_needing_rotation"] = len(self.get_keys_needing_rotation())
            stats["oldest_active_key_age_days"] = oldest_active_age

            if usage_counts:
                stats["average_key_usage"] = sum(usage_counts) / len(usage_counts)

            return stats

        except Exception as e:
            logger.error(f"Failed to get key statistics: {e}")
            return stats


# Global key lifecycle manager instance
_key_lifecycle_manager = None


def get_key_lifecycle_manager() -> RSAKeyLifecycleManager:
    """Get global key lifecycle manager instance"""
    global _key_lifecycle_manager
    if _key_lifecycle_manager is None:
        _key_lifecycle_manager = RSAKeyLifecycleManager()
    return _key_lifecycle_manager


# Convenience functions
def rotate_jwt_keys() -> str:
    """Rotate JWT signing keys"""
    return get_key_lifecycle_manager().rotate_keys()


def get_active_jwt_key_id() -> Optional[str]:
    """Get current active JWT key ID"""
    return get_key_lifecycle_manager().get_active_key_id()


def check_keys_for_rotation() -> List[str]:
    """Check for keys needing rotation"""
    return get_key_lifecycle_manager().get_keys_needing_rotation()
