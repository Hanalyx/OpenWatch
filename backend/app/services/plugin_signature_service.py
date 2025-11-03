"""
Plugin Signature Service
Cryptographic verification for plugin authenticity
"""

import hashlib
import json
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from pathlib import Path
import logging
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature

from ..models.plugin_models import PluginSignature, PluginPackage, SecurityCheckResult

logger = logging.getLogger(__name__)


class PluginSignatureService:
    """Handle plugin signature verification and trust management"""

    def __init__(self, trusted_keys_dir: Optional[Path] = None):
        """
        Initialize signature service

        Args:
            trusted_keys_dir: Directory containing trusted public keys
        """
        self.trusted_keys_dir = trusted_keys_dir or Path("/app/security/plugin_keys")
        self.trusted_keys_cache = {}
        self._load_trusted_keys()

    def _load_trusted_keys(self):
        """Load trusted public keys from disk"""
        if not self.trusted_keys_dir.exists():
            logger.warning(f"Trusted keys directory not found: {self.trusted_keys_dir}")
            return

        for key_file in self.trusted_keys_dir.glob("*.pem"):
            try:
                with open(key_file, "rb") as f:
                    public_key = load_pem_public_key(f.read())

                key_id = self._calculate_key_id(public_key)
                self.trusted_keys_cache[key_id] = {
                    "key": public_key,
                    "file": key_file.name,
                    "loaded_at": datetime.utcnow(),
                }
                logger.info(f"Loaded trusted key: {key_id} from {key_file.name}")

            except Exception as e:
                logger.error(f"Failed to load key from {key_file}: {e}")

    def _calculate_key_id(self, public_key) -> str:
        """Calculate unique key ID from public key"""
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(public_bytes).hexdigest()[:16]

    async def verify_plugin_signature(
        self, package: PluginPackage, require_trusted_signature: bool = True
    ) -> SecurityCheckResult:
        """
        Verify plugin package signature

        Args:
            package: Plugin package to verify
            require_trusted_signature: Whether to require signature from trusted publisher

        Returns:
            Security check result with verification status
        """
        if not package.signature:
            return SecurityCheckResult(
                check_name="signature_verification",
                passed=not require_trusted_signature,
                severity="critical" if require_trusted_signature else "warning",
                message=(
                    "No signature provided" if require_trusted_signature else "Package not signed"
                ),
                details={"signed": False},
            )

        try:
            # Verify signature authenticity
            verification_result = await self._verify_signature_authenticity(
                package, package.signature
            )

            if not verification_result["valid"]:
                return SecurityCheckResult(
                    check_name="signature_verification",
                    passed=False,
                    severity="critical",
                    message=verification_result["error"],
                    details=verification_result,
                )

            # Check if signer is trusted
            trust_result = self._check_signer_trust(package.signature)

            severity = "info"
            message = "Signature verified successfully"

            if require_trusted_signature and not trust_result["trusted"]:
                severity = "warning"
                message = "Signature valid but signer not in trusted list"

            return SecurityCheckResult(
                check_name="signature_verification",
                passed=True,
                severity=severity,
                message=message,
                details={
                    "signed": True,
                    "signer": package.signature.signer,
                    "trusted": trust_result["trusted"],
                    "algorithm": package.signature.algorithm,
                    "signed_at": package.signature.signed_at.isoformat(),
                },
            )

        except Exception as e:
            logger.error(f"Signature verification error: {e}")
            return SecurityCheckResult(
                check_name="signature_verification",
                passed=False,
                severity="critical",
                message=f"Signature verification failed: {str(e)}",
            )

    async def _verify_signature_authenticity(
        self, package: PluginPackage, signature: PluginSignature
    ) -> Dict:
        """Verify the cryptographic signature"""
        try:
            # Get signing data (package content without signature)
            signing_data = self._get_signing_data(package)

            # Get public key for verification
            public_key_result = await self._get_verification_key(signature.public_key_id)
            if not public_key_result["found"]:
                return {
                    "valid": False,
                    "error": f"Public key not found: {signature.public_key_id}",
                    "key_available": False,
                }

            public_key = public_key_result["key"]

            # Convert signature from hex
            signature_bytes = bytes.fromhex(signature.signature)

            # Verify signature based on algorithm
            if signature.algorithm == "SHA256":
                hash_algo = hashes.SHA256()
            elif signature.algorithm == "SHA384":
                hash_algo = hashes.SHA384()
            elif signature.algorithm == "SHA512":
                hash_algo = hashes.SHA512()
            else:
                return {
                    "valid": False,
                    "error": f"Unsupported hash algorithm: {signature.algorithm}",
                }

            # Perform RSA-PSS signature verification
            try:
                public_key.verify(
                    signature_bytes,
                    signing_data,
                    padding.PSS(mgf=padding.MGF1(hash_algo), salt_length=padding.PSS.MAX_LENGTH),
                    hash_algo,
                )

                return {
                    "valid": True,
                    "algorithm": signature.algorithm,
                    "key_id": signature.public_key_id,
                }

            except InvalidSignature:
                return {
                    "valid": False,
                    "error": "Invalid signature - content may have been tampered with",
                }

        except Exception as e:
            return {"valid": False, "error": f"Signature verification error: {str(e)}"}

    def _get_signing_data(self, package: PluginPackage) -> bytes:
        """Get canonical signing data from package"""
        # Create reproducible signing data
        signing_content = {
            "manifest": package.manifest.dict(),
            "executors": {k: v.dict() for k, v in package.executors.items()},
            "checksum": package.checksum,
        }

        # Convert to canonical JSON (sorted keys, no whitespace)
        json_str = json.dumps(signing_content, sort_keys=True, separators=(",", ":"))
        return json_str.encode("utf-8")

    async def _get_verification_key(self, key_id: str) -> Dict:
        """Get public key for signature verification"""
        # Check trusted keys cache first
        if key_id in self.trusted_keys_cache:
            return {
                "found": True,
                "key": self.trusted_keys_cache[key_id]["key"],
                "trusted": True,
                "source": "trusted_cache",
            }

        # Could implement key retrieval from external sources here
        # For now, only support pre-loaded trusted keys

        return {
            "found": False,
            "trusted": False,
            "error": f"Key {key_id} not in trusted keystore",
        }

    def _check_signer_trust(self, signature: PluginSignature) -> Dict:
        """Check if signer is in trusted list"""
        key_info = self.trusted_keys_cache.get(signature.public_key_id, {})

        return {
            "trusted": signature.public_key_id in self.trusted_keys_cache,
            "key_file": key_info.get("file"),
            "signer": signature.signer,
        }

    def get_trusted_signers(self) -> List[Dict]:
        """Get list of trusted signers"""
        return [
            {
                "key_id": key_id,
                "key_file": info["file"],
                "loaded_at": info["loaded_at"].isoformat(),
            }
            for key_id, info in self.trusted_keys_cache.items()
        ]

    async def add_trusted_key(self, public_key_pem: str, key_name: str, signer_info: Dict) -> Dict:
        """Add a new trusted public key"""
        try:
            # Parse public key
            public_key = load_pem_public_key(public_key_pem.encode())
            key_id = self._calculate_key_id(public_key)

            # Check if key already exists
            if key_id in self.trusted_keys_cache:
                return {
                    "success": False,
                    "error": "Key already exists in trusted keystore",
                }

            # Save key to disk
            key_file_path = self.trusted_keys_dir / f"{key_name}.pem"
            if key_file_path.exists():
                return {"success": False, "error": "Key file name already exists"}

            # Create directory if needed
            self.trusted_keys_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

            # Write key file
            with open(key_file_path, "w") as f:
                f.write(public_key_pem)

            # Set restrictive permissions
            key_file_path.chmod(0o600)

            # Add to cache
            self.trusted_keys_cache[key_id] = {
                "key": public_key,
                "file": key_file_path.name,
                "loaded_at": datetime.utcnow(),
                "signer_info": signer_info,
            }

            logger.info(f"Added trusted key: {key_id} ({key_name})")

            return {"success": True, "key_id": key_id, "key_name": key_name}

        except Exception as e:
            logger.error(f"Failed to add trusted key: {e}")
            return {"success": False, "error": str(e)}

    async def remove_trusted_key(self, key_id: str) -> Dict:
        """Remove a trusted public key"""
        try:
            if key_id not in self.trusted_keys_cache:
                return {"success": False, "error": "Key not found in trusted keystore"}

            # Get key info
            key_info = self.trusted_keys_cache[key_id]
            key_file = self.trusted_keys_dir / key_info["file"]

            # Remove from disk
            if key_file.exists():
                key_file.unlink()

            # Remove from cache
            del self.trusted_keys_cache[key_id]

            logger.info(f"Removed trusted key: {key_id}")

            return {"success": True, "key_id": key_id}

        except Exception as e:
            logger.error(f"Failed to remove trusted key: {e}")
            return {"success": False, "error": str(e)}

    def validate_signature_format(self, signature_data: Dict) -> Tuple[bool, Optional[str]]:
        """Validate signature data format"""
        required_fields = [
            "algorithm",
            "signature",
            "signer",
            "public_key_id",
            "signed_at",
        ]

        for field in required_fields:
            if field not in signature_data:
                return False, f"Missing required field: {field}"

        # Validate algorithm
        if signature_data["algorithm"] not in ["SHA256", "SHA384", "SHA512"]:
            return False, f"Unsupported algorithm: {signature_data['algorithm']}"

        # Validate signature format (hex)
        try:
            bytes.fromhex(signature_data["signature"])
        except ValueError:
            return False, "Invalid signature format - must be hexadecimal"

        # Validate timestamp
        try:
            datetime.fromisoformat(signature_data["signed_at"].replace("Z", "+00:00"))
        except ValueError:
            return False, "Invalid timestamp format"

        return True, None

    def get_signature_requirements(self) -> Dict:
        """Get signature requirements for plugin publishers"""
        return {
            "supported_algorithms": ["SHA256", "SHA384", "SHA512"],
            "key_requirements": {
                "type": "RSA",
                "min_size": 2048,
                "recommended_size": 4096,
            },
            "signature_format": "RSA-PSS with MGF1 padding",
            "encoding": "PEM for public keys, hex for signatures",
            "signing_data": "Canonical JSON of manifest + executors + checksum",
        }
