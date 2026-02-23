"""
Kensa SSH Executor - OpenWatch Integration

Thin wrapper that bridges OpenWatch's credential management with Kensa's
SSH execution. This module does NOT implement SSH logic - it retrieves
credentials from OpenWatch and passes them to Kensa.

The actual SSH execution is handled by runner.ssh.SSHSession.

Note: Kensa SSHSession uses key_path (file path) not key_content (string).
This module writes credentials to secure temporary files for Kensa to use.
"""

import logging
import os
import stat
import tempfile
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Any, Generator

from sqlalchemy import text

logger = logging.getLogger(__name__)


class OpenWatchCredentialProvider:
    """
    Retrieves SSH credentials from OpenWatch for use with Kensa.

    This is the bridge between OpenWatch's encrypted credential storage
    and Kensa's SSH session requirements.
    """

    def __init__(self, db: Any):
        """
        Initialize credential provider.

        Args:
            db: SQLAlchemy database session for credential access.
        """
        self.db = db

    async def get_credentials_for_host(self, host_id: str) -> dict:
        """
        Retrieve SSH credentials for a host from OpenWatch.

        Uses CentralizedAuthService to resolve credentials with proper
        decryption and fallback to system defaults.

        Args:
            host_id: OpenWatch host UUID.

        Returns:
            Dictionary with hostname, port, username, private_key, passphrase, use_sudo.

        Raises:
            RuntimeError: If host or credentials not found.
        """
        from app.config import get_settings
        from app.encryption import EncryptionConfig, create_encryption_service
        from app.services.auth import CredentialNotFoundError, get_auth_service

        settings = get_settings()

        # Get host from PostgreSQL
        host_query = text("SELECT id, hostname, ip_address, port FROM hosts WHERE id = :host_id")
        host_result = self.db.execute(host_query, {"host_id": host_id}).fetchone()

        if not host_result:
            raise RuntimeError(f"Host not found: {host_id}")

        # Prefer IP address for container connectivity (hostname may not be resolvable)
        hostname = host_result.ip_address or host_result.hostname
        ssh_port = host_result.port or 22

        # Use CentralizedAuthService to resolve credentials
        enc_service = create_encryption_service(master_key=settings.master_key, config=EncryptionConfig())
        auth_service = get_auth_service(self.db, enc_service)

        try:
            credential = auth_service.resolve_credential(target_id=str(host_id))
        except CredentialNotFoundError:
            raise RuntimeError(f"No SSH credentials for host: {hostname}")

        # CredentialData.private_key is already decrypted by auth service
        return {
            "hostname": str(hostname),
            "port": ssh_port,
            "username": credential.username,
            "private_key": credential.private_key,
            "password": credential.password,
            "passphrase": credential.private_key_passphrase,
            "use_sudo": True,  # Default to sudo for compliance scans
        }


@contextmanager
def secure_key_file(private_key: str) -> Generator[str, None, None]:
    """
    Create a secure temporary file for the SSH private key.

    Kensa SSHSession requires a file path for the private key (key_path),
    not the key content as a string. This context manager writes the key
    to a secure temporary file and cleans it up afterwards.

    Security measures:
    - File permissions set to 0600 (owner read/write only)
    - File created in secure temp directory
    - Key content zeroed and file deleted on cleanup

    Args:
        private_key: SSH private key content as string.

    Yields:
        Path to the temporary key file.
    """
    fd = None
    key_path = None
    try:
        # Create secure temp file
        fd, key_path = tempfile.mkstemp(prefix="kensa_key_", suffix=".pem")

        # Set restrictive permissions (0600)
        os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)

        # Write key content
        with os.fdopen(fd, "w") as f:
            f.write(private_key)
            fd = None  # fd is now owned by the file object

        logger.debug("Created secure key file: %s", key_path)
        yield key_path

    finally:
        # Secure cleanup
        if key_path and Path(key_path).exists():
            try:
                # Overwrite with zeros before deletion
                with open(key_path, "wb") as f:
                    f.write(b"\x00" * 4096)
                os.unlink(key_path)
                logger.debug("Securely deleted key file: %s", key_path)
            except OSError as e:
                logger.warning("Failed to securely delete key file: %s", e)

        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


class KensaSessionFactory:
    """
    Factory for creating Kensa SSH sessions using OpenWatch credentials.

    Usage:
        factory = KensaSessionFactory(db)

        async with factory.create_session(host_id) as session:
            # session is a Kensa SSHSession, connected and ready
            result = session.run("uname -a")
            print(result.stdout)

    Or for manual control:
        factory = KensaSessionFactory(db)
        credentials = await factory.get_credentials(host_id)

        # Use credentials with secure_key_file context manager
        with secure_key_file(credentials["private_key"]) as key_path:
            from runner.ssh import SSHSession
            session = SSHSession(
                hostname=credentials["hostname"],
                port=credentials["port"],
                user=credentials["username"],
                key_path=key_path,
                password=credentials["passphrase"],
                sudo=credentials["use_sudo"],
            )
            session.connect()
            # ... use session
            session.close()
    """

    def __init__(self, db: Any):
        """
        Initialize session factory.

        Args:
            db: SQLAlchemy database session.
        """
        self._credential_provider = OpenWatchCredentialProvider(db)

    async def get_credentials(self, host_id: str) -> dict:
        """
        Get SSH credentials for a host.

        Args:
            host_id: OpenWatch host UUID.

        Returns:
            Credentials dictionary for Kensa SSHSession.
        """
        return await self._credential_provider.get_credentials_for_host(host_id)

    @asynccontextmanager
    async def create_session(self, host_id: str, use_sudo: bool | None = None):
        """
        Create and connect a Kensa SSH session for a host.

        This handles:
        - Credential retrieval from OpenWatch
        - Secure temporary key file creation
        - Session connection and cleanup

        Args:
            host_id: OpenWatch host UUID.
            use_sudo: Override sudo setting. If None, uses credential default (True).
                      Set to False for commands that don't require sudo.

        Yields:
            Connected Kensa SSHSession.
        """
        from runner.ssh import SSHSession

        credentials = await self.get_credentials(host_id)

        # Allow overriding sudo setting (useful for collection commands)
        sudo_enabled = use_sudo if use_sudo is not None else credentials["use_sudo"]

        # Handle key-based or password-based auth
        if credentials.get("private_key"):
            with secure_key_file(credentials["private_key"]) as key_path:
                session = SSHSession(
                    hostname=credentials["hostname"],
                    port=credentials["port"],
                    user=credentials["username"],
                    key_path=key_path,
                    password=credentials.get("passphrase"),
                    sudo=sudo_enabled,
                )
                try:
                    session.connect()
                    yield session
                finally:
                    session.close()
        else:
            # Password-only auth
            session = SSHSession(
                hostname=credentials["hostname"],
                port=credentials["port"],
                user=credentials["username"],
                password=credentials.get("password"),
                sudo=sudo_enabled,
            )
            try:
                session.connect()
                yield session
            finally:
                session.close()


__all__ = [
    "OpenWatchCredentialProvider",
    "KensaSessionFactory",
    "secure_key_file",
]
