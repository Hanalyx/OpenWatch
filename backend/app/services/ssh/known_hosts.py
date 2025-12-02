"""
SSH Known Hosts Database Manager Module

Provides database-backed management of SSH known hosts as an alternative
to or supplement of the traditional ~/.ssh/known_hosts file.

This module handles:
- Storage and retrieval of known host public keys in PostgreSQL
- SHA256 fingerprint generation for host key identification
- Trust status management for host verification
- Audit trail for known host changes

Database Storage vs File Storage:
    Traditional SSH uses ~/.ssh/known_hosts file for storing known hosts.
    OpenWatch provides database storage as an alternative because:
    - Centralized management across multiple scanner nodes
    - Audit trail for compliance (who added which host, when)
    - Trust status beyond simple presence (trusted, untrusted, pending)
    - Integration with host inventory for correlation

Table Schema (ssh_known_hosts):
    - id: Primary key
    - hostname: Target hostname or IP
    - ip_address: Resolved IP address
    - key_type: SSH key algorithm (rsa, ecdsa, ed25519, dsa)
    - public_key: Full public key content
    - fingerprint: SHA256 fingerprint for identification
    - first_seen: When the host key was first recorded
    - last_verified: When the key was last verified/updated
    - is_trusted: Whether the host is explicitly trusted
    - notes: Optional notes about the host

Usage:
    from backend.app.services.ssh.known_hosts import KnownHostsManager

    known_hosts = KnownHostsManager(db)

    # List all known hosts
    hosts = known_hosts.get_known_hosts()

    # Add a new known host
    known_hosts.add_known_host(
        hostname="server.example.com",
        ip_address="192.168.1.100",
        key_type="ed25519",
        public_key="ssh-ed25519 AAAAC3... admin@server",
        notes="Production web server"
    )

    # Remove a host (e.g., after decommissioning)
    known_hosts.remove_known_host("server.example.com", "ed25519")

Security Notes:
    - Fingerprints are SHA256 in OpenSSH format (SHA256:base64hash)
    - Public keys should be verified out-of-band before adding
    - Removal of known hosts is logged for audit compliance
    - Trust status changes require explicit user action

References:
    - OpenSSH known_hosts format: man 8 sshd (AUTHORIZED_KEYS FILE FORMAT)
    - SSH public key fingerprints: RFC 4716
"""

import base64
import hashlib
import logging
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from sqlalchemy import text

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


class KnownHostsManager:
    """
    Manages SSH known hosts stored in the database.

    This class provides CRUD operations for SSH known hosts with
    automatic fingerprint generation and audit logging. It serves
    as an alternative to traditional file-based known_hosts management.

    The manager follows security best practices:
    - All operations are logged for audit trail
    - Fingerprints are generated server-side to prevent tampering
    - Trust status requires explicit management
    - Database transactions are properly handled

    Attributes:
        db: SQLAlchemy database session for persistence operations

    Example:
        >>> from backend.app.services.ssh.known_hosts import KnownHostsManager
        >>> manager = KnownHostsManager(db)
        >>>
        >>> # Get all known hosts
        >>> hosts = manager.get_known_hosts()
        >>> for host in hosts:
        ...     print(f"{host['hostname']}: {host['fingerprint']}")
        >>>
        >>> # Filter by hostname
        >>> server_keys = manager.get_known_hosts(hostname="server.example.com")
    """

    def __init__(self, db: Optional["Session"] = None) -> None:
        """
        Initialize the known hosts manager.

        Args:
            db: Optional SQLAlchemy session for database operations.
                If not provided, all operations will return empty/False.
        """
        self.db = db

    def get_known_hosts(
        self,
        hostname: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get SSH known hosts from the database.

        Retrieves known host entries with optional filtering by hostname.
        Results are ordered by first_seen date (newest first).

        Args:
            hostname: Optional filter to get hosts matching this hostname.
                If not provided, returns all known hosts.

        Returns:
            List of dictionaries containing known host information:
                - id: Database record ID
                - hostname: Target hostname
                - ip_address: IP address (may be None)
                - key_type: SSH key type (rsa, ecdsa, ed25519, dsa)
                - fingerprint: SHA256 fingerprint
                - first_seen: ISO format datetime when first recorded
                - last_verified: ISO format datetime when last verified
                - is_trusted: Boolean trust status
                - notes: Optional notes

            Returns empty list if no database session or on error.

        Note:
            The public_key field is intentionally not included in the
            response to reduce data transfer. Use a separate query if
            the full key content is needed.
        """
        try:
            if not self.db:
                logger.warning("No database session available for SSH known hosts")
                return []

            # Build query with optional hostname filter
            # Using parameterized query to prevent SQL injection
            query = """
                SELECT id, hostname, ip_address, key_type, fingerprint,
                       first_seen, last_verified, is_trusted, notes
                FROM ssh_known_hosts
                WHERE 1=1
            """
            params: Dict[str, Any] = {}

            if hostname:
                query += " AND hostname = :hostname"
                params["hostname"] = hostname

            query += " ORDER BY first_seen DESC"

            result = self.db.execute(text(query), params)

            hosts = []
            for row in result:
                hosts.append(
                    {
                        "id": row.id,
                        "hostname": row.hostname,
                        "ip_address": row.ip_address,
                        "key_type": row.key_type,
                        "fingerprint": row.fingerprint,
                        "first_seen": (row.first_seen.isoformat() if row.first_seen else None),
                        "last_verified": (row.last_verified.isoformat() if row.last_verified else None),
                        "is_trusted": row.is_trusted,
                        "notes": row.notes,
                    }
                )

            return hosts

        except Exception as e:
            logger.error("Failed to get known hosts: %s", e)
            return []

    def add_known_host(
        self,
        hostname: str,
        ip_address: Optional[str],
        key_type: str,
        public_key: str,
        notes: Optional[str] = None,
    ) -> bool:
        """
        Add a known host to the database.

        Stores a new SSH host key with automatically generated SHA256
        fingerprint. The host is marked as trusted by default.

        Args:
            hostname: Target hostname or FQDN
            ip_address: Optional IP address (useful when hostname resolves
                to multiple IPs or for direct IP connections)
            key_type: SSH key algorithm (rsa, ecdsa, ed25519, dsa)
            public_key: Full public key content in OpenSSH format
                (e.g., "ssh-rsa AAAAB3... comment")
            notes: Optional human-readable notes about this host

        Returns:
            True if the host was successfully added, False otherwise

        Fingerprint Generation:
            The fingerprint is generated from the base64-decoded key data
            portion of the public key, hashed with SHA256, and formatted
            in OpenSSH style (SHA256:base64hash).

        Security Note:
            The public key should be verified through an out-of-band
            channel before adding. Simply accepting keys from first
            connection is vulnerable to MITM attacks.

        Example:
            >>> manager.add_known_host(
            ...     hostname="server.example.com",
            ...     ip_address="192.168.1.100",
            ...     key_type="ed25519",
            ...     public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... admin@server",
            ...     notes="Production web server - verified by ops team"
            ... )
            True
        """
        try:
            if not self.db:
                logger.warning("No database session available for adding known host")
                return False

            # Generate SHA256 fingerprint from public key
            # Public key format: "algorithm base64-key comment"
            # We extract the base64 portion (second field)
            fingerprint = self._generate_fingerprint(public_key)

            if fingerprint is None:
                logger.error("Failed to generate fingerprint for host %s - invalid key format", hostname)
                return False

            # Insert new known host record
            self.db.execute(
                text(
                    """
                    INSERT INTO ssh_known_hosts
                    (hostname, ip_address, key_type, public_key, fingerprint,
                     first_seen, is_trusted, notes)
                    VALUES (:hostname, :ip_address, :key_type, :public_key,
                            :fingerprint, :first_seen, :is_trusted, :notes)
                """
                ),
                {
                    "hostname": hostname,
                    "ip_address": ip_address,
                    "key_type": key_type,
                    "public_key": public_key,
                    "fingerprint": fingerprint,
                    "first_seen": datetime.utcnow(),
                    "is_trusted": True,
                    "notes": notes,
                },
            )

            self.db.commit()
            logger.info("Added known host: %s (%s)", hostname, key_type)
            return True

        except Exception as e:
            logger.error("Failed to add known host %s: %s", hostname, e)
            if self.db:
                self.db.rollback()
            return False

    def remove_known_host(self, hostname: str, key_type: str) -> bool:
        """
        Remove a known host from the database.

        Deletes the known host entry matching the hostname and key type.
        This is typically done when decommissioning a host or when a
        host key has been compromised and needs to be re-verified.

        Args:
            hostname: Hostname of the known host to remove
            key_type: Key type to remove (a host may have multiple key types)

        Returns:
            True if a host was removed, False if not found or on error

        Security Note:
            Removal of known hosts is logged for audit compliance.
            Consider why the host is being removed - if due to a
            potential compromise, investigate before re-adding.

        Example:
            >>> # Remove when decommissioning a server
            >>> manager.remove_known_host("old-server.example.com", "rsa")
            True
            >>>
            >>> # Remove all key types for a host
            >>> for key_type in ["rsa", "ecdsa", "ed25519"]:
            ...     manager.remove_known_host("server.example.com", key_type)
        """
        try:
            if not self.db:
                logger.warning("No database session available for removing known host")
                return False

            result = self.db.execute(
                text(
                    """
                    DELETE FROM ssh_known_hosts
                    WHERE hostname = :hostname AND key_type = :key_type
                """
                ),
                {"hostname": hostname, "key_type": key_type},
            )

            self.db.commit()

            if result.rowcount > 0:
                logger.info("Removed known host: %s (%s)", hostname, key_type)
                return True
            else:
                logger.warning("Known host not found: %s (%s)", hostname, key_type)
                return False

        except Exception as e:
            logger.error("Failed to remove known host %s: %s", hostname, e)
            if self.db:
                self.db.rollback()
            return False

    def update_last_verified(self, hostname: str, key_type: str) -> bool:
        """
        Update the last_verified timestamp for a known host.

        This should be called when a successful SSH connection is made
        to a known host, confirming the key is still valid.

        Args:
            hostname: Hostname that was verified
            key_type: Key type that was verified

        Returns:
            True if the record was updated, False otherwise

        Note:
            This method is useful for identifying stale known hosts
            that haven't been connected to recently.
        """
        try:
            if not self.db:
                return False

            result = self.db.execute(
                text(
                    """
                    UPDATE ssh_known_hosts
                    SET last_verified = :last_verified
                    WHERE hostname = :hostname AND key_type = :key_type
                """
                ),
                {
                    "hostname": hostname,
                    "key_type": key_type,
                    "last_verified": datetime.utcnow(),
                },
            )

            self.db.commit()
            return result.rowcount > 0

        except Exception as e:
            logger.error("Failed to update last_verified for %s: %s", hostname, e)
            if self.db:
                self.db.rollback()
            return False

    def set_trust_status(
        self,
        hostname: str,
        key_type: str,
        is_trusted: bool,
    ) -> bool:
        """
        Update the trust status of a known host.

        Args:
            hostname: Target hostname
            key_type: Key type to update
            is_trusted: New trust status

        Returns:
            True if the record was updated, False otherwise

        Note:
            Untrusted hosts will generate warnings during connection
            even if their key is known, allowing for a "pending review"
            state.
        """
        try:
            if not self.db:
                return False

            result = self.db.execute(
                text(
                    """
                    UPDATE ssh_known_hosts
                    SET is_trusted = :is_trusted
                    WHERE hostname = :hostname AND key_type = :key_type
                """
                ),
                {
                    "hostname": hostname,
                    "key_type": key_type,
                    "is_trusted": is_trusted,
                },
            )

            self.db.commit()

            if result.rowcount > 0:
                status = "trusted" if is_trusted else "untrusted"
                logger.info("Set %s (%s) to %s", hostname, key_type, status)
                return True

            return False

        except Exception as e:
            logger.error("Failed to update trust status for %s: %s", hostname, e)
            if self.db:
                self.db.rollback()
            return False

    def find_by_fingerprint(self, fingerprint: str) -> Optional[Dict[str, Any]]:
        """
        Find a known host by its fingerprint.

        Useful for identifying a host when only the fingerprint is
        available (e.g., from SSH connection warnings).

        Args:
            fingerprint: SHA256 fingerprint to search for

        Returns:
            Dictionary with host information if found, None otherwise
        """
        try:
            if not self.db:
                return None

            result = self.db.execute(
                text(
                    """
                    SELECT id, hostname, ip_address, key_type, fingerprint,
                           first_seen, last_verified, is_trusted, notes
                    FROM ssh_known_hosts
                    WHERE fingerprint = :fingerprint
                """
                ),
                {"fingerprint": fingerprint},
            )

            row = result.fetchone()
            if row:
                return {
                    "id": row.id,
                    "hostname": row.hostname,
                    "ip_address": row.ip_address,
                    "key_type": row.key_type,
                    "fingerprint": row.fingerprint,
                    "first_seen": (row.first_seen.isoformat() if row.first_seen else None),
                    "last_verified": (row.last_verified.isoformat() if row.last_verified else None),
                    "is_trusted": row.is_trusted,
                    "notes": row.notes,
                }

            return None

        except Exception as e:
            logger.error("Failed to find host by fingerprint: %s", e)
            return None

    def _generate_fingerprint(self, public_key: str) -> Optional[str]:
        """
        Generate SHA256 fingerprint from public key in OpenSSH format.

        The fingerprint is generated in the same format as OpenSSH's
        ssh-keygen -l command output: SHA256:base64-encoded-hash

        Args:
            public_key: Full public key string in OpenSSH format
                (e.g., "ssh-rsa AAAAB3... comment")

        Returns:
            Fingerprint string in format "SHA256:base64hash" or None
            if the key format is invalid.

        Algorithm:
            1. Split key string to extract base64 portion
            2. Decode base64 to get raw key data
            3. Hash with SHA256
            4. Encode hash as base64 (without padding)
            5. Prepend "SHA256:" prefix
        """
        try:
            # Public key format: "algorithm base64-key [comment]"
            # We need the base64-key portion (second field)
            parts = public_key.split()
            if len(parts) < 2:
                logger.warning("Invalid public key format - missing key data")
                return None

            key_data = base64.b64decode(parts[1])
            sha256_hash = hashlib.sha256(key_data).digest()

            # Format as OpenSSH fingerprint (no padding)
            fingerprint = base64.b64encode(sha256_hash).decode().rstrip("=")
            return f"SHA256:{fingerprint}"

        except Exception as e:
            logger.error("Failed to generate fingerprint: %s", e)
            return None


__all__ = [
    "KnownHostsManager",
]
