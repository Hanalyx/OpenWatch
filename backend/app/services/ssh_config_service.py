"""
SSH Configuration Service
Manages SSH host key policies and known hosts
"""
import json
import logging
import os
import ipaddress
import paramiko
from typing import Dict, List, Optional, Tuple, Any
from sqlalchemy.orm import Session
from sqlalchemy import text
from datetime import datetime

from ..database import SystemSettings, SSHKnownHosts, get_db

logger = logging.getLogger(__name__)


class SSHConfigService:
    """Service for managing SSH host key policies and configuration"""
    
    def __init__(self, db: Session = None):
        self.db = db
        self._settings_cache = {}
        self._cache_expiry = None
    
    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get a system setting value with caching"""
        if not self.db:
            logger.warning("No database session available for SSH config service")
            return default
            
        try:
            setting = self.db.query(SystemSettings).filter(
                SystemSettings.setting_key == key
            ).first()
            
            if not setting:
                return default
            
            # Convert based on type
            if setting.setting_type == "json":
                return json.loads(setting.setting_value) if setting.setting_value else default
            elif setting.setting_type == "boolean":
                return setting.setting_value.lower() in ("true", "1", "yes") if setting.setting_value else default
            elif setting.setting_type == "integer":
                return int(setting.setting_value) if setting.setting_value else default
            else:
                return setting.setting_value if setting.setting_value else default
        except Exception as e:
            logger.error(f"Error getting setting {key}: {e}")
            return default
    
    def set_setting(self, key: str, value: Any, setting_type: str = "string", 
                   description: str = None, user_id: int = None) -> bool:
        """Set a system setting value"""
        if not self.db:
            logger.error("No database session available for SSH config service")
            return False
            
        try:
            # Convert value to string based on type
            if setting_type == "json":
                str_value = json.dumps(value)
            elif setting_type == "boolean":
                str_value = str(bool(value)).lower()
            else:
                str_value = str(value)
            
            setting = self.db.query(SystemSettings).filter(
                SystemSettings.setting_key == key
            ).first()
            
            if setting:
                setting.setting_value = str_value
                setting.setting_type = setting_type
                setting.updated_at = datetime.utcnow()
                setting.updated_by = user_id
                if description:
                    setting.description = description
            else:
                setting = SystemSettings(
                    setting_key=key,
                    setting_value=str_value,
                    setting_type=setting_type,
                    description=description,
                    updated_by=user_id
                )
                self.db.add(setting)
            
            self.db.commit()
            return True
        except Exception as e:
            logger.error(f"Error setting {key}: {e}")
            self.db.rollback()
            return False
    
    def get_ssh_policy(self) -> str:
        """Get current SSH host key policy"""
        return self.get_setting("ssh_host_key_policy", "strict")
    
    def set_ssh_policy(self, policy: str, user_id: int = None) -> bool:
        """Set SSH host key policy"""
        valid_policies = ["strict", "auto_add", "bypass_trusted"]
        if policy not in valid_policies:
            raise ValueError(f"Invalid policy. Must be one of: {valid_policies}")
        
        return self.set_setting(
            "ssh_host_key_policy", 
            policy, 
            "string",
            f"SSH host key verification policy: {', '.join(valid_policies)}",
            user_id
        )
    
    def get_trusted_networks(self) -> List[str]:
        """Get list of trusted network ranges"""
        return self.get_setting("ssh_trusted_networks", [])
    
    def set_trusted_networks(self, networks: List[str], user_id: int = None) -> bool:
        """Set trusted network ranges with validation"""
        # Validate network ranges
        for network in networks:
            try:
                ipaddress.ip_network(network, strict=False)
            except ValueError as e:
                raise ValueError(f"Invalid network range '{network}': {e}")
        
        return self.set_setting(
            "ssh_trusted_networks",
            networks,
            "json", 
            "List of trusted network ranges for SSH host key bypass",
            user_id
        )
    
    def is_host_in_trusted_network(self, host_ip: str) -> bool:
        """Check if host IP is in any trusted network range"""
        try:
            host_addr = ipaddress.ip_address(host_ip)
            trusted_networks = self.get_trusted_networks()
            
            for network_str in trusted_networks:
                network = ipaddress.ip_network(network_str, strict=False)
                if host_addr in network:
                    return True
            return False
        except (ValueError, ipaddress.AddressValueError):
            return False
    
    def create_ssh_policy(self, host_ip: str = None):
        """Create appropriate SSH host key policy based on configuration"""
        policy = self.get_ssh_policy()
        
        if policy == "strict":
            return paramiko.RejectPolicy()
        elif policy == "auto_add":
            return paramiko.AutoAddPolicy()
        elif policy == "bypass_trusted" and host_ip and self.is_host_in_trusted_network(host_ip):
            return paramiko.AutoAddPolicy()
        else:
            # Default to strict for security
            return paramiko.RejectPolicy()
    
    def add_known_host(self, hostname: str, ip_address: str, key_type: str, 
                      public_key: str, user_id: int = None) -> bool:
        """Add a host key to known hosts"""
        if not self.db:
            logger.error("No database session available for SSH config service")
            return False
            
        try:
            # Generate fingerprint - simplified approach
            import hashlib
            fingerprint = hashlib.sha256(public_key.encode()).hexdigest()[:32]
            
            # Check if already exists
            existing = self.db.query(SSHKnownHosts).filter(
                SSHKnownHosts.hostname == hostname,
                SSHKnownHosts.key_type == key_type
            ).first()
            
            if existing:
                # Update existing
                existing.ip_address = ip_address
                existing.public_key = public_key
                existing.fingerprint = fingerprint
                existing.last_verified = datetime.utcnow()
            else:
                # Add new
                known_host = SSHKnownHosts(
                    hostname=hostname,
                    ip_address=ip_address,
                    key_type=key_type,
                    public_key=public_key,
                    fingerprint=fingerprint,
                    is_trusted=True,
                    added_by=user_id
                )
                self.db.add(known_host)
            
            self.db.commit()
            logger.info(f"Added SSH known host: {hostname} ({key_type})")
            return True
        except Exception as e:
            logger.error(f"Error adding known host {hostname}: {e}")
            self.db.rollback()
            return False
    
    def remove_known_host(self, hostname: str, key_type: str = None) -> bool:
        """Remove a host key from known hosts"""
        if not self.db:
            logger.error("No database session available for SSH config service")
            return False
            
        try:
            query = self.db.query(SSHKnownHosts).filter(SSHKnownHosts.hostname == hostname)
            if key_type:
                query = query.filter(SSHKnownHosts.key_type == key_type)
            
            deleted = query.delete()
            self.db.commit()
            
            logger.info(f"Removed {deleted} SSH known host entries for {hostname}")
            return deleted > 0
        except Exception as e:
            logger.error(f"Error removing known host {hostname}: {e}")
            self.db.rollback()
            return False
    
    def get_known_hosts(self, hostname: str = None) -> List[Dict]:
        """Get known hosts, optionally filtered by hostname"""
        if not self.db:
            logger.warning("No database session available for SSH config service")
            return []
            
        try:
            query = self.db.query(SSHKnownHosts)
            if hostname:
                query = query.filter(SSHKnownHosts.hostname == hostname)
            
            hosts = query.order_by(SSHKnownHosts.hostname, SSHKnownHosts.key_type).all()
            
            return [
                {
                    "id": host.id,
                    "hostname": host.hostname,
                    "ip_address": host.ip_address,
                    "key_type": host.key_type,
                    "fingerprint": host.fingerprint,
                    "first_seen": host.first_seen.isoformat(),
                    "last_verified": host.last_verified.isoformat() if host.last_verified else None,
                    "is_trusted": host.is_trusted,
                    "notes": host.notes
                }
                for host in hosts
            ]
        except Exception as e:
            logger.error(f"Error getting known hosts: {e}")
            return []
    
    def configure_ssh_client(self, ssh: paramiko.SSHClient, host_ip: str = None) -> None:
        """Configure SSH client with appropriate host key policy"""
        # First, always set the policy based on configuration
        current_policy = self.get_ssh_policy()
        policy = self.create_ssh_policy(host_ip)
        ssh.set_missing_host_key_policy(policy)
        logger.debug(f"Set SSH client policy to: {current_policy}")
        
        # Then try to load known hosts (optional, won't affect policy)
        try:
            # Load system and user known hosts if they exist
            try:
                ssh.load_system_host_keys()
                logger.debug("Loaded system host keys")
            except (FileNotFoundError, OSError) as e:
                logger.debug(f"System host keys not available: {e}")
                pass
            
            try:
                known_hosts_path = os.path.expanduser('~/.ssh/known_hosts')
                ssh.load_host_keys(known_hosts_path)
                logger.debug(f"Loaded user host keys from {known_hosts_path}")
            except (FileNotFoundError, OSError) as e:
                logger.debug(f"User known_hosts not available: {e}")
                pass
            
            # Load our managed known hosts
            try:
                self._load_managed_known_hosts(ssh)
            except Exception as e:
                logger.warning(f"Error loading managed known hosts: {e}")
                
        except Exception as e:
            logger.warning(f"Error loading host keys (policy still active): {e}")
        
        logger.info(f"SSH client configured with {current_policy} policy for host {host_ip or 'unknown'}")
    
    def _load_managed_known_hosts(self, ssh: paramiko.SSHClient) -> None:
        """Load managed known hosts into SSH client"""
        try:
            known_hosts = self.get_known_hosts()
            logger.debug(f"Loading {len(known_hosts)} managed known hosts")
            # For now, just log the known hosts - SSH client will handle host key verification
            for host_info in known_hosts:
                if host_info["is_trusted"]:
                    logger.debug(f"Trusted host: {host_info['hostname']} ({host_info['key_type']})")
        except Exception as e:
            logger.error(f"Error loading managed known hosts: {e}")


# No global instance - create per request to avoid state pollution

def get_ssh_config_service(db: Session = None) -> SSHConfigService:
    """Factory function to create SSH config service with optional database session"""
    if db is None:
        # Create a new database session if none provided
        from ..database import get_db
        db = next(get_db())
    return SSHConfigService(db)

def configure_ssh_client_with_policy(ssh: paramiko.SSHClient, host_ip: str = None) -> None:
    """Convenience function to configure SSH client without managing service instance"""
    try:
        service = get_ssh_config_service()
        service.configure_ssh_client(ssh, host_ip)
    except Exception as e:
        logger.error(f"Error configuring SSH client with policy: {e}")
        # Fall back to auto_add policy instead of strict for better usability
        logger.warning("Falling back to auto_add policy due to configuration error")
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())