"""
Host Monitoring Service
Provides various methods to check host availability and status
"""
import asyncio
import base64
import logging
import socket
import subprocess
import time
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import paramiko
from sqlalchemy.orm import Session
from sqlalchemy import text
from .email_service import email_service
from .unified_ssh_service import parse_ssh_key, validate_ssh_key, SSHKeyError, format_validation_message
from .unified_ssh_service import UnifiedSSHService

logger = logging.getLogger(__name__)

class HostMonitor:
    def __init__(self, db_session: Session = None):
        """
        Initialize HostMonitor with optional database session
        
        Args:
            db_session: SQLAlchemy database session for SSH service configuration
        """
        self.ssh_timeout = 10  # seconds
        self.ping_timeout = 5   # seconds
        self.unified_ssh = UnifiedSSHService(db=db_session)
        self.db_session = db_session
    
    def set_database_session(self, db_session: Session):
        """
        Set or update the database session for SSH service configuration
        
        Args:
            db_session: SQLAlchemy database session
        """
        self.db_session = db_session
        self.unified_ssh.db = db_session
        
    async def ping_host(self, ip_address: str) -> bool:
        """
        Simple ICMP ping to check basic connectivity with fallback to socket test
        """
        try:
            # First try actual ping command
            cmd = ['ping', '-c', '1', '-W', str(self.ping_timeout), ip_address]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.ping_timeout + 2)
            if result.returncode == 0:
                return True
                
        except FileNotFoundError:
            logger.debug("Ping command not found, using socket fallback")
        except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
            logger.debug(f"Ping command failed: {type(e).__name__}")
        
        # Fallback to socket connection test
        try:
            # Use socket connection test as ping alternative
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.ping_timeout)
            
            # Try to connect to common ports
            ports_to_try = [22, 80, 443, 21, 23, 25]
            
            for port in ports_to_try:
                try:
                    result = sock.connect_ex((ip_address, port))
                    sock.close()
                    if result == 0:
                        logger.debug(f"Socket test successful on port {port} for {ip_address}")
                        return True  # Connection successful, host is reachable
                    # Create new socket for next attempt
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.ping_timeout)
                except:
                    continue
            
            sock.close()
            return False
            
        except Exception as e:
            logger.debug(f"Socket connectivity test failed: {type(e).__name__}")
            return False
    
    async def check_port_connectivity(self, ip_address: str, port: int) -> bool:
        """
        Check if a specific port is reachable
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.ping_timeout)
            result = sock.connect_ex((ip_address, port))
            sock.close()
            return result == 0
        except Exception as e:
            logger.debug(f"Port check failed: {type(e).__name__}")
            return False
    
    async def check_ssh_connectivity(self, ip_address: str, port: int = 22, 
                                   username: Optional[str] = None, 
                                   key_path: Optional[str] = None,
                                   private_key_content: Optional[str] = None,
                                   password: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """
        Test SSH connectivity to determine if host is accessible for scanning
        Returns (is_connected, error_message)
        
        Uses unified SSH service for consistent security policies and audit logging.
        """
        # Determine authentication method and credential
        auth_method = None
        credential = None
        
        if key_path:
            # Read SSH key from file
            try:
                with open(key_path, 'r') as f:
                    credential = f.read().strip()
                auth_method = "ssh-key"
            except Exception as e:
                logger.error(f"Failed to read SSH key file {key_path}: {e}")
                return False, f"Failed to read SSH key file: {str(e)}"
        elif private_key_content:
            credential = private_key_content
            auth_method = "ssh-key"
        elif password:
            credential = password
            auth_method = "password"
        else:
            return False, "No authentication credentials provided"
        
        if not username:
            return False, "Username is required for SSH connectivity check"
        
        # Use unified SSH service to establish connection
        connection_result = self.unified_ssh.connect_with_credentials(
            hostname=ip_address,
            port=port,
            username=username,
            auth_method=auth_method,
            credential=credential,
            service_name="Host_Monitor_Connectivity_Check",
            timeout=self.ssh_timeout
        )
        
        if not connection_result.success:
            # Map unified service error types to user-friendly messages while preserving detail
            # Log the original detailed error for debugging
            logger.warning(f"SSH connectivity check failed: {connection_result.error_type} - {connection_result.error_message}")
            
            if connection_result.error_type == "auth_failed":
                error_message = f"SSH authentication failed: {connection_result.error_message}"
            elif connection_result.error_type == "auth_error":
                error_message = f"SSH authentication error: {connection_result.error_message}"
            elif connection_result.error_type == "key_error":
                error_message = f"SSH key error: {connection_result.error_message}"
            elif connection_result.error_type == "timeout":
                error_message = "Connection timeout - host may be unreachable"
            elif connection_result.error_type == "connection_error":
                error_message = f"Connection error: {connection_result.error_message}"
            elif connection_result.error_type == "ssh_error":
                error_message = f"SSH protocol error: {connection_result.error_message}"
            else:
                # Preserve any unhandled error details
                error_message = f"SSH connection failed ({connection_result.error_type}): {connection_result.error_message}"
            
            return False, error_message
        
        # Test basic command execution to ensure SSH is fully functional
        try:
            ssh = connection_result.connection
            command_result = self.unified_ssh.execute_command_advanced(
                ssh_connection=ssh,
                command='echo "test"',
                timeout=5
            )
            
            # Close the connection
            ssh.close()
            
            if command_result.success:
                logger.debug(f"SSH connectivity check successful for {ip_address}")
                return True, None
            else:
                error_msg = "SSH command execution failed"
                logger.warning(f"SSH command test failed: {command_result.error_type}")
                return False, error_msg
                
        except Exception as e:
            # Ensure connection is closed even if test fails
            try:
                if connection_result.connection:
                    connection_result.connection.close()
            except:
                pass
            
            error_msg = "SSH test command error"
            logger.error(f"SSH test command failed: {type(e).__name__}")
            return False, error_msg
    
    async def get_effective_ssh_credentials(self, host_data: Dict, db) -> Dict:
        """
        Get effective SSH credentials for a host using centralized authentication service.
        Uses unified credential resolution with proper encryption and field naming.
        """
        try:
            # Use centralized authentication service for all credential resolution
            from ..services.auth_service import get_auth_service
            auth_service = get_auth_service(db)
            
            # Determine if we should use default credentials or host-specific
            host_auth_method = host_data.get('auth_method')
            use_default = host_auth_method in ['default', 'system_default']
            target_id = None if use_default else host_data.get('id')
            
            logger.info(f"Resolving credentials for host monitoring {host_data.get('hostname')}: use_default={use_default}, target_id={target_id}")
            
            # First, try to get host-specific credentials from the hosts table
            if not use_default and target_id:
                from sqlalchemy import text
                result = db.execute(text("""
                    SELECT encrypted_credentials, username, auth_method 
                    FROM hosts 
                    WHERE id = :id AND encrypted_credentials IS NOT NULL
                """), {"id": target_id})
                
                row = result.fetchone()
                if row and row.encrypted_credentials:
                    logger.info(f"Found host-specific credentials in hosts table for {host_data.get('hostname')}")
                    # Decrypt the credentials
                    from ..services.crypto import decrypt_credentials
                    import json
                    try:
                        # Handle memoryview objects from database
                        encrypted_data = row.encrypted_credentials
                        # Handle memoryview objects from database securely
                        if isinstance(encrypted_data, memoryview):
                            encrypted_data = bytes(encrypted_data)
                        
                        decrypted_data = decrypt_credentials(encrypted_data)
                        cred_data = json.loads(decrypted_data)
                        
                        credentials = {
                            'username': cred_data.get('username', row.username),
                            'auth_method': cred_data.get('auth_method', row.auth_method),
                            'password': cred_data.get('password'),
                            'private_key': cred_data.get('ssh_key'),
                            'private_key_passphrase': None,
                            'source': 'host_encrypted_credentials'
                        }
                        logger.info(f"✅ Decrypted host credentials for {host_data.get('hostname')}")
                        return credentials
                    except Exception as e:
                        logger.error(f"Failed to decrypt host credentials: {type(e).__name__}")
            
            # Try centralized auth service (for system defaults or if host decryption failed)
            credential_data = auth_service.resolve_credential(
                target_id=target_id,
                use_default=use_default
            )
            
            if not credential_data:
                logger.warning(f"No credentials available for host {host_data.get('hostname')}")
                logger.info("Please configure system SSH credentials in Settings to enable remote host monitoring and scanning")
                return None
            
            # Convert to format expected by host monitoring
            credentials = {
                'username': credential_data.username,
                'auth_method': credential_data.auth_method.value,
                'password': credential_data.password,
                'private_key': credential_data.private_key,  # ✅ Consistent field naming
                'private_key_passphrase': credential_data.private_key_passphrase,
                'source': credential_data.source
            }
            
            logger.info(f"✅ Resolved {credential_data.source} credentials for host monitoring {host_data.get('hostname')}")
            return credentials
            
        except Exception as e:
            logger.error(f"Failed to resolve credentials for host monitoring: {type(e).__name__}")
            return None
    
    def validate_ssh_credentials(self, credentials: Dict) -> Tuple[bool, str]:
        """
        Validate that SSH credentials are configured and not placeholder values
        Returns (is_valid, error_message)
        """
        if not credentials:
            return False, "No SSH credentials available. Please configure system credentials in Settings."
        
        username = credentials.get('username')
        password = credentials.get('password')
        private_key = credentials.get('private_key')
        auth_method = credentials.get('auth_method', 'password')
        
        if not username:
            return False, "SSH username is required. Please update credentials in Settings."
        
        if auth_method in ['password', 'both']:
            if not password or password == 'CHANGE_ME_PLEASE':
                return False, "SSH password is required or contains placeholder value. Please update credentials in Settings."
        
        if auth_method in ['ssh_key', 'both']:
            if not private_key or 'CHANGE_ME_PLEASE' in private_key:
                return False, "SSH private key is required or contains placeholder value. Please update credentials in Settings."
        
        return True, ""

    async def comprehensive_host_check(self, host_data: Dict, db=None) -> Dict:
        """
        Perform comprehensive host availability check
        Returns status information
        """
        ip_address = host_data.get('ip_address')
        hostname = host_data.get('hostname')
        port = int(host_data.get('port', 22))
        username = host_data.get('username')
        
        logger.info(f"Starting comprehensive check for {hostname}, db connection: {'available' if db else 'None'}")
        
        check_results = {
            'host_id': host_data.get('id'),
            'hostname': hostname,
            'ip_address': ip_address,
            'timestamp': datetime.utcnow().isoformat(),
            'ping_success': False,
            'port_open': False,
            'ssh_accessible': False,
            'status': 'offline',
            'error_message': None,
            'response_time_ms': None,
            'ssh_credentials_source': None,
            'ssh_username': None,
            'credential_details': None
        }
        
        start_time = time.time()
        
        try:
            # Step 1: Connectivity test (ping alternative)
            logger.info(f"Checking connectivity for {hostname} ({ip_address})")
            check_results['ping_success'] = await self.ping_host(ip_address)
            
            # Step 2: Port connectivity
            logger.info(f"Checking port {port} connectivity for {hostname}")
            check_results['port_open'] = await self.check_port_connectivity(ip_address, port)
            
            # Step 3: SSH connectivity (with credentials inheritance)
            ssh_credentials = None
            if db:
                logger.info(f"Database connection available, looking up SSH credentials for {hostname}")
                ssh_credentials = await self.get_effective_ssh_credentials(host_data, db)
            else:
                logger.warning(f"No database connection available for SSH credential lookup for {hostname}")
            
            if ssh_credentials:
                # Validate credentials before attempting connection
                is_valid, validation_error = self.validate_ssh_credentials(ssh_credentials)
                
                username = ssh_credentials['username']
                password = ssh_credentials.get('password')
                private_key = ssh_credentials.get('private_key')
                source = ssh_credentials.get('source', 'unknown')
                auth_method = ssh_credentials.get('auth_method', 'unknown')
                
                # Store credential details for response
                check_results['ssh_credentials_source'] = source
                check_results['ssh_username'] = username
                
                if not is_valid:
                    check_results['ssh_accessible'] = False
                    check_results['credential_details'] = f"❌ {validation_error}"
                    check_results['error_message'] = validation_error
                    logger.warning(f"SSH credentials validation failed for {hostname}: {validation_error}")
                else:
                    check_results['credential_details'] = f"Using {source} credentials (user: ***REDACTED***, method: {auth_method})"
                    
                    logger.info(f"Checking SSH connectivity for {hostname} using {source} credentials (user: ***REDACTED***, method: {auth_method})")
                    
                    # Try SSH connection with validated credentials
                    ssh_success, ssh_error = await self.check_ssh_connectivity(
                        ip_address, port, username, None, private_key, password
                    )
                    check_results['ssh_accessible'] = ssh_success
                    
                    if ssh_success:
                        check_results['credential_details'] += " - ✅ SSH authentication successful"
                        logger.info(f"SSH authentication successful for {hostname} using {source} credentials (user: ***REDACTED***)")
                    else:
                        check_results['credential_details'] += f" - ❌ SSH authentication failed: {ssh_error}"
                        check_results['error_message'] = f"SSH authentication failed with {source} credentials: {ssh_error}"
                        logger.warning(f"SSH authentication failed for {hostname} using {source} credentials (user: ***REDACTED***): {ssh_error}")
                    
            else:
                check_results['credential_details'] = "❌ No SSH credentials available (neither host-specific nor system default)"
                check_results['error_message'] = "No SSH credentials configured. Please configure system credentials in Settings to enable SSH operations."
                logger.warning(f"No SSH credentials available for {hostname} - configure in Settings")
                logger.info(f"No SSH credentials available for {hostname} (neither host-specific nor system default)")
            
            # Determine overall status
            if check_results['ssh_accessible']:
                check_results['status'] = 'online'
                logger.info(f"Host {hostname} is ONLINE (SSH accessible)")
            elif check_results['port_open']:
                check_results['status'] = 'reachable'  # Port open but can't SSH
                logger.info(f"Host {hostname} is REACHABLE (port open, SSH issues)")
            elif check_results['ping_success']:
                check_results['status'] = 'ping_only'  # Responds to connectivity test but port closed
                logger.info(f"Host {hostname} responds to connectivity test but port {port} closed")
            else:
                check_results['status'] = 'offline'
                check_results['error_message'] = 'Host unreachable - no response on any tested ports'
                logger.info(f"Host {hostname} is OFFLINE (unreachable)")
            
            # Calculate response time
            end_time = time.time()
            check_results['response_time_ms'] = int((end_time - start_time) * 1000)
            
        except Exception as e:
            logger.error(f"Error checking host {hostname}: {type(e).__name__}")
            check_results['error_message'] = "Monitoring error occurred"
            check_results['status'] = 'error'
        
        return check_results
    
    async def update_host_status(self, db: Session, host_id: str, status: str, 
                               last_seen: Optional[datetime] = None,
                               error_message: Optional[str] = None) -> bool:
        """
        Update host status in database with last check timestamp
        """
        try:
            update_data = {
                'id': host_id,
                'status': status,
                'updated_at': datetime.utcnow(),
                'last_check': datetime.utcnow()
            }
            
            query = """
                UPDATE hosts 
                SET status = :status, updated_at = :updated_at, last_check = :last_check
                WHERE id = :id
            """
            
            db.execute(text(query), update_data)
            db.commit()
            
            logger.info(f"Updated host {host_id} status to {status} with last_check timestamp")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update host status: {type(e).__name__}")
            db.rollback()
            return False
    
    async def monitor_all_hosts(self, db: Session) -> List[Dict]:
        """
        Monitor all hosts in the database
        """
        try:
            # Get all active hosts
            result = db.execute(text("""
                SELECT id, hostname, ip_address, port, username, auth_method, status, last_check
                FROM hosts 
                WHERE is_active = true
                ORDER BY hostname
            """))
            
            hosts = []
            for row in result:
                hosts.append({
                    'id': str(row.id),
                    'hostname': row.hostname,
                    'ip_address': str(row.ip_address),
                    'port': row.port or 22,
                    'username': row.username,
                    'auth_method': row.auth_method,
                    'current_status': row.status,
                    'last_check': row.last_check
                })
            
            # Check each host
            check_results = []
            for host in hosts:
                result = await self.comprehensive_host_check(host, db)
                check_results.append(result)
                
                # Update database if status changed
                if result['status'] != host['current_status']:
                    # Send alert before updating database
                    await self.send_status_change_alerts(db, host, host['current_status'], result['status'])
                    
                    await self.update_host_status(
                        db, host['id'], result['status'],
                        datetime.utcnow() if result['status'] == 'online' else None
                    )
            
            return check_results
            
        except Exception as e:
            logger.error(f"Error monitoring hosts: {type(e).__name__}")
            return []
    
    async def get_alert_recipients(self, db: Session, alert_type: str) -> List[str]:
        """Get email recipients for a specific alert type"""
        try:
            result = db.execute(text("""
                SELECT email_addresses 
                FROM alert_settings 
                WHERE alert_type = :alert_type 
                AND enabled = true 
                AND email_enabled = true
                AND email_addresses IS NOT NULL
            """), {"alert_type": alert_type})
            
            recipients = []
            for row in result:
                if row.email_addresses:
                    recipients.extend(row.email_addresses)
            
            return list(set(recipients))  # Remove duplicates
            
        except Exception as e:
            logger.error(f"Error getting alert recipients: {type(e).__name__}")
            return []
    
    async def send_status_change_alerts(self, db: Session, host: Dict, old_status: str, new_status: str):
        """Send email alerts when host status changes"""
        try:
            hostname = host.get('hostname', 'Unknown')
            ip_address = host.get('ip_address', 'Unknown')
            last_check = host.get('last_check') or datetime.utcnow()
            
            # Host went offline
            if old_status == 'online' and new_status in ['offline', 'error']:
                recipients = await self.get_alert_recipients(db, 'host_offline')
                if recipients:
                    logger.info(f"Sending offline alert for {hostname} to {len(recipients)} recipients")
                    await email_service.send_host_offline_alert(
                        hostname, ip_address, last_check, recipients
                    )
            
            # Host came back online
            elif old_status in ['offline', 'error'] and new_status == 'online':
                recipients = await self.get_alert_recipients(db, 'host_online')
                if recipients:
                    logger.info(f"Sending online alert for {hostname} to {len(recipients)} recipients")
                    await email_service.send_host_online_alert(
                        hostname, ip_address, last_check, recipients
                    )
                    
        except Exception as e:
            logger.error(f"Error sending status change alerts: {type(e).__name__}")

# Global monitor instance - database session will be provided per-operation
host_monitor = HostMonitor()