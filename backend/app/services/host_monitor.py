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
from .ssh_utils import parse_ssh_key, validate_ssh_key, SSHKeyError, format_validation_message

logger = logging.getLogger(__name__)

class HostMonitor:
    def __init__(self):
        self.ssh_timeout = 10  # seconds
        self.ping_timeout = 5   # seconds
        
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
            logger.debug(f"Ping command not found, using socket fallback for {ip_address}")
        except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
            logger.debug(f"Ping command failed for {ip_address}: {e}")
        
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
            logger.debug(f"Socket connectivity test failed for {ip_address}: {e}")
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
            logger.debug(f"Port check failed for {ip_address}:{port}: {e}")
            return False
    
    async def check_ssh_connectivity(self, ip_address: str, port: int = 22, 
                                   username: Optional[str] = None, 
                                   key_path: Optional[str] = None,
                                   private_key_content: Optional[str] = None,
                                   password: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """
        Test SSH connectivity to determine if host is accessible for scanning
        Returns (is_connected, error_message)
        """
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            connect_kwargs = {
                'hostname': ip_address,
                'port': port,
                'timeout': self.ssh_timeout,
                'banner_timeout': self.ssh_timeout
            }
            
            if username:
                connect_kwargs['username'] = username
                
            if key_path:
                connect_kwargs['key_filename'] = key_path
            elif private_key_content:
                # Load private key from content string using new utility
                try:
                    # Validate key first
                    validation_result = validate_ssh_key(private_key_content)
                    if not validation_result.is_valid:
                        logger.error(f"Invalid SSH key for {ip_address}: {validation_result.error_message}")
                        return False, f"Invalid SSH key: {validation_result.error_message}"
                    
                    # Log any warnings
                    if validation_result.warnings:
                        logger.warning(f"SSH key warnings for {ip_address}: {'; '.join(validation_result.warnings)}")
                    
                    # Parse key using unified parser
                    private_key = parse_ssh_key(private_key_content)
                    connect_kwargs['pkey'] = private_key
                except SSHKeyError as e:
                    logger.error(f"SSH key parsing failed for {ip_address}: {e}")
                    return False, f"SSH key error: {str(e)}"
                except Exception as e:
                    logger.error(f"Failed to load private key for {ip_address}: {e}")
                    return False, f"Invalid private key: {str(e)}"
            elif password:
                connect_kwargs['password'] = password
            
            ssh.connect(**connect_kwargs)
            
            # Test basic command execution
            stdin, stdout, stderr = ssh.exec_command('echo "test"', timeout=5)
            exit_status = stdout.channel.recv_exit_status()
            
            ssh.close()
            
            if exit_status == 0:
                return True, None
            else:
                return False, "SSH command execution failed"
                
        except paramiko.AuthenticationException:
            logger.warning(f"SSH authentication failed for {ip_address} - check credentials in Settings")
            return False, "Authentication failed - verify SSH credentials in Settings"
        except paramiko.SSHException as e:
            logger.error(f"SSH connection error to {ip_address}: {e}")
            return False, f"SSH error: {str(e)}"
        except socket.timeout:
            logger.warning(f"SSH connection timeout to {ip_address}")
            return False, "Connection timeout - host may be unreachable"
        except Exception as e:
            logger.error(f"SSH connection failed to {ip_address}: {e}")
            return False, f"Connection error: {str(e)}"
    
    async def get_effective_ssh_credentials(self, host_data: Dict, db) -> Dict:
        """
        Get effective SSH credentials for a host using inheritance logic:
        1. If host has auth_method='default' -> use default system credentials
        2. If host has SSH credentials -> use host credentials
        3. If host has no SSH credentials -> use default system credentials
        """
        try:
            # Check if host is explicitly set to use default credentials
            host_auth_method = host_data.get('auth_method')
            if host_auth_method in ['default', 'system_default']:
                logger.info(f"Host {host_data.get('hostname')} is set to use default system credentials")
                # Skip to system credentials lookup
                pass
            else:
                # Check if host has SSH credentials
                host_username = host_data.get('username')
                encrypted_credentials = host_data.get('encrypted_credentials')
                
                if host_username and encrypted_credentials:
                    # Host has credentials, decrypt them
                    try:
                        import base64
                        import json
                        
                        # Decrypt the credentials (currently using base64)
                        decoded_data = base64.b64decode(encrypted_credentials).decode('utf-8')
                        credentials_data = json.loads(decoded_data)
                        
                        return {
                            'username': host_username,
                            'auth_method': host_data.get('auth_method', 'ssh_key'),
                            'password': credentials_data.get('password'),
                            'private_key': credentials_data.get('ssh_key'),
                            'private_key_passphrase': credentials_data.get('passphrase'),
                            'source': 'host'
                        }
                    except Exception as e:
                        logger.error(f"Failed to decrypt host credentials: {e}")
                        # Fall through to system credentials
                elif host_username:
                    # Host has username but no encrypted credentials (legacy case)
                    return {
                        'username': host_username,
                        'auth_method': host_data.get('auth_method', 'ssh_key'),
                        'password': None,
                        'private_key': None,
                        'source': 'host'
                    }
            
            # Host has auth_method='default' or no credentials, try to get default system credentials
            from sqlalchemy import text
            logger.info(f"Looking for default system credentials for host {host_data.get('hostname')}")
            
            result = db.execute(text("""
                SELECT username, auth_method, encrypted_password, 
                       encrypted_private_key, private_key_passphrase
                FROM system_credentials 
                WHERE is_default = true AND is_active = true
                LIMIT 1
            """))
            
            row = result.fetchone()
            if not row:
                logger.warning("No default system credentials found in database - SSH operations will fail")
                logger.info("Please configure system SSH credentials in Settings to enable remote host monitoring and scanning")
                return None  # No system credentials available
            
            logger.info(f"Found default system credentials: user={row.username}, auth_method={row.auth_method}")
            
            # Decrypt system credentials
            from ..services.encryption import decrypt_data
            password = None
            private_key = None
            passphrase = None
            
            if row.encrypted_password:
                # Handle both string and memoryview (bytea) types from database
                encrypted_pw = row.encrypted_password
                if isinstance(encrypted_pw, memoryview):
                    # Convert memoryview to string (bytea contains base64 string as UTF-8)
                    encrypted_pw = encrypted_pw.tobytes().decode('utf-8')
                password = decrypt_data(encrypted_pw).decode()
            if row.encrypted_private_key:
                # Handle both string and memoryview (bytea) types from database
                encrypted_key = row.encrypted_private_key
                if isinstance(encrypted_key, memoryview):
                    # Convert memoryview to string (bytea contains base64 string as UTF-8)
                    encrypted_key = encrypted_key.tobytes().decode('utf-8')
                private_key = decrypt_data(encrypted_key).decode()
            if row.private_key_passphrase:
                # Handle both string and memoryview (bytea) types from database
                encrypted_phrase = row.private_key_passphrase
                if isinstance(encrypted_phrase, memoryview):
                    # Convert memoryview to string (bytea contains base64 string as UTF-8)
                    encrypted_phrase = encrypted_phrase.tobytes().decode('utf-8')
                passphrase = decrypt_data(encrypted_phrase).decode()
            
            return {
                'username': row.username,
                'auth_method': row.auth_method,
                'password': password,
                'private_key': private_key,
                'private_key_passphrase': passphrase,
                'source': 'system'
            }
            
        except Exception as e:
            logger.error(f"Error getting SSH credentials: {e}")
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
                    check_results['credential_details'] = f"Using {source} credentials (user: {username}, method: {auth_method})"
                    
                    logger.info(f"Checking SSH connectivity for {hostname} using {source} credentials (user: {username}, method: {auth_method})")
                    
                    # Try SSH connection with validated credentials
                    ssh_success, ssh_error = await self.check_ssh_connectivity(
                        ip_address, port, username, None, private_key, password
                    )
                    check_results['ssh_accessible'] = ssh_success
                    
                    if ssh_success:
                        check_results['credential_details'] += " - ✅ SSH authentication successful"
                        logger.info(f"SSH authentication successful for {hostname} using {source} credentials")
                    else:
                        check_results['credential_details'] += f" - ❌ SSH authentication failed: {ssh_error}"
                        check_results['error_message'] = f"SSH authentication failed with {source} credentials: {ssh_error}"
                        logger.warning(f"SSH authentication failed for {hostname} using {source} credentials: {ssh_error}")
                    
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
            logger.error(f"Error checking host {hostname}: {e}")
            check_results['error_message'] = f"Monitoring error: {str(e)}"
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
            logger.error(f"Failed to update host status: {e}")
            db.rollback()
            return False
    
    async def monitor_all_hosts(self, db: Session) -> List[Dict]:
        """
        Monitor all hosts in the database
        """
        try:
            # Get all active hosts
            result = db.execute(text("""
                SELECT id, hostname, ip_address, port, username, auth_method, encrypted_credentials, status, last_check
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
                    'encrypted_credentials': row.encrypted_credentials,
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
            logger.error(f"Error monitoring hosts: {e}")
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
            logger.error(f"Error getting alert recipients: {e}")
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
            logger.error(f"Error sending status change alerts: {e}")

# Global monitor instance
host_monitor = HostMonitor()