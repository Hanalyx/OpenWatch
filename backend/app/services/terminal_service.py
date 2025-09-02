"""
WebSocket Terminal Service for OpenWatch

Provides SSH-based terminal access to hosts for credential testing
and interactive debugging.
"""

import asyncio
import logging
import json
from typing import Dict, Optional
import paramiko
from fastapi import WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session
from sqlalchemy import text

from ..database import get_db, Host
from ..services.ssh_utils import validate_ssh_key, SSHKeyValidationResult
from ..services.crypto import decrypt_credentials
from ..audit_db import log_security_event

logger = logging.getLogger(__name__)


class SSHTerminalSession:
    """
    Manages an SSH terminal session with WebSocket communication
    """
    
    def __init__(self, websocket: WebSocket, host: Host, db: Session):
        self.websocket = websocket
        self.host = host
        self.db = db  # Database session for centralized auth service
        self.ssh_client: Optional[paramiko.SSHClient] = None
        self.ssh_channel: Optional[paramiko.Channel] = None
        self.is_connected = False
        self.tasks: Dict[str, asyncio.Task] = {}
        
    async def connect(self) -> bool:
        """
        Establish SSH connection to the host
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            # Initialize SSH client
            self.ssh_client = paramiko.SSHClient()
            # Security Fix: Use strict host key checking instead of AutoAddPolicy
            self.ssh_client.set_missing_host_key_policy(paramiko.RejectPolicy())
            # Load system and user host keys for validation
            try:
                self.ssh_client.load_system_host_keys()
                self.ssh_client.load_host_keys('/home/openwatch/.ssh/known_hosts')
            except FileNotFoundError:
                logger.warning("No known_hosts files found - SSH connections may fail without proper host key management")
            
            # Get host credentials
            auth_method, credentials = await self._get_host_credentials()
            if not auth_method:
                await self._send_error("No authentication method configured for host")
                return False
            
            # Connect to host
            connect_kwargs = {
                'hostname': self.host.ip_address,
                'port': self.host.port or 22,
                'username': credentials.get('username', 'root'),
                'timeout': 10,
                'allow_agent': False,
                'look_for_keys': False
            }
            
            if auth_method == 'password':
                if not credentials.get('password'):
                    await self._send_error("Password not configured for host")
                    return False
                connect_kwargs['password'] = credentials['password']
                
            elif auth_method in ['ssh_key', 'system_default']:
                if not credentials.get('private_key'):
                    await self._send_error("SSH key not configured for host")
                    return False
                
                # Validate SSH key first
                validation_result = validate_ssh_key(credentials['private_key'])
                if not validation_result.is_valid:
                    await self._send_error(f"Invalid SSH key: {validation_result.error_message}")
                    return False
                
                # Load private key
                try:
                    from io import StringIO
                    key_io = StringIO(credentials['private_key'])
                    
                    # Try different key types
                    private_key = None
                    for key_class in [paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.DSSKey]:
                        try:
                            key_io.seek(0)
                            private_key = key_class.from_private_key(
                                key_io, 
                                password=credentials.get('passphrase')
                            )
                            break
                        except Exception:
                            continue
                    
                    if not private_key:
                        await self._send_error("Could not load SSH private key")
                        return False
                        
                    connect_kwargs['pkey'] = private_key
                    
                except Exception as e:
                    await self._send_error(f"SSH key loading failed: {str(e)}")
                    return False
            else:
                await self._send_error(f"Unsupported authentication method: {auth_method}")
                return False
            
            # Attempt SSH connection
            logger.info(f"Connecting to {self.host.hostname} ({self.host.ip_address}:{self.host.port})")
            self.ssh_client.connect(**connect_kwargs)
            
            # Create interactive shell channel
            self.ssh_channel = self.ssh_client.invoke_shell(
                term='xterm-256color',
                width=80,
                height=24
            )
            
            self.is_connected = True
            logger.info(f"SSH connection established to {self.host.hostname}")
            
            # Start background tasks for data transfer
            self.tasks['ssh_to_ws'] = asyncio.create_task(self._ssh_to_websocket())
            self.tasks['ws_to_ssh'] = asyncio.create_task(self._websocket_to_ssh())
            
            return True
            
        except paramiko.AuthenticationException:
            await self._send_error("SSH authentication failed - invalid credentials")
            return False
        except paramiko.SSHException as e:
            await self._send_error(f"SSH connection error: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"SSH connection failed: {e}")
            await self._send_error(f"Connection failed: {str(e)}")
            return False
    
    async def _get_host_credentials(self) -> tuple[Optional[str], Dict[str, str]]:
        """
        Get host authentication credentials
        
        Returns:
            Tuple of (auth_method, credentials_dict)
        """
        try:
            auth_method = self.host.auth_method or 'system_default'
            credentials = {}
            
            logger.info(f"Getting credentials for host {self.host.hostname} with auth_method: {auth_method}")
            
            # Use centralized authentication service instead of old dual system
            try:
                from ..services.auth_service import get_auth_service
                auth_service = get_auth_service(self.db)
                
                # Determine if we should use default credentials or host-specific
                use_default = auth_method in ['default', 'system_default']
                target_id = None if use_default else str(self.host.id)
                
                # Resolve credentials using centralized service
                credential_data = auth_service.resolve_credential(
                    target_id=target_id,
                    use_default=use_default
                )
                
                if credential_data:
                    credentials = {
                        'username': credential_data.username,
                        'private_key': credential_data.private_key,
                        'password': credential_data.password,
                        'private_key_passphrase': credential_data.private_key_passphrase
                    }
                    logger.info(f"Successfully resolved {credential_data.source} credentials for terminal service")
                else:
                    logger.warning("No credentials available via centralized auth service")
                    
            except Exception as e:
                logger.error(f"Failed to resolve credentials via centralized service: {e}")
                # Fallback to system default if centralized service fails
                if auth_method == 'system_default':
                    try:
                        with open('/home/rracine/hanalyx/rsa_private_key', 'r') as f:
                            credentials['private_key'] = f.read()
                            credentials['username'] = 'root'
                            logger.info("Using fallback system default SSH key")
                    except FileNotFoundError:
                        logger.error("System default SSH key not found")
                        return None, {}
            
            # If we still don't have credentials and this is a password auth host, try test credentials
            if not credentials and auth_method == 'password':
                # For test hosts with known credentials (temporary workaround)
                test_hosts = {
                    '146.190.45.61': {'username': 'root', 'password': 'DRUCrItroS7I@E3iv&CR'},
                    '146.190.156.198': {'username': 'root', 'password': 'DRUCrItroS7I@E3iv&CR'}
                }
                
                if self.host.ip_address in test_hosts:
                    logger.info(f"Using test credentials for host {self.host.ip_address}")
                    credentials = test_hosts[self.host.ip_address]
                else:
                    logger.warning(f"No credentials available for host {self.host.hostname}")
                    return None, {}
            
            # If we still don't have credentials, fail
            if not credentials:
                logger.error(f"No credentials found for host {self.host.hostname}")
                return None, {}
            
            # Set default username if not provided
            if 'username' not in credentials:
                credentials['username'] = self.host.username or 'root'
            
            logger.info(f"Returning auth_method: {auth_method}, credentials keys: {list(credentials.keys())}")
            return auth_method, credentials
            
        except Exception as e:
            logger.error(f"Error getting host credentials: {e}")
            return None, {}
    
    async def _ssh_to_websocket(self):
        """
        Transfer data from SSH channel to WebSocket
        """
        try:
            while self.is_connected and self.ssh_channel:
                if self.ssh_channel.recv_ready():
                    data = self.ssh_channel.recv(4096)
                    if data:
                        await self.websocket.send_bytes(data)
                else:
                    await asyncio.sleep(0.01)
        except Exception as e:
            logger.error(f"SSH to WebSocket transfer error: {e}")
            await self._send_error("SSH session terminated unexpectedly")
    
    async def _websocket_to_ssh(self):
        """
        Transfer data from WebSocket to SSH channel
        """
        try:
            while self.is_connected:
                try:
                    # Receive data from WebSocket
                    data = await self.websocket.receive()
                    
                    if data.get('type') == 'websocket.receive':
                        if 'bytes' in data:
                            # Binary data (terminal input)
                            if self.ssh_channel:
                                self.ssh_channel.send(data['bytes'])
                        elif 'text' in data:
                            # Text data (terminal input)
                            if self.ssh_channel:
                                self.ssh_channel.send(data['text'].encode('utf-8'))
                    elif data.get('type') == 'websocket.disconnect':
                        break
                        
                except WebSocketDisconnect:
                    break
                except Exception as e:
                    logger.error(f"WebSocket to SSH transfer error: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"WebSocket to SSH handler error: {e}")
    
    async def _send_error(self, message: str):
        """
        Send error message to WebSocket client
        """
        try:
            await self.websocket.send_text(f"ERROR: {message}")
        except Exception:
            pass
    
    async def resize_terminal(self, cols: int, rows: int):
        """
        Resize the SSH terminal
        """
        if self.ssh_channel:
            try:
                self.ssh_channel.resize_pty(width=cols, height=rows)
            except Exception as e:
                logger.error(f"Terminal resize error: {e}")
    
    async def disconnect(self):
        """
        Close SSH connection and cleanup resources
        """
        self.is_connected = False
        
        # Cancel background tasks
        for task_name, task in self.tasks.items():
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        
        # Close SSH resources
        if self.ssh_channel:
            try:
                self.ssh_channel.close()
            except Exception:
                pass
            self.ssh_channel = None
        
        if self.ssh_client:
            try:
                self.ssh_client.close()
            except Exception:
                pass
            self.ssh_client = None
        
        logger.info(f"SSH session to {self.host.hostname} closed")


class TerminalService:
    """
    Service for managing WebSocket terminal connections
    """
    
    def __init__(self):
        self.active_sessions: Dict[str, SSHTerminalSession] = {}
    
    async def handle_websocket_connection(
        self, 
        websocket: WebSocket, 
        host_id: str,
        db: Session,
        client_ip: str
    ):
        """
        Handle new WebSocket terminal connection
        
        Args:
            websocket: WebSocket connection
            host_id: Host ID for terminal session
            db: Database session
            client_ip: Client IP address for audit logging
        """
        session_key = f"{host_id}_{id(websocket)}"
        
        try:
            # Accept WebSocket connection
            await websocket.accept()
            
            # Get host information using raw SQL
            result = db.execute(text("SELECT * FROM hosts WHERE id = :host_id"), {"host_id": host_id})
            host_data = result.fetchone()
            
            if not host_data:
                await websocket.send_text("ERROR: Host not found")
                await websocket.close()
                return
            
            # Create a simple host object with the required attributes
            class SimpleHost:
                def __init__(self, row):
                    self.id = str(row.id)
                    self.hostname = row.hostname
                    self.ip_address = row.ip_address
                    self.port = row.port
                    self.username = row.username
                    self.auth_method = row.auth_method
                    # NOTE: encrypted_credentials removed - using centralized auth service
            
            host = SimpleHost(host_data)
            
            # Log terminal access attempt
            await log_security_event(
                db=db,
                event_type="TERMINAL_ACCESS",
                ip_address=client_ip,
                details=f"Terminal access requested for host {host.hostname} ({host.ip_address})"
            )
            
            # Create terminal session
            session = SSHTerminalSession(websocket, host, db)
            self.active_sessions[session_key] = session
            
            # Attempt SSH connection
            connection_success = await session.connect()
            
            if connection_success:
                # Log successful connection
                await log_security_event(
                    db=db,
                    event_type="TERMINAL_CONNECTED",
                    ip_address=client_ip,
                    details=f"SSH terminal connected to {host.hostname} ({host.ip_address})"
                )
                
                # Keep connection alive until WebSocket closes
                try:
                    while True:
                        await asyncio.sleep(1)
                        if not session.is_connected:
                            break
                except WebSocketDisconnect:
                    pass
            else:
                # Log failed connection
                await log_security_event(
                    db=db,
                    event_type="TERMINAL_FAILED",
                    ip_address=client_ip,
                    details=f"SSH terminal connection failed for {host.hostname} ({host.ip_address})"
                )
            
        except WebSocketDisconnect:
            logger.info(f"WebSocket disconnected for host {host_id}")
        except Exception as e:
            logger.error(f"Terminal WebSocket error: {e}")
            try:
                await websocket.send_text(f"ERROR: Terminal service error: {str(e)}")
            except Exception:
                pass
        finally:
            # Cleanup session
            if session_key in self.active_sessions:
                await self.active_sessions[session_key].disconnect()
                del self.active_sessions[session_key]
            
            try:
                await websocket.close()
            except Exception:
                pass


# Global terminal service instance
terminal_service = TerminalService()