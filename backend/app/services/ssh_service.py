"""
SSH Service for Host Discovery
Provides SSH connectivity and command execution for host discovery operations
"""
import paramiko
import logging
from typing import Dict, Any, Optional
from datetime import datetime

from ..database import Host

logger = logging.getLogger(__name__)


class SSHService:
    """
    Service for SSH operations during host discovery
    """
    
    def __init__(self):
        """Initialize SSH service"""
        self.client = None
        self.current_host = None
    
    def connect(self, host: Host, timeout: int = 10) -> bool:
        """
        Establish SSH connection to a host
        
        Args:
            host: Host object to connect to
            timeout: Connection timeout in seconds
            
        Returns:
            True if connection successful, False otherwise
        """
        try:
            if self.client:
                self.disconnect()
            
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Extract connection details
            hostname = host.ip_address or host.hostname
            port = host.port or 22
            username = host.username
            
            # For now, we'll handle key-based authentication
            # In a real implementation, you'd decrypt the stored credentials
            self.client.connect(
                hostname=hostname,
                port=port,
                username=username,
                timeout=timeout,
                # Note: In production, you'd handle credential decryption here
                look_for_keys=True,
                allow_agent=True
            )
            
            self.current_host = host
            logger.info(f"SSH connection established to {hostname}:{port}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to {host.hostname}: {str(e)}")
            if self.client:
                self.client.close()
                self.client = None
            return False
    
    def disconnect(self):
        """Close SSH connection"""
        if self.client:
            self.client.close()
            self.client = None
            self.current_host = None
            logger.debug("SSH connection closed")
    
    def execute_command(self, command: str, timeout: int = 30) -> Dict[str, Any]:
        """
        Execute a command on the connected host
        
        Args:
            command: Command to execute
            timeout: Command timeout in seconds
            
        Returns:
            Dictionary with execution results
        """
        if not self.client:
            return {
                'success': False,
                'stdout': '',
                'stderr': 'No SSH connection established',
                'exit_code': -1,
                'command': command,
                'execution_time': 0
            }
        
        start_time = datetime.utcnow()
        
        try:
            logger.debug(f"Executing command: {command}")
            
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            
            # Read output
            stdout_data = stdout.read().decode('utf-8', errors='ignore')
            stderr_data = stderr.read().decode('utf-8', errors='ignore')
            exit_code = stdout.channel.recv_exit_status()
            
            execution_time = (datetime.utcnow() - start_time).total_seconds()
            
            result = {
                'success': exit_code == 0,
                'stdout': stdout_data,
                'stderr': stderr_data,
                'exit_code': exit_code,
                'command': command,
                'execution_time': execution_time
            }
            
            logger.debug(f"Command executed: {command} (exit_code: {exit_code}, "
                        f"execution_time: {execution_time:.2f}s)")
            
            return result
            
        except Exception as e:
            execution_time = (datetime.utcnow() - start_time).total_seconds()
            
            logger.error(f"Command execution failed: {command} - {str(e)}")
            
            return {
                'success': False,
                'stdout': '',
                'stderr': str(e),
                'exit_code': -1,
                'command': command,
                'execution_time': execution_time
            }
    
    def is_connected(self) -> bool:
        """Check if SSH connection is active"""
        try:
            if self.client and self.client.get_transport():
                return self.client.get_transport().is_active()
        except:
            pass
        return False
    
    def test_connection(self, host: Host) -> Dict[str, Any]:
        """
        Test SSH connectivity without establishing persistent connection
        
        Args:
            host: Host to test connection to
            
        Returns:
            Dictionary with test results
        """
        test_start = datetime.utcnow()
        
        try:
            test_client = paramiko.SSHClient()
            test_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            hostname = host.ip_address or host.hostname
            port = host.port or 22
            username = host.username
            
            test_client.connect(
                hostname=hostname,
                port=port,
                username=username,
                timeout=5,
                look_for_keys=True,
                allow_agent=True
            )
            
            # Test basic command execution
            stdin, stdout, stderr = test_client.exec_command('echo "test"', timeout=5)
            test_output = stdout.read().decode('utf-8', errors='ignore').strip()
            
            test_client.close()
            
            test_time = (datetime.utcnow() - test_start).total_seconds()
            
            return {
                'success': True,
                'message': 'SSH connection test successful',
                'test_time': test_time,
                'test_output': test_output
            }
            
        except Exception as e:
            test_time = (datetime.utcnow() - test_start).total_seconds()
            
            return {
                'success': False,
                'message': f'SSH connection test failed: {str(e)}',
                'test_time': test_time,
                'error': str(e)
            }