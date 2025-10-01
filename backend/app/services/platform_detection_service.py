"""
Platform Detection Service
Advanced platform detection and system capability analysis
"""
import asyncio
import json
import re
import subprocess
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

from backend.app.models.unified_rule_models import Platform, PlatformVersionRange


class SystemCapability(str, Enum):
    """System capabilities that can be detected"""
    SYSTEMD = "systemd"
    DOCKER = "docker"
    PODMAN = "podman"
    SELINUX = "selinux"
    APPARMOR = "apparmor"
    FIPS = "fips"
    TPM = "tpm"
    UEFI = "uefi"
    VIRTUALIZATION = "virtualization"
    CONTAINERS = "containers"
    KUBERNETES = "kubernetes"
    SNAP = "snap"
    FLATPAK = "flatpak"
    WAYLAND = "wayland"
    X11 = "x11"


@dataclass
class PlatformInfo:
    """Comprehensive platform information"""
    platform: Platform
    version: str
    architecture: str
    kernel_version: str
    hostname: str
    distribution: str
    codename: Optional[str] = None
    build_id: Optional[str] = None
    variant: Optional[str] = None
    capabilities: List[SystemCapability] = None
    package_managers: List[str] = None
    init_system: Optional[str] = None
    virtualization_type: Optional[str] = None
    container_runtime: Optional[str] = None
    security_modules: List[str] = None
    desktop_environment: Optional[str] = None
    shell: Optional[str] = None
    python_version: Optional[str] = None
    
    def __post_init__(self):
        if self.capabilities is None:
            self.capabilities = []
        if self.package_managers is None:
            self.package_managers = []
        if self.security_modules is None:
            self.security_modules = []


@dataclass
class CompatibilityResult:
    """Result of platform compatibility check"""
    is_compatible: bool
    platform_match: bool
    version_match: bool
    architecture_match: bool
    excluded_version: bool
    compatibility_score: float
    missing_capabilities: List[str] = None
    warnings: List[str] = None
    
    def __post_init__(self):
        if self.missing_capabilities is None:
            self.missing_capabilities = []
        if self.warnings is None:
            self.warnings = []


class PlatformDetectionService:
    """Advanced platform detection and compatibility checking service"""
    
    def __init__(self):
        """Initialize platform detection service"""
        self.cached_platform_info: Optional[PlatformInfo] = None
        self.detection_cache_ttl = 300  # 5 minutes
        self.last_detection_time = 0
    
    async def detect_platform_info(self, force_refresh: bool = False) -> PlatformInfo:
        """
        Detect comprehensive platform information
        
        Args:
            force_refresh: Force refresh of cached information
            
        Returns:
            Comprehensive platform information
        """
        current_time = asyncio.get_event_loop().time()
        
        # Return cached info if available and not expired
        if (not force_refresh and 
            self.cached_platform_info and 
            (current_time - self.last_detection_time) < self.detection_cache_ttl):
            return self.cached_platform_info
        
        # Detect platform information
        platform_info = PlatformInfo(
            platform=await self._detect_platform(),
            version=await self._detect_version(),
            architecture=await self._detect_architecture(),
            kernel_version=await self._detect_kernel_version(),
            hostname=await self._detect_hostname(),
            distribution=await self._detect_distribution()
        )
        
        # Detect additional information
        platform_info.codename = await self._detect_codename()
        platform_info.build_id = await self._detect_build_id()
        platform_info.variant = await self._detect_variant()
        platform_info.capabilities = await self._detect_capabilities()
        platform_info.package_managers = await self._detect_package_managers()
        platform_info.init_system = await self._detect_init_system()
        platform_info.virtualization_type = await self._detect_virtualization()
        platform_info.container_runtime = await self._detect_container_runtime()
        platform_info.security_modules = await self._detect_security_modules()
        platform_info.desktop_environment = await self._detect_desktop_environment()
        platform_info.shell = await self._detect_shell()
        platform_info.python_version = await self._detect_python_version()
        
        # Cache the result
        self.cached_platform_info = platform_info
        self.last_detection_time = current_time
        
        return platform_info
    
    async def check_compatibility(
        self,
        platform_range: PlatformVersionRange,
        required_capabilities: Optional[List[str]] = None
    ) -> CompatibilityResult:
        """
        Check compatibility with platform requirements
        
        Args:
            platform_range: Platform version range requirements
            required_capabilities: Optional required system capabilities
            
        Returns:
            Compatibility check result
        """
        platform_info = await self.detect_platform_info()
        
        # Check platform match
        platform_match = platform_info.platform == platform_range.platform
        
        # Check architecture match
        architecture_match = True
        if platform_range.architecture:
            architecture_match = platform_info.architecture == platform_range.architecture
        
        # Check version compatibility
        version_match = True
        excluded_version = False
        
        if platform_range.min_version:
            version_match = version_match and self._compare_versions(
                platform_info.version, platform_range.min_version
            ) >= 0
        
        if platform_range.max_version:
            version_match = version_match and self._compare_versions(
                platform_info.version, platform_range.max_version
            ) <= 0
        
        if platform_range.excluded_versions:
            excluded_version = platform_info.version in platform_range.excluded_versions
        
        # Check required capabilities
        missing_capabilities = []
        if required_capabilities:
            platform_capabilities = [cap.value for cap in platform_info.capabilities]
            missing_capabilities = [
                cap for cap in required_capabilities 
                if cap not in platform_capabilities
            ]
        
        # Calculate compatibility score
        score = 0.0
        if platform_match:
            score += 0.4
        if version_match and not excluded_version:
            score += 0.3
        if architecture_match:
            score += 0.2
        if not missing_capabilities:
            score += 0.1
        
        # Overall compatibility
        is_compatible = (
            platform_match and 
            version_match and 
            architecture_match and 
            not excluded_version and 
            not missing_capabilities
        )
        
        # Generate warnings
        warnings = []
        if not platform_match:
            warnings.append(f"Platform mismatch: expected {platform_range.platform.value}, got {platform_info.platform.value}")
        if not version_match:
            warnings.append(f"Version incompatible: {platform_info.version}")
        if excluded_version:
            warnings.append(f"Version excluded: {platform_info.version}")
        if not architecture_match:
            warnings.append(f"Architecture mismatch: expected {platform_range.architecture}, got {platform_info.architecture}")
        if missing_capabilities:
            warnings.append(f"Missing capabilities: {', '.join(missing_capabilities)}")
        
        return CompatibilityResult(
            is_compatible=is_compatible,
            platform_match=platform_match,
            version_match=version_match,
            architecture_match=architecture_match,
            excluded_version=excluded_version,
            compatibility_score=score,
            missing_capabilities=missing_capabilities,
            warnings=warnings
        )
    
    async def get_compatible_platforms(
        self,
        platform_ranges: List[PlatformVersionRange]
    ) -> List[Tuple[PlatformVersionRange, CompatibilityResult]]:
        """
        Get compatibility results for multiple platform ranges
        
        Args:
            platform_ranges: List of platform ranges to check
            
        Returns:
            List of tuples with platform range and compatibility result
        """
        results = []
        for platform_range in platform_ranges:
            compatibility = await self.check_compatibility(platform_range)
            results.append((platform_range, compatibility))
        
        # Sort by compatibility score (descending)
        results.sort(key=lambda x: x[1].compatibility_score, reverse=True)
        return results
    
    async def _detect_platform(self) -> Platform:
        """Detect the operating system platform"""
        try:
            # Read /etc/os-release
            os_release = await self._read_file('/etc/os-release')
            if not os_release:
                # Fallback to other methods
                return await self._detect_platform_fallback()
            
            # Parse os-release
            os_info = self._parse_os_release(os_release)
            
            # Detect based on ID and NAME
            os_id = os_info.get('ID', '').lower()
            os_name = os_info.get('NAME', '').lower()
            version_id = os_info.get('VERSION_ID', '')
            
            if 'rhel' in os_id or 'red hat enterprise linux' in os_name:
                if version_id.startswith('8'):
                    return Platform.RHEL_8
                elif version_id.startswith('9'):
                    return Platform.RHEL_9
                else:
                    return Platform.RHEL_9  # Default to latest
            
            elif 'ubuntu' in os_id or 'ubuntu' in os_name:
                if version_id == '20.04':
                    return Platform.UBUNTU_20_04
                elif version_id == '22.04':
                    return Platform.UBUNTU_22_04
                elif version_id == '24.04':
                    return Platform.UBUNTU_24_04
                else:
                    return Platform.UBUNTU_22_04  # Default
            
            elif 'centos' in os_id or 'centos' in os_name:
                if version_id.startswith('7'):
                    return Platform.CENTOS_7
                elif version_id.startswith('8'):
                    return Platform.CENTOS_8
                else:
                    return Platform.CENTOS_8  # Default
            
            elif 'debian' in os_id or 'debian' in os_name:
                if version_id == '11':
                    return Platform.DEBIAN_11
                elif version_id == '12':
                    return Platform.DEBIAN_12
                else:
                    return Platform.DEBIAN_11  # Default
            
            # Default fallback
            return Platform.RHEL_9
            
        except Exception:
            return await self._detect_platform_fallback()
    
    async def _detect_platform_fallback(self) -> Platform:
        """Fallback platform detection using uname and other methods"""
        try:
            # Try uname -a
            uname_output = await self._run_command('uname -a')
            if 'Ubuntu' in uname_output:
                return Platform.UBUNTU_22_04
            elif 'Red Hat' in uname_output or 'RHEL' in uname_output:
                return Platform.RHEL_9
            elif 'CentOS' in uname_output:
                return Platform.CENTOS_8
            elif 'Debian' in uname_output:
                return Platform.DEBIAN_11
            
            # Try lsb_release
            lsb_output = await self._run_command('lsb_release -a 2>/dev/null')
            if 'Ubuntu' in lsb_output:
                return Platform.UBUNTU_22_04
            elif 'RedHat' in lsb_output or 'RHEL' in lsb_output:
                return Platform.RHEL_9
            
            return Platform.RHEL_9  # Final fallback
            
        except Exception:
            return Platform.RHEL_9
    
    async def _detect_version(self) -> str:
        """Detect platform version"""
        try:
            os_release = await self._read_file('/etc/os-release')
            if os_release:
                os_info = self._parse_os_release(os_release)
                return os_info.get('VERSION_ID', 'unknown').strip('"')
            
            # Fallback methods
            version_output = await self._run_command('lsb_release -r 2>/dev/null | cut -f2')
            if version_output and version_output != 'unknown':
                return version_output.strip()
            
            return 'unknown'
            
        except Exception:
            return 'unknown'
    
    async def _detect_architecture(self) -> str:
        """Detect system architecture"""
        try:
            arch = await self._run_command('uname -m')
            return arch.strip()
        except Exception:
            return 'x86_64'
    
    async def _detect_kernel_version(self) -> str:
        """Detect kernel version"""
        try:
            kernel = await self._run_command('uname -r')
            return kernel.strip()
        except Exception:
            return 'unknown'
    
    async def _detect_hostname(self) -> str:
        """Detect system hostname"""
        try:
            hostname = await self._run_command('hostname')
            return hostname.strip()
        except Exception:
            return 'unknown'
    
    async def _detect_distribution(self) -> str:
        """Detect distribution name"""
        try:
            os_release = await self._read_file('/etc/os-release')
            if os_release:
                os_info = self._parse_os_release(os_release)
                return os_info.get('NAME', 'Unknown').strip('"')
            return 'Unknown'
        except Exception:
            return 'Unknown'
    
    async def _detect_codename(self) -> Optional[str]:
        """Detect distribution codename"""
        try:
            os_release = await self._read_file('/etc/os-release')
            if os_release:
                os_info = self._parse_os_release(os_release)
                return os_info.get('VERSION_CODENAME', os_info.get('UBUNTU_CODENAME', '')).strip('"') or None
            return None
        except Exception:
            return None
    
    async def _detect_build_id(self) -> Optional[str]:
        """Detect build ID"""
        try:
            os_release = await self._read_file('/etc/os-release')
            if os_release:
                os_info = self._parse_os_release(os_release)
                return os_info.get('BUILD_ID', '').strip('"') or None
            return None
        except Exception:
            return None
    
    async def _detect_variant(self) -> Optional[str]:
        """Detect platform variant"""
        try:
            os_release = await self._read_file('/etc/os-release')
            if os_release:
                os_info = self._parse_os_release(os_release)
                return os_info.get('VARIANT', '').strip('"') or None
            return None
        except Exception:
            return None
    
    async def _detect_capabilities(self) -> List[SystemCapability]:
        """Detect system capabilities"""
        capabilities = []
        
        # Check systemd
        if await self._command_exists('systemctl'):
            capabilities.append(SystemCapability.SYSTEMD)
        
        # Check container runtimes
        if await self._command_exists('docker'):
            capabilities.append(SystemCapability.DOCKER)
        if await self._command_exists('podman'):
            capabilities.append(SystemCapability.PODMAN)
        
        # Check security modules
        if await self._path_exists('/sys/fs/selinux'):
            capabilities.append(SystemCapability.SELINUX)
        if await self._command_exists('aa-status'):
            capabilities.append(SystemCapability.APPARMOR)
        
        # Check FIPS mode
        fips_enabled = await self._read_file('/proc/sys/crypto/fips_enabled')
        if fips_enabled and fips_enabled.strip() == '1':
            capabilities.append(SystemCapability.FIPS)
        
        # Check TPM
        if await self._path_exists('/dev/tpm0') or await self._path_exists('/sys/class/tpm/tpm0'):
            capabilities.append(SystemCapability.TPM)
        
        # Check UEFI
        if await self._path_exists('/sys/firmware/efi'):
            capabilities.append(SystemCapability.UEFI)
        
        # Check virtualization
        virt_type = await self._detect_virtualization()
        if virt_type and virt_type != 'none':
            capabilities.append(SystemCapability.VIRTUALIZATION)
        
        # Check if running in container
        if await self._is_running_in_container():
            capabilities.append(SystemCapability.CONTAINERS)
        
        # Check Kubernetes
        if (await self._command_exists('kubectl') or 
            await self._path_exists('/var/run/secrets/kubernetes.io')):
            capabilities.append(SystemCapability.KUBERNETES)
        
        # Check package systems
        if await self._command_exists('snap'):
            capabilities.append(SystemCapability.SNAP)
        if await self._command_exists('flatpak'):
            capabilities.append(SystemCapability.FLATPAK)
        
        # Check display systems
        if await self._is_wayland_running():
            capabilities.append(SystemCapability.WAYLAND)
        if await self._is_x11_running():
            capabilities.append(SystemCapability.X11)
        
        return capabilities
    
    async def _detect_package_managers(self) -> List[str]:
        """Detect available package managers"""
        managers = []
        
        package_managers = {
            'dnf': 'dnf',
            'yum': 'yum',
            'apt': 'apt',
            'apt-get': 'apt-get',
            'zypper': 'zypper',
            'pacman': 'pacman',
            'apk': 'apk',
            'rpm': 'rpm',
            'dpkg': 'dpkg',
            'snap': 'snap',
            'flatpak': 'flatpak',
            'pip': 'pip',
            'pip3': 'pip3'
        }
        
        for name, command in package_managers.items():
            if await self._command_exists(command):
                managers.append(name)
        
        return managers
    
    async def _detect_init_system(self) -> Optional[str]:
        """Detect init system"""
        try:
            # Check if systemd is running
            if await self._path_exists('/run/systemd/system'):
                return 'systemd'
            
            # Check for other init systems
            init_output = await self._run_command('ps -p 1 -o comm=')
            init_name = init_output.strip().lower()
            
            if 'systemd' in init_name:
                return 'systemd'
            elif 'init' in init_name:
                return 'sysvinit'
            elif 'upstart' in init_name:
                return 'upstart'
            else:
                return init_name or None
                
        except Exception:
            return None
    
    async def _detect_virtualization(self) -> Optional[str]:
        """Detect virtualization type"""
        try:
            # Try systemd-detect-virt if available
            if await self._command_exists('systemd-detect-virt'):
                virt = await self._run_command('systemd-detect-virt')
                if virt and virt.strip() != 'none':
                    return virt.strip()
            
            # Check DMI information
            dmi_product = await self._read_file('/sys/class/dmi/id/product_name')
            if dmi_product:
                product = dmi_product.lower()
                if 'vmware' in product:
                    return 'vmware'
                elif 'virtualbox' in product:
                    return 'virtualbox'
                elif 'kvm' in product:
                    return 'kvm'
                elif 'qemu' in product:
                    return 'qemu'
                elif 'xen' in product:
                    return 'xen'
                elif 'hyper-v' in product:
                    return 'hyperv'
            
            # Check for container indicators
            if await self._is_running_in_container():
                return 'container'
            
            return None
            
        except Exception:
            return None
    
    async def _detect_container_runtime(self) -> Optional[str]:
        """Detect container runtime"""
        try:
            runtimes = []
            
            if await self._command_exists('docker'):
                runtimes.append('docker')
            if await self._command_exists('podman'):
                runtimes.append('podman')
            if await self._command_exists('containerd'):
                runtimes.append('containerd')
            if await self._command_exists('cri-o'):
                runtimes.append('cri-o')
            if await self._command_exists('runc'):
                runtimes.append('runc')
            
            return ', '.join(runtimes) if runtimes else None
            
        except Exception:
            return None
    
    async def _detect_security_modules(self) -> List[str]:
        """Detect security modules"""
        modules = []
        
        try:
            # Check SELinux
            if await self._path_exists('/sys/fs/selinux'):
                selinux_status = await self._run_command('getenforce 2>/dev/null')
                if selinux_status:
                    modules.append(f"SELinux ({selinux_status.strip()})")
                else:
                    modules.append("SELinux")
            
            # Check AppArmor
            if await self._command_exists('aa-status'):
                aa_status = await self._run_command('aa-status --enabled 2>/dev/null && echo enabled || echo disabled')
                modules.append(f"AppArmor ({aa_status.strip()})")
            
            # Check FIPS
            fips_enabled = await self._read_file('/proc/sys/crypto/fips_enabled')
            if fips_enabled and fips_enabled.strip() == '1':
                modules.append("FIPS (enabled)")
            
        except Exception:
            pass
        
        return modules
    
    async def _detect_desktop_environment(self) -> Optional[str]:
        """Detect desktop environment"""
        try:
            # Check environment variables
            desktop_env = await self._run_command('echo $XDG_CURRENT_DESKTOP')
            if desktop_env and desktop_env.strip():
                return desktop_env.strip()
            
            session_env = await self._run_command('echo $DESKTOP_SESSION')
            if session_env and session_env.strip():
                return session_env.strip()
            
            # Check running processes
            processes = await self._run_command('ps aux')
            if 'gnome-shell' in processes:
                return 'GNOME'
            elif 'kde' in processes or 'plasma' in processes:
                return 'KDE'
            elif 'xfce' in processes:
                return 'XFCE'
            elif 'lxde' in processes:
                return 'LXDE'
            elif 'mate' in processes:
                return 'MATE'
            elif 'cinnamon' in processes:
                return 'Cinnamon'
            
            return None
            
        except Exception:
            return None
    
    async def _detect_shell(self) -> Optional[str]:
        """Detect default shell"""
        try:
            shell = await self._run_command('echo $SHELL')
            if shell:
                return Path(shell.strip()).name
            return None
        except Exception:
            return None
    
    async def _detect_python_version(self) -> Optional[str]:
        """Detect Python version"""
        try:
            # Try python3 first
            version = await self._run_command('python3 --version 2>&1')
            if version and 'Python' in version:
                return version.strip().replace('Python ', '')
            
            # Try python
            version = await self._run_command('python --version 2>&1')
            if version and 'Python' in version:
                return version.strip().replace('Python ', '')
            
            return None
        except Exception:
            return None
    
    async def _is_running_in_container(self) -> bool:
        """Check if running inside a container"""
        try:
            # Check for container-specific files
            container_indicators = [
                '/.dockerenv',
                '/run/.containerenv',
                '/.containerenv'
            ]
            
            for indicator in container_indicators:
                if await self._path_exists(indicator):
                    return True
            
            # Check cgroup
            cgroup = await self._read_file('/proc/1/cgroup')
            if cgroup and ('docker' in cgroup or 'lxc' in cgroup or 'containerd' in cgroup):
                return True
            
            return False
            
        except Exception:
            return False
    
    async def _is_wayland_running(self) -> bool:
        """Check if Wayland is running"""
        try:
            wayland_display = await self._run_command('echo $WAYLAND_DISPLAY')
            return bool(wayland_display and wayland_display.strip())
        except Exception:
            return False
    
    async def _is_x11_running(self) -> bool:
        """Check if X11 is running"""
        try:
            x_display = await self._run_command('echo $DISPLAY')
            return bool(x_display and x_display.strip())
        except Exception:
            return False
    
    def _parse_os_release(self, content: str) -> Dict[str, str]:
        """Parse /etc/os-release content"""
        info = {}
        for line in content.split('\n'):
            line = line.strip()
            if '=' in line and not line.startswith('#'):
                key, value = line.split('=', 1)
                info[key] = value.strip('"')
        return info
    
    def _compare_versions(self, version1: str, version2: str) -> int:
        """
        Compare two version strings
        Returns: -1 if version1 < version2, 0 if equal, 1 if version1 > version2
        """
        try:
            # Split versions into components
            v1_parts = [int(x) for x in version1.split('.')]
            v2_parts = [int(x) for x in version2.split('.')]
            
            # Pad shorter version with zeros
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            # Compare components
            for v1, v2 in zip(v1_parts, v2_parts):
                if v1 < v2:
                    return -1
                elif v1 > v2:
                    return 1
            
            return 0
            
        except Exception:
            # Fallback to string comparison
            if version1 < version2:
                return -1
            elif version1 > version2:
                return 1
            else:
                return 0
    
    async def _run_command(self, command: str) -> str:
        """Run shell command and return output"""
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            return stdout.decode('utf-8', errors='ignore')
        except Exception:
            return ''
    
    async def _read_file(self, file_path: str) -> Optional[str]:
        """Read file content"""
        try:
            with open(file_path, 'r') as f:
                return f.read()
        except Exception:
            return None
    
    async def _path_exists(self, path: str) -> bool:
        """Check if path exists"""
        return Path(path).exists()
    
    async def _command_exists(self, command: str) -> bool:
        """Check if command exists"""
        try:
            result = await self._run_command(f'which {command}')
            return bool(result.strip())
        except Exception:
            return False
    
    async def export_platform_info(self, format: str = 'json') -> str:
        """
        Export platform information in specified format
        
        Args:
            format: Export format ('json', 'yaml', 'text')
            
        Returns:
            Formatted platform information
        """
        platform_info = await self.detect_platform_info()
        
        if format == 'json':
            return json.dumps({
                'platform': platform_info.platform.value,
                'version': platform_info.version,
                'architecture': platform_info.architecture,
                'kernel_version': platform_info.kernel_version,
                'hostname': platform_info.hostname,
                'distribution': platform_info.distribution,
                'codename': platform_info.codename,
                'build_id': platform_info.build_id,
                'variant': platform_info.variant,
                'capabilities': [cap.value for cap in platform_info.capabilities],
                'package_managers': platform_info.package_managers,
                'init_system': platform_info.init_system,
                'virtualization_type': platform_info.virtualization_type,
                'container_runtime': platform_info.container_runtime,
                'security_modules': platform_info.security_modules,
                'desktop_environment': platform_info.desktop_environment,
                'shell': platform_info.shell,
                'python_version': platform_info.python_version
            }, indent=2)
        
        elif format == 'text':
            lines = [
                f"Platform: {platform_info.platform.value}",
                f"Version: {platform_info.version}",
                f"Architecture: {platform_info.architecture}",
                f"Kernel: {platform_info.kernel_version}",
                f"Hostname: {platform_info.hostname}",
                f"Distribution: {platform_info.distribution}",
            ]
            
            if platform_info.codename:
                lines.append(f"Codename: {platform_info.codename}")
            if platform_info.variant:
                lines.append(f"Variant: {platform_info.variant}")
            if platform_info.init_system:
                lines.append(f"Init System: {platform_info.init_system}")
            if platform_info.virtualization_type:
                lines.append(f"Virtualization: {platform_info.virtualization_type}")
            if platform_info.container_runtime:
                lines.append(f"Container Runtime: {platform_info.container_runtime}")
            if platform_info.desktop_environment:
                lines.append(f"Desktop Environment: {platform_info.desktop_environment}")
            if platform_info.shell:
                lines.append(f"Shell: {platform_info.shell}")
            if platform_info.python_version:
                lines.append(f"Python Version: {platform_info.python_version}")
            
            lines.append(f"Capabilities: {', '.join([cap.value for cap in platform_info.capabilities])}")
            lines.append(f"Package Managers: {', '.join(platform_info.package_managers)}")
            lines.append(f"Security Modules: {', '.join(platform_info.security_modules)}")
            
            return '\n'.join(lines)
        
        else:
            raise ValueError(f"Unsupported format: {format}")