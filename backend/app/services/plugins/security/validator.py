"""
Plugin Security Service
Comprehensive security validation for imported plugins
"""

import logging
import re
import subprocess
import tarfile
import tempfile
import zipfile
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from app.models.plugin_models import (
    PluginManifest,
    PluginPackage,
    PluginTrustLevel,
    SecurityCheckResult,
)

logger = logging.getLogger(__name__)


class PluginSecurityService:
    """Multi-layered security validation for plugins"""

    # Dangerous patterns to detect
    DANGEROUS_PATTERNS = {
        "shell": [
            r"rm\s+-rf\s+/",  # Dangerous file deletion
            r":(){ :|:& };:",  # Fork bomb
            r">\s*/dev/sda",  # Disk overwrite
            r"dd\s+if=/dev/zero",  # Disk wipe
            r"mkfs\.",  # Filesystem format
            r"wget.*\|.*sh",  # Download and execute
            r"curl.*\|.*bash",  # Download and execute
        ],
        "python": [
            r"__import__\s*\(",  # Dynamic imports
            r"eval\s*\(",  # Code evaluation
            r"exec\s*\(",  # Code execution
            r"compile\s*\(",  # Code compilation
            r'open\s*\([\'"]\/etc\/passwd',  # Sensitive file access
            r"subprocess.*shell\s*=\s*True",  # Shell injection risk
            r"pickle\.loads",  # Deserialization vulnerability
        ],
        "ansible": [
            r"raw:\s*.*rm\s+-rf",  # Dangerous raw commands
            r"shell:\s*.*\|.*sh",  # Pipe to shell
            r"become:\s*yes.*become_user:\s*root",  # Privilege escalation
        ],
        "network": [
            r"(\d{1,3}\.){3}\d{1,3}",  # IP addresses (potential backdoor)
            r"https?://[^\s]+\.(tk|ml|ga|cf)",  # Suspicious domains
            r"nc\s+-l",  # Netcat listener
            r"nmap\s+",  # Network scanning
        ],
    }

    # File paths that should never be accessed
    FORBIDDEN_PATHS = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/root",
        "~/.ssh",
        "/proc",
        "/sys",
        "/var/log/secure",
        "/var/log/auth.log",
    ]

    # Maximum file sizes (in bytes)
    MAX_FILE_SIZES = {
        "manifest": 50 * 1024,  # 50KB for manifest
        "script": 1024 * 1024,  # 1MB for scripts
        "total": 10 * 1024 * 1024,  # 10MB total package
    }

    def __init__(self):
        self.temp_dir = Path(tempfile.gettempdir()) / "openwatch_plugin_scan"
        self.temp_dir.mkdir(exist_ok=True, mode=0o700)

    async def validate_plugin_package(
        self, package_data: bytes, package_format: str = "tar.gz"
    ) -> Tuple[bool, List[SecurityCheckResult], Optional[PluginPackage]]:
        """
        Comprehensive plugin package validation
        Returns: (is_valid, security_checks, extracted_package)
        """
        checks = []

        try:
            # Step 1: Size validation
            size_check = self._check_package_size(package_data)
            checks.append(size_check)
            if not size_check.passed:
                return False, checks, None

            # Step 2: Extract package safely
            extraction_result = await self._safe_extract_package(package_data, package_format)
            checks.append(extraction_result["check"])
            if not extraction_result["check"].passed:
                return False, checks, None

            extracted_path = extraction_result["path"]

            # Step 3: Validate manifest
            manifest_check, manifest = await self._validate_manifest(extracted_path)
            checks.append(manifest_check)
            if not manifest_check.passed:
                return False, checks, None

            # Step 4: Security scans
            security_checks = await self._run_security_scans(extracted_path, manifest)
            checks.extend(security_checks)

            # Step 5: Build package if all checks pass
            critical_failures = [c for c in checks if not c.passed and c.severity in ["critical", "high"]]
            if critical_failures:
                return False, checks, None

            package = await self._build_plugin_package(extracted_path, manifest)

            # Cleanup
            self._cleanup_temp_files(extracted_path)

            return True, checks, package

        except Exception as e:
            logger.error(f"Plugin validation error: {e}")
            checks.append(
                SecurityCheckResult(
                    check_name="validation_error",
                    passed=False,
                    severity="critical",
                    message=f"Validation failed: {str(e)}",
                )
            )
            return False, checks, None

    def _check_package_size(self, package_data: bytes) -> SecurityCheckResult:
        """Check package size limits"""
        size = len(package_data)
        max_size = self.MAX_FILE_SIZES["total"]

        return SecurityCheckResult(
            check_name="package_size",
            passed=size <= max_size,
            severity="high" if size > max_size else "info",
            message=f"Package size: {size} bytes (max: {max_size})",
            details={"size": size, "max_allowed": max_size},
        )

    async def _safe_extract_package(self, package_data: bytes, package_format: str) -> Dict[str, Any]:
        """Safely extract package with path traversal protection"""
        temp_extract_dir = self.temp_dir / f"extract_{datetime.utcnow().timestamp()}"
        temp_extract_dir.mkdir(mode=0o700)

        try:
            if package_format == "tar.gz":
                with tarfile.open(fileobj=BytesIO(package_data), mode="r:gz") as tar:
                    # Safe extraction with path validation
                    for member in tar.getmembers():
                        # Check for path traversal
                        if self._is_path_traversal(member.name):
                            return {
                                "check": SecurityCheckResult(
                                    check_name="path_traversal_check",
                                    passed=False,
                                    severity="critical",
                                    message=f"Path traversal detected: {member.name}",
                                ),
                                "path": None,
                            }

                        # Extract each member individually after validation
                        # This is safer than extractall() as it ensures path is resolved
                        member_path = temp_extract_dir / member.name
                        if not member_path.resolve().is_relative_to(temp_extract_dir.resolve()):
                            return {
                                "check": SecurityCheckResult(
                                    check_name="path_traversal_check",
                                    passed=False,
                                    severity="critical",
                                    message=f"Path escapes extraction directory: {member.name}",
                                ),
                                "path": None,
                            }

                        tar.extract(member, temp_extract_dir)

            elif package_format == "zip":
                with zipfile.ZipFile(BytesIO(package_data), "r") as zip_file:
                    # Safe extraction with path validation
                    for name in zip_file.namelist():
                        # Check for path traversal
                        if self._is_path_traversal(name):
                            return {
                                "check": SecurityCheckResult(
                                    check_name="path_traversal_check",
                                    passed=False,
                                    severity="critical",
                                    message=f"Path traversal detected: {name}",
                                ),
                                "path": None,
                            }

                        # Extract each file individually after validation
                        # This is safer than extractall() as it ensures path is resolved
                        member_path = temp_extract_dir / name
                        if not member_path.resolve().is_relative_to(temp_extract_dir.resolve()):
                            return {
                                "check": SecurityCheckResult(
                                    check_name="path_traversal_check",
                                    passed=False,
                                    severity="critical",
                                    message=f"Path escapes extraction directory: {name}",
                                ),
                                "path": None,
                            }

                        zip_file.extract(name, temp_extract_dir)

            else:
                return {
                    "check": SecurityCheckResult(
                        check_name="format_check",
                        passed=False,
                        severity="high",
                        message=f"Unsupported package format: {package_format}",
                    ),
                    "path": None,
                }

            return {
                "check": SecurityCheckResult(
                    check_name="extraction",
                    passed=True,
                    severity="info",
                    message="Package extracted successfully",
                ),
                "path": temp_extract_dir,
            }

        except Exception as e:
            return {
                "check": SecurityCheckResult(
                    check_name="extraction",
                    passed=False,
                    severity="critical",
                    message=f"Extraction failed: {str(e)}",
                ),
                "path": None,
            }

    def _is_path_traversal(self, path: str) -> bool:
        """Check for path traversal attempts"""
        return path.startswith("/") or ".." in path or path.startswith("~")

    async def _validate_manifest(self, extracted_path: Path) -> Tuple[SecurityCheckResult, Optional[PluginManifest]]:
        """Validate and parse plugin manifest"""
        manifest_path = extracted_path / "openwatch-plugin.yml"

        if not manifest_path.exists():
            return (
                SecurityCheckResult(
                    check_name="manifest_exists",
                    passed=False,
                    severity="critical",
                    message="Plugin manifest not found",
                ),
                None,
            )

        # Check manifest size
        if manifest_path.stat().st_size > self.MAX_FILE_SIZES["manifest"]:
            return (
                SecurityCheckResult(
                    check_name="manifest_size",
                    passed=False,
                    severity="high",
                    message="Manifest file too large",
                ),
                None,
            )

        try:
            with open(manifest_path, "r") as f:
                manifest_data = yaml.safe_load(f)

            # Create and validate manifest
            manifest = PluginManifest(**manifest_data)

            return (
                SecurityCheckResult(
                    check_name="manifest_validation",
                    passed=True,
                    severity="info",
                    message="Manifest validated successfully",
                    details={"name": manifest.name, "version": manifest.version},
                ),
                manifest,
            )

        except Exception as e:
            return (
                SecurityCheckResult(
                    check_name="manifest_validation",
                    passed=False,
                    severity="critical",
                    message=f"Invalid manifest: {str(e)}",
                ),
                None,
            )

    async def _run_security_scans(self, extracted_path: Path, manifest: PluginManifest) -> List[SecurityCheckResult]:
        """Run comprehensive security scans"""
        checks = []

        # Scan based on plugin capabilities
        for capability in manifest.capabilities:
            if capability.value in ["shell", "python", "ansible"]:
                checks.extend(await self._scan_code_patterns(extracted_path, capability.value))

        # Check for forbidden file access
        checks.append(await self._scan_file_access_patterns(extracted_path))

        # Check for network backdoors
        checks.append(await self._scan_network_patterns(extracted_path))

        # Check for excessive permissions
        checks.append(await self._check_file_permissions(extracted_path))

        # Virus/malware scan if available
        if self._is_clamav_available():
            checks.append(await self._run_malware_scan(extracted_path))

        return checks

    async def _scan_code_patterns(self, path: Path, code_type: str) -> List[SecurityCheckResult]:
        """Scan for dangerous code patterns"""
        checks = []
        patterns = self.DANGEROUS_PATTERNS.get(code_type, [])

        # Define file extensions to scan
        extensions = {
            "shell": [".sh", ".bash"],
            "python": [".py"],
            "ansible": [".yml", ".yaml"],
        }

        files_to_scan = []
        for ext in extensions.get(code_type, []):
            files_to_scan.extend(path.rglob(f"*{ext}"))

        dangerous_findings = []

        for file_path in files_to_scan:
            if file_path.stat().st_size > self.MAX_FILE_SIZES["script"]:
                checks.append(
                    SecurityCheckResult(
                        check_name="file_size_check",
                        passed=False,
                        severity="high",
                        message=f"Script file too large: {file_path.name}",
                    )
                )
                continue

            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()

                # Check each dangerous pattern
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        dangerous_findings.append(
                            {
                                "file": str(file_path.relative_to(path)),
                                "pattern": pattern,
                                "type": code_type,
                            }
                        )

            except Exception as e:
                logger.warning(f"Failed to scan file {file_path}: {e}")

        if dangerous_findings:
            checks.append(
                SecurityCheckResult(
                    check_name=f"{code_type}_pattern_scan",
                    passed=False,
                    severity="critical",
                    message=f"Dangerous {code_type} patterns detected",
                    details={"findings": dangerous_findings[:10]},  # Limit details
                )
            )
        else:
            checks.append(
                SecurityCheckResult(
                    check_name=f"{code_type}_pattern_scan",
                    passed=True,
                    severity="info",
                    message=f"No dangerous {code_type} patterns found",
                )
            )

        return checks

    async def _scan_file_access_patterns(self, path: Path) -> SecurityCheckResult:
        """Check for forbidden file access attempts"""
        forbidden_accesses = []

        for file_path in path.rglob("*"):
            if file_path.is_file():
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()

                    for forbidden in self.FORBIDDEN_PATHS:
                        if forbidden in content:
                            forbidden_accesses.append(
                                {
                                    "file": str(file_path.relative_to(path)),
                                    "path": forbidden,
                                }
                            )
                except Exception:
                    continue

        return SecurityCheckResult(
            check_name="forbidden_access_scan",
            passed=len(forbidden_accesses) == 0,
            severity="critical" if forbidden_accesses else "info",
            message=("Forbidden file access detected" if forbidden_accesses else "No forbidden file access found"),
            details={"accesses": forbidden_accesses} if forbidden_accesses else None,
        )

    async def _scan_network_patterns(self, path: Path) -> SecurityCheckResult:
        """Scan for network backdoors and suspicious domains"""
        network_findings = []

        for pattern in self.DANGEROUS_PATTERNS["network"]:
            for file_path in path.rglob("*"):
                if file_path.is_file() and file_path.stat().st_size < self.MAX_FILE_SIZES["script"]:
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()

                        matches = re.findall(pattern, content)
                        if matches:
                            network_findings.append(
                                {
                                    "file": str(file_path.relative_to(path)),
                                    "pattern": pattern,
                                    "matches": matches[:5],  # Limit matches
                                }
                            )
                    except Exception:
                        continue

        return SecurityCheckResult(
            check_name="network_scan",
            passed=len(network_findings) == 0,
            severity="high" if network_findings else "info",
            message=("Suspicious network patterns detected" if network_findings else "No suspicious network patterns"),
            details={"findings": network_findings} if network_findings else None,
        )

    async def _check_file_permissions(self, path: Path) -> SecurityCheckResult:
        """Check for excessive file permissions"""
        permission_issues = []

        for file_path in path.rglob("*"):
            if file_path.is_file():
                mode = file_path.stat().st_mode
                # Check for world-writable files
                if mode & 0o002:
                    permission_issues.append(
                        {
                            "file": str(file_path.relative_to(path)),
                            "issue": "world-writable",
                        }
                    )
                # Check for setuid/setgid
                if mode & 0o4000 or mode & 0o2000:
                    permission_issues.append(
                        {
                            "file": str(file_path.relative_to(path)),
                            "issue": "setuid/setgid",
                        }
                    )

        return SecurityCheckResult(
            check_name="permission_check",
            passed=len(permission_issues) == 0,
            severity="high" if permission_issues else "info",
            message=("Excessive file permissions found" if permission_issues else "File permissions acceptable"),
            details={"issues": permission_issues} if permission_issues else None,
        )

    def _is_clamav_available(self) -> bool:
        """Check if ClamAV is available for malware scanning"""
        try:
            subprocess.run(["clamscan", "--version"], capture_output=True, check=True)
            return True
        except Exception:
            return False

    async def _run_malware_scan(self, path: Path) -> SecurityCheckResult:
        """Run ClamAV malware scan"""
        try:
            result = subprocess.run(
                ["clamscan", "-r", "--quiet", str(path)],
                capture_output=True,
                text=True,
                timeout=60,
            )

            infected = result.returncode != 0

            return SecurityCheckResult(
                check_name="malware_scan",
                passed=not infected,
                severity="critical" if infected else "info",
                message="Malware detected" if infected else "No malware detected",
                details={"output": result.stdout} if infected else None,
            )
        except subprocess.TimeoutExpired:
            return SecurityCheckResult(
                check_name="malware_scan",
                passed=False,
                severity="warning",
                message="Malware scan timeout",
            )
        except Exception as e:
            return SecurityCheckResult(
                check_name="malware_scan",
                passed=True,
                severity="info",
                message=f"Malware scan skipped: {str(e)}",
            )

    async def _build_plugin_package(self, extracted_path: Path, manifest: PluginManifest) -> PluginPackage:
        """Build plugin package from extracted files"""
        # Read manifest file
        with open(extracted_path / "openwatch-plugin.yml", "r") as f:
            yaml.safe_load(f)

        # Read executors
        executors = {}
        executors_dir = extracted_path / "executors"
        if executors_dir.exists():
            for executor_file in executors_dir.glob("*.yml"):
                with open(executor_file, "r") as f:
                    executor_data = yaml.safe_load(f)
                    # Validate executor data structure here
                    executors[executor_file.stem] = executor_data

        # Read plugin files
        files = {}
        for file_path in extracted_path.rglob("*"):
            if file_path.is_file():
                relative_path = file_path.relative_to(extracted_path)
                # Skip manifest and large files
                if (
                    str(relative_path) != "openwatch-plugin.yml"
                    and file_path.stat().st_size < self.MAX_FILE_SIZES["script"]
                ):
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        files[str(relative_path)] = f.read()

        # Create package
        package = PluginPackage(
            manifest=manifest,
            executors=executors,
            files=files,
            checksum="",  # Will be calculated
        )

        # Calculate checksum
        package.checksum = package.calculate_checksum()

        return package

    def _cleanup_temp_files(self, path: Path):
        """Safely cleanup temporary files"""
        try:
            import shutil

            shutil.rmtree(path)
        except Exception as e:
            logger.warning(f"Failed to cleanup temp files: {e}")

    def calculate_trust_level(self, checks: List[SecurityCheckResult]) -> PluginTrustLevel:
        """Calculate plugin trust level based on security checks"""
        critical_failures = sum(1 for c in checks if not c.passed and c.severity == "critical")
        high_failures = sum(1 for c in checks if not c.passed and c.severity == "high")

        if critical_failures > 0:
            return PluginTrustLevel.UNTRUSTED
        elif high_failures > 0:
            return PluginTrustLevel.COMMUNITY
        else:
            return PluginTrustLevel.COMMUNITY  # Can be upgraded to VERIFIED with signature
