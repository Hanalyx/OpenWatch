"""
Compliance Rules Security Service
Security validation for uploaded compliance rule archives (tar.gz with BSON/JSON files)
"""

import hashlib
import logging
import tarfile
import tempfile
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class SecurityCheckResult:
    """Result of a security check"""

    def __init__(
        self,
        check_name: str,
        passed: bool,
        severity: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ):
        self.check_name = check_name
        self.passed = passed
        self.severity = severity  # 'info', 'low', 'medium', 'high', 'critical'
        self.message = message
        self.details = details or {}
        self.timestamp = datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "check_name": self.check_name,
            "passed": self.passed,
            "severity": self.severity,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp.isoformat(),
        }


class ComplianceRulesSecurityService:
    """Security validation for compliance rule uploads"""

    # Size limits
    MAX_ARCHIVE_SIZE = 100 * 1024 * 1024  # 100MB for BSON archives
    MAX_RULE_FILE_SIZE = 1 * 1024 * 1024  # 1MB per rule file
    MAX_RULES_COUNT = 10000  # User-specified maximum

    # Forbidden filenames (security-sensitive files)
    FORBIDDEN_FILENAMES = [
        ".env",
        ".env.local",
        ".env.production",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "passwd",
        "shadow",
        "sudoers",
        ".bash_history",
        ".zsh_history",
        ".ssh",
        "authorized_keys",
        "known_hosts",
        "credentials",
        "secrets",
        "private_key",
        ".aws",
        ".docker",
        ".kube",
    ]

    # Forbidden extensions (executable/script files)
    FORBIDDEN_EXTENSIONS = [
        ".sh",
        ".bash",
        ".zsh",
        ".py",
        ".pyc",
        ".pyo",
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".bat",
        ".cmd",
        ".ps1",
        ".psm1",
        ".jar",
        ".war",
        ".class",
    ]

    # Allowed extensions for rule files
    ALLOWED_EXTENSIONS = [".bson", ".json"]

    def __init__(self):
        self.temp_dir = Path(tempfile.gettempdir()) / "openwatch_compliance_upload"
        self.temp_dir.mkdir(exist_ok=True, mode=0o700)

    async def validate_archive(self, archive_data: bytes) -> Tuple[bool, List[SecurityCheckResult], Optional[Path]]:
        """
        Comprehensive security validation of compliance rules archive

        Args:
            archive_data: Raw tar.gz archive bytes

        Returns:
            Tuple of (is_valid, security_checks, extracted_path)
        """
        checks = []

        try:
            # Check 1: Archive size
            size_check = self._check_archive_size(archive_data)
            checks.append(size_check)
            if not size_check.passed:
                return False, checks, None

            # Check 2: Calculate archive hash (for provenance)
            archive_hash = self.calculate_archive_hash(archive_data)
            checks.append(
                SecurityCheckResult(
                    check_name="archive_hash",
                    passed=True,
                    severity="info",
                    message=f"Archive SHA-512: {archive_hash[:16]}...",
                    details={"hash": archive_hash, "algorithm": "sha512"},
                )
            )

            # Check 3: Extract with safety checks
            extraction_result = await self._safe_extract_archive(archive_data)
            checks.append(extraction_result["check"])
            if not extraction_result["check"].passed:
                return False, checks, None

            extracted_path = extraction_result["path"]

            # Check 4: Archive structure validation
            structure_check = await self._validate_archive_structure(extracted_path)
            checks.append(structure_check)
            if not structure_check.passed:
                return False, checks, None

            # Check 5: File content validation
            content_checks = await self._validate_file_contents(extracted_path)
            checks.extend(content_checks)

            # Check 6: Evaluate overall result
            critical_failures = [c for c in checks if not c.passed and c.severity in ["critical", "high"]]

            if critical_failures:
                logger.warning(
                    f"Security validation failed: {len(critical_failures)} " f"critical/high severity issues"
                )
                return False, checks, extracted_path

            # All critical checks passed
            logger.info("Security validation passed")
            return True, checks, extracted_path

        except Exception as e:
            logger.error(f"Archive validation error: {e}")
            checks.append(
                SecurityCheckResult(
                    check_name="validation_error",
                    passed=False,
                    severity="critical",
                    message=f"Validation failed: {str(e)}",
                )
            )
            return False, checks, None

    def _check_archive_size(self, archive_data: bytes) -> SecurityCheckResult:
        """Validate archive size against limits"""
        size = len(archive_data)

        return SecurityCheckResult(
            check_name="archive_size",
            passed=size <= self.MAX_ARCHIVE_SIZE,
            severity="critical" if size > self.MAX_ARCHIVE_SIZE else "info",
            message=f"Archive size: {size:,} bytes (max: {self.MAX_ARCHIVE_SIZE:,})",
            details={"size": size, "max_allowed": self.MAX_ARCHIVE_SIZE},
        )

    async def _safe_extract_archive(self, archive_data: bytes) -> Dict[str, Any]:
        """
        Safely extract tar.gz archive with security checks

        Protects against:
        - Path traversal attacks
        - Archive bombs
        - Malicious filenames
        """
        temp_extract_dir = self.temp_dir / f"extract_{datetime.utcnow().timestamp()}"
        temp_extract_dir.mkdir(mode=0o700)

        try:
            with tarfile.open(fileobj=BytesIO(archive_data), mode="r:gz") as tar:
                # Security checks on all members
                for member in tar.getmembers():
                    # Path traversal check
                    if self._is_path_traversal(member.name):
                        return {
                            "check": SecurityCheckResult(
                                check_name="path_traversal",
                                passed=False,
                                severity="critical",
                                message=f"Path traversal detected: {member.name}",
                            ),
                            "path": None,
                        }

                    # Forbidden filename check
                    if self._is_forbidden_filename(member.name):
                        return {
                            "check": SecurityCheckResult(
                                check_name="forbidden_filename",
                                passed=False,
                                severity="critical",
                                message=f"Forbidden filename detected: {member.name}",
                            ),
                            "path": None,
                        }

                    # File size check (archive bomb protection)
                    if member.size > self.MAX_RULE_FILE_SIZE:
                        return {
                            "check": SecurityCheckResult(
                                check_name="file_size",
                                passed=False,
                                severity="high",
                                message=f"File too large: {member.name} ({member.size:,} bytes)",
                            ),
                            "path": None,
                        }

                    # Symlink check (security risk)
                    if member.issym() or member.islnk():
                        return {
                            "check": SecurityCheckResult(
                                check_name="symlink_check",
                                passed=False,
                                severity="high",
                                message=f"Symlink detected (not allowed): {member.name}",
                            ),
                            "path": None,
                        }

                # Safe extraction
                tar.extractall(temp_extract_dir, filter="data")

            return {
                "check": SecurityCheckResult(
                    check_name="extraction",
                    passed=True,
                    severity="info",
                    message="Archive extracted successfully",
                ),
                "path": temp_extract_dir,
            }

        except tarfile.TarError as e:
            return {
                "check": SecurityCheckResult(
                    check_name="extraction",
                    passed=False,
                    severity="critical",
                    message=f"Invalid tar.gz archive: {str(e)}",
                ),
                "path": None,
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
        """
        Check for path traversal attempts

        Args:
            path: File path to check

        Returns:
            True if path traversal detected
        """
        return path.startswith("/") or path.startswith("\\") or ".." in path or path.startswith("~")

    def _is_forbidden_filename(self, filename: str) -> bool:
        """
        Check for forbidden filenames

        Args:
            filename: Filename to check

        Returns:
            True if filename is forbidden
        """
        name_lower = filename.lower()
        base_name = Path(filename).name.lower()

        # Allow BSON and JSON compliance rule files
        # These are expected to have rule-related names (e.g., ow-accounts_password_*.bson)
        if base_name.endswith((".bson", ".json")):
            # Only block exact matches of sensitive files, not substrings
            # E.g., block "passwd" but allow "ow-accounts_password_pam_minlen.bson"
            if base_name in [
                "passwd",
                "shadow",
                "sudoers",
                "id_rsa",
                "id_dsa",
                "id_ecdsa",
                "id_ed25519",
                "credentials",
                "secrets",
            ]:
                return True
            # Block files that look like SSH keys or env files
            if base_name.startswith(".env") or base_name.startswith("id_"):
                return True
            return False

        # Allow OVAL XML files in oval/ directory
        # These contain compliance check definitions (e.g., audit_rules_sudoers.xml)
        if base_name.endswith(".xml") and "/oval/" in filename.lower():
            # Only block exact matches of sensitive files, not substrings
            if base_name in [
                "passwd",
                "shadow",
                "sudoers",
                "id_rsa",
                "id_dsa",
                "id_ecdsa",
                "id_ed25519",
                "credentials",
                "secrets",
            ]:
                return True
            return False

        # For non-rule files, check forbidden filenames (exact or substring match)
        if any(forbidden in base_name for forbidden in self.FORBIDDEN_FILENAMES):
            return True

        # Check forbidden extensions
        if any(name_lower.endswith(ext) for ext in self.FORBIDDEN_EXTENSIONS):
            return True

        return False

    async def _validate_archive_structure(self, extracted_path: Path) -> SecurityCheckResult:
        """
        Validate archive has required structure

        Checks for:
        - manifest.bson or manifest.json exists
        - Contains rule files (.bson or .json)
        - Rule count within limits
        """
        # Check for manifest (BSON preferred, JSON for backward compatibility)
        manifest_bson = extracted_path / "manifest.bson"
        manifest_json = extracted_path / "manifest.json"

        if not manifest_bson.exists() and not manifest_json.exists():
            return SecurityCheckResult(
                check_name="archive_structure",
                passed=False,
                severity="critical",
                message="Archive missing required manifest (manifest.bson or manifest.json)",
            )

        # Count rule files
        bson_files = list(extracted_path.glob("**/*.bson"))
        bson_files = [f for f in bson_files if f.name != "manifest.bson"]

        json_files = list(extracted_path.glob("**/*.json"))
        json_files = [f for f in json_files if f.name not in ["manifest.json", "checksums.sha512"]]

        total_rule_files = len(bson_files) + len(json_files)

        # Check for rule files
        if total_rule_files == 0:
            return SecurityCheckResult(
                check_name="archive_structure",
                passed=False,
                severity="high",
                message="Archive contains no rule files (.bson or .json)",
            )

        # Check rule count limit
        if total_rule_files > self.MAX_RULES_COUNT:
            return SecurityCheckResult(
                check_name="rule_count_limit",
                passed=False,
                severity="high",
                message=f"Archive contains {total_rule_files} rules (max: {self.MAX_RULES_COUNT})",
                details={
                    "rule_count": total_rule_files,
                    "max_allowed": self.MAX_RULES_COUNT,
                },
            )

        # Structure valid
        return SecurityCheckResult(
            check_name="archive_structure",
            passed=True,
            severity="info",
            message=f"Archive structure valid ({len(bson_files)} BSON, {len(json_files)} JSON files)",
            details={
                "bson_files": len(bson_files),
                "json_files": len(json_files),
                "total_rules": total_rule_files,
                "has_manifest_bson": manifest_bson.exists(),
                "has_manifest_json": manifest_json.exists(),
            },
        )

    async def _validate_file_contents(self, extracted_path: Path) -> List[SecurityCheckResult]:
        """
        Validate individual file contents

        Checks for:
        - Null bytes (binary content in text files)
        - Excessive file sizes
        - Invalid file types
        """
        checks = []

        # Get all files (excluding manifest and checksums)
        all_files = list(extracted_path.glob("**/*"))
        all_files = [
            f for f in all_files if f.is_file() and f.name not in ["manifest.bson", "manifest.json", "checksums.sha512"]
        ]

        # Validate each file
        for file_path in all_files:
            # Allow XML files in oval/ directory (OVAL definitions for compliance checks)
            relative_path = str(file_path.relative_to(extracted_path))
            is_oval_file = relative_path.startswith("oval/") and file_path.suffix == ".xml"

            # Check extension is allowed
            if not is_oval_file and file_path.suffix not in self.ALLOWED_EXTENSIONS:
                checks.append(
                    SecurityCheckResult(
                        check_name="file_extension",
                        passed=False,
                        severity="high",
                        message=f"Disallowed file type: {file_path.name} ({file_path.suffix})",
                        details={"file": str(file_path.name)},
                    )
                )
                continue

            # Check file size
            file_size = file_path.stat().st_size
            if file_size > self.MAX_RULE_FILE_SIZE:
                checks.append(
                    SecurityCheckResult(
                        check_name="file_size",
                        passed=False,
                        severity="medium",
                        message=f"File too large: {file_path.name} ({file_size:,} bytes)",
                        details={"file": str(file_path.name), "size": file_size},
                    )
                )

            # For JSON files, check for null bytes
            if file_path.suffix == ".json":
                try:
                    content = file_path.read_bytes()
                    if b"\x00" in content:
                        checks.append(
                            SecurityCheckResult(
                                check_name="file_content",
                                passed=False,
                                severity="critical",
                                message=f"Binary content detected in JSON file: {file_path.name}",
                                details={"file": str(file_path.name)},
                            )
                        )
                except Exception as e:
                    checks.append(
                        SecurityCheckResult(
                            check_name="file_read",
                            passed=False,
                            severity="medium",
                            message=f"Cannot read file {file_path.name}: {str(e)}",
                            details={"file": str(file_path.name)},
                        )
                    )

        # If no issues found, add success check
        if not checks or all(c.passed for c in checks):
            checks.append(
                SecurityCheckResult(
                    check_name="file_contents",
                    passed=True,
                    severity="info",
                    message=f"All {len(all_files)} file contents validated successfully",
                )
            )

        return checks

    def calculate_archive_hash(self, archive_data: bytes) -> str:
        """
        Calculate SHA-512 hash of archive

        Args:
            archive_data: Raw archive bytes

        Returns:
            Hex digest of SHA-512 hash
        """
        return hashlib.sha512(archive_data).hexdigest()

    def cleanup_extracted_files(self, extracted_path: Optional[Path]):
        """
        Clean up temporary extracted files

        Args:
            extracted_path: Path to extracted directory
        """
        import shutil

        if not extracted_path:
            return

        try:
            if extracted_path.exists() and extracted_path.is_dir():
                shutil.rmtree(extracted_path)
                logger.debug(f"Cleaned up temporary directory: {extracted_path}")
        except Exception as e:
            logger.error(f"Failed to cleanup {extracted_path}: {e}")

    def get_security_summary(self, checks: List[SecurityCheckResult]) -> Dict[str, Any]:
        """
        Generate security validation summary

        Args:
            checks: List of security check results

        Returns:
            Summary dictionary
        """
        by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}

        for check in checks:
            by_severity[check.severity].append(check)

        total_checks = len(checks)
        passed_checks = sum(1 for c in checks if c.passed)
        failed_checks = total_checks - passed_checks

        return {
            "total_checks": total_checks,
            "passed_checks": passed_checks,
            "failed_checks": failed_checks,
            "critical_failures": len([c for c in by_severity["critical"] if not c.passed]),
            "high_failures": len([c for c in by_severity["high"] if not c.passed]),
            "medium_failures": len([c for c in by_severity["medium"] if not c.passed]),
            "checks_by_severity": {severity: len(checks_list) for severity, checks_list in by_severity.items()},
            "validation_passed": failed_checks == 0 or all(c.passed or c.severity in ["low", "info"] for c in checks),
        }
