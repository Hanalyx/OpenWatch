"""
OpenWatch Security Audit Logger
Handles secure logging of sensitive error information for audit purposes
"""

import hashlib
import json
import logging
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, List, Optional

from ...models.error_models import ErrorSeverity, SecurityAuditLog


class SecurityAuditLogger:
    """Secure audit logger for error classification events"""

    def __init__(self, log_directory: str = "/openwatch/logs/security"):
        self.log_directory = Path(log_directory)
        self.log_directory.mkdir(parents=True, exist_ok=True)

        # Set up security audit logger
        self.logger = logging.getLogger("openwatch.security.audit")
        self.logger.setLevel(logging.INFO)

        # Prevent duplicate handlers
        if not self.logger.handlers:
            self._setup_handlers()

    def _setup_handlers(self):
        """Set up rotating file handler for security audit logs"""

        # Security audit log file
        security_log_file = self.log_directory / "security_audit.log"

        # Rotating file handler - 100MB max, keep 10 files
        security_handler = RotatingFileHandler(
            security_log_file,
            maxBytes=100 * 1024 * 1024,  # 100MB
            backupCount=10,
            encoding="utf-8",
        )

        # JSON formatter for structured logging
        security_formatter = SecurityJSONFormatter()
        security_handler.setFormatter(security_formatter)

        self.logger.addHandler(security_handler)

        # Error classification log file (separate from general security events)
        error_log_file = self.log_directory / "error_classification.log"

        error_handler = RotatingFileHandler(
            error_log_file,
            maxBytes=50 * 1024 * 1024,  # 50MB
            backupCount=5,
            encoding="utf-8",
        )
        error_handler.setFormatter(security_formatter)

        # Create separate logger for error classification
        self.error_logger = logging.getLogger("openwatch.security.error_classification")
        self.error_logger.setLevel(logging.INFO)
        self.error_logger.addHandler(error_handler)

        # Prevent propagation to avoid duplicate logs
        self.logger.propagate = False
        self.error_logger.propagate = False

    def log_error_classification_event(
        self,
        error_code: str,
        technical_details: Dict[str, Any],
        sanitized_response: Dict[str, Any],
        user_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        session_id: Optional[str] = None,
        request_path: Optional[str] = None,
        user_agent: Optional[str] = None,
        severity: ErrorSeverity = ErrorSeverity.ERROR,
    ):
        """Log error classification event with full technical details"""

        # Create audit log entry
        audit_entry = SecurityAuditLog(
            event_type="error_classification",
            error_code=error_code,
            user_id=user_id,
            source_ip=(self._hash_ip(source_ip) if source_ip else None),  # Hash IP for privacy
            session_id=session_id,
            technical_details=technical_details,
            sanitized_response=sanitized_response,
            severity=severity,
            request_path=request_path,
            user_agent=self._sanitize_user_agent(user_agent) if user_agent else None,
        )

        # Log to error classification log
        self.error_logger.info(
            "Error Classification Event",
            extra={
                "audit_entry": audit_entry.dict(),
                "event_type": "error_classification",
                "error_code": error_code,
                "severity": severity.value,
                "user_id_hash": self._hash_value(user_id) if user_id else None,
                "source_ip_hash": self._hash_ip(source_ip) if source_ip else None,
            },
        )

    def log_rate_limit_event(
        self,
        source_ip: str,
        error_count: int,
        action_taken: str,
        user_id: Optional[str] = None,
    ):
        """Log rate limiting security event"""

        self.logger.warning(
            "Rate Limit Security Event",
            extra={
                "event_type": "rate_limit_violation",
                "source_ip_hash": self._hash_ip(source_ip),
                "error_count": error_count,
                "action_taken": action_taken,
                "user_id_hash": self._hash_value(user_id) if user_id else None,
                "timestamp": datetime.utcnow().isoformat(),
            },
        )

    def log_reconnaissance_attempt(
        self,
        source_ip: str,
        suspicious_patterns: List[str],
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ):
        """Log potential reconnaissance attempt"""

        self.logger.critical(
            "Potential Reconnaissance Attempt",
            extra={
                "event_type": "reconnaissance_attempt",
                "source_ip_hash": self._hash_ip(source_ip),
                "suspicious_patterns": suspicious_patterns,
                "user_id_hash": self._hash_value(user_id) if user_id else None,
                "session_id": session_id,
                "timestamp": datetime.utcnow().isoformat(),
                "severity": "critical",
            },
        )

    def _hash_ip(self, ip_address: str) -> str:
        """Hash IP address for privacy while maintaining uniqueness"""
        if not ip_address:
            return None

        # Use SHA-256 with a salt for consistent hashing
        salt = "openwatch_security_salt_2024"
        return hashlib.sha256(f"{salt}{ip_address}".encode()).hexdigest()[:16]

    def _hash_value(self, value: str) -> str:
        """Hash any sensitive value for logging"""
        if not value:
            return None

        salt = "openwatch_audit_salt_2024"
        return hashlib.sha256(f"{salt}{value}".encode()).hexdigest()[:16]

    def _sanitize_user_agent(self, user_agent: str) -> str:
        """Sanitize user agent string to remove potentially sensitive information"""
        if not user_agent:
            return None

        # Keep only the browser/client type, remove version details
        import re

        # Common patterns to keep
        patterns = [
            r"Chrome/[\d\.]+",
            r"Firefox/[\d\.]+",
            r"Safari/[\d\.]+",
            r"Edge/[\d\.]+",
            r"curl/[\d\.]+",
            r"wget/[\d\.]+",
            r"Python-urllib/[\d\.]+",
            r"requests/[\d\.]+",
        ]

        sanitized = "unknown"
        for pattern in patterns:
            match = re.search(pattern, user_agent, re.IGNORECASE)
            if match:
                sanitized = match.group(0)
                break

        return sanitized


class SecurityJSONFormatter(logging.Formatter):
    """JSON formatter for security audit logs"""

    def format(self, record):
        """Format log record as JSON"""

        # Create base log entry
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add extra fields if present
        if hasattr(record, "audit_entry"):
            log_entry["audit_data"] = record.audit_entry

        if hasattr(record, "event_type"):
            log_entry["event_type"] = record.event_type

        if hasattr(record, "error_code"):
            log_entry["error_code"] = record.error_code

        if hasattr(record, "severity"):
            log_entry["severity"] = record.severity

        if hasattr(record, "user_id_hash"):
            log_entry["user_id_hash"] = record.user_id_hash

        if hasattr(record, "source_ip_hash"):
            log_entry["source_ip_hash"] = record.source_ip_hash

        # Add any other extra fields
        for key, value in record.__dict__.items():
            if key not in [
                "name",
                "msg",
                "args",
                "levelname",
                "levelno",
                "pathname",
                "filename",
                "module",
                "exc_info",
                "exc_text",
                "stack_info",
                "lineno",
                "funcName",
                "created",
                "msecs",
                "relativeCreated",
                "thread",
                "threadName",
                "processName",
                "process",
                "message",
                "audit_entry",
                "event_type",
                "error_code",
                "severity",
                "user_id_hash",
                "source_ip_hash",
            ]:
                log_entry[key] = value

        return json.dumps(log_entry, default=str, ensure_ascii=False)


# Global instance for dependency injection
_security_audit_logger = None


def get_security_audit_logger() -> SecurityAuditLogger:
    """Get or create the global security audit logger"""
    global _security_audit_logger
    if _security_audit_logger is None:
        _security_audit_logger = SecurityAuditLogger()
    return _security_audit_logger
