"""
Infrastructure services module.

Provides infrastructure-level services including terminal access,
command sandboxing, HTTP client, email notifications, and webhook security.

Usage:
    from app.services.infrastructure import (
        terminal_service,
        CommandSandbox,
        EmailService,
        verify_webhook_signature,
    )
"""

from .email import EmailService, email_service
from .http import (
    CircuitBreaker,
    HttpClient,
    WebhookHttpClient,
    close_all_clients,
    get_default_client,
    get_webhook_client,
)
from .sandbox import (
    CommandResult,
    CommandSandbox,
    CommandSandboxService,
    CommandSecurityLevel,
    ExecutionRequest,
    ExecutionStatus,
    SecureCommand,
)
from .terminal import TerminalService, terminal_service
from .webhooks import (
    WebhookSecurity,
    create_scan_completed_payload,
    create_scan_failed_payload,
    create_webhook_headers,
    generate_webhook_signature,
    get_webhook_security,
    verify_webhook_signature,
)

__all__ = [
    # Terminal
    "TerminalService",
    "terminal_service",
    # Sandbox
    "CommandSandbox",
    "CommandSandboxService",
    "CommandSecurityLevel",
    "CommandResult",
    "ExecutionRequest",
    "ExecutionStatus",
    "SecureCommand",
    # HTTP
    "HttpClient",
    "WebhookHttpClient",
    "CircuitBreaker",
    "get_default_client",
    "get_webhook_client",
    "close_all_clients",
    # Email
    "EmailService",
    "email_service",
    # Webhooks
    "WebhookSecurity",
    "get_webhook_security",
    "generate_webhook_signature",
    "verify_webhook_signature",
    "create_webhook_headers",
    "create_scan_completed_payload",
    "create_scan_failed_payload",
]
