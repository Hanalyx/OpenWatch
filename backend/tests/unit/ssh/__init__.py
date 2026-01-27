"""
SSH Module Unit Tests

Comprehensive unit test suite for the modular SSH service components
implementing the Phase 1-4 SSH modularization architecture.

Test Modules:
    test_config_manager.py:
        - SSHConfigManager initialization with/without database
        - get_setting/set_setting with type conversion
        - SSH host key policy management (strict, auto_add, warning, bypass)
        - Trusted network configuration and CIDR validation
        - SSH client configuration with policy application

    test_known_hosts.py:
        - Known hosts CRUD operations (add, get, remove, update)
        - SHA256 fingerprint generation from public keys
        - Trust status management
        - Database error handling and rollback

    test_connection_manager.py:
        - Connection establishment with multiple auth methods
          (password, ssh_key, agent, both)
        - Command execution with timeout handling
        - Error categorization (auth_failed, key_error, timeout, etc.)
        - Debug mode for paramiko logging

    test_key_validation.py:
        - Security assessment based on NIST SP 800-57
        - Key validation for RSA, Ed25519, ECDSA, DSA
        - Security level determination (SECURE, ACCEPTABLE, DEPRECATED, REJECTED)
        - Key fingerprint generation (MD5 and SHA256)

Test Architecture:
    All tests use mocked dependencies (database sessions, SSH clients)
    to ensure true unit test isolation. Integration tests requiring
    actual SSH connections or database operations are in separate
    test directories.

CLAUDE.md Compliance:
    - Descriptive docstrings on all test functions
    - Type hints where applicable
    - Defensive error handling verification
    - Security-focused test cases (key strength, authentication)
    - No emojis in code
    - Repository pattern not applicable (unit tests with mocks)

Security Testing Coverage:
    - NIST SP 800-57 key management compliance
    - DSA key rejection (disabled in OpenSSH 7.0+)
    - RSA key size validation (minimum 2048 bits)
    - Ed25519 as recommended modern key type
    - Encrypted key passphrase handling
    - Host key verification policies

Usage:
    # Run all SSH unit tests
    pytest backend/tests/unit/ssh/ -v

    # Run specific test module
    pytest backend/tests/unit/ssh/test_config_manager.py -v

    # Run with coverage
    pytest backend/tests/unit/ssh/ --cov=backend.app.services.ssh

References:
    - NIST SP 800-57: Recommendation for Key Management
    - NIST SP 800-53 IA-2: Identification and Authentication
    - OpenSSH Protocol: RFC 4252 (Authentication Protocol)
"""
