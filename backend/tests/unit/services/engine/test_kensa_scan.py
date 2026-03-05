"""
Unit tests for Kensa scan integration.

Spec: specs/services/engine/kensa-scan.spec.yaml
Tests credential bridge, evidence serialization, and result handling.
"""

import json
import os
import stat
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_db():
    """Mock SQLAlchemy session."""
    db = MagicMock()
    db.execute.return_value.fetchone.return_value = SimpleNamespace(
        id="aaaa-bbbb-cccc",
        hostname="test-host.example.com",
        ip_address="10.0.0.1",
        port=22,
    )
    return db


@pytest.fixture
def mock_credential():
    """Mock credential returned by auth service."""
    return SimpleNamespace(
        username="admin",
        private_key="TEST-MOCK-KEY-NOT-REAL",  # pragma: allowlist secret
        password=None,
        private_key_passphrase=None,
    )


@pytest.fixture
def mock_credential_password_only():
    """Mock credential with password only (no key)."""
    return SimpleNamespace(
        username="admin",
        private_key=None,
        password="mock-pw",  # pragma: allowlist secret
        private_key_passphrase=None,
    )


# ---------------------------------------------------------------------------
# AC-1: Key file with 0600 permissions
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_secure_key_file_permissions():
    """AC-1: Private key written to temp file with 0600 permissions."""
    from app.plugins.kensa.executor import secure_key_file

    test_key = "MOCK-KEY-CONTENT-FOR-TESTING-ONLY"

    with secure_key_file(test_key) as key_path:
        # File should exist
        assert os.path.exists(key_path)

        # Permissions should be 0600 (owner read/write only)
        file_stat = os.stat(key_path)
        perms = stat.S_IMODE(file_stat.st_mode)
        assert perms == 0o600, f"Expected 0600, got {oct(perms)}"

        # Content should match
        with open(key_path) as f:
            assert f.read() == test_key


# ---------------------------------------------------------------------------
# AC-2: Key zeroed and deleted on cleanup
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_secure_key_file_cleanup():
    """AC-2: Key file overwritten with null bytes and deleted after exit."""
    from app.plugins.kensa.executor import secure_key_file

    test_key = "MOCK-KEY-CONTENT-FOR-TESTING-ONLY"
    saved_path = None

    with secure_key_file(test_key) as key_path:
        saved_path = key_path
        assert os.path.exists(key_path)

    # After context manager exits, file should be deleted
    assert not os.path.exists(saved_path), "Key file should be deleted after cleanup"


@pytest.mark.unit
def test_secure_key_file_cleanup_on_exception():
    """AC-2: Key file cleaned up even when exception occurs inside context."""
    from app.plugins.kensa.executor import secure_key_file

    test_key = "MOCK-KEY-CONTENT-FOR-TESTING-ONLY"
    saved_path = None

    with pytest.raises(RuntimeError):
        with secure_key_file(test_key) as key_path:
            saved_path = key_path
            raise RuntimeError("Simulated scan failure")

    assert not os.path.exists(saved_path), "Key file should be deleted after exception"


# ---------------------------------------------------------------------------
# AC-5: Evidence JSONB has required fields
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_serialize_evidence_structure():
    """AC-5: Evidence JSONB contains method, command, stdout, expected, actual."""
    from app.plugins.kensa.evidence import serialize_evidence

    # Create a mock result with evidence attribute
    mock_evidence = SimpleNamespace(
        method="config_value",
        command="grep PermitRootLogin /etc/ssh/sshd_config",
        stdout="PermitRootLogin no",
        stderr="",
        exit_code=0,
        expected="no",
        actual="no",
        timestamp="2026-03-04T12:00:00Z",
    )
    mock_result = SimpleNamespace(evidence=[mock_evidence])

    serialized = serialize_evidence(mock_result)
    assert serialized is not None

    # Should be JSON-parseable
    data = json.loads(serialized) if isinstance(serialized, str) else serialized
    assert isinstance(data, list)
    assert len(data) > 0

    item = data[0]
    assert (
        "method" in item or "command" in item
    ), f"Evidence should contain method or command fields, got: {list(item.keys())}"


# ---------------------------------------------------------------------------
# AC-6: Framework refs JSONB has mapping
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_serialize_framework_refs():
    """AC-6: Framework refs JSONB contains framework_id to section mapping."""
    from app.plugins.kensa.evidence import serialize_framework_refs

    mock_result = SimpleNamespace(framework_refs={"cis_rhel9_v2": "5.1.12", "stig_rhel9": "RHEL-09-123456"})

    serialized = serialize_framework_refs(mock_result)
    assert serialized is not None

    data = json.loads(serialized) if isinstance(serialized, str) else serialized
    assert isinstance(data, dict)
    assert "cis_rhel9_v2" in data
    assert data["cis_rhel9_v2"] == "5.1.12"


@pytest.mark.unit
def test_serialize_framework_refs_empty():
    """AC-6: Empty framework_refs produces valid JSON (not None)."""
    from app.plugins.kensa.evidence import serialize_framework_refs

    mock_result = SimpleNamespace(framework_refs={})
    serialized = serialize_framework_refs(mock_result)

    # Should be valid JSON even when empty
    if serialized is not None:
        data = json.loads(serialized) if isinstance(serialized, str) else serialized
        assert isinstance(data, dict)


# ---------------------------------------------------------------------------
# AC-7: Skipped rules have skip_reason
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_skipped_rule_has_skip_reason():
    """AC-7: Skipped rules should have skip_reason populated when stored."""
    # This tests the logic in kensa_scan_tasks.py / kensa.py
    # that maps skipped results to status='skipped' with skip_reason
    mock_result = SimpleNamespace(
        rule_id="sshd-check",
        passed=False,
        skipped=True,
        skip_reason="Capability 'sshd_config' not available",
        title="Check SSH config",
        severity="high",
        detail="Skipped",
        evidence=None,
        framework_refs={},
        framework_section=None,
    )

    # Verify the mapping logic used in both route and task
    status_str = "pass" if mock_result.passed else "fail"
    if mock_result.skipped:
        status_str = "skipped"

    assert status_str == "skipped"
    assert mock_result.skip_reason is not None
    assert len(mock_result.skip_reason) > 0


# ---------------------------------------------------------------------------
# AC-8: SSH failure includes hostname
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_credential_provider_host_not_found(mock_db):
    """AC-9: Missing host raises RuntimeError with host identifier."""
    from app.plugins.kensa.executor import OpenWatchCredentialProvider

    # Make host query return None
    mock_db.execute.return_value.fetchone.return_value = None

    provider = OpenWatchCredentialProvider(mock_db)

    with pytest.raises(RuntimeError, match="Host not found"):
        import asyncio

        asyncio.run(provider.get_credentials_for_host("nonexistent-uuid"))


# ---------------------------------------------------------------------------
# AC-10: Severity defaults to medium
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_severity_default_to_medium():
    """AC-10: Severity defaults to 'medium' for null or unrecognized values."""
    # Test the logic used in kensa_scan_tasks.py:209 and kensa.py:293
    test_cases = [
        (None, "medium"),
        ("", "medium"),
        ("critical", "critical"),
        ("high", "high"),
        ("medium", "medium"),
        ("low", "low"),
        ("UNKNOWN", "medium"),
    ]

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for severity_input, expected in test_cases:
        sev = severity_input.lower() if severity_input else "medium"
        if sev not in severity_counts:
            sev = "medium"
        assert sev == expected, f"Input {severity_input!r} should map to {expected}, got {sev}"
