"""
Unit tests for engine data models.

Tests ScanResult, ExecutionContext, enums, and result logic.
"""

import pytest

from app.services.engine.models import (
    ExecutionContext,
    FileTransferSpec,
    LocalScanResult,
    RemoteScanResult,
    ScannerCapabilities,
    ScanProvider,
    ScanResult,
    ScanStatus,
    ScanType,
)


@pytest.mark.unit
class TestScanTypeEnum:
    """Test ScanType enum values."""

    def test_xccdf_profile(self) -> None:
        assert ScanType.XCCDF_PROFILE.value == "xccdf_profile"

    def test_datastream(self) -> None:
        assert ScanType.DATASTREAM.value == "datastream"

    def test_all_values_are_strings(self) -> None:
        for st in ScanType:
            assert isinstance(st.value, str)


@pytest.mark.unit
class TestScanStatusEnum:
    """Test ScanStatus enum values."""

    def test_lifecycle_states(self) -> None:
        """All expected lifecycle states exist."""
        states = {s.value for s in ScanStatus}
        assert "pending" in states
        assert "running" in states
        assert "completed" in states
        assert "failed" in states
        assert "cancelled" in states


@pytest.mark.unit
class TestExecutionContext:
    """Test ExecutionContext data class."""

    def test_basic_creation(self) -> None:
        ctx = ExecutionContext(
            scan_id="scan-123",
            scan_type=ScanType.XCCDF_PROFILE,
            hostname="target.example.com",
            port=22,
            username="scanner",
            timeout=600,
        )
        assert ctx.scan_id == "scan-123"
        assert ctx.hostname == "target.example.com"
        assert ctx.port == 22
        assert ctx.timeout == 600

    def test_defaults(self) -> None:
        ctx = ExecutionContext(
            scan_id="scan-456",
            scan_type=ScanType.DATASTREAM,
            hostname="host1",
        )
        assert ctx.port == 22
        assert ctx.timeout == 1800
        assert ctx.username == ""


@pytest.mark.unit
class TestScanResult:
    """Test ScanResult data class and methods."""

    def test_successful_result(self) -> None:
        result = ScanResult(
            success=True,
            scan_id="scan-1",
            status=ScanStatus.COMPLETED,
            exit_code=0,
            stdout="pass: 10, fail: 2",
            stderr="",
        )
        assert result.success is True
        assert result.status == ScanStatus.COMPLETED

    def test_failed_result(self) -> None:
        result = ScanResult(
            success=False,
            scan_id="scan-2",
            status=ScanStatus.FAILED,
            exit_code=1,
            stdout="",
            stderr="oscap: error",
            error_message="Scan failed",
        )
        assert result.success is False
        assert result.error_message == "Scan failed"

    def test_to_dict(self) -> None:
        result = ScanResult(
            success=True,
            scan_id="scan-3",
            status=ScanStatus.COMPLETED,
            exit_code=0,
        )
        d = result.to_dict()
        assert isinstance(d, dict)
        assert d["scan_id"] == "scan-3"
        assert d["success"] is True

    def test_execution_time(self) -> None:
        result = ScanResult(
            success=True,
            scan_id="scan-4",
            status=ScanStatus.COMPLETED,
            exit_code=0,
            execution_time_seconds=45.5,
        )
        assert result.execution_time_seconds == 45.5


@pytest.mark.unit
class TestRemoteScanResult:
    """Test RemoteScanResult."""

    def test_extends_scan_result(self) -> None:
        result = RemoteScanResult(
            success=True,
            scan_id="scan-5",
            status=ScanStatus.COMPLETED,
            exit_code=0,
            hostname="remote-host",
            result_files=["/tmp/results.xml"],
            files_transferred=2,
        )
        assert result.hostname == "remote-host"
        assert len(result.result_files) == 1
        assert result.files_transferred == 2


@pytest.mark.unit
class TestLocalScanResult:
    """Test LocalScanResult."""

    def test_extends_scan_result(self) -> None:
        result = LocalScanResult(
            success=True,
            scan_id="scan-6",
            status=ScanStatus.COMPLETED,
            exit_code=0,
            content_path="/scap/ssg.xml",
            profile_id="xccdf_profile_stig",
        )
        assert result.content_path == "/scap/ssg.xml"
        assert result.profile_id == "xccdf_profile_stig"


@pytest.mark.unit
class TestScannerCapabilities:
    """Test ScannerCapabilities."""

    def test_creation(self) -> None:
        caps = ScannerCapabilities(
            provider=ScanProvider.OSCAP,
            supported_scan_types=[ScanType.XCCDF_PROFILE, ScanType.DATASTREAM],
            supported_formats=["xccdf", "arf"],
            supports_remote=True,
            supports_local=True,
        )
        assert caps.provider == ScanProvider.OSCAP
        assert len(caps.supported_scan_types) == 2
        assert caps.supports_remote is True


@pytest.mark.unit
class TestFileTransferSpec:
    """Test FileTransferSpec."""

    def test_creation(self) -> None:
        spec = FileTransferSpec(
            local_path="/local/file.xml",
            remote_path="/remote/file.xml",
            direction="upload",
        )
        assert spec.local_path == "/local/file.xml"
        assert spec.direction == "upload"

    def test_defaults(self) -> None:
        spec = FileTransferSpec(
            local_path="/a",
            remote_path="/b",
        )
        assert spec.required is True
        assert spec.verify_size is True


@pytest.mark.unit
class TestEngineExceptions:
    """Test exception hierarchy."""

    def test_engine_error_base(self) -> None:
        from app.services.engine.exceptions import EngineError

        exc = EngineError("test error")
        assert "test error" in str(exc)

    def test_executor_error(self) -> None:
        from app.services.engine.exceptions import ExecutorError

        exc = ExecutorError("executor failed")
        assert isinstance(exc, Exception)

    def test_ssh_execution_error(self) -> None:
        from app.services.engine.exceptions import ExecutorError, SSHExecutionError

        exc = SSHExecutionError("ssh failed")
        assert isinstance(exc, ExecutorError)

    def test_scan_timeout_error(self) -> None:
        from app.services.engine.exceptions import ScanTimeoutError

        exc = ScanTimeoutError("timed out")
        assert isinstance(exc, Exception)

    def test_result_parse_error(self) -> None:
        from app.services.engine.exceptions import ResultParseError

        exc = ResultParseError("parse failed")
        assert isinstance(exc, Exception)

    def test_content_validation_error(self) -> None:
        from app.services.engine.exceptions import ContentValidationError

        exc = ContentValidationError("invalid content")
        assert isinstance(exc, Exception)
