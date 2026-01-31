"""
Unit tests for engine executors.

Tests BaseExecutor helper methods (command building, result paths,
file transfers, failed result creation) via a concrete test subclass.
"""

from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services.engine.executors.base import BaseExecutor
from app.services.engine.models import ExecutionContext, ExecutionMode, ScanStatus, ScanType


class StubExecutor(BaseExecutor):
    """Concrete stub for testing BaseExecutor helper methods."""

    @property
    def execution_mode(self) -> ExecutionMode:
        return ExecutionMode.LOCAL

    def execute(self, context, content_path, profile_id, credential_data=None, dependencies=None):
        raise NotImplementedError("Stub")

    def validate_environment(self) -> bool:
        return True


@pytest.fixture
def executor() -> StubExecutor:
    return StubExecutor(name="TestStub")


@pytest.fixture
def context() -> ExecutionContext:
    return ExecutionContext(
        scan_id="scan-100",
        scan_type=ScanType.XCCDF_PROFILE,
        hostname="host.example.com",
        port=22,
    )


# ---------------------------------------------------------------------------
# build_result_paths
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestBuildResultPaths:
    """Test result file path generation."""

    def test_returns_three_paths(self, executor: BaseExecutor) -> None:
        paths = executor.build_result_paths(Path("/results"), "scan-1")
        assert "xml" in paths
        assert "html" in paths
        assert "arf" in paths

    def test_paths_contain_scan_id(self, executor: BaseExecutor) -> None:
        paths = executor.build_result_paths(Path("/results"), "scan-42")
        assert "scan-42" in str(paths["xml"])
        assert "scan-42" in str(paths["html"])
        assert "scan-42" in str(paths["arf"])

    def test_paths_use_working_dir(self, executor: BaseExecutor) -> None:
        paths = executor.build_result_paths(Path("/data/output"), "s1")
        for p in paths.values():
            assert str(p).startswith("/data/output")


# ---------------------------------------------------------------------------
# build_oscap_command
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestBuildOscapCommand:
    """Test oscap command line construction."""

    def test_basic_command(self, executor: BaseExecutor) -> None:
        cmd = executor.build_oscap_command(
            profile_id="xccdf_stig",
            content_path="/tmp/ssg.xml",
            result_xml="/tmp/results.xml",
            result_html="/tmp/report.html",
        )
        assert cmd[0] == "oscap"
        assert cmd[1] == "xccdf"
        assert cmd[2] == "eval"
        assert "--profile" in cmd
        assert "xccdf_stig" in cmd
        assert "--results" in cmd
        assert "--report" in cmd
        # Content file must be last
        assert cmd[-1] == "/tmp/ssg.xml"

    def test_with_arf(self, executor: BaseExecutor) -> None:
        cmd = executor.build_oscap_command(
            profile_id="prof",
            content_path="/tmp/ssg.xml",
            result_xml="/tmp/r.xml",
            result_html="/tmp/r.html",
            result_arf="/tmp/arf.xml",
        )
        assert "--results-arf" in cmd
        assert "/tmp/arf.xml" in cmd
        # Content file still last
        assert cmd[-1] == "/tmp/ssg.xml"

    def test_with_rule_id(self, executor: BaseExecutor) -> None:
        cmd = executor.build_oscap_command(
            profile_id="prof",
            content_path="/tmp/ssg.xml",
            result_xml="/tmp/r.xml",
            result_html="/tmp/r.html",
            rule_id="xccdf_rule_enable_fips",
        )
        assert "--rule" in cmd
        assert "xccdf_rule_enable_fips" in cmd

    def test_no_shell_true_risk(self, executor: BaseExecutor) -> None:
        """Command is a list, not a string -- safe from shell injection."""
        cmd = executor.build_oscap_command(
            profile_id="prof; rm -rf /",
            content_path="/tmp/ssg.xml",
            result_xml="/tmp/r.xml",
            result_html="/tmp/r.html",
        )
        assert isinstance(cmd, list)
        # The malicious string is just one element, not interpreted by shell
        assert "prof; rm -rf /" in cmd


# ---------------------------------------------------------------------------
# create_failed_result
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestCreateFailedResult:
    """Test failed-result helper."""

    def test_basic_failure(self, executor: BaseExecutor, context: ExecutionContext) -> None:
        result = executor.create_failed_result(context, RuntimeError("boom"))
        assert result.success is False
        assert result.status == ScanStatus.FAILED
        assert result.exit_code == -1
        assert "boom" in result.error_message

    def test_truncates_long_error(self, executor: BaseExecutor, context: ExecutionContext) -> None:
        long_msg = "x" * 2000
        result = executor.create_failed_result(context, RuntimeError(long_msg))
        assert len(result.error_message) <= 1000

    def test_records_execution_time(self, executor: BaseExecutor, context: ExecutionContext) -> None:
        result = executor.create_failed_result(context, RuntimeError("err"), execution_time=12.5)
        assert result.execution_time_seconds == 12.5


# ---------------------------------------------------------------------------
# prepare_file_transfers
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestPrepareFileTransfers:
    """Test file transfer spec generation."""

    def test_primary_content_only(self, executor: BaseExecutor) -> None:
        transfers = executor.prepare_file_transfers(Path("/local/ssg.xml"))
        assert len(transfers) == 1
        assert transfers[0].direction == "upload"
        assert transfers[0].required is True

    def test_with_dependencies(self, executor: BaseExecutor) -> None:
        dep1 = SimpleNamespace(file_path=Path("/local/dep1.xml"))
        dep2 = SimpleNamespace(file_path=Path("/local/dep2.xml"))
        transfers = executor.prepare_file_transfers(Path("/local/ssg.xml"), dependencies=[dep1, dep2])
        assert len(transfers) == 3

    def test_custom_remote_dir(self, executor: BaseExecutor) -> None:
        transfers = executor.prepare_file_transfers(Path("/local/ssg.xml"), remote_dir="/opt/scap")
        assert "/opt/scap/" in transfers[0].remote_path

    def test_dependency_without_file_path_ignored(self, executor: BaseExecutor) -> None:
        dep = SimpleNamespace(name="no_path")
        transfers = executor.prepare_file_transfers(Path("/local/ssg.xml"), dependencies=[dep])
        # Only the primary content file
        assert len(transfers) == 1


# ---------------------------------------------------------------------------
# Executor properties
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestExecutorProperties:
    """Test executor initialization and properties."""

    def test_name(self) -> None:
        e = StubExecutor(name="MyExec")
        assert e.name == "MyExec"

    def test_execution_mode(self, executor: StubExecutor) -> None:
        assert executor.execution_mode == ExecutionMode.LOCAL

    def test_validate_environment(self, executor: StubExecutor) -> None:
        assert executor.validate_environment() is True
