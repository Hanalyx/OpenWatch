"""
Unit tests for ComplianceRuleRepository.

Tests query building, aggregation pipelines, bulk upsert, and deduplication
using mocked Beanie Document operations.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.repositories.compliance_repository import ComplianceRuleRepository


def _mock_repo() -> ComplianceRuleRepository:
    """Create a ComplianceRuleRepository with mocked base methods."""
    repo = ComplianceRuleRepository.__new__(ComplianceRuleRepository)
    repo.model = MagicMock()
    repo.model.__name__ = "ComplianceRule"
    repo.logger = MagicMock()
    repo._slow_query_threshold = 1.0

    # Mock base methods
    repo.find_one = AsyncMock(return_value=None)
    repo.find_many = AsyncMock(return_value=[])
    repo.count = AsyncMock(return_value=0)
    repo.aggregate = AsyncMock(return_value=[])
    repo.create = AsyncMock()
    repo.update_one = AsyncMock()
    return repo


# --- Query building tests ---


@pytest.mark.unit
class TestFindByFramework:
    """Test ComplianceRuleRepository.find_by_framework."""

    @pytest.mark.asyncio
    async def test_builds_correct_query(self) -> None:
        repo = _mock_repo()
        await repo.find_by_framework("CIS")
        repo.find_many.assert_awaited_once_with({"frameworks.CIS": {"$exists": True}})

    @pytest.mark.asyncio
    async def test_with_version(self) -> None:
        repo = _mock_repo()
        await repo.find_by_framework("CIS", version="2.0.0")
        expected = {
            "frameworks.CIS": {"$exists": True},
            "frameworks.CIS.versions.2.0.0": {"$exists": True},
        }
        repo.find_many.assert_awaited_once_with(expected)


@pytest.mark.unit
class TestFindByPlatform:
    """Test ComplianceRuleRepository.find_by_platform."""

    @pytest.mark.asyncio
    async def test_builds_correct_query(self) -> None:
        repo = _mock_repo()
        await repo.find_by_platform("RHEL")
        repo.find_many.assert_awaited_once_with({"platforms.RHEL": {"$exists": True}})

    @pytest.mark.asyncio
    async def test_with_version(self) -> None:
        repo = _mock_repo()
        await repo.find_by_platform("RHEL", version="8")
        expected = {
            "platforms.RHEL": {"$exists": True},
            "platforms.RHEL.versions": "8",
        }
        repo.find_many.assert_awaited_once_with(expected)


@pytest.mark.unit
class TestSearchByTitle:
    """Test ComplianceRuleRepository.search_by_title."""

    @pytest.mark.asyncio
    async def test_case_insensitive_by_default(self) -> None:
        repo = _mock_repo()
        await repo.search_by_title("password")
        repo.find_many.assert_awaited_once_with({"title": {"$regex": "password", "$options": "i"}})

    @pytest.mark.asyncio
    async def test_case_sensitive(self) -> None:
        repo = _mock_repo()
        await repo.search_by_title("SSH", case_sensitive=True)
        repo.find_many.assert_awaited_once_with({"title": {"$regex": "SSH", "$options": ""}})


@pytest.mark.unit
class TestFindBySeverity:
    """Test ComplianceRuleRepository.find_by_severity."""

    @pytest.mark.asyncio
    async def test_builds_correct_query(self) -> None:
        repo = _mock_repo()
        await repo.find_by_severity("critical")
        repo.find_many.assert_awaited_once_with({"severity": "critical"})


@pytest.mark.unit
class TestFindByRuleId:
    """Test ComplianceRuleRepository.find_by_rule_id."""

    @pytest.mark.asyncio
    async def test_builds_correct_query(self) -> None:
        repo = _mock_repo()
        await repo.find_by_rule_id("xccdf_rule_123")
        repo.find_one.assert_awaited_once_with({"rule_id": "xccdf_rule_123"})


@pytest.mark.unit
class TestFindByMultipleFrameworks:
    """Test ComplianceRuleRepository.find_by_multiple_frameworks."""

    @pytest.mark.asyncio
    async def test_builds_or_query(self) -> None:
        repo = _mock_repo()
        await repo.find_by_multiple_frameworks(["CIS", "NIST"])
        expected = {
            "$or": [
                {"frameworks.CIS": {"$exists": True}},
                {"frameworks.NIST": {"$exists": True}},
            ]
        }
        repo.find_many.assert_awaited_once_with(expected)


@pytest.mark.unit
class TestFindByFrameworkAndPlatform:
    """Test ComplianceRuleRepository.find_by_framework_and_platform."""

    @pytest.mark.asyncio
    async def test_builds_correct_query(self) -> None:
        repo = _mock_repo()
        await repo.find_by_framework_and_platform("CIS", "RHEL")
        expected = {
            "frameworks.CIS": {"$exists": True},
            "platforms.RHEL": {"$exists": True},
        }
        repo.find_many.assert_awaited_once_with(expected)


# --- Aggregation tests ---


@pytest.mark.unit
class TestGetStatistics:
    """Test ComplianceRuleRepository.get_statistics."""

    @pytest.mark.asyncio
    async def test_returns_statistics_dict(self) -> None:
        repo = _mock_repo()
        repo.count = AsyncMock(side_effect=[100, 10, 30, 40, 15, 5])
        repo.aggregate = AsyncMock(
            side_effect=[
                [{"_id": "CIS", "count": 80}, {"_id": "NIST", "count": 60}],
                [{"_id": "RHEL", "count": 70}, {"_id": "Ubuntu", "count": 30}],
            ]
        )

        stats = await repo.get_statistics()

        assert stats["total_rules"] == 100
        assert stats["by_severity"]["critical"] == 10
        assert stats["by_framework"]["CIS"] == 80
        assert stats["by_platform"]["RHEL"] == 70


@pytest.mark.unit
class TestGetFrameworkVersions:
    """Test ComplianceRuleRepository.get_framework_versions."""

    @pytest.mark.asyncio
    async def test_returns_version_list(self) -> None:
        repo = _mock_repo()
        repo.aggregate = AsyncMock(return_value=[{"_id": "1.0.0"}, {"_id": "2.0.0"}])

        versions = await repo.get_framework_versions("CIS")

        assert versions == ["1.0.0", "2.0.0"]
        # Verify pipeline has correct $match
        pipeline = repo.aggregate.call_args[0][0]
        assert pipeline[0] == {"$match": {"frameworks.CIS": {"$exists": True}}}


@pytest.mark.unit
class TestFindDuplicates:
    """Test ComplianceRuleRepository.find_duplicates."""

    @pytest.mark.asyncio
    async def test_returns_duplicates(self) -> None:
        repo = _mock_repo()
        repo.aggregate = AsyncMock(return_value=[{"_id": "rule_123", "count": 3, "ids": ["a", "b", "c"]}])

        duplicates = await repo.find_duplicates()

        assert len(duplicates) == 1
        assert duplicates[0]["_id"] == "rule_123"
        assert duplicates[0]["count"] == 3

    @pytest.mark.asyncio
    async def test_pipeline_groups_by_rule_id(self) -> None:
        repo = _mock_repo()
        repo.aggregate = AsyncMock(return_value=[])

        await repo.find_duplicates()

        pipeline = repo.aggregate.call_args[0][0]
        assert pipeline[0]["$group"]["_id"] == "$rule_id"
        assert pipeline[1] == {"$match": {"count": {"$gt": 1}}}


# --- Bulk upsert tests ---


@pytest.mark.unit
class TestBulkUpsert:
    """Test ComplianceRuleRepository.bulk_upsert."""

    @pytest.mark.asyncio
    async def test_inserts_new_rules(self) -> None:
        repo = _mock_repo()
        repo.find_by_rule_id = AsyncMock(return_value=None)

        rule = MagicMock()
        rule.rule_id = "new_rule_1"

        stats = await repo.bulk_upsert([rule], batch_size=10)

        assert stats["inserted"] == 1
        assert stats["updated"] == 0
        repo.create.assert_awaited_once_with(rule)

    @pytest.mark.asyncio
    async def test_updates_existing_rules(self) -> None:
        repo = _mock_repo()
        existing = MagicMock()
        existing.source_hash = "old_hash"
        repo.find_by_rule_id = AsyncMock(return_value=existing)

        rule = MagicMock()
        rule.rule_id = "existing_rule"
        rule.source_hash = "new_hash"
        rule.dict = MagicMock(return_value={"title": "Updated", "severity": "high"})

        stats = await repo.bulk_upsert([rule], batch_size=10)

        assert stats["updated"] == 1
        assert stats["inserted"] == 0
        repo.update_one.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_skips_unchanged_rules(self) -> None:
        repo = _mock_repo()
        existing = MagicMock()
        existing.source_hash = "same_hash"
        repo.find_by_rule_id = AsyncMock(return_value=existing)

        rule = MagicMock()
        rule.rule_id = "unchanged_rule"
        rule.source_hash = "same_hash"

        stats = await repo.bulk_upsert([rule], batch_size=10)

        assert stats["skipped"] == 1
        repo.create.assert_not_awaited()
        repo.update_one.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_handles_per_rule_errors(self) -> None:
        repo = _mock_repo()
        repo.find_by_rule_id = AsyncMock(side_effect=RuntimeError("db error"))

        rule = MagicMock()
        rule.rule_id = "error_rule"

        stats = await repo.bulk_upsert([rule], batch_size=10)

        assert stats["errors"] == 1

    @pytest.mark.asyncio
    async def test_calls_progress_callback(self) -> None:
        repo = _mock_repo()
        repo.find_by_rule_id = AsyncMock(return_value=None)

        rule = MagicMock()
        rule.rule_id = "rule_1"

        callback = MagicMock()
        await repo.bulk_upsert([rule], batch_size=1, progress_callback=callback)

        callback.assert_called_once()
        args = callback.call_args[0]
        assert args[0] == 1  # processed
        assert args[1] == 1  # total
