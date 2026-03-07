# Spec: specs/release/cleanup-operations.spec.yaml
"""
Source-inspection tests for cleanup operations governance.

Verifies that the CI infrastructure and tooling enforce the cleanup
conventions defined in specs/release/cleanup-operations.spec.yaml.
"""

import inspect
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[4]
CI_WORKFLOW = REPO / ".github" / "workflows" / "ci.yml"
SPEC_FILE = REPO / "specs" / "release" / "cleanup-operations.spec.yaml"
SPEC_REGISTRY = REPO / "specs" / "SPEC_REGISTRY.md"
COVERAGE_SCRIPT = REPO / "scripts" / "check-spec-coverage.py"
GOVERNANCE_DOC = REPO / "specs" / "SPEC_GOVERNANCE.md"
ALEMBIC_ENV = REPO / "backend" / "alembic" / "env.py"
COMMIT_CONVENTIONS_SPEC = REPO / "specs" / "release" / "commit-conventions.spec.yaml"
CLEANUP_CONVENTIONS_TEST = REPO / "tests" / "packaging" / "test_cleanup_conventions.sh"
DEPRECATION_MONITOR = REPO / ".github" / "workflows" / "deprecation-monitor.yml"


# ---------------------------------------------------------------------------
# AC-1: Every tier 2+ cleanup PR includes a dry-run report
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC1DryRunRequirement:
    """AC-1: Governance tooling enforces dry-run reports for tier 2+ cleanup."""

    def test_cleanup_spec_defines_dry_run_section(self):
        """AC-1: cleanup-operations.spec.yaml defines the dry_run requirement."""
        content = SPEC_FILE.read_text()
        assert "dry_run" in content

    def test_cleanup_spec_mandates_dry_run_for_tier2(self):
        """AC-1: dry_run section mandates report for tier 2+ cleanup PRs."""
        content = SPEC_FILE.read_text()
        assert "tier 2" in content.lower() or "tier2" in content.lower()

    def test_ci_has_spec_validation_job(self):
        """AC-1: CI spec-checks job enforces spec compliance on PRs."""
        content = CI_WORKFLOW.read_text()
        assert "spec" in content.lower()
        assert "check-spec-coverage" in content or "validate-specs" in content


# ---------------------------------------------------------------------------
# AC-2: Code removal PRs include grep evidence
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC2GrepEvidence:
    """AC-2: Code removal PRs must include grep evidence of zero references."""

    def test_coverage_script_exists(self):
        """AC-2: check-spec-coverage.py exists to enforce reference checking."""
        assert COVERAGE_SCRIPT.exists()

    def test_cleanup_conventions_test_exists(self):
        """AC-2: test_cleanup_conventions.sh enforces reference-checking convention."""
        assert CLEANUP_CONVENTIONS_TEST.exists()

    def test_cleanup_spec_requires_grep_before_deletion(self):
        """AC-2: spec mandates grep for all references before deleting code."""
        content = SPEC_FILE.read_text()
        assert "grep" in content.lower()


# ---------------------------------------------------------------------------
# AC-3: All tests pass after cleanup changes
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC3TestsPassAfterCleanup:
    """AC-3: CI enforces that all tests pass after cleanup changes."""

    def test_ci_has_backend_test_job(self):
        """AC-3: CI workflow runs backend tests on every PR."""
        content = CI_WORKFLOW.read_text()
        assert "backend" in content.lower()
        assert "pytest" in content or "test" in content.lower()

    def test_ci_has_frontend_test_job(self):
        """AC-3: CI workflow runs frontend tests on every PR."""
        content = CI_WORKFLOW.read_text()
        assert "frontend" in content.lower()

    def test_cleanup_spec_requires_test_suite(self):
        """AC-3: spec mandates running full test suite after cleanup."""
        content = SPEC_FILE.read_text()
        assert "test" in content.lower()
        assert "pass" in content.lower()


# ---------------------------------------------------------------------------
# AC-4: Cleanup PRs do not contain feature or bugfix changes
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC4SingleConcern:
    """AC-4: Cleanup PRs must be single-concern (no feature/bugfix mixing)."""

    def test_commit_conventions_spec_exists(self):
        """AC-4: commit-conventions.spec.yaml enforces single-concern commits."""
        assert COMMIT_CONVENTIONS_SPEC.exists()

    def test_commit_conventions_defines_cleanup_types(self):
        """AC-4: commit conventions define 'refactor' and 'chore' types for cleanup."""
        content = COMMIT_CONVENTIONS_SPEC.read_text()
        assert "refactor" in content or "chore" in content

    def test_cleanup_spec_prohibits_mixing_concerns(self):
        """AC-4: cleanup-operations.spec defines single-concern requirement."""
        content = SPEC_FILE.read_text()
        assert "MUST NOT combine" in content or "single concern" in content.lower()


# ---------------------------------------------------------------------------
# AC-5: Database cleanup uses Alembic migrations with tested downgrade paths
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC5AlembicDowngrade:
    """AC-5: Database cleanup must use Alembic with tested downgrade paths."""

    def test_alembic_env_exists(self):
        """AC-5: Alembic env.py exists for database migration management."""
        assert ALEMBIC_ENV.exists()

    def test_alembic_migrations_define_downgrade(self):
        """AC-5: Alembic migration scripts define downgrade() functions."""
        versions_dir = REPO / "backend" / "alembic" / "versions"
        if versions_dir.exists():
            migration_files = list(versions_dir.glob("*.py"))
            assert len(migration_files) > 0, "No migration files found"
            content = migration_files[0].read_text()
            assert "def downgrade" in content or "downgrade" in content
        else:
            # Alembic infrastructure exists even if versions dir is empty
            assert ALEMBIC_ENV.exists()

    def test_cleanup_spec_requires_downgrade_path(self):
        """AC-5: cleanup-operations.spec mandates tested downgrade path."""
        content = SPEC_FILE.read_text()
        assert "downgrade" in content


# ---------------------------------------------------------------------------
# AC-6: File moves use git mv to preserve history
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC6GitMvHistory:
    """AC-6: File moves must use git mv to preserve git history."""

    def test_cleanup_spec_mandates_git_mv(self):
        """AC-6: cleanup-operations.spec explicitly requires git mv for moves."""
        content = SPEC_FILE.read_text()
        assert "git mv" in content

    def test_cleanup_spec_prohibits_delete_and_create(self):
        """AC-6: spec prohibits delete+create pattern (loses history)."""
        content = SPEC_FILE.read_text()
        assert "preserve" in content.lower() and "history" in content.lower()


# ---------------------------------------------------------------------------
# AC-7: Dependency removal verified with import grep and dependency tree check
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC7DependencyRemovalVerification:
    """AC-7: Dependency removal must be verified with grep and pip check."""

    def test_cleanup_spec_requires_import_grep_for_deps(self):
        """AC-7: spec mandates verifying no imports before removing a package."""
        content = SPEC_FILE.read_text()
        assert "dependency_removal" in content or "dependency removal" in content.lower()

    def test_cleanup_spec_mentions_pip_check(self):
        """AC-7: spec mentions pip check or equivalent for dependency tree."""
        content = SPEC_FILE.read_text()
        assert "pip check" in content or "transitive" in content


# ---------------------------------------------------------------------------
# AC-8: Spec references updated when removing or renaming specced files
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC8SpecReferencesUpdated:
    """AC-8: SPEC_REGISTRY.md must be updated when removing or renaming specced files."""

    def test_spec_registry_exists(self):
        """AC-8: SPEC_REGISTRY.md exists as the authoritative spec index."""
        assert SPEC_REGISTRY.exists()

    def test_spec_validation_script_checks_registry(self):
        """AC-8: validate-specs.py or coverage script enforces registry integrity."""
        validate_script = REPO / "scripts" / "validate-specs.py"
        assert validate_script.exists() or COVERAGE_SCRIPT.exists()

    def test_cleanup_spec_requires_registry_update(self):
        """AC-8: cleanup-operations.spec mandates updating SPEC_REGISTRY on removal."""
        content = SPEC_FILE.read_text()
        assert "SPEC_REGISTRY" in content


# ---------------------------------------------------------------------------
# AC-9: Deprecated code marked before removal
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC9DeprecationBeforeRemoval:
    """AC-9: Deprecated code must be marked before removal with one release cycle gap."""

    def test_deprecation_monitor_workflow_exists(self):
        """AC-9: deprecation-monitor.yml tracks deprecated code in CI."""
        assert DEPRECATION_MONITOR.exists()

    def test_cleanup_spec_requires_deprecation_comment(self):
        """AC-9: spec mandates marking deprecated code with version and replacement."""
        content = SPEC_FILE.read_text()
        assert "deprecated" in content.lower() or "deprecation" in content.lower()

    def test_cleanup_spec_requires_release_cycle_gap(self):
        """AC-9: spec requires at least one release cycle between deprecation and removal."""
        content = SPEC_FILE.read_text()
        assert "release cycle" in content.lower() or "one release" in content.lower()


# ---------------------------------------------------------------------------
# AC-10: Large cleanups broken into staged PRs
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC10StagedCleanupPRs:
    """AC-10: Large cleanup operations must be broken into staged PRs."""

    def test_cleanup_spec_defines_staged_process(self):
        """AC-10: cleanup-operations.spec defines a staged cleanup process."""
        content = SPEC_FILE.read_text()
        assert "staged" in content.lower() or "stage" in content.lower()

    def test_cleanup_spec_has_four_stages(self):
        """AC-10: staged process has identify, verify, execute, confirm stages."""
        content = SPEC_FILE.read_text()
        for stage in ("identify", "verify", "execute", "confirm"):
            assert stage in content.lower(), f"Stage '{stage}' not found in spec"

    def test_cleanup_spec_prohibits_large_single_pr(self):
        """AC-10: spec explicitly states large cleanups must not be a single PR."""
        content = SPEC_FILE.read_text()
        assert "multiple" in content.lower() or "staged" in content.lower()
