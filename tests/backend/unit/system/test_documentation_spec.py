"""
Source-inspection tests for documentation structure.

Spec: specs/system/documentation.spec.yaml
"""

import os

import pytest

PROJECT_ROOT = os.path.join(os.path.dirname(__file__), "../../../..")


@pytest.mark.unit
class TestAC1DocsReadme:
    """AC-1: docs/README.md exists and serves as documentation index."""

    def test_readme_exists(self):
        path = os.path.join(PROJECT_ROOT, "docs/README.md")
        assert os.path.exists(path)

    def test_readme_not_empty(self):
        path = os.path.join(PROJECT_ROOT, "docs/README.md")
        assert os.path.getsize(path) > 100


@pytest.mark.unit
class TestAC2GuidesDirectory:
    """AC-2: docs/guides/ contains quickstart, installation, security guides."""

    def test_quickstart_exists(self):
        path = os.path.join(PROJECT_ROOT, "docs/guides/QUICKSTART.md")
        assert os.path.exists(path)

    def test_installation_exists(self):
        path = os.path.join(PROJECT_ROOT, "docs/guides/INSTALLATION.md")
        assert os.path.exists(path)

    def test_security_hardening_exists(self):
        path = os.path.join(PROJECT_ROOT, "docs/guides/SECURITY_HARDENING.md")
        assert os.path.exists(path)


@pytest.mark.unit
class TestAC3APIGuide:
    """AC-3: docs/guides/API_GUIDE.md documents API endpoints."""

    def test_api_guide_exists(self):
        path = os.path.join(PROJECT_ROOT, "docs/guides/API_GUIDE.md")
        assert os.path.exists(path)


@pytest.mark.unit
class TestAC4UserRolesGuide:
    """AC-4: docs/guides/USER_ROLES.md documents all 6 RBAC roles."""

    def test_user_roles_exists(self):
        path = os.path.join(PROJECT_ROOT, "docs/guides/USER_ROLES.md")
        assert os.path.exists(path)

    def test_roles_documented(self):
        path = os.path.join(PROJECT_ROOT, "docs/guides/USER_ROLES.md")
        content = open(path).read()
        assert "super_admin" in content.lower() or "SUPER_ADMIN" in content


@pytest.mark.unit
class TestAC5Runbooks:
    """AC-5: docs/runbooks/ contains incident response runbooks."""

    def test_runbooks_directory_exists(self):
        path = os.path.join(PROJECT_ROOT, "docs/runbooks")
        assert os.path.isdir(path)

    def test_runbooks_not_empty(self):
        path = os.path.join(PROJECT_ROOT, "docs/runbooks")
        files = [f for f in os.listdir(path) if f.endswith(".md")]
        assert len(files) > 0
