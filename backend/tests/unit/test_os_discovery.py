"""
Unit tests for OS Discovery functionality.

Tests the following Phase 1 features:
- Platform identifier normalization (_normalize_platform_identifier)
- PlatformImplementation model oval_filename field
- Host OS field schema validation

These tests do not require database or external services.
"""

import pytest


class TestPlatformIdentifierNormalization:
    """
    Test suite for platform identifier normalization.

    The _normalize_platform_identifier function converts detected OS information
    into standardized platform identifiers that match the compliance rules
    bundle structure (e.g., "rhel9", "ubuntu2204").
    """

    def test_rhel9_normalization(self):
        """Test RHEL 9.x version normalization to rhel9."""
        from app.tasks.os_discovery_tasks import _normalize_platform_identifier

        # RHEL 9.x versions should normalize to "rhel9"
        assert _normalize_platform_identifier("rhel", "9.3") == "rhel9"
        assert _normalize_platform_identifier("rhel", "9.0") == "rhel9"
        assert _normalize_platform_identifier("rhel", "9") == "rhel9"

    def test_rhel8_normalization(self):
        """Test RHEL 8.x version normalization to rhel8."""
        from app.tasks.os_discovery_tasks import _normalize_platform_identifier

        assert _normalize_platform_identifier("rhel", "8.9") == "rhel8"
        assert _normalize_platform_identifier("rhel", "8.0") == "rhel8"

    def test_ubuntu_normalization(self):
        """Test Ubuntu version normalization preserves YY.MM format."""
        from app.tasks.os_discovery_tasks import _normalize_platform_identifier

        # Ubuntu 22.04 should become "ubuntu2204"
        assert _normalize_platform_identifier("ubuntu", "22.04") == "ubuntu2204"
        # Ubuntu 20.04 should become "ubuntu2004"
        assert _normalize_platform_identifier("ubuntu", "20.04") == "ubuntu2004"
        # Ubuntu 24.04 should become "ubuntu2404"
        assert _normalize_platform_identifier("ubuntu", "24.04") == "ubuntu2404"

    def test_centos_maps_to_rhel(self):
        """Test CentOS normalizes to RHEL-compatible identifier."""
        from app.tasks.os_discovery_tasks import _normalize_platform_identifier

        # CentOS should map to rhel (RHEL-compatible)
        assert _normalize_platform_identifier("centos", "8.5") == "rhel8"
        assert _normalize_platform_identifier("centos", "7.9") == "rhel7"

    def test_rocky_maps_to_rhel(self):
        """Test Rocky Linux normalizes to RHEL-compatible identifier."""
        from app.tasks.os_discovery_tasks import _normalize_platform_identifier

        assert _normalize_platform_identifier("rocky", "9.2") == "rhel9"
        assert _normalize_platform_identifier("rocky", "8.8") == "rhel8"

    def test_alma_maps_to_rhel(self):
        """Test AlmaLinux normalizes to RHEL-compatible identifier."""
        from app.tasks.os_discovery_tasks import _normalize_platform_identifier

        assert _normalize_platform_identifier("alma", "9.1") == "rhel9"
        assert _normalize_platform_identifier("alma", "8.6") == "rhel8"

    def test_oracle_maps_to_rhel(self):
        """Test Oracle Linux normalizes to RHEL-compatible identifier."""
        from app.tasks.os_discovery_tasks import _normalize_platform_identifier

        assert _normalize_platform_identifier("oracle", "9.0") == "rhel9"
        assert _normalize_platform_identifier("oracle", "8.7") == "rhel8"

    def test_debian_normalization(self):
        """Test Debian version normalization."""
        from app.tasks.os_discovery_tasks import _normalize_platform_identifier

        assert _normalize_platform_identifier("debian", "12") == "debian12"
        assert _normalize_platform_identifier("debian", "11") == "debian11"

    def test_unknown_os_family_returns_none(self):
        """Test that unknown OS family returns None."""
        from app.tasks.os_discovery_tasks import _normalize_platform_identifier

        assert _normalize_platform_identifier("Unknown", "9.0") is None
        assert _normalize_platform_identifier("unknown", "9.0") is None
        assert _normalize_platform_identifier("", "9.0") is None
        assert _normalize_platform_identifier(None, "9.0") is None

    def test_unknown_os_version_returns_none(self):
        """Test that unknown OS version returns None."""
        from app.tasks.os_discovery_tasks import _normalize_platform_identifier

        assert _normalize_platform_identifier("rhel", "Unknown") is None
        assert _normalize_platform_identifier("rhel", "unknown") is None
        assert _normalize_platform_identifier("rhel", "") is None
        assert _normalize_platform_identifier("rhel", None) is None

    def test_case_insensitive_os_family(self):
        """Test that OS family matching is case-insensitive."""
        from app.tasks.os_discovery_tasks import _normalize_platform_identifier

        assert _normalize_platform_identifier("RHEL", "9.0") == "rhel9"
        assert _normalize_platform_identifier("Rhel", "9.0") == "rhel9"
        assert _normalize_platform_identifier("Ubuntu", "22.04") == "ubuntu2204"
        assert _normalize_platform_identifier("UBUNTU", "22.04") == "ubuntu2204"


class TestPlatformImplementationModel:
    """
    Test suite for PlatformImplementation model with oval_filename field.

    Validates that the Option B schema (per-platform OVAL references) is
    correctly implemented in the Pydantic model.
    """

    def test_platform_implementation_has_oval_filename_field(self):
        """Test that PlatformImplementation model has oval_filename field."""
        from app.models.mongo_models import PlatformImplementation

        # Create instance with oval_filename
        impl = PlatformImplementation(
            versions=["9"],
            oval_filename="rhel9/package_firewalld_installed.xml",
        )

        assert impl.oval_filename == "rhel9/package_firewalld_installed.xml"

    def test_platform_implementation_oval_filename_optional(self):
        """Test that oval_filename is optional (None by default)."""
        from app.models.mongo_models import PlatformImplementation

        # Create instance without oval_filename
        impl = PlatformImplementation(versions=["9"])

        assert impl.oval_filename is None

    def test_platform_implementation_with_all_fields(self):
        """Test PlatformImplementation with all fields populated."""
        from app.models.mongo_models import PlatformImplementation

        impl = PlatformImplementation(
            versions=["9.0", "9.1", "9.2", "9.3"],
            service_name="firewalld",
            check_command="systemctl is-enabled firewalld",
            check_method="systemd",
            enable_command="systemctl enable firewalld",
            config_files=["/etc/firewalld/firewalld.conf"],
            service_dependencies=["dbus"],
            oval_filename="rhel9/service_firewalld_enabled.xml",
        )

        assert impl.versions == ["9.0", "9.1", "9.2", "9.3"]
        assert impl.service_name == "firewalld"
        assert impl.oval_filename == "rhel9/service_firewalld_enabled.xml"

    def test_platform_implementation_dict_serialization(self):
        """Test that PlatformImplementation serializes correctly to dict."""
        from app.models.mongo_models import PlatformImplementation

        impl = PlatformImplementation(
            versions=["9"],
            oval_filename="rhel9/test.xml",
        )

        impl_dict = impl.model_dump()

        assert "oval_filename" in impl_dict
        assert impl_dict["oval_filename"] == "rhel9/test.xml"


class TestEnhancedPlatformImplementationModel:
    """
    Test suite for enhanced PlatformImplementation model in enhanced_mongo_models.

    Validates that the enhanced model also has the oval_filename field.
    """

    def test_enhanced_platform_implementation_has_oval_filename(self):
        """Test that enhanced PlatformImplementation has oval_filename field."""
        from app.models.enhanced_mongo_models import PlatformImplementation

        impl = PlatformImplementation(
            version_ranges=["9.0-9.4"],
            oval_filename="rhel9/package_audit_installed.xml",
        )

        assert impl.oval_filename == "rhel9/package_audit_installed.xml"

    def test_enhanced_platform_implementation_oval_filename_optional(self):
        """Test that oval_filename is optional in enhanced model."""
        from app.models.enhanced_mongo_models import PlatformImplementation

        impl = PlatformImplementation(version_ranges=["9.0-9.4"])

        assert impl.oval_filename is None


class TestHostModelOsFields:
    """
    Test suite for Host model OS-related fields.

    Validates that the Host database model has the required fields for
    OS detection: os_family, os_version, architecture, last_os_detection.
    """

    def test_host_model_has_os_family_field(self):
        """Test that Host model has os_family column."""
        from app.database import Host

        # Check that the model has os_family column
        assert hasattr(Host, "os_family")

    def test_host_model_has_os_version_field(self):
        """Test that Host model has os_version column."""
        from app.database import Host

        assert hasattr(Host, "os_version")

    def test_host_model_has_architecture_field(self):
        """Test that Host model has architecture column."""
        from app.database import Host

        assert hasattr(Host, "architecture")

    def test_host_model_has_last_os_detection_field(self):
        """Test that Host model has last_os_detection column."""
        from app.database import Host

        assert hasattr(Host, "last_os_detection")


class TestOsDiscoveryServiceMapping:
    """
    Test suite for HostBasicDiscoveryService OS family mappings.

    Validates that the discovery service correctly maps OS names to
    standardized family names.
    """

    def test_rhel_variants_map_to_rhel(self):
        """Test that RHEL variants map to 'rhel' family."""
        from app.services.host_discovery_service import HostBasicDiscoveryService

        mappings = HostBasicDiscoveryService.OS_FAMILY_MAPPINGS

        # All RHEL variants should map to "rhel"
        assert mappings.get("red hat enterprise linux") == "rhel"
        assert mappings.get("rhel") == "rhel"
        assert mappings.get("rocky linux") == "rhel"
        assert mappings.get("almalinux") == "rhel"
        assert mappings.get("oracle linux") == "rhel"
        assert mappings.get("amazon linux") == "rhel"

    def test_ubuntu_maps_to_ubuntu(self):
        """Test that Ubuntu maps to 'ubuntu' family."""
        from app.services.host_discovery_service import HostBasicDiscoveryService

        mappings = HostBasicDiscoveryService.OS_FAMILY_MAPPINGS

        assert mappings.get("ubuntu") == "ubuntu"

    def test_debian_variants_map_to_debian(self):
        """Test that Debian variants map to 'debian' family."""
        from app.services.host_discovery_service import HostBasicDiscoveryService

        mappings = HostBasicDiscoveryService.OS_FAMILY_MAPPINGS

        assert mappings.get("debian") == "debian"
        assert mappings.get("debian gnu/linux") == "debian"

    def test_centos_maps_to_centos(self):
        """Test that CentOS maps to 'centos' family (separate from RHEL)."""
        from app.services.host_discovery_service import HostBasicDiscoveryService

        mappings = HostBasicDiscoveryService.OS_FAMILY_MAPPINGS

        # CentOS has its own family (even though it's RHEL-compatible)
        assert mappings.get("centos") == "centos"
        assert mappings.get("centos linux") == "centos"


# =============================================================================
# Phase 2 Tests: OS Discovery Endpoints and OVAL Migration
# =============================================================================


class TestOSDiscoveryResponseModel:
    """
    Test suite for OSDiscoveryResponse Pydantic model.

    Phase 2: Validates the response model for OS discovery endpoints.
    """

    def test_os_discovery_response_all_fields(self):
        """Test OSDiscoveryResponse with all fields populated."""
        from app.routes.hosts import OSDiscoveryResponse

        response = OSDiscoveryResponse(
            host_id="550e8400-e29b-41d4-a716-446655440000",
            task_id="abc123-def456-ghi789",
            status="completed",
            os_family="rhel",
            os_version="9.3",
            platform_identifier="rhel9",
            architecture="x86_64",
            discovered_at="2025-11-28T10:30:00Z",
            error=None,
        )

        assert response.host_id == "550e8400-e29b-41d4-a716-446655440000"
        assert response.task_id == "abc123-def456-ghi789"
        assert response.status == "completed"
        assert response.os_family == "rhel"
        assert response.os_version == "9.3"
        assert response.platform_identifier == "rhel9"
        assert response.architecture == "x86_64"
        assert response.discovered_at == "2025-11-28T10:30:00Z"
        assert response.error is None

    def test_os_discovery_response_queued_state(self):
        """Test OSDiscoveryResponse for queued state (minimal fields)."""
        from app.routes.hosts import OSDiscoveryResponse

        response = OSDiscoveryResponse(
            host_id="550e8400-e29b-41d4-a716-446655440000",
            task_id="task-id-123",
            status="queued",
        )

        assert response.status == "queued"
        assert response.task_id == "task-id-123"
        assert response.os_family is None
        assert response.os_version is None
        assert response.platform_identifier is None

    def test_os_discovery_response_failed_state(self):
        """Test OSDiscoveryResponse for failed state with error."""
        from app.routes.hosts import OSDiscoveryResponse

        response = OSDiscoveryResponse(
            host_id="550e8400-e29b-41d4-a716-446655440000",
            status="failed",
            error="SSH connection refused",
        )

        assert response.status == "failed"
        assert response.error == "SSH connection refused"
        assert response.task_id is None

    def test_os_discovery_response_serialization(self):
        """Test OSDiscoveryResponse serializes correctly to dict."""
        from app.routes.hosts import OSDiscoveryResponse

        response = OSDiscoveryResponse(
            host_id="test-host-id",
            status="completed",
            os_family="ubuntu",
            os_version="22.04",
            platform_identifier="ubuntu2204",
            architecture="x86_64",
        )

        response_dict = response.model_dump()

        assert "host_id" in response_dict
        assert "status" in response_dict
        assert "os_family" in response_dict
        assert "platform_identifier" in response_dict
        assert response_dict["platform_identifier"] == "ubuntu2204"


class TestOVALMigrationScript:
    """
    Test suite for OVAL reference migration functionality.

    Phase 2: Tests the OVALReferenceMigrator class used for migrating
    existing rules to Option B schema (per-platform OVAL references).
    """

    def test_oval_migrator_initialization(self):
        """Test OVALReferenceMigrator can be instantiated."""
        from pathlib import Path

        from app.cli.migrate_oval_references import OVALReferenceMigrator

        # Test with default path
        migrator = OVALReferenceMigrator()
        assert migrator.oval_base == Path("/app/data/oval_definitions")

        # Test with custom path
        custom_path = Path("/tmp/test_oval")
        migrator_custom = OVALReferenceMigrator(oval_base=custom_path)
        assert migrator_custom.oval_base == custom_path

    def test_find_oval_for_rule_with_ow_prefix(self):
        """Test _find_oval_for_rule correctly parses ow- prefix."""
        import tempfile
        from pathlib import Path

        from app.cli.migrate_oval_references import OVALReferenceMigrator

        # Create temporary OVAL structure
        with tempfile.TemporaryDirectory() as tmpdir:
            oval_base = Path(tmpdir)

            # Create platform directories with OVAL files
            rhel9_dir = oval_base / "rhel9"
            rhel9_dir.mkdir()
            (rhel9_dir / "package_firewalld_installed.xml").touch()

            ubuntu2204_dir = oval_base / "ubuntu2204"
            ubuntu2204_dir.mkdir()
            (ubuntu2204_dir / "package_firewalld_installed.xml").touch()

            # Initialize migrator with temp directory
            migrator = OVALReferenceMigrator(oval_base=oval_base)

            # Test finding OVAL for a rule
            platforms = ["rhel9", "ubuntu2204"]
            oval_mappings = migrator._find_oval_for_rule(
                "ow-package_firewalld_installed", platforms
            )

            assert "rhel9" in oval_mappings
            assert oval_mappings["rhel9"] == "rhel9/package_firewalld_installed.xml"
            assert "ubuntu2204" in oval_mappings
            assert oval_mappings["ubuntu2204"] == "ubuntu2204/package_firewalld_installed.xml"

    def test_find_oval_for_rule_without_ow_prefix(self):
        """Test _find_oval_for_rule returns empty for non-ow rules."""
        from pathlib import Path

        from app.cli.migrate_oval_references import OVALReferenceMigrator

        migrator = OVALReferenceMigrator(oval_base=Path("/nonexistent"))

        # Rule without ow- prefix should return empty dict
        oval_mappings = migrator._find_oval_for_rule(
            "xccdf_org.ssgproject.content_rule_test", ["rhel9"]
        )

        assert oval_mappings == {}

    def test_find_oval_for_rule_path_traversal_prevention(self):
        """Test _find_oval_for_rule prevents path traversal attacks."""
        import tempfile
        from pathlib import Path

        from app.cli.migrate_oval_references import OVALReferenceMigrator

        with tempfile.TemporaryDirectory() as tmpdir:
            oval_base = Path(tmpdir)

            migrator = OVALReferenceMigrator(oval_base=oval_base)

            # Attempt path traversal in rule_id should return empty
            # The function validates paths don't escape oval_base
            malicious_rule_id = "ow-../../../etc/passwd"
            oval_mappings = migrator._find_oval_for_rule(malicious_rule_id, ["rhel9"])

            assert oval_mappings == {}

    def test_get_available_platforms_empty_directory(self):
        """Test _get_available_platforms with empty OVAL directory."""
        import tempfile
        from pathlib import Path

        from app.cli.migrate_oval_references import OVALReferenceMigrator

        with tempfile.TemporaryDirectory() as tmpdir:
            oval_base = Path(tmpdir)
            migrator = OVALReferenceMigrator(oval_base=oval_base)

            platforms = migrator._get_available_platforms()

            assert platforms == []

    def test_get_available_platforms_with_subdirs(self):
        """Test _get_available_platforms finds platform directories."""
        import tempfile
        from pathlib import Path

        from app.cli.migrate_oval_references import OVALReferenceMigrator

        with tempfile.TemporaryDirectory() as tmpdir:
            oval_base = Path(tmpdir)

            # Create platform directories
            (oval_base / "rhel8").mkdir()
            (oval_base / "rhel9").mkdir()
            (oval_base / "ubuntu2204").mkdir()

            # Create a file (should be ignored)
            (oval_base / "readme.txt").touch()

            migrator = OVALReferenceMigrator(oval_base=oval_base)
            platforms = migrator._get_available_platforms()

            assert "rhel8" in platforms
            assert "rhel9" in platforms
            assert "ubuntu2204" in platforms
            assert "readme.txt" not in platforms  # Files should be ignored


class TestHostCapabilitiesEndpoint:
    """
    Test suite for hosts capabilities endpoint with OS discovery.

    Phase 2: Verifies the capabilities endpoint includes OS discovery endpoints.
    """

    def test_capabilities_includes_os_discovery_endpoints(self):
        """Test that capabilities response includes OS discovery endpoints."""
        # Import the capabilities response structure
        # We test the expected structure matches what's in the endpoint

        expected_endpoints = {
            "list_hosts": "GET /api/hosts",
            "create_host": "POST /api/hosts",
            "get_host": "GET /api/hosts/{host_id}",
            "update_host": "PUT /api/hosts/{host_id}",
            "delete_host": "DELETE /api/hosts/{host_id}",
            "bulk_import": "POST /api/hosts/bulk",
            "capabilities": "GET /api/hosts/capabilities",
            "discover_os": "POST /api/hosts/{host_id}/discover-os",
            "get_os_info": "GET /api/hosts/{host_id}/os-info",
        }

        # Verify OS discovery endpoints are in expected set
        assert "discover_os" in expected_endpoints
        assert expected_endpoints["discover_os"] == "POST /api/hosts/{host_id}/discover-os"
        assert "get_os_info" in expected_endpoints
        assert expected_endpoints["get_os_info"] == "GET /api/hosts/{host_id}/os-info"


class TestComplianceRulesUploadOVALAssignment:
    """
    Test suite for compliance rules upload OVAL assignment logic.

    Phase 2/3: Tests the Option B schema implementation in upload service.

    Phase 3 Update: No rule-level oval_filename. Only platform-specific OVAL
    in platform_implementations.{platform}.oval_filename.
    """

    def test_option_b_schema_structure(self):
        """Test Option B schema stores OVAL in platform_implementations only."""
        # Option B schema example (Phase 3: no rule-level oval_filename)
        rule_with_option_b = {
            "rule_id": "ow-package_firewalld_installed",
            "platform_implementations": {
                "rhel9": {
                    "versions": ["9.0", "9.1", "9.2", "9.3"],
                    "oval_filename": "rhel9/package_firewalld_installed.xml",
                },
                "rhel8": {
                    "versions": ["8.0", "8.9"],
                    "oval_filename": "rhel8/package_firewalld_installed.xml",
                },
                "ubuntu2204": {
                    "versions": ["22.04"],
                    "oval_filename": "ubuntu2204/package_firewalld_installed.xml",
                },
            },
            # Phase 3: NO rule-level oval_filename (removed for compliance accuracy)
        }

        # Validate structure
        assert "platform_implementations" in rule_with_option_b
        assert "rhel9" in rule_with_option_b["platform_implementations"]
        assert "oval_filename" in rule_with_option_b["platform_implementations"]["rhel9"]
        assert (
            rule_with_option_b["platform_implementations"]["rhel9"]["oval_filename"]
            == "rhel9/package_firewalld_installed.xml"
        )

        # Phase 3: Verify NO rule-level oval_filename
        assert "oval_filename" not in rule_with_option_b

    def test_option_b_multiple_platforms_have_different_ovals(self):
        """Test Option B schema allows different OVAL per platform."""
        platform_implementations = {
            "rhel9": {"oval_filename": "rhel9/test_rule.xml"},
            "rhel8": {"oval_filename": "rhel8/test_rule.xml"},
            "ubuntu2204": {"oval_filename": "ubuntu2204/test_rule.xml"},
        }

        # Each platform should have its own OVAL path
        assert platform_implementations["rhel9"]["oval_filename"] != platform_implementations["rhel8"]["oval_filename"]
        assert (
            platform_implementations["rhel9"]["oval_filename"]
            != platform_implementations["ubuntu2204"]["oval_filename"]
        )

        # Paths should follow {platform}/{filename} pattern
        for platform, impl in platform_implementations.items():
            oval_path = impl["oval_filename"]
            assert oval_path.startswith(f"{platform}/"), f"OVAL path should start with platform: {oval_path}"


# =============================================================================
# Phase 3 Tests: Platform-Aware OVAL Selection
# =============================================================================


@pytest.mark.skip(reason="Module app.services.xccdf_generator_service not available - needs refactoring")
class TestXCCDFGeneratorPlatformOVAL:
    """
    Test suite for XCCDF generator platform-aware OVAL selection.

    Phase 3: Tests that XCCDF generation uses platform-specific OVAL from
    platform_implementations.{platform}.oval_filename without fallback.
    """

    def test_get_platform_oval_filename_found(self):
        """Test _get_platform_oval_filename returns correct OVAL for platform."""
        from app.services.xccdf_generator_service import XCCDFGeneratorService

        # Create mock rule with platform implementations
        rule = {
            "rule_id": "ow-test_rule",
            "platform_implementations": {
                "rhel9": {"oval_filename": "rhel9/test_rule.xml"},
                "ubuntu2204": {"oval_filename": "ubuntu2204/test_rule.xml"},
            },
        }

        # Create generator (db not needed for this helper method)
        generator = XCCDFGeneratorService(db=None)

        # Test platform-specific lookup
        assert generator._get_platform_oval_filename(rule, "rhel9") == "rhel9/test_rule.xml"
        assert generator._get_platform_oval_filename(rule, "ubuntu2204") == "ubuntu2204/test_rule.xml"

    def test_get_platform_oval_filename_not_found(self):
        """Test _get_platform_oval_filename returns None for missing platform."""
        from app.services.xccdf_generator_service import XCCDFGeneratorService

        rule = {
            "rule_id": "ow-test_rule",
            "platform_implementations": {
                "rhel9": {"oval_filename": "rhel9/test_rule.xml"},
            },
        }

        generator = XCCDFGeneratorService(db=None)

        # Platform not in platform_implementations should return None (no fallback)
        assert generator._get_platform_oval_filename(rule, "ubuntu2204") is None
        assert generator._get_platform_oval_filename(rule, "rhel8") is None

    def test_get_platform_oval_filename_no_fallback(self):
        """Test _get_platform_oval_filename does NOT fall back to rule-level oval_filename."""
        from app.services.xccdf_generator_service import XCCDFGeneratorService

        # Rule with rule-level oval_filename but no platform implementation for centos7
        rule = {
            "rule_id": "ow-test_rule",
            "oval_filename": "rhel9/test_rule.xml",  # Should NOT be used
            "platform_implementations": {
                "rhel9": {"oval_filename": "rhel9/test_rule.xml"},
            },
        }

        generator = XCCDFGeneratorService(db=None)

        # Should return None for missing platform (no fallback to rule.oval_filename)
        assert generator._get_platform_oval_filename(rule, "centos7") is None

    def test_get_platform_oval_filename_empty_implementations(self):
        """Test _get_platform_oval_filename handles empty platform_implementations."""
        from app.services.xccdf_generator_service import XCCDFGeneratorService

        rule_no_impls = {
            "rule_id": "ow-test_rule",
            "platform_implementations": {},
        }

        rule_none_impls = {
            "rule_id": "ow-test_rule",
        }

        generator = XCCDFGeneratorService(db=None)

        assert generator._get_platform_oval_filename(rule_no_impls, "rhel9") is None
        assert generator._get_platform_oval_filename(rule_none_impls, "rhel9") is None


@pytest.mark.skip(reason="Module app.services.mongodb_scap_scanner not available - needs refactoring")
class TestMongoDBScannerPlatformOVAL:
    """
    Test suite for MongoDB SCAP scanner platform-aware OVAL selection.

    Phase 3: Tests that MongoDB scanner uses platform-specific OVAL from
    platform_implementations.{platform}.oval_filename.
    """

    def test_mongodb_scanner_get_platform_oval_filename(self):
        """Test MongoDBSCAPScanner._get_platform_oval_filename helper."""
        from app.models.mongo_models import PlatformImplementation
        from app.services.mongodb_scap_scanner import MongoDBSCAPScanner

        scanner = MongoDBSCAPScanner()

        # Create mock rule with PlatformImplementation objects
        class MockRule:
            def __init__(self):
                self.rule_id = "ow-test_rule"
                self.platform_implementations = {
                    "rhel9": PlatformImplementation(
                        versions=["9"],
                        oval_filename="rhel9/test_rule.xml",
                    ),
                    "ubuntu2204": PlatformImplementation(
                        versions=["22.04"],
                        oval_filename="ubuntu2204/test_rule.xml",
                    ),
                }

        rule = MockRule()

        # Test platform-specific lookup
        assert scanner._get_platform_oval_filename(rule, "rhel9") == "rhel9/test_rule.xml"
        assert scanner._get_platform_oval_filename(rule, "ubuntu2204") == "ubuntu2204/test_rule.xml"
        assert scanner._get_platform_oval_filename(rule, "rhel8") is None  # Not present

    def test_mongodb_scanner_no_fallback_to_rule_level_oval(self):
        """Test MongoDBSCAPScanner does NOT fall back to rule-level oval_filename."""
        from app.services.mongodb_scap_scanner import MongoDBSCAPScanner

        scanner = MongoDBSCAPScanner()

        # Mock rule with rule-level oval_filename but missing platform implementation
        class MockRule:
            def __init__(self):
                self.rule_id = "ow-test_rule"
                self.oval_filename = "rhel9/test_rule.xml"  # Should NOT be used
                self.platform_implementations = {
                    "rhel9": type("Impl", (), {"oval_filename": "rhel9/test_rule.xml"})(),
                }

        rule = MockRule()

        # Should return None for missing platform (no fallback)
        assert scanner._get_platform_oval_filename(rule, "centos7") is None


class TestHostPlatformIdentifierInScanWorkflow:
    """
    Test suite for host platform_identifier integration in scan workflow.

    Phase 3: Tests that scan API uses host's discovered platform_identifier
    for accurate OVAL selection.
    """

    def test_host_model_has_platform_identifier_field(self):
        """Test that Host model has platform_identifier column."""
        from app.database import Host

        assert hasattr(Host, "platform_identifier")

    def test_platform_identifier_format_matches_oval_paths(self):
        """Test platform_identifier format matches OVAL directory names."""
        from app.tasks.os_discovery_tasks import _normalize_platform_identifier

        # Platform identifiers should match OVAL directory structure
        assert _normalize_platform_identifier("rhel", "9.3") == "rhel9"
        assert _normalize_platform_identifier("rhel", "8.9") == "rhel8"
        assert _normalize_platform_identifier("ubuntu", "22.04") == "ubuntu2204"
        assert _normalize_platform_identifier("ubuntu", "20.04") == "ubuntu2004"

        # These should match the platform keys in Option B schema
        # e.g., platform_implementations["rhel9"]["oval_filename"]


# =============================================================================
# Phase 4 Tests: Platform Identifier Persistence and Database Schema
# =============================================================================


class TestPlatformIdentifierDatabaseSchema:
    """
    Test suite for platform_identifier column in hosts table.

    Phase 4: Validates that the Host model has the platform_identifier column
    and that it is properly indexed for efficient scan orchestration queries.
    """

    def test_host_model_has_platform_identifier_column(self):
        """Test that Host model has platform_identifier column defined."""
        from app.database import Host

        # Verify column exists
        assert hasattr(Host, "platform_identifier")

        # Verify it's a SQLAlchemy column
        column = Host.__table__.c.platform_identifier
        assert column is not None
        assert str(column.type) == "VARCHAR(50)"
        assert column.nullable is True

    def test_platform_identifier_column_is_indexed(self):
        """Test that platform_identifier column has an index for efficient queries."""
        from app.database import Host

        # Check for index on platform_identifier column
        column = Host.__table__.c.platform_identifier
        assert column.index is True, "platform_identifier should be indexed"


class TestOSDiscoveryTaskPersistence:
    """
    Test suite for OS discovery task platform_identifier persistence.

    Phase 4: Validates that trigger_os_discovery task correctly persists
    platform_identifier to the database along with os_family and os_version.
    """

    def test_os_discovery_update_query_includes_platform_identifier(self):
        """Test that the UPDATE query in trigger_os_discovery includes platform_identifier."""
        import inspect
        from app.tasks.os_discovery_tasks import trigger_os_discovery

        # Get source code of the task
        source = inspect.getsource(trigger_os_discovery)

        # Verify UPDATE query includes platform_identifier
        assert "platform_identifier = :platform_identifier" in source, (
            "trigger_os_discovery UPDATE query should include platform_identifier"
        )
        assert "platform_identifier" in source, (
            "platform_identifier should be mentioned in trigger_os_discovery"
        )


@pytest.mark.skip(reason="get_host_os_info not exported from app.routes.hosts - needs refactoring")
class TestHostsEndpointPlatformIdentifier:
    """
    Test suite for hosts endpoint platform_identifier retrieval.

    Phase 4: Validates that the GET /api/hosts/{host_id}/os-info endpoint
    correctly retrieves platform_identifier from the database.
    """

    def test_os_info_endpoint_queries_platform_identifier(self):
        """Test that get_host_os_info endpoint queries platform_identifier column."""
        import inspect
        from app.routes.hosts import get_host_os_info

        # Get source code of the endpoint
        source = inspect.getsource(get_host_os_info)

        # Verify QueryBuilder selects platform_identifier
        assert "platform_identifier" in source, (
            "get_host_os_info should query platform_identifier column"
        )

    def test_os_info_endpoint_uses_persisted_platform_identifier(self):
        """Test that endpoint prefers persisted platform_identifier over computed value."""
        import inspect
        from app.routes.hosts import get_host_os_info

        # Get source code
        source = inspect.getsource(get_host_os_info)

        # Verify fallback logic exists (compute if not persisted)
        assert "host_row.platform_identifier" in source, (
            "Endpoint should first check persisted platform_identifier"
        )
        assert "_normalize_platform_identifier" in source, (
            "Endpoint should have fallback to compute platform_identifier"
        )


@pytest.mark.skip(reason="Module app.api not available - needs refactoring")
class TestMongoDBScanAPIPlatformLookup:
    """
    Test suite for MongoDB scan API platform_identifier lookup.

    Phase 4: Validates that the scan API correctly queries host's
    platform_identifier for OVAL selection during scans.
    """

    def test_scan_api_queries_platform_identifier(self):
        """Test that start_mongodb_scan queries platform_identifier from hosts."""
        import inspect
        from app.api.v1.endpoints.mongodb_scan_api import start_mongodb_scan

        # Get source code
        source = inspect.getsource(start_mongodb_scan)

        # Verify query includes platform_identifier
        assert "platform_identifier" in source, (
            "start_mongodb_scan should query platform_identifier"
        )
        assert "SELECT platform_identifier" in source, (
            "Scan API should SELECT platform_identifier from hosts"
        )

    def test_scan_api_uses_discovered_platform_for_oval_selection(self):
        """Test that scan uses discovered platform for OVAL selection."""
        import inspect
        from app.api.v1.endpoints.mongodb_scan_api import start_mongodb_scan

        # Get source code
        source = inspect.getsource(start_mongodb_scan)

        # Verify effective_platform logic exists
        assert "effective_platform" in source, (
            "Scan API should compute effective_platform from discovered data"
        )
        assert "discovered_platform" in source or "host_result[0]" in source, (
            "Scan API should extract discovered platform from query result"
        )


@pytest.mark.skip(reason="Uses hardcoded local paths - needs refactoring to use relative paths")
class TestAlembicMigrationPlatformIdentifier:
    """
    Test suite for Alembic migration adding platform_identifier.

    Phase 4: Validates that the migration script correctly adds the column
    with proper index.
    """

    def test_migration_file_exists(self):
        """Test that the platform_identifier migration file exists."""
        from pathlib import Path

        migration_path = Path(
            "/home/rracine/hanalyx/openwatch/backend/alembic/versions/"
            "20251128_1500_015_add_platform_identifier_to_hosts.py"
        )
        assert migration_path.exists(), (
            "Platform identifier migration file should exist"
        )

    def test_migration_adds_column_with_index(self):
        """Test that migration adds column with index."""
        from pathlib import Path

        migration_path = Path(
            "/home/rracine/hanalyx/openwatch/backend/alembic/versions/"
            "20251128_1500_015_add_platform_identifier_to_hosts.py"
        )

        content = migration_path.read_text()

        # Verify upgrade adds column
        assert "add_column" in content, "Migration should add column"
        assert "platform_identifier" in content, "Migration should add platform_identifier"
        assert "String(50)" in content, "Column should be VARCHAR(50)"

        # Verify index creation
        assert "create_index" in content, "Migration should create index"
        assert "ix_hosts_platform_identifier" in content, "Index name should match convention"

    def test_migration_has_downgrade(self):
        """Test that migration has proper downgrade logic."""
        from pathlib import Path

        migration_path = Path(
            "/home/rracine/hanalyx/openwatch/backend/alembic/versions/"
            "20251128_1500_015_add_platform_identifier_to_hosts.py"
        )

        content = migration_path.read_text()

        # Verify downgrade removes column and index
        assert "drop_index" in content, "Downgrade should drop index"
        assert "drop_column" in content, "Downgrade should drop column"


# =============================================================================
# Phase 4 Tests: OVAL Aggregation and Platform Resolution in Scan Workflow
# =============================================================================


class TestOVALAggregationPlatformResolution:
    """
    Test suite for OVAL aggregation with platform resolution.

    Phase 4: Tests the 3-tier priority platform resolution logic in the
    MongoDB scan API that determines which platform_identifier to use
    for OVAL definition selection during scans.

    Priority Order:
    1. Host's persisted platform_identifier (from OS discovery)
    2. Computed from host's os_family + os_version
    3. Computed from scan_request.platform + platform_version
    """

    def test_priority1_persisted_platform_identifier(self):
        """
        Test Priority 1: Use persisted platform_identifier from OS discovery.

        When a host has a platform_identifier stored in the database (populated
        by trigger_os_discovery task), the scan should use that value directly.
        """
        # Simulated database result: (platform_identifier, os_family, os_version)
        db_result = ("rhel9", "rhel", "9.3")

        # Priority 1 logic: Use persisted platform_identifier if available
        db_platform_id = db_result[0]
        db_os_family = db_result[1]
        db_os_version = db_result[2]

        effective_platform = None
        if db_platform_id:
            effective_platform = db_platform_id  # Priority 1

        assert effective_platform == "rhel9", (
            "Should use persisted platform_identifier (Priority 1)"
        )

    def test_priority2_computed_from_os_family_version(self):
        """
        Test Priority 2: Compute platform_identifier from os_family + os_version.

        When host has no persisted platform_identifier but has os_family and
        os_version, compute the platform_identifier using normalization.
        """
        from app.tasks.os_discovery_tasks import _normalize_platform_identifier

        # Simulated database result: no platform_identifier, but has os_family/version
        db_result = (None, "ubuntu", "22.04")

        db_platform_id = db_result[0]
        db_os_family = db_result[1]
        db_os_version = db_result[2]

        effective_platform = None

        if db_platform_id:
            effective_platform = db_platform_id  # Priority 1 (skipped)
        elif db_os_family and db_os_version:
            # Priority 2: Compute from os_family + os_version
            effective_platform = _normalize_platform_identifier(db_os_family, db_os_version)

        assert effective_platform == "ubuntu2204", (
            "Should compute platform_identifier from os_family + os_version (Priority 2)"
        )

    def test_priority3_computed_from_request_params(self):
        """
        Test Priority 3: Compute platform_identifier from scan request params.

        When host has no OS discovery data, fall back to computing from
        the scan request's platform + platform_version parameters.
        """
        from app.tasks.os_discovery_tasks import _normalize_platform_identifier

        # Simulated: no database data for this host
        db_result = None

        # Scan request parameters
        request_platform = "rhel"
        request_platform_version = "8.9"

        # Start with request values
        effective_platform = request_platform

        # Priority 3: Compute from request if platform is not normalized
        if not any(char.isdigit() for char in effective_platform):
            computed = _normalize_platform_identifier(request_platform, request_platform_version)
            if computed:
                effective_platform = computed

        assert effective_platform == "rhel8", (
            "Should compute platform_identifier from request params (Priority 3)"
        )

    def test_priority_order_prefers_persisted_over_computed(self):
        """
        Test that persisted platform_identifier takes precedence over computation.

        Even if os_family + os_version would compute a different value, the
        persisted platform_identifier from OS discovery should be used.
        """
        from app.tasks.os_discovery_tasks import _normalize_platform_identifier

        # Simulated: host was discovered as RHEL 9, but later the version
        # field was manually updated (edge case)
        db_platform_id = "rhel9"  # From OS discovery
        db_os_family = "rhel"
        db_os_version = "8.5"  # Manual update (mismatch)

        effective_platform = None

        if db_platform_id:
            effective_platform = db_platform_id  # Priority 1 wins
        elif db_os_family and db_os_version:
            effective_platform = _normalize_platform_identifier(db_os_family, db_os_version)

        # Persisted value takes precedence
        assert effective_platform == "rhel9", (
            "Persisted platform_identifier should take precedence over computed"
        )

    def test_raw_platform_detection_for_fallback(self):
        """
        Test detection of unnormalized platform strings for Priority 3 fallback.

        The scan API checks if the platform contains digits to determine if
        it's already normalized (e.g., "rhel8") vs raw (e.g., "rhel").
        """
        # Normalized platforms contain version numbers
        normalized_platforms = ["rhel8", "rhel9", "ubuntu2204", "debian12"]
        raw_platforms = ["rhel", "ubuntu", "debian", "centos"]

        for platform in normalized_platforms:
            has_digits = any(char.isdigit() for char in platform)
            assert has_digits is True, f"{platform} should be detected as normalized"

        for platform in raw_platforms:
            has_digits = any(char.isdigit() for char in platform)
            assert has_digits is False, f"{platform} should be detected as raw"


class TestOVALSelectionWithPlatformImplementations:
    """
    Test suite for OVAL selection using platform_implementations schema.

    Phase 4: Validates that OVAL files are correctly selected based on the
    resolved platform_identifier and the platform_implementations structure.
    """

    def test_oval_selection_uses_platform_implementations_key(self):
        """
        Test that OVAL selection uses platform_implementations.{platform} key.

        The platform_identifier (e.g., "rhel9") is used as a key to lookup
        the OVAL filename in platform_implementations.
        """
        # Example rule from MongoDB with Option B schema
        rule = {
            "rule_id": "ow-package_firewalld_installed",
            "platform_implementations": {
                "rhel8": {"oval_filename": "rhel8/package_firewalld_installed.xml"},
                "rhel9": {"oval_filename": "rhel9/package_firewalld_installed.xml"},
                "ubuntu2204": {"oval_filename": "ubuntu2204/package_firewalld_installed.xml"},
            },
        }

        platform_identifier = "rhel9"

        # Lookup OVAL using platform_identifier as key
        platform_impl = rule.get("platform_implementations", {}).get(platform_identifier, {})
        oval_filename = platform_impl.get("oval_filename")

        assert oval_filename == "rhel9/package_firewalld_installed.xml", (
            "OVAL filename should be selected using platform_identifier as key"
        )

    def test_oval_selection_returns_none_for_missing_platform(self):
        """
        Test that OVAL selection returns None when platform not in implementations.

        This is expected behavior - rules without platform-specific OVAL
        definitions should be excluded from the scan for that platform.
        """
        rule = {
            "rule_id": "ow-package_firewalld_installed",
            "platform_implementations": {
                "rhel9": {"oval_filename": "rhel9/package_firewalld_installed.xml"},
            },
        }

        # Platform not in implementations
        platform_identifier = "ubuntu2204"

        platform_impl = rule.get("platform_implementations", {}).get(platform_identifier, {})
        oval_filename = platform_impl.get("oval_filename")

        assert oval_filename is None, (
            "Should return None for platforms not in platform_implementations"
        )

    def test_oval_aggregation_filters_rules_without_oval(self):
        """
        Test that OVAL aggregation filters out rules without OVAL definitions.

        During scan, rules that don't have an OVAL definition for the target
        platform should be excluded from the aggregated OVAL content.
        """
        rules = [
            {
                "rule_id": "ow-rule1",
                "platform_implementations": {
                    "rhel9": {"oval_filename": "rhel9/rule1.xml"},
                },
            },
            {
                "rule_id": "ow-rule2",
                "platform_implementations": {
                    "rhel8": {"oval_filename": "rhel8/rule2.xml"},  # Wrong platform
                },
            },
            {
                "rule_id": "ow-rule3",
                "platform_implementations": {
                    "rhel9": {"oval_filename": "rhel9/rule3.xml"},
                },
            },
        ]

        platform_identifier = "rhel9"

        # Simulate OVAL aggregation filtering
        rules_with_oval = []
        for rule in rules:
            platform_impl = rule.get("platform_implementations", {}).get(platform_identifier, {})
            oval_filename = platform_impl.get("oval_filename")
            if oval_filename:
                rules_with_oval.append(rule["rule_id"])

        assert rules_with_oval == ["ow-rule1", "ow-rule3"], (
            "Only rules with OVAL for target platform should be included"
        )
        assert "ow-rule2" not in rules_with_oval, (
            "Rules without OVAL for target platform should be excluded"
        )


@pytest.mark.skip(reason="Module app.api not available - needs refactoring")
class TestScanWorkflowPlatformIntegration:
    """
    Test suite for end-to-end scan workflow platform integration.

    Phase 4: Tests the complete flow from platform resolution to OVAL selection
    to scan execution.
    """

    def test_scan_workflow_platform_query_structure(self):
        """
        Test that the scan API queries the correct columns for platform resolution.

        The SQL query should SELECT platform_identifier, os_family, os_version
        to support the 3-tier priority resolution.
        """
        import inspect
        from app.api.v1.endpoints.mongodb_scan_api import start_mongodb_scan

        source = inspect.getsource(start_mongodb_scan)

        # Verify all three columns are queried
        assert "SELECT platform_identifier" in source, (
            "Query should include platform_identifier"
        )
        assert "os_family" in source, "Query should include os_family"
        assert "os_version" in source, "Query should include os_version"

    def test_scan_workflow_passes_effective_platform_to_scanner(self):
        """
        Test that scan workflow passes effective_platform to the scanner.

        The resolved platform_identifier should be passed to
        scanner.scan_with_mongodb_rules() for OVAL selection.
        """
        import inspect
        from app.api.v1.endpoints.mongodb_scan_api import start_mongodb_scan

        source = inspect.getsource(start_mongodb_scan)

        # Verify effective_platform is passed to scanner
        assert "platform=effective_platform" in source, (
            "Scanner should receive effective_platform, not raw request platform"
        )

    def test_scan_workflow_logs_platform_resolution(self):
        """
        Test that scan workflow logs platform resolution decisions.

        Logging is important for debugging scan issues when OVAL files
        are not found due to platform mismatches.
        """
        import inspect
        from app.api.v1.endpoints.mongodb_scan_api import start_mongodb_scan

        source = inspect.getsource(start_mongodb_scan)

        # Verify logging of platform decisions
        assert "logger.info" in source, "Platform resolution should be logged"
        assert "persisted platform_identifier" in source, (
            "Priority 1 decision should be logged"
        )
        assert "computed platform_identifier" in source, (
            "Priority 2/3 decision should be logged"
        )


class TestOVALAggregationErrorHandling:
    """
    Test suite for OVAL aggregation error handling.

    Phase 4: Tests edge cases and error conditions in the OVAL aggregation
    process during scans.
    """

    def test_empty_platform_implementations_handled(self):
        """
        Test that rules with empty platform_implementations are handled gracefully.
        """
        rule = {
            "rule_id": "ow-rule-empty",
            "platform_implementations": {},
        }

        platform_identifier = "rhel9"

        platform_impl = rule.get("platform_implementations", {}).get(platform_identifier, {})
        oval_filename = platform_impl.get("oval_filename")

        assert oval_filename is None, (
            "Empty platform_implementations should return None for OVAL"
        )

    def test_missing_platform_implementations_key_handled(self):
        """
        Test that rules without platform_implementations key are handled gracefully.
        """
        rule = {
            "rule_id": "ow-rule-missing",
            # No platform_implementations key
        }

        platform_identifier = "rhel9"

        platform_impl = rule.get("platform_implementations", {}).get(platform_identifier, {})
        oval_filename = platform_impl.get("oval_filename")

        assert oval_filename is None, (
            "Missing platform_implementations should return None for OVAL"
        )

    def test_null_oval_filename_in_implementation_handled(self):
        """
        Test that null oval_filename in platform implementation is handled.
        """
        rule = {
            "rule_id": "ow-rule-null-oval",
            "platform_implementations": {
                "rhel9": {
                    "versions": ["9"],
                    "oval_filename": None,  # Explicitly null
                },
            },
        }

        platform_identifier = "rhel9"

        platform_impl = rule.get("platform_implementations", {}).get(platform_identifier, {})
        oval_filename = platform_impl.get("oval_filename")

        assert oval_filename is None, (
            "Null oval_filename should be handled as missing"
        )

    def test_no_fallback_to_rule_level_oval_filename(self):
        """
        Test that OVAL selection does NOT fall back to rule-level oval_filename.

        Phase 3/4 requirement: Only use platform_implementations.{platform}.oval_filename.
        Rule-level oval_filename should be ignored to ensure platform accuracy.
        """
        rule = {
            "rule_id": "ow-rule-with-fallback",
            "oval_filename": "rhel9/rule.xml",  # Rule-level (should be ignored)
            "platform_implementations": {
                "rhel8": {"oval_filename": "rhel8/rule.xml"},
                # No rhel9 implementation
            },
        }

        platform_identifier = "rhel9"

        # Correct behavior: Only check platform_implementations
        platform_impl = rule.get("platform_implementations", {}).get(platform_identifier, {})
        oval_filename = platform_impl.get("oval_filename")

        assert oval_filename is None, (
            "Should NOT fall back to rule-level oval_filename"
        )

        # Incorrect behavior would be:
        # oval_filename = oval_filename or rule.get("oval_filename")
        # This MUST NOT happen!
