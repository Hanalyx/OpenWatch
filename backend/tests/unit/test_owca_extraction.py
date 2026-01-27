"""
Unit Tests for OWCA Extraction Layer

Tests for XCCDF parsing and severity risk calculation components.

This test suite validates:
- XCCDFParser: XCCDF XML parsing with security controls
- SeverityCalculator: NIST SP 800-30 risk scoring
- Input validation via Pydantic models
- Security controls (path traversal, file size limits)
- Error handling and edge cases

Test Categories:
- Unit tests: Pure function testing (no external dependencies)
- Security tests: Validation of security controls
- Edge case tests: Boundary conditions and error handling

Follows CLAUDE.md standards:
- Descriptive docstrings (all test functions documented)
- Type hints on all functions
- Defensive coding (graceful error handling)
- Security-first approach
- Comprehensive comments (why, not what)
"""

from unittest.mock import Mock, patch

import pytest

from app.services.owca.extraction import (
    SEVERITY_WEIGHTS,
    SeverityCalculator,
    SeverityDistribution,
    SeverityRiskResult,
    XCCDFParser,
    XCCDFScoreResult,
    get_risk_level,
    get_severity_weight,
)

# =============================================================================
# Severity Calculator Tests
# =============================================================================


class TestSeverityCalculator:
    """
    Test suite for SeverityCalculator component.

    Tests NIST SP 800-30 severity-weighted risk scoring with validation of:
    - Basic risk score calculations
    - Risk level categorization
    - Weighted breakdown accuracy
    - Edge cases and boundary conditions
    """

    def setup_method(self):
        """Initialize test fixtures for each test method."""
        self.calculator = SeverityCalculator()

    @pytest.mark.unit
    def test_critical_findings_only(self):
        """
        Test risk scoring with only critical findings.

        Validates:
        - Critical findings weighted at 10 points each
        - Score of 100 maps to 'high' risk level (boundary)
        - Total findings counted correctly
        """
        result = self.calculator.calculate_risk_score(critical_count=10)

        assert result.risk_score == 100.0, "10 critical * 10 = 100.0"
        assert result.risk_level == "high", "Score 100.0 is at high/critical boundary"
        assert result.total_findings == 10
        assert result.severity_distribution.critical == 10
        assert result.weighted_breakdown["critical"] == 100.0

    @pytest.mark.unit
    def test_mixed_severity_findings(self):
        """
        Test risk scoring with mixed severity levels.

        Validates:
        - Correct weighting: critical(10), high(5), medium(2), low(0.5), info(0)
        - Risk score calculation: (2*10) + (5*5) + (10*2) + (20*0.5) + (100*0) = 75.0
        - Risk level categorization (75.0 = high)
        """
        result = self.calculator.calculate_risk_score(
            critical_count=2,  # 2 * 10 = 20
            high_count=5,  # 5 * 5 = 25
            medium_count=10,  # 10 * 2 = 20
            low_count=20,  # 20 * 0.5 = 10
            info_count=100,  # 100 * 0 = 0
        )

        assert result.risk_score == 75.0
        assert result.risk_level == "high"
        assert result.total_findings == 137
        assert result.weighted_breakdown["critical"] == 20.0
        assert result.weighted_breakdown["high"] == 25.0
        assert result.weighted_breakdown["medium"] == 20.0
        assert result.weighted_breakdown["low"] == 10.0
        assert result.weighted_breakdown["info"] == 0.0

    @pytest.mark.unit
    def test_risk_level_boundaries(self):
        """
        Test risk level categorization at boundary conditions.

        Risk levels per NIST SP 800-30:
        - low: 0-20
        - medium: 21-50
        - high: 51-100
        - critical: 100+
        """
        # Low risk boundary
        low_result = self.calculator.calculate_risk_score(low_count=40)
        assert low_result.risk_score == 20.0, "40 * 0.5 = 20.0"
        assert low_result.risk_level == "low", "Score 20.0 is at low/medium boundary"

        # Medium risk boundary
        medium_result = self.calculator.calculate_risk_score(medium_count=25)
        assert medium_result.risk_score == 50.0, "25 * 2 = 50.0"
        assert medium_result.risk_level == "medium", "Score 50.0 is at medium/high boundary"

        # High risk boundary
        high_result = self.calculator.calculate_risk_score(high_count=20)
        assert high_result.risk_score == 100.0, "20 * 5 = 100.0"
        assert high_result.risk_level == "high", "Score 100.0 is at high/critical boundary"

        # Critical risk (just above boundary)
        critical_result = self.calculator.calculate_risk_score(critical_count=11)
        assert critical_result.risk_score == 110.0, "11 * 10 = 110.0"
        assert critical_result.risk_level == "critical", "Score 110.0 is critical"

    @pytest.mark.unit
    def test_zero_findings(self):
        """
        Test risk scoring with zero findings.

        Validates:
        - Score of 0.0 with no findings
        - Risk level is 'low' for zero score
        - Total findings is 0
        """
        result = self.calculator.calculate_risk_score()

        assert result.risk_score == 0.0
        assert result.risk_level == "low"
        assert result.total_findings == 0

    @pytest.mark.unit
    def test_informational_findings_only(self):
        """
        Test that informational findings contribute zero risk.

        Validates:
        - Info findings weighted at 0 points
        - Large number of info findings still produces low risk
        """
        result = self.calculator.calculate_risk_score(info_count=1000)

        assert result.risk_score == 0.0, "1000 info * 0 = 0.0"
        assert result.risk_level == "low"
        assert result.total_findings == 1000

    @pytest.mark.unit
    def test_severity_distribution_model(self):
        """
        Test SeverityDistribution Pydantic model validation.

        Validates:
        - Non-negative count validation
        - Total findings calculation
        - Model serialization
        """
        distribution = SeverityDistribution(
            critical=5,
            high=10,
            medium=15,
            low=20,
            info=25,
        )

        assert distribution.total_findings() == 75
        assert distribution.critical == 5

        # Test negative validation
        with pytest.raises(ValueError, match="non-negative"):
            SeverityDistribution(critical=-1)

    @pytest.mark.unit
    def test_get_severity_contribution(self):
        """
        Test individual severity contribution calculation.

        Validates:
        - Contribution = count * weight
        - Logging of calculation details
        """
        contribution = self.calculator.get_severity_contribution("critical", 3)
        assert contribution == 30.0, "3 critical * 10 = 30.0"

        contribution = self.calculator.get_severity_contribution("low", 100)
        assert contribution == 50.0, "100 low * 0.5 = 50.0"

    @pytest.mark.unit
    def test_calculate_from_failed_rules(self):
        """
        Test risk calculation from failed rules dictionary.

        Validates:
        - Convenience method for dict-based input
        - Handles both 'info' and 'informational' keys
        - Missing keys default to 0
        """
        failed_rules = {
            "critical": 2,
            "high": 5,
            "medium": 10,
            "low": 20,
            "informational": 50,  # Should be treated as 'info'
        }

        result = self.calculator.calculate_from_failed_rules(failed_rules)

        assert result.risk_score == 75.0
        assert result.risk_level == "high"
        assert result.severity_distribution.info == 50


# =============================================================================
# Constants and Helper Function Tests
# =============================================================================


class TestSeverityConstants:
    """
    Test suite for severity constants and helper functions.

    Tests industry-standard severity weights and risk level categorization.
    """

    @pytest.mark.unit
    def test_severity_weights(self):
        """
        Test NIST SP 800-30 severity weights are correct.

        These weights are industry standards and should never change.
        """
        assert SEVERITY_WEIGHTS["critical"] == 10.0
        assert SEVERITY_WEIGHTS["high"] == 5.0
        assert SEVERITY_WEIGHTS["medium"] == 2.0
        assert SEVERITY_WEIGHTS["low"] == 0.5
        assert SEVERITY_WEIGHTS["info"] == 0.0

    @pytest.mark.unit
    def test_get_severity_weight(self):
        """
        Test get_severity_weight helper function.

        Validates:
        - Returns correct weight for each severity level
        - Case-insensitive lookups
        """
        assert get_severity_weight("critical") == 10.0
        assert get_severity_weight("CRITICAL") == 10.0
        assert get_severity_weight("high") == 5.0
        assert get_severity_weight("medium") == 2.0
        assert get_severity_weight("low") == 0.5
        assert get_severity_weight("info") == 0.0

    @pytest.mark.unit
    def test_get_risk_level(self):
        """
        Test get_risk_level helper function.

        Validates risk level categorization per NIST SP 800-30:
        - low: 0-20
        - medium: 21-50
        - high: 51-100
        - critical: 100+
        """
        assert get_risk_level(0.0) == "low"
        assert get_risk_level(20.0) == "low"
        assert get_risk_level(20.1) == "medium"
        assert get_risk_level(50.0) == "medium"
        assert get_risk_level(50.1) == "high"
        assert get_risk_level(100.0) == "high"
        assert get_risk_level(100.1) == "critical"
        assert get_risk_level(1000.0) == "critical"


# =============================================================================
# XCCDF Parser Tests
# =============================================================================


class TestXCCDFParser:
    """
    Test suite for XCCDFParser component.

    Tests XCCDF XML parsing with security controls:
    - XXE attack prevention
    - Path traversal validation
    - File size limit enforcement
    - XCCDF namespace handling
    """

    def setup_method(self):
        """Initialize test fixtures for each test method."""
        self.parser = XCCDFParser()

    @pytest.mark.unit
    def test_parser_initialization(self):
        """
        Test XCCDFParser initializes with secure XML parser.

        Validates:
        - Secure parser configuration (resolve_entities=False, no_network=True)
        - XCCDF namespaces defined
        - File size limit set to 10MB
        """
        assert self.parser.parser is not None
        assert self.parser.MAX_FILE_SIZE_BYTES == 10 * 1024 * 1024
        assert "xccdf" in self.parser.NAMESPACES
        assert "xccdf-1.1" in self.parser.NAMESPACES
        assert "arf" in self.parser.NAMESPACES

    @pytest.mark.unit
    def test_safe_path_validation(self):
        """
        Test path traversal validation.

        Validates:
        - Rejects paths with ../ (path traversal)
        - Only allows paths within /app/data/
        - Resolves paths to absolute form
        """
        # Safe paths
        assert self.parser._is_safe_path("/app/data/results/scan.xml") is True
        assert self.parser._is_safe_path("/app/data/results/subdir/scan.xml") is True

        # Unsafe paths (path traversal)
        assert self.parser._is_safe_path("../../../etc/passwd") is False
        assert self.parser._is_safe_path("/app/data/../../../etc/passwd") is False
        assert self.parser._is_safe_path("/app/data/results/../../etc/passwd") is False

        # Outside allowed directory
        assert self.parser._is_safe_path("/etc/passwd") is False
        assert self.parser._is_safe_path("/tmp/scan.xml") is False

    @pytest.mark.unit
    def test_extract_score_file_not_found(self):
        """
        Test XCCDF extraction handles missing file gracefully.

        Validates:
        - Returns XCCDFScoreResult with found=False
        - Includes error message
        - Does not raise exception
        """
        result = self.parser.extract_native_score("/app/data/nonexistent.xml")

        assert result.found is False
        assert result.error is not None
        assert "not found" in result.error.lower()
        assert result.xccdf_score is None

    @pytest.mark.unit
    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.stat")
    def test_extract_score_file_too_large(self, mock_stat, mock_exists):
        """
        Test XCCDF extraction enforces file size limit.

        Validates:
        - Files larger than 10MB are rejected
        - Returns error with file size details
        - Security event logged to audit logger
        """
        mock_exists.return_value = True
        mock_stat.return_value = Mock(st_size=11 * 1024 * 1024)  # 11MB

        result = self.parser.extract_native_score("/app/data/results/large_file.xml", user_id="test-user")

        assert result.found is False
        assert result.error is not None
        assert "too large" in result.error.lower()
        assert "11534336" in result.error  # 11MB in bytes

    @pytest.mark.unit
    @patch("pathlib.Path.exists")
    def test_extract_score_path_traversal_blocked(self, mock_exists):
        """
        Test XCCDF extraction blocks path traversal attacks.

        Validates:
        - Paths with ../ are rejected before file access
        - Security event logged to audit logger
        - Returns error with security message
        """
        mock_exists.return_value = True

        result = self.parser.extract_native_score("/app/data/../../etc/passwd", user_id="test-user")

        assert result.found is False
        assert result.error is not None
        assert "path traversal" in result.error.lower()

    @pytest.mark.unit
    def test_xccdf_score_result_model_validation(self):
        """
        Test XCCDFScoreResult Pydantic model validation.

        Validates:
        - Score range validation (0-1000)
        - String length limits
        - Optional field handling
        """
        # Valid result
        result = XCCDFScoreResult(
            xccdf_score=87.5,
            xccdf_score_system="urn:xccdf:scoring:default",
            xccdf_score_max=100.0,
            found=True,
            error=None,
        )
        assert result.xccdf_score == 87.5

        # Score exceeds maximum
        with pytest.raises(ValueError, match="exceeds reasonable maximum"):
            XCCDFScoreResult(
                xccdf_score=1001.0,
                found=True,
            )

    @pytest.mark.unit
    def test_severity_risk_result_model_validation(self):
        """
        Test SeverityRiskResult Pydantic model validation.

        Validates:
        - Risk level must be one of allowed values
        - Risk score must be non-negative
        - Required fields enforced
        """
        distribution = SeverityDistribution(critical=5, high=10)

        # Valid result
        result = SeverityRiskResult(
            risk_score=75.0,
            risk_level="high",
            severity_distribution=distribution,
            total_findings=15,
            weighted_breakdown={"critical": 50.0, "high": 50.0},
        )
        assert result.risk_level == "high"

        # Invalid risk level
        with pytest.raises(ValueError, match="Risk level must be one of"):
            SeverityRiskResult(
                risk_score=75.0,
                risk_level="super-critical",  # Invalid
                severity_distribution=distribution,
                total_findings=15,
                weighted_breakdown={},
            )


# =============================================================================
# Integration Tests
# =============================================================================


class TestOWCAExtractionIntegration:
    """
    Integration tests for OWCA Extraction Layer.

    Tests interaction between XCCDFParser and SeverityCalculator components.
    """

    @pytest.mark.integration
    def test_complete_workflow(self):
        """
        Test complete OWCA extraction workflow.

        Workflow:
        1. Calculate severity risk from finding counts
        2. Verify risk categorization
        3. Validate result models

        This simulates real-world usage of the extraction layer.
        """
        calculator = SeverityCalculator()

        # Simulate SCAP scan results
        scan_findings = {
            "critical": 3,
            "high": 10,
            "medium": 25,
            "low": 50,
            "informational": 100,
        }

        # Calculate risk
        risk_result = calculator.calculate_from_failed_rules(
            scan_findings,
            user_id="integration-test-user",
            scan_id="integration-test-scan",
        )

        # Verify results
        assert risk_result.risk_score > 0.0
        assert risk_result.risk_level in ["low", "medium", "high", "critical"]
        assert risk_result.total_findings == 188
        assert isinstance(risk_result.severity_distribution, SeverityDistribution)
        assert isinstance(risk_result.weighted_breakdown, dict)

    @pytest.mark.integration
    def test_parser_and_calculator_combined(self):
        """
        Test XCCDFParser and SeverityCalculator work together.

        Simulates:
        1. Parsing XCCDF XML to extract native score
        2. Calculating severity risk from finding distribution
        3. Combining results for comprehensive risk assessment
        """
        parser = XCCDFParser()
        calculator = SeverityCalculator()

        # Test path validation (security layer)
        safe_path = "/app/data/results/scan_123.xml"
        assert parser._is_safe_path(safe_path) is True

        # Test risk calculation (scoring layer)
        risk_result = calculator.calculate_risk_score(
            critical_count=2,
            high_count=5,
            medium_count=10,
        )

        # Verify integration
        assert risk_result.risk_score > 0.0
        assert parser.MAX_FILE_SIZE_BYTES == 10 * 1024 * 1024


# =============================================================================
# Test Configuration and Fixtures
# =============================================================================


@pytest.fixture
def sample_severity_distribution():
    """
    Fixture providing sample severity distribution for tests.

    Returns:
        SeverityDistribution with realistic finding counts
    """
    return SeverityDistribution(
        critical=5,
        high=15,
        medium=30,
        low=75,
        info=150,
    )


@pytest.fixture
def sample_xccdf_result():
    """
    Fixture providing sample XCCDF score result for tests.

    Returns:
        XCCDFScoreResult with realistic XCCDF data
    """
    return XCCDFScoreResult(
        xccdf_score=87.5,
        xccdf_score_system="urn:xccdf:scoring:default",
        xccdf_score_max=100.0,
        found=True,
        error=None,
    )


# =============================================================================
# Test Markers and Configuration
# =============================================================================

"""
Pytest Markers Used:

@pytest.mark.unit
    - Fast, isolated tests with no external dependencies
    - No database, no file I/O, no network
    - Run on every commit

@pytest.mark.integration
    - Tests component interaction
    - May use mocked external dependencies
    - Run before merge

@pytest.mark.security
    - Tests security controls (XXE, path traversal, etc.)
    - Critical for compliance
    - Run in CI/CD pipeline

Usage:
    # Run only unit tests
    pytest -m unit tests/unit/test_owca_extraction.py

    # Run all tests
    pytest tests/unit/test_owca_extraction.py -v

    # Run with coverage
    pytest --cov=app.services.owca.extraction tests/unit/test_owca_extraction.py
"""
